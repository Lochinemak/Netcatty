//! Addressing a session by name.
//!
//! Every tool that takes a `sessionId` used to need the opaque id, which
//! meant a `get_environment` round trip before the first command and a bare
//! "not in the current scope" when the model guessed. A `sessionId` that is
//! not a scoped id is now matched against the labels and hostnames of the
//! caller's own scope:
//!
//! * exactly one session matches → the call proceeds against it;
//! * several match → the call is rejected and the candidates are returned,
//!   never guessed between (a label is not unique, and running a command on
//!   the wrong host is the failure this must not have);
//! * none match → the usual scope error, with the scope's sessions attached
//!   so the next call can be right.
//!
//! Resolution only ever looks inside the scope the caller already has, and
//! it runs before permission evaluation, so approvals and grants see the
//! session that will actually be used.

use super::{McpHost, EXTERNAL_MCP_CHAT_SESSION_ID};
use serde_json::{json, Map, Value};

/// Sessions listed in an error. A scope is normally a handful of tabs.
const MAX_LISTED_SESSIONS: usize = 20;

#[derive(Debug, PartialEq)]
pub(crate) enum SessionTarget {
    /// A scoped session id already, or nothing to resolve against.
    Unchanged,
    /// The name of exactly one scoped session.
    Resolved(String),
    /// A name shared by several scoped sessions: `{ ok: false, error, sessions }`.
    Ambiguous(Value),
}

struct Candidate {
    id: String,
    label: String,
    hostname: String,
    username: String,
    connected: bool,
}

impl Candidate {
    fn matches(&self, name: &str) -> bool {
        let eq = |v: &str| !v.is_empty() && v.eq_ignore_ascii_case(name);
        eq(&self.label) || eq(&self.hostname) || (!self.username.is_empty() && eq(&format!("{}@{}", self.username, self.hostname)))
    }

    /// Structured, so the privacy boundary masks `hostname` like it does in
    /// `get_environment`; the error text itself carries no host details.
    fn to_value(&self) -> Value {
        json!({ "sessionId": self.id, "label": self.label, "hostname": self.hostname, "username": self.username, "connected": self.connected })
    }
}

fn scoped_ids(p: &Map<String, Value>) -> Option<Vec<String>> {
    p.get("scopedSessionIds").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
}

impl McpHost {
    fn scope_candidates(&self, chat: Option<&str>, ids: &[String]) -> Vec<Candidate> {
        ids.iter()
            .map(|id| {
                let meta = self.session_meta(id, chat);
                let live = self.backend.session(id);
                let pick = |from_meta: Option<&String>, from_live: Option<String>| from_meta.filter(|v| !v.is_empty()).cloned().or(from_live).unwrap_or_default();
                Candidate {
                    id: id.clone(),
                    label: pick(meta.as_ref().map(|m| &m.label), live.as_ref().map(|s| s.label())),
                    hostname: pick(meta.as_ref().map(|m| &m.hostname), live.as_ref().map(|s| s.hostname())),
                    username: pick(meta.as_ref().map(|m| &m.username), live.as_ref().map(|s| s.username())),
                    connected: match &meta {
                        Some(m) => m.connected,
                        None => live.as_ref().is_some_and(|s| s.writer().is_some()),
                    },
                }
            })
            .collect()
    }

    /// The caller's scope, refreshed first when it is the External MCP scope
    /// (which mirrors the live tabs and is otherwise only rebuilt by
    /// `get_environment`) and does not know `wanted`.
    fn scope_for_target(&self, wanted: &str, chat: Option<&str>, explicit: Option<&[String]>) -> Option<Vec<String>> {
        let ids = self.resolve_scoped_session_ids(chat, explicit)?;
        if chat == Some(EXTERNAL_MCP_CHAT_SESSION_ID) && self.external_enabled() && !ids.iter().any(|id| id == wanted) {
            self.sync_live_sessions_to_external_scope();
            return self.resolve_scoped_session_ids(chat, explicit);
        }
        Some(ids)
    }

    /// Resolve `params.sessionId` when it names a session instead of
    /// identifying one.
    pub(crate) fn resolve_session_target(&self, params: &Map<String, Value>) -> SessionTarget {
        let Some(wanted) = params.get("sessionId").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) else {
            return SessionTarget::Unchanged;
        };
        let chat = params.get("chatSessionId").and_then(Value::as_str).filter(|c| !c.is_empty());
        let explicit = scoped_ids(params);
        let Some(ids) = self.scope_for_target(wanted, chat, explicit.as_deref()) else {
            return SessionTarget::Unchanged;
        };
        if ids.iter().any(|id| id == wanted) {
            return SessionTarget::Unchanged;
        }
        let matches: Vec<Candidate> = self.scope_candidates(chat, &ids).into_iter().filter(|c| c.matches(wanted)).collect();
        match matches.as_slice() {
            [] => SessionTarget::Unchanged,
            [only] => SessionTarget::Resolved(only.id.clone()),
            many => SessionTarget::Ambiguous(json!({
                "ok": false,
                "error": format!("\"{wanted}\" matches {} sessions in the current scope. Pass the sessionId of the one you mean.", many.len()),
                "sessions": many.iter().take(MAX_LISTED_SESSIONS).map(Candidate::to_value).collect::<Vec<_>>(),
            })),
        }
    }

    /// A scope error with the sessions the caller could have meant.
    pub(crate) fn scope_error(&self, error: String, params: &Map<String, Value>) -> Value {
        let chat = params.get("chatSessionId").and_then(Value::as_str).filter(|c| !c.is_empty());
        let explicit = scoped_ids(params);
        let mut out = json!({ "ok": false, "error": error });
        if let Some(ids) = self.resolve_scoped_session_ids(chat, explicit.as_deref()) {
            let sessions: Vec<Value> = self.scope_candidates(chat, &ids).iter().take(MAX_LISTED_SESSIONS).map(Candidate::to_value).collect();
            out["sessions"] = Value::Array(sessions);
        }
        out
    }
}
