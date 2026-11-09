//! Per-chat session scopes (Electron `mcpServerBridge.cjs` metadata
//! functions, `retainOwnedSessions.cjs`, `sessionOwnership.cjs`).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Metadata of one terminal session as pushed by the renderer.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionMeta {
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub shell_type: String,
    #[serde(default)]
    pub device_type: String,
    #[serde(default = "default_true")]
    pub connected: bool,
    #[serde(default)]
    pub host_id: String,
    /// `None` = not reported (merge keeps the previous value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_host_id: Option<String>,
    /// `None` = not reported; `Some([])` clears.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_chain: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_port_forwards: Option<Vec<Value>>,
    /// Bridge-assigned update revision (never serialized).
    #[serde(skip)]
    pub revision: u64,
}

fn default_true() -> bool {
    true
}

fn str_field(v: &Map<String, Value>, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

impl SessionMeta {
    /// Normalise one renderer entry (`{ sessionId, hostname, ... }`).
    pub fn from_entry(entry: &Map<String, Value>, revision: u64) -> Self {
        Self {
            hostname: str_field(entry, "hostname"),
            label: str_field(entry, "label"),
            os: str_field(entry, "os"),
            username: str_field(entry, "username"),
            protocol: str_field(entry, "protocol"),
            shell_type: str_field(entry, "shellType"),
            device_type: str_field(entry, "deviceType"),
            connected: entry.get("connected").and_then(Value::as_bool) != Some(false),
            host_id: str_field(entry, "hostId"),
            saved_host_id: Some(str_field(entry, "savedHostId")),
            host_chain: Some(entry.get("hostChain").and_then(Value::as_array).cloned().unwrap_or_default()),
            active_port_forwards: Some(entry.get("activePortForwards").and_then(Value::as_array).cloned().unwrap_or_default()),
            revision,
        }
    }

    /// Public view (`toPublicSessionMeta`): arrays always present.
    pub fn to_public(&self) -> Value {
        serde_json::json!({
            "hostname": self.hostname,
            "label": self.label,
            "os": self.os,
            "username": self.username,
            "protocol": self.protocol,
            "shellType": self.shell_type,
            "deviceType": self.device_type,
            "connected": self.connected,
            "hostId": self.host_id,
            "savedHostId": self.saved_host_id.clone().unwrap_or_default(),
            "hostChain": self.host_chain.clone().unwrap_or_default(),
            "activePortForwards": self.active_port_forwards.clone().unwrap_or_default(),
        })
    }

    /// Host entry of `netcatty/getContext`.
    pub fn to_host(&self, session_id: &str) -> Value {
        serde_json::json!({
            "sessionId": session_id,
            "hostname": self.hostname,
            "label": self.label,
            "os": self.os,
            "username": self.username,
            "protocol": self.protocol,
            "shellType": self.shell_type,
            "deviceType": self.device_type,
            "connected": self.connected,
            "hostId": self.host_id,
            "hostChain": self.host_chain.clone().unwrap_or_default(),
            "activePortForwards": self.active_port_forwards.clone().unwrap_or_default(),
        })
    }

    pub fn is_network_device_like(&self) -> bool {
        let ssh_or_serial = self.protocol == "ssh" || self.protocol == "serial";
        (self.device_type == "network" && ssh_or_serial) || self.protocol == "serial"
    }
}

fn or<'a>(a: &'a str, b: &'a str) -> String {
    if a.is_empty() { b.to_string() } else { a.to_string() }
}

/// Merge two snapshots; the higher revision wins per field (Electron
/// `mergeRetentionMeta`, unversioned input = fallback wins).
pub fn merge_retention_meta(previous: Option<&SessionMeta>, fallback: Option<&SessionMeta>) -> Option<SessionMeta> {
    match (previous, fallback) {
        (None, None) => None,
        (None, Some(f)) => Some(f.clone()),
        (Some(p), None) => Some(p.clone()),
        (Some(p), Some(f)) => {
            let (newer, older) = if f.revision >= p.revision { (f, p) } else { (p, f) };
            Some(SessionMeta {
                hostname: or(&newer.hostname, &older.hostname),
                label: or(&newer.label, &older.label),
                os: or(&newer.os, &older.os),
                username: or(&newer.username, &older.username),
                protocol: or(&newer.protocol, &older.protocol),
                shell_type: or(&newer.shell_type, &older.shell_type),
                device_type: or(&newer.device_type, &older.device_type),
                connected: newer.connected,
                host_id: or(&newer.host_id, &older.host_id),
                saved_host_id: newer.saved_host_id.clone().or_else(|| older.saved_host_id.clone()),
                host_chain: newer.host_chain.clone().or_else(|| older.host_chain.clone()),
                active_port_forwards: newer.active_port_forwards.clone().or_else(|| older.active_port_forwards.clone()),
                revision: p.revision.max(f.revision),
            })
        }
    }
}

/// One chat's scope.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub session_ids: Vec<String>,
    pub metadata: HashMap<String, SessionMeta>,
}

/// Generation token of a chat scope (`captureGeneration`).
#[derive(Debug)]
pub struct ScopeGeneration {
    /// Monotonic identity (survives allocation reuse).
    pub id: u64,
    pub chat_session_id: String,
    pub revoked: std::sync::atomic::AtomicBool,
}

/// `host_open`-owned sessions per chat (`sessionOwnership.cjs`).
#[derive(Default)]
pub struct OwnershipRegistry {
    owned: HashMap<String, HashSet<String>>,
    generations: HashMap<String, Arc<ScopeGeneration>>,
}

impl OwnershipRegistry {
    pub fn capture_generation(&mut self, chat: &str) -> Option<Arc<ScopeGeneration>> {
        if chat.is_empty() {
            return None;
        }
        Some(
            self.generations
                .entry(chat.to_string())
                .or_insert_with(|| {
                    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
                    Arc::new(ScopeGeneration {
                        id: NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                        chat_session_id: chat.to_string(),
                        revoked: Default::default(),
                    })
                })
                .clone(),
        )
    }

    pub fn register(&mut self, chat: &str, session_id: &str, expected: Option<&Arc<ScopeGeneration>>) -> bool {
        if chat.is_empty() || session_id.is_empty() {
            return false;
        }
        if let Some(gen) = expected {
            let current = self.generations.get(chat);
            if gen.revoked.load(std::sync::atomic::Ordering::SeqCst)
                || gen.chat_session_id != chat
                || !current.is_some_and(|c| Arc::ptr_eq(c, gen))
            {
                return false;
            }
        }
        self.owned.entry(chat.to_string()).or_default().insert(session_id.to_string());
        true
    }

    pub fn validate(&self, chat: Option<&str>, session_id: &str) -> Value {
        let Some(chat) = chat.filter(|c| !c.is_empty()) else {
            return serde_json::json!({ "ok": false, "error": "chatSessionId is required." });
        };
        if !self.owned.get(chat).is_some_and(|s| s.contains(session_id)) {
            return serde_json::json!({
                "ok": false,
                "error": format!("Session \"{session_id}\" was not opened by the current AI scope."),
            });
        }
        serde_json::json!({ "ok": true })
    }

    pub fn is_owned(&self, chat: Option<&str>, session_id: &str) -> bool {
        chat.and_then(|c| self.owned.get(c)).is_some_and(|s| s.contains(session_id))
    }

    pub fn list_owned(&self, chat: &str) -> Vec<String> {
        let mut v: Vec<String> = self.owned.get(chat).map(|s| s.iter().cloned().collect()).unwrap_or_default();
        v.sort();
        v
    }

    pub fn forget_session(&mut self, session_id: &str) {
        self.owned.retain(|_, set| {
            set.remove(session_id);
            !set.is_empty()
        });
    }

    /// Drop retained ownership without revoking the generation.
    pub fn release_scope_ownership(&mut self, chat: &str) {
        self.owned.remove(chat);
    }

    /// The chat was deleted: revoke its generation.
    pub fn clear_scope(&mut self, chat: &str) {
        self.owned.remove(chat);
        if let Some(gen) = self.generations.remove(chat) {
            gen.revoked.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    pub fn tracked_generation_count(&self) -> usize {
        self.generations.len()
    }
}

/// Keep owned sessions a full replace would drop (`retainOwnedSessions`).
pub fn retain_owned_sessions(
    incoming: Vec<(String, SessionMeta)>,
    owned: &[String],
    previous: Option<&HashMap<String, SessionMeta>>,
    find_fallback: impl Fn(&str) -> Option<SessionMeta>,
) -> Vec<(String, SessionMeta)> {
    if incoming.is_empty() || owned.is_empty() {
        return incoming;
    }
    let mut out = incoming;
    for id in owned {
        let id = id.trim();
        if id.is_empty() || out.iter().any(|(sid, _)| sid == id) {
            continue;
        }
        let prev = previous.and_then(|m| m.get(id));
        let fallback = find_fallback(id);
        if let Some(meta) = merge_retention_meta(prev, fallback.as_ref()) {
            out.push((id.to_string(), meta));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn meta(connected: bool, rev: u64) -> SessionMeta {
        SessionMeta { label: "web".into(), connected, revision: rev, ..Default::default() }
    }

    #[test]
    fn retains_owned_sessions_on_full_replace_but_not_empty() {
        let incoming = vec![("a".to_string(), meta(true, 2))];
        let mut prev = HashMap::new();
        prev.insert("owned".to_string(), meta(true, 1));
        let out = retain_owned_sessions(incoming.clone(), &["owned".into()], Some(&prev), |_| None);
        assert_eq!(out.len(), 2);
        assert!(retain_owned_sessions(Vec::new(), &["owned".into()], Some(&prev), |_| None).is_empty());
        let out = retain_owned_sessions(incoming, &["ghost".into()], None, |_| None);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn merge_prefers_higher_revision_and_explicit_empty_arrays() {
        let mut older = meta(true, 1);
        older.active_port_forwards = Some(vec![json!({ "ruleId": "r" })]);
        let mut newer = meta(false, 3);
        newer.active_port_forwards = Some(vec![]);
        let merged = merge_retention_meta(Some(&older), Some(&newer)).unwrap();
        assert!(!merged.connected);
        assert_eq!(merged.active_port_forwards, Some(vec![]));
        assert_eq!(merged.revision, 3);
        let merged = merge_retention_meta(Some(&newer), Some(&older)).unwrap();
        assert!(!merged.connected, "higher revision wins in either argument");
        let mut omit = meta(true, 5);
        omit.active_port_forwards = None;
        let merged = merge_retention_meta(Some(&older), Some(&omit)).unwrap();
        assert_eq!(merged.active_port_forwards.unwrap().len(), 1);
    }

    #[test]
    fn ownership_generations() {
        let mut reg = OwnershipRegistry::default();
        let g = reg.capture_generation("chat").unwrap();
        assert!(reg.register("chat", "s1", Some(&g)));
        assert_eq!(reg.validate(Some("chat"), "s1")["ok"], true);
        assert_eq!(reg.validate(Some("other"), "s1")["ok"], false);
        reg.clear_scope("chat");
        assert!(!reg.register("chat", "s2", Some(&g)));
        assert_eq!(reg.tracked_generation_count(), 0);
        reg.register("chat", "s3", None);
        reg.forget_session("s3");
        assert!(reg.list_owned("chat").is_empty());
    }
}
