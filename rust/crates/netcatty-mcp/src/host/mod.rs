//! The per-chat AI control host (Electron `electron/bridges/mcpServerBridge.cjs`
//! and `mcpServerBridge/*.cjs`): session scopes, permission settings,
//! approvals, command execution (foreground + background jobs), session-
//! backed SFTP, attachments, the loopback NDJSON JSON-RPC TCP server with
//! its discovery file, and the capability dispatch shared by the stdio MCP
//! server, the tool CLI, the external MCP server and the renderer harness.

pub mod approvals;
pub mod backend;
pub mod dispatch;
pub mod exec;
pub mod find;
pub mod idle;
pub mod jobs;
pub mod meta;
pub mod sftp;
pub mod target;
pub mod tcp;
pub mod vault_agent;

#[cfg(test)]
mod tests;

use backend::HostBackend;
use idle::SessionIdleManager;
use meta::{merge_retention_meta, retain_owned_sessions, OwnershipRegistry, Scope, SessionMeta};
use netcatty_capabilities::grants::{sanitize_permission_grants, PermissionGrant};
use netcatty_capabilities::{CapabilityDispatcher, SessionService};
use netcatty_ptyexec::cancel::ActiveExecs;
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Weak};

/// Reserved chat scope of External MCP clients.
pub const EXTERNAL_MCP_CHAT_SESSION_ID: &str = "__external_mcp__";
pub const MAX_COMMAND_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
/// Keep below external SDK tool-call timeouts (~120 s).
pub const MCP_APPROVAL_TIMEOUT_MS: u64 = 110_000;
const MAX_CLOSED_TERMINAL_SESSION_REVISIONS: usize = 2048;

/// External MCP enable state and activity hooks (set by the controller).
pub trait ExternalHooks: Send + Sync {
    fn is_enabled(&self) -> bool;
    fn record_activity(&self) {}
    fn on_permission_mode_changed(&self) {}
    fn on_bridge_host_ready(&self, _port: u16) {}
}

/// An attachment registered for a chat scope.
#[derive(Debug, Clone)]
pub struct Attachment {
    pub filename: String,
    pub media_type: String,
    pub file_path: String,
    pub base64_data: String,
    pub size_bytes: Option<usize>,
}

/// Mutable host settings and scope state.
pub(crate) struct State {
    pub command_blocklist: Vec<String>,
    pub command_timeout_ms: u64,
    pub max_iterations: u64,
    pub permission_mode: String,
    pub tool_integration_mode: String,
    pub grants: Vec<PermissionGrant>,
    pub scoped: HashMap<String, Scope>,
    pub live: HashMap<String, SessionMeta>,
    pub revision: u64,
    pub close_revision: u64,
    pub closed_revisions: VecDeque<(String, u64)>,
    pub attachments: HashMap<String, Vec<(String, Attachment)>>,
    pub cancelled_chats: HashSet<String>,
    pub active_chat_execs: HashMap<String, (String, String)>,
    pub ownership: OwnershipRegistry,
}

impl Default for State {
    fn default() -> Self {
        Self {
            command_blocklist: Vec::new(),
            command_timeout_ms: 60_000,
            max_iterations: 20,
            permission_mode: "confirm".into(),
            tool_integration_mode: "mcp".into(),
            grants: Vec::new(),
            scoped: HashMap::new(),
            live: HashMap::new(),
            revision: 0,
            close_revision: 0,
            closed_revisions: VecDeque::new(),
            attachments: HashMap::new(),
            cancelled_chats: HashSet::new(),
            active_chat_execs: HashMap::new(),
            ownership: OwnershipRegistry::default(),
        }
    }
}

pub struct McpHost {
    pub(crate) backend: Arc<dyn HostBackend>,
    pub(crate) st: Mutex<State>,
    pub active_execs: Arc<ActiveExecs>,
    pub(crate) jobs: jobs::Jobs,
    pub(crate) approvals: approvals::Approvals,
    pub idle: Arc<SessionIdleManager>,
    pub vault_agent: Arc<vault_agent::VaultAgentBridge>,
    pub(crate) sessions_svc: Arc<SessionService>,
    pub(crate) capabilities: CapabilityDispatcher,
    pub(crate) tcp: tcp::TcpState,
    pub(crate) external: Mutex<Option<Arc<dyn ExternalHooks>>>,
    pub(crate) me: Weak<McpHost>,
}

impl McpHost {
    /// `cli_discovery_path`: where the tool-CLI discovery file is written.
    pub fn new(backend: Arc<dyn HostBackend>, cli_discovery_path: Option<PathBuf>) -> Arc<Self> {
        Arc::new_cyclic(|me: &Weak<McpHost>| {
            let vault_agent = Arc::new(vault_agent::VaultAgentBridge::new(backend.clone()));
            let hooks = Arc::new(dispatch::HostSessionHooks(me.clone()));
            let sessions_svc = Arc::new(SessionService::new(vault_agent.clone(), hooks));
            let capabilities = CapabilityDispatcher {
                agent: vault_agent.clone(),
                portforward: Arc::new(dispatch::HostPortForwards(backend.clone())),
                sessions: sessions_svc.clone(),
                host: Arc::new(dispatch::HostCapabilityHooks(me.clone())),
            };
            let idle = SessionIdleManager::new(None);
            let weak = me.clone();
            idle.set_on_idle(Arc::new(move |chat, session, version| {
                let weak = weak.clone();
                Box::pin(async move {
                    if let Some(host) = weak.upgrade() {
                        host.on_session_idle(&chat, &session, version).await;
                    }
                })
            }));
            McpHost {
                backend,
                st: Mutex::new(State::default()),
                active_execs: Arc::new(ActiveExecs::default()),
                jobs: jobs::Jobs::default(),
                approvals: approvals::Approvals::default(),
                idle,
                vault_agent,
                sessions_svc,
                capabilities,
                tcp: tcp::TcpState::new(cli_discovery_path),
                external: Mutex::new(None),
                me: me.clone(),
            }
        })
    }

    pub fn set_external_hooks(&self, hooks: Option<Arc<dyn ExternalHooks>>) {
        *self.external.lock() = hooks;
    }

    pub(crate) fn external_enabled(&self) -> bool {
        self.external.lock().as_ref().is_some_and(|h| h.is_enabled())
    }

    // ── settings ─────────────────────────────────────────────────────

    pub fn set_command_blocklist(&self, list: Vec<String>) {
        self.st.lock().command_blocklist = list;
    }

    pub fn command_blocklist(&self) -> Vec<String> {
        self.st.lock().command_blocklist.clone()
    }

    pub fn set_command_timeout(&self, seconds: f64) {
        let s = if seconds.is_finite() && seconds > 0.0 { seconds } else { 60.0 };
        let s = s.clamp(1.0, MAX_COMMAND_TIMEOUT_SECONDS as f64);
        self.st.lock().command_timeout_ms = (s * 1000.0) as u64;
    }

    pub fn command_timeout_ms(&self) -> u64 {
        self.st.lock().command_timeout_ms
    }

    pub fn set_max_iterations(&self, value: f64) {
        let v = if value.is_finite() && value > 0.0 { value } else { 20.0 };
        self.st.lock().max_iterations = v.clamp(1.0, 100.0) as u64;
    }

    pub fn max_iterations(&self) -> u64 {
        self.st.lock().max_iterations
    }

    pub fn set_permission_mode(&self, mode: &str) {
        if !matches!(mode, "observer" | "confirm" | "auto") {
            return;
        }
        self.st.lock().permission_mode = mode.to_string();
        self.write_cli_discovery_file();
        if let Some(h) = self.external.lock().clone() {
            h.on_permission_mode_changed();
        }
    }

    pub fn permission_mode(&self) -> String {
        self.st.lock().permission_mode.clone()
    }

    pub fn set_tool_integration_mode(&self, mode: &str) {
        self.st.lock().tool_integration_mode = mode.to_string();
    }

    pub fn tool_integration_mode(&self) -> String {
        self.st.lock().tool_integration_mode.clone()
    }

    pub fn set_permission_grants(&self, raw: &Value) -> usize {
        let grants = sanitize_permission_grants(raw, now_ms() as f64);
        let n = grants.len();
        self.st.lock().grants = grants;
        n
    }

    pub fn permission_grants(&self) -> Vec<PermissionGrant> {
        self.st.lock().grants.clone()
    }

    pub fn set_session_idle_timeout_minutes(&self, minutes: Option<f64>) -> u64 {
        self.idle.set_timeout_minutes(minutes)
    }

    // ── cancellation ─────────────────────────────────────────────────

    pub fn set_chat_session_cancelled(&self, chat: &str, cancelled: bool) {
        if chat.is_empty() {
            return;
        }
        let mut st = self.st.lock();
        if cancelled {
            st.cancelled_chats.insert(chat.to_string());
        } else {
            st.cancelled_chats.remove(chat);
        }
    }

    pub fn is_chat_session_cancelled(&self, chat: Option<&str>) -> bool {
        chat.is_some_and(|c| !c.is_empty() && self.st.lock().cancelled_chats.contains(c))
    }

    /// Cancel in-flight PTY / channel executions of a chat (`aiCattyCancelExec`).
    pub fn cancel_pty_execs_for_session(&self, chat: &str) {
        self.active_execs.cancel_for_chat(chat);
    }

    pub async fn apply_chat_session_cancelled(&self, chat: &str, cancelled: bool) -> Value {
        if chat.is_empty() {
            return json!({ "ok": false, "error": "chatSessionId is required" });
        }
        self.set_chat_session_cancelled(chat, cancelled);
        if cancelled {
            self.cancel_pty_execs_for_session(chat);
            self.cancel_background_jobs_for_chat(chat);
            self.clear_pending_approvals(Some(chat));
            self.cancel_sftp_ops_for_chat(chat).await;
        }
        json!({ "ok": true, "chatSessionId": chat, "cancelled": cancelled })
    }

    pub(crate) fn begin_chat_execution(&self, chat: Option<&str>, session_id: &str, command: &str) -> Result<ChatExecLock, (String, String)> {
        let Some(chat) = chat.filter(|c| !c.is_empty()) else {
            return Ok(ChatExecLock { host: None, chat: String::new(), session_id: String::new(), command: String::new() });
        };
        let mut st = self.st.lock();
        if let Some((s, c)) = st.active_chat_execs.get(chat) {
            return Err((s.clone(), c.clone()));
        }
        st.active_chat_execs.insert(chat.to_string(), (session_id.to_string(), command.to_string()));
        Ok(ChatExecLock {
            host: Some(self.me.clone()),
            chat: chat.to_string(),
            session_id: session_id.to_string(),
            command: command.to_string(),
        })
    }

    // ── session metadata / scopes ────────────────────────────────────

    /// Authoritative replace of a chat scope (`aiMcpUpdateSessions`).
    pub fn update_session_metadata(&self, sessions: &[Value], chat: Option<&str>) {
        let mut st = self.st.lock();
        st.revision += 1;
        let rev = st.revision;
        let incoming: Vec<(String, SessionMeta)> = sessions
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|e| {
                let id = e.get("sessionId").and_then(Value::as_str).filter(|s| !s.is_empty())?;
                Some((id.to_string(), SessionMeta::from_entry(e, rev)))
            })
            .collect();
        let Some(chat) = chat.filter(|c| !c.is_empty()) else {
            return;
        };
        if incoming.is_empty() {
            st.ownership.release_scope_ownership(chat);
        }
        let owned = st.ownership.list_owned(chat);
        let previous = st.scoped.get(chat).map(|s| s.metadata.clone());
        let effective = {
            let st_ref = &*st;
            retain_owned_sessions(incoming, &owned, previous.as_ref(), |id| find_meta_across_scopes(st_ref, id, Some(chat)))
        };
        Self::store_scope(&mut st, chat, effective);
    }

    fn store_scope(st: &mut State, chat: &str, entries: Vec<(String, SessionMeta)>) {
        let mut scope = Scope::default();
        for (id, meta) in entries {
            if !scope.session_ids.contains(&id) {
                scope.session_ids.push(id.clone());
            }
            scope.metadata.insert(id, meta);
        }
        st.scoped.insert(chat.to_string(), scope);
    }

    /// App-owned live snapshot (`aiMcpUpdateLiveSessions`).
    pub fn update_live_session_metadata(&self, sessions: &[Value]) -> Value {
        let mut st = self.st.lock();
        st.revision += 1;
        let rev = st.revision;
        let mut next = HashMap::new();
        let mut connected = Vec::new();
        for e in sessions.iter().filter_map(Value::as_object) {
            let Some(id) = e.get("sessionId").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
                continue;
            };
            let meta = SessionMeta::from_entry(e, rev);
            if e.get("connected").and_then(Value::as_bool) == Some(true) {
                connected.push(id.to_string());
            }
            next.insert(id.to_string(), meta);
        }
        let count = next.len();
        st.live = next;
        drop(st);
        for id in connected {
            self.sessions_svc.forget_reconnect(&id);
        }
        json!({ "ok": true, "count": count })
    }

    /// Merge into a scope without dropping entries (`aiMcpMergeSessions`).
    pub fn merge_session_metadata(&self, sessions: &[Value], chat: &str) -> Value {
        if chat.is_empty() {
            return json!({ "ok": false, "count": 0 });
        }
        let mut merged: Vec<(String, SessionMeta)> = {
            let st = self.st.lock();
            let mut v: Vec<(String, SessionMeta)> = Vec::new();
            if let Some(scope) = st.scoped.get(chat) {
                for id in &scope.session_ids {
                    if let Some(m) = scope.metadata.get(id) {
                        v.push((id.clone(), m.clone()));
                    }
                }
            }
            v
        };
        for e in sessions.iter().filter_map(Value::as_object) {
            let Some(id) = e.get("sessionId").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
                continue;
            };
            let prev = merged.iter().find(|(i, _)| i == id).map(|(_, m)| m.clone()).unwrap_or_default();
            let s = |k: &str, p: &str| e.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_string).unwrap_or_else(|| p.to_string());
            let meta = SessionMeta {
                hostname: s("hostname", &prev.hostname),
                label: s("label", &prev.label),
                os: s("os", &prev.os),
                username: s("username", &prev.username),
                protocol: s("protocol", &prev.protocol),
                shell_type: s("shellType", &prev.shell_type),
                device_type: s("deviceType", &prev.device_type),
                connected: match e.get("connected") {
                    Some(v) if !v.is_null() => v.as_bool() != Some(false),
                    _ => prev.connected,
                },
                host_id: s("hostId", &prev.host_id),
                saved_host_id: if e.contains_key("savedHostId") {
                    Some(e.get("savedHostId").and_then(Value::as_str).unwrap_or("").to_string())
                } else {
                    prev.saved_host_id.clone()
                },
                host_chain: e.get("hostChain").and_then(Value::as_array).cloned().or(prev.host_chain.clone()),
                active_port_forwards: e.get("activePortForwards").and_then(Value::as_array).cloned().or(prev.active_port_forwards.clone()),
                revision: 0,
            };
            match merged.iter_mut().find(|(i, _)| i == id) {
                Some(slot) => slot.1 = meta,
                None => merged.push((id.to_string(), meta)),
            }
        }
        let count = merged.len();
        let values: Vec<Value> = merged
            .into_iter()
            .map(|(id, m)| {
                let mut v = m.to_public();
                v["sessionId"] = json!(id);
                if m.saved_host_id.is_none() {
                    v.as_object_mut().unwrap().remove("savedHostId");
                }
                v
            })
            .collect();
        self.update_session_metadata(&values, Some(chat));
        json!({ "ok": true, "count": count })
    }

    pub fn scoped_session_ids(&self, chat: Option<&str>) -> Vec<String> {
        chat.and_then(|c| self.st.lock().scoped.get(c).map(|s| s.session_ids.clone())).unwrap_or_default()
    }

    /// Effective scope: explicit ids may only narrow a chat scope.
    pub fn resolve_scoped_session_ids(&self, chat: Option<&str>, explicit: Option<&[String]>) -> Option<Vec<String>> {
        let has_chat = chat.is_some_and(|c| !c.is_empty());
        match (explicit, has_chat) {
            (None, false) => None,
            (Some(e), false) => Some(e.to_vec()),
            (None, true) => Some(self.scoped_session_ids(chat)),
            (Some(e), true) => {
                let ids = self.scoped_session_ids(chat);
                Some(e.iter().filter(|s| ids.contains(s)).cloned().collect())
            }
        }
    }

    /// `None` = allowed; else the scope error message.
    pub fn validate_session_scope(&self, session_id: &str, chat: Option<&str>, explicit: Option<&[String]>) -> Option<String> {
        if session_id.is_empty() {
            return None;
        }
        match self.resolve_scoped_session_ids(chat, explicit) {
            None => Some("chatSessionId or scopedSessionIds is required.".into()),
            Some(ids) if !ids.iter().any(|s| s == session_id) => Some(format!("Session \"{session_id}\" is not in the current scope.")),
            _ => None,
        }
    }

    /// Scoped metadata, refreshed from fresher copies for owned / stale entries.
    pub fn session_meta(&self, session_id: &str, chat: Option<&str>) -> Option<SessionMeta> {
        let chat = chat.filter(|c| !c.is_empty())?;
        let mut st = self.st.lock();
        let meta = st.scoped.get(chat)?.metadata.get(session_id)?.clone();
        let owned = st.ownership.is_owned(Some(chat), session_id);
        if !owned && meta.connected {
            return Some(meta);
        }
        let Some(fresher) = find_meta_across_scopes(&st, session_id, Some(chat)) else {
            return Some(meta);
        };
        if !owned && !fresher.connected {
            return Some(meta);
        }
        let refreshed = merge_retention_meta(Some(&meta), Some(&fresher))?;
        if let Some(scope) = st.scoped.get_mut(chat) {
            scope.metadata.insert(session_id.to_string(), refreshed.clone());
        }
        Some(refreshed)
    }

    pub(crate) fn approval_target(&self, params: &Map<String, Value>) -> Option<Value> {
        let session_id = params.get("sessionId").and_then(Value::as_str).filter(|s| !s.is_empty())?;
        let meta = self.session_meta(session_id, params.get("chatSessionId").and_then(Value::as_str))?;
        let label = if !meta.label.is_empty() {
            meta.label.clone()
        } else if !meta.hostname.is_empty() {
            meta.hostname.clone()
        } else {
            session_id.to_string()
        };
        Some(json!({
            "sessionId": session_id,
            "hostId": meta.saved_host_id.clone().unwrap_or_default(),
            "label": label,
            "hostname": meta.hostname,
        }))
    }

    /// Drop ownership + metadata of a closed terminal session.
    pub fn forget_closed_terminal_session(&self, session_id: &str) {
        if session_id.is_empty() {
            return;
        }
        self.sessions_svc.forget_reconnect(session_id);
        self.sessions_svc.forget_recovery(session_id);
        self.idle.forget_session(session_id);
        let mut st = self.st.lock();
        st.close_revision += 1;
        let rev = st.close_revision;
        st.closed_revisions.retain(|(id, _)| id != session_id);
        st.closed_revisions.push_back((session_id.to_string(), rev));
        while st.closed_revisions.len() > MAX_CLOSED_TERMINAL_SESSION_REVISIONS {
            st.closed_revisions.pop_front();
        }
        Self::forget_meta_locked(&mut st, session_id);
    }

    fn forget_meta_locked(st: &mut State, session_id: &str) {
        st.ownership.forget_session(session_id);
        st.live.remove(session_id);
        for scope in st.scoped.values_mut() {
            scope.session_ids.retain(|id| id != session_id);
            scope.metadata.remove(session_id);
        }
    }

    pub(crate) fn closed_revision_of(&self, session_id: &str) -> u64 {
        self.st.lock().closed_revisions.iter().find(|(id, _)| id == session_id).map(|(_, r)| *r).unwrap_or(0)
    }

    /// `phase`: `begin` | `end` | `touch` | `closed` (renderer activity).
    pub fn report_opened_session_activity(&self, session_id: &str, phase: &str) -> bool {
        match phase {
            "closed" => {
                self.forget_closed_terminal_session(session_id);
                true
            }
            "begin" => self.idle.begin_activity(session_id),
            "end" => self.idle.end_activity(session_id),
            _ => self.idle.touch(session_id),
        }
    }

    async fn on_session_idle(&self, chat: &str, session_id: &str, version: u64) {
        if !self.idle.is_idle_check_current(session_id, version) {
            return;
        }
        if self.jobs.is_session_busy(session_id) {
            self.idle.resume(session_id);
            return;
        }
        if !self.idle.begin_idle_close(session_id, version) {
            return;
        }
        let params = json!({ "chatSessionId": chat, "sessionId": session_id });
        let _ = self.sessions_svc.close(params.as_object().unwrap(), None, true).await;
    }

    /// Chat deleted / cleared (`cleanupScopedMetadata`).
    pub async fn cleanup_scoped_metadata(&self, chat: &str) {
        if chat.is_empty() {
            return;
        }
        {
            let mut st = self.st.lock();
            st.scoped.remove(chat);
            st.attachments.remove(chat);
            st.ownership.clear_scope(chat);
            st.cancelled_chats.remove(chat);
        }
        self.cancel_background_jobs_for_chat(chat);
        self.clear_pending_approvals(Some(chat));
        self.cancel_sftp_ops_for_chat(chat).await;
    }

    /// Rebuild the External MCP scope from live sessions.
    pub fn sync_live_sessions_to_external_scope(&self) -> Value {
        let chat = EXTERNAL_MCP_CHAT_SESSION_ID;
        let ids = self.backend.session_ids();
        let mut list: Vec<Value> = Vec::new();
        let existing: HashMap<String, SessionMeta> = self.st.lock().scoped.get(chat).map(|s| s.metadata.clone()).unwrap_or_default();
        for id in &ids {
            let Some(session) = self.backend.session(id) else {
                continue;
            };
            let previous = existing.get(id).cloned().or_else(|| find_meta_across_scopes(&self.st.lock(), id, None)).unwrap_or_default();
            let pick = |a: String, b: &str| if a.is_empty() { b.to_string() } else { a };
            let label = pick(session.label(), &if previous.label.is_empty() { id.clone() } else { previous.label.clone() });
            let shell = session.shell_kind().shell_kind();
            list.push(json!({
                "sessionId": id,
                "hostId": pick(session.host_id(), &previous.host_id),
                "savedHostId": previous.saved_host_id.clone().unwrap_or_default(),
                "hostname": pick(session.hostname(), &previous.hostname),
                "label": label,
                "os": previous.os,
                "username": pick(session.username(), &previous.username),
                "protocol": pick(session.protocol().to_string(), &previous.protocol),
                "shellType": pick(shell, &previous.shell_type),
                "deviceType": previous.device_type,
                "connected": true,
                "hostChain": previous.host_chain.clone().unwrap_or_default(),
                "activePortForwards": previous.active_port_forwards.clone().unwrap_or_default(),
            }));
        }
        if list.is_empty() {
            let count = existing.len();
            if count > 0 {
                return json!({ "ok": true, "count": count, "chatSessionId": chat, "preserved": true });
            }
            if !self.st.lock().scoped.contains_key(chat) {
                let seeded = self.seed_external_scope_from_other_scopes();
                if seeded > 0 {
                    return json!({ "ok": true, "count": seeded, "chatSessionId": chat, "seeded": true });
                }
            }
            return json!({ "ok": true, "count": 0, "chatSessionId": chat });
        }
        for (id, meta) in &existing {
            if !ids.contains(id) && !meta.connected {
                let mut v = meta.to_public();
                v["sessionId"] = json!(id);
                list.push(v);
            }
        }
        let count = list.len();
        self.update_session_metadata(&list, Some(chat));
        json!({ "ok": true, "count": count, "chatSessionId": chat })
    }

    fn seed_external_scope_from_other_scopes(&self) -> usize {
        let chat = EXTERNAL_MCP_CHAT_SESSION_ID;
        let mut by_id: HashMap<String, SessionMeta> = HashMap::new();
        for (scope_id, scope) in &self.st.lock().scoped {
            if scope_id == chat {
                continue;
            }
            for (id, meta) in &scope.metadata {
                if by_id.get(id).is_none_or(|e| meta.revision > e.revision) {
                    by_id.insert(id.clone(), meta.clone());
                }
            }
        }
        if by_id.is_empty() {
            return 0;
        }
        let n = by_id.len();
        let list: Vec<Value> = by_id
            .into_iter()
            .map(|(id, m)| {
                let mut v = m.to_public();
                v["sessionId"] = json!(id);
                v
            })
            .collect();
        self.update_session_metadata(&list, Some(chat));
        n
    }

    // ── attachments ──────────────────────────────────────────────────

    pub fn update_attachment_metadata(&self, attachments: &[Value], chat: &str) {
        if chat.is_empty() {
            return;
        }
        let mut st = self.st.lock();
        let entry = st.attachments.entry(chat.to_string()).or_default();
        for a in attachments.iter().filter_map(Value::as_object) {
            let filename = a.get("filename").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).unwrap_or("attachment").to_string();
            let media_type = a
                .get("mediaType")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("application/octet-stream")
                .to_string();
            let base64_data = a.get("base64Data").and_then(Value::as_str).unwrap_or("").to_string();
            let file_path = a.get("filePath").and_then(Value::as_str).map(str::trim).unwrap_or("").to_string();
            if base64_data.is_empty() && file_path.is_empty() {
                continue;
            }
            let file_path = if file_path.is_empty() { file_path } else { absolutize(&file_path) };
            let size_bytes = (!base64_data.is_empty()).then(|| base64_decoded_len(&base64_data));
            let key = if file_path.is_empty() { filename.clone() } else { file_path.clone() };
            entry.retain(|(k, _)| k != &key);
            entry.push((key, Attachment { filename, media_type, file_path, base64_data, size_bytes }));
        }
    }

    pub(crate) fn scoped_attachments(&self, chat: &str) -> Vec<Attachment> {
        self.st.lock().attachments.get(chat).map(|v| v.iter().map(|(_, a)| a.clone()).collect()).unwrap_or_default()
    }
}

/// Releases the per-chat execution lock on drop.
pub(crate) struct ChatExecLock {
    host: Option<Weak<McpHost>>,
    chat: String,
    session_id: String,
    command: String,
}

impl Drop for ChatExecLock {
    fn drop(&mut self) {
        if let Some(host) = self.host.as_ref().and_then(Weak::upgrade) {
            let mut st = host.st.lock();
            if st.active_chat_execs.get(&self.chat).is_some_and(|(s, c)| s == &self.session_id && c == &self.command) {
                st.active_chat_execs.remove(&self.chat);
            }
        }
    }
}

pub(crate) fn find_meta_across_scopes(st: &State, session_id: &str, exclude: Option<&str>) -> Option<SessionMeta> {
    let mut latest = st.live.get(session_id).cloned();
    let mut latest_rev = latest.as_ref().map(|m| m.revision as i64).unwrap_or(-1);
    for (scope_id, scope) in &st.scoped {
        if exclude == Some(scope_id.as_str()) {
            continue;
        }
        if let Some(meta) = scope.metadata.get(session_id) {
            if meta.revision as i64 > latest_rev {
                latest_rev = meta.revision as i64;
                latest = Some(meta.clone());
            }
        }
    }
    latest
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn absolutize(path: &str) -> String {
    let p = std::path::Path::new(path);
    if p.is_absolute() {
        return normalize_path(p);
    }
    std::env::current_dir().map(|d| normalize_path(&d.join(p))).unwrap_or_else(|_| path.to_string())
}

fn normalize_path(p: &std::path::Path) -> String {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out.to_string_lossy().into_owned()
}

pub(crate) fn base64_decoded_len(b64: &str) -> usize {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(b64.trim()).map(|v| v.len()).unwrap_or(0)
}
