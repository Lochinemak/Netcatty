//! Confirm-mode approval gate (Electron `requestApprovalFromRenderer` and
//! friends): `netcatty:ai:mcp:approval-request` → renderer card →
//! `respondMcpApproval`; idle auto-deny after 110 s, never past the
//! absolute deadline; `netcatty:ai:mcp:approval-cleared` removes cards.

use super::{McpHost, EXTERNAL_MCP_CHAT_SESSION_ID, MCP_APPROVAL_TIMEOUT_MS};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;

pub const APPROVAL_REQUEST_EVENT: &str = "netcatty:ai:mcp:approval-request";
pub const APPROVAL_CLEARED_EVENT: &str = "netcatty:ai:mcp:approval-cleared";

struct Pending {
    tx: oneshot::Sender<bool>,
    chat_session_id: Option<String>,
    external_client: Option<u64>,
    absolute_expires_at: Instant,
    idle_cancelled: bool,
    timer: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Default)]
pub struct Approvals {
    pending: Mutex<HashMap<String, Pending>>,
    counter: AtomicU64,
    /// Connected external MCP clients.
    pub(crate) external_clients: Mutex<HashSet<u64>>,
    /// Clients approved for the rest of their connection ("allow session").
    pub(crate) session_approved: Mutex<HashSet<u64>>,
    next_client: AtomicU64,
}

impl Approvals {
    pub fn new_client_id(&self) -> u64 {
        self.next_client.fetch_add(1, Ordering::SeqCst) + 1
    }
}

impl McpHost {
    /// Register an external MCP client (socket / HTTP session).
    pub fn attach_external_client(&self, client: u64) {
        self.approvals.external_clients.lock().insert(client);
    }

    /// The client disconnected: deny its pending approvals.
    pub fn detach_external_client(&self, client: u64) {
        self.approvals.external_clients.lock().remove(&client);
        self.approvals.session_approved.lock().remove(&client);
        let ids: Vec<String> = {
            let mut pending = self.approvals.pending.lock();
            let ids: Vec<String> = pending.iter().filter(|(_, p)| p.external_client == Some(client)).map(|(k, _)| k.clone()).collect();
            for id in &ids {
                if let Some(p) = pending.remove(id) {
                    if let Some(t) = p.timer {
                        t.abort();
                    }
                    let _ = p.tx.send(false);
                }
            }
            ids
        };
        self.notify_approval_cleared(ids);
    }

    pub fn new_external_client_id(&self) -> u64 {
        self.approvals.new_client_id()
    }

    pub(crate) fn is_external_client(&self, client: Option<u64>) -> bool {
        client.is_some_and(|c| self.approvals.external_clients.lock().contains(&c))
    }

    pub(crate) fn has_session_approval(&self, client: Option<u64>) -> bool {
        client.is_some_and(|c| self.approvals.session_approved.lock().contains(&c))
    }

    /// Soft revoke: forget "allow session" approvals (External MCP disabled).
    pub fn revoke_external_session_approvals(&self) {
        self.approvals.session_approved.lock().clear();
    }

    fn arm_timer(&self, id: &str, at: Instant) -> tokio::task::JoinHandle<()> {
        let weak = self.me.clone();
        let id = id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep_until(at).await;
            if let Some(host) = weak.upgrade() {
                host.deny_timed_out(&id);
            }
        })
    }

    fn deny_timed_out(&self, id: &str) {
        let Some(p) = self.approvals.pending.lock().remove(id) else {
            return;
        };
        let _ = p.tx.send(false);
        self.notify_approval_cleared(vec![id.to_string()]);
    }

    pub(crate) fn notify_approval_cleared(&self, ids: Vec<String>) {
        if ids.is_empty() {
            return;
        }
        self.backend.emit(APPROVAL_CLEARED_EVENT, json!({ "approvalIds": ids }));
        self.sync_external_attention();
    }

    fn sync_external_attention(&self) {
        let count = self
            .approvals
            .pending
            .lock()
            .values()
            .filter(|p| p.chat_session_id.as_deref() == Some(EXTERNAL_MCP_CHAT_SESSION_ID))
            .count();
        self.backend.sync_external_approval_attention(count);
    }

    /// Ask the user; resolves `false` on deny / timeout / no window.
    pub async fn request_approval(
        &self,
        tool_name: &str,
        args: Value,
        chat_session_id: Option<String>,
        target: Option<Value>,
        external_client: Option<u64>,
    ) -> bool {
        if !self.backend.has_approval_window() {
            return false;
        }
        let n = self.approvals.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let id = format!("mcp_approval_{n}_{}", super::now_ms());
        let absolute = Instant::now() + Duration::from_millis(MCP_APPROVAL_TIMEOUT_MS);
        let (tx, rx) = oneshot::channel();
        let timer = self.arm_timer(&id, absolute);
        let allow_session = chat_session_id.as_deref() == Some(EXTERNAL_MCP_CHAT_SESSION_ID) && self.is_external_client(external_client);
        self.approvals.pending.lock().insert(
            id.clone(),
            Pending {
                tx,
                chat_session_id: chat_session_id.clone(),
                external_client,
                absolute_expires_at: absolute,
                idle_cancelled: false,
                timer: Some(timer),
            },
        );
        let mut payload = json!({ "approvalId": id, "toolName": tool_name, "args": args, "allowSession": allow_session });
        if let Some(chat) = &chat_session_id {
            payload["chatSessionId"] = json!(chat);
        }
        if let Some(t) = target {
            payload["target"] = t;
        }
        self.backend.emit(APPROVAL_REQUEST_EVENT, payload);
        self.sync_external_attention();
        rx.await.unwrap_or(false)
    }

    /// `respondMcpApproval` → `accepted` (false when the external client is gone).
    pub fn resolve_approval(&self, approval_id: &str, approved: bool, scope: &str) -> bool {
        let Some(entry) = self.approvals.pending.lock().remove(approval_id) else {
            return false;
        };
        if let Some(t) = &entry.timer {
            t.abort();
        }
        let is_external = entry.chat_session_id.as_deref() == Some(EXTERNAL_MCP_CHAT_SESSION_ID);
        let socket_valid = !is_external || (self.is_external_client(entry.external_client) && self.external_enabled());
        let accepted = approved && socket_valid;
        let mut cleared = vec![approval_id.to_string()];
        if accepted && scope == "session" && is_external {
            if let Some(client) = entry.external_client {
                self.approvals.session_approved.lock().insert(client);
                let mut pending = self.approvals.pending.lock();
                let ids: Vec<String> = pending.iter().filter(|(_, p)| p.external_client == Some(client)).map(|(k, _)| k.clone()).collect();
                for id in ids {
                    if let Some(p) = pending.remove(&id) {
                        if let Some(t) = p.timer {
                            t.abort();
                        }
                        let _ = p.tx.send(true);
                        cleared.push(id);
                    }
                }
            }
        }
        let _ = entry.tx.send(accepted);
        self.notify_approval_cleared(cleared);
        socket_valid
    }

    /// The user started reviewing: drop the idle timer, keep the absolute one.
    pub fn cancel_approval_timeout(&self, approval_id: &str) -> bool {
        let mut pending = self.approvals.pending.lock();
        let Some(entry) = pending.get_mut(approval_id) else {
            return false;
        };
        if entry.idle_cancelled {
            return false;
        }
        entry.idle_cancelled = true;
        if let Some(t) = entry.timer.take() {
            t.abort();
        }
        let at = entry.absolute_expires_at;
        entry.timer = Some(self.arm_timer(approval_id, at));
        true
    }

    /// Deny pending approvals (of one chat, or all).
    pub fn clear_pending_approvals(&self, chat: Option<&str>) {
        let ids: Vec<String> = {
            let mut pending = self.approvals.pending.lock();
            let ids: Vec<String> = pending
                .iter()
                .filter(|(_, p)| chat.is_none() || p.chat_session_id.as_deref() == chat)
                .map(|(k, _)| k.clone())
                .collect();
            for id in &ids {
                if let Some(p) = pending.remove(id) {
                    if let Some(t) = p.timer {
                        t.abort();
                    }
                    let _ = p.tx.send(false);
                }
            }
            ids
        };
        self.notify_approval_cleared(ids);
    }

    pub fn pending_approval_count(&self) -> usize {
        self.approvals.pending.lock().len()
    }
}
