//! Renderer request bridge for vault / port-forward / terminal lifecycle
//! data (Electron `aiBridge/vaultAgentBridge.cjs`): the host emits
//! `netcatty:ai:vault-agent:request { requestId, op, params }` and the
//! renderer answers with `respondVaultAgent(requestId, result)`.

use super::backend::HostBackend;
use netcatty_capabilities::VaultAgent;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

pub const VAULT_AGENT_TIMEOUT_MS: u64 = 15_000;
pub const VAULT_AGENT_REQUEST_EVENT: &str = "netcatty:ai:vault-agent:request";

pub struct VaultAgentBridge {
    backend: Arc<dyn HostBackend>,
    pending: Mutex<HashMap<String, oneshot::Sender<Value>>>,
}

impl VaultAgentBridge {
    pub fn new(backend: Arc<dyn HostBackend>) -> Self {
        Self { backend, pending: Default::default() }
    }

    /// Renderer reply. Returns `{ ok }` like the Electron IPC handler.
    pub fn respond(&self, request_id: &str, result: Value) -> Value {
        if request_id.is_empty() {
            return json!({ "ok": false, "error": "requestId is required" });
        }
        match self.pending.lock().remove(request_id) {
            Some(tx) => {
                let _ = tx.send(result);
                json!({ "ok": true })
            }
            None => json!({ "ok": false, "error": "Unknown or expired vault agent request." }),
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }
}

#[async_trait::async_trait]
impl VaultAgent for VaultAgentBridge {
    async fn invoke(&self, op: &str, params: Value, timeout_ms: Option<u64>) -> Value {
        if !self.backend.has_approval_window() {
            return json!({ "ok": false, "error": "No active Netcatty window is available for vault access." });
        }
        let request_id = uuid_v4();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(request_id.clone(), tx);
        self.backend.emit(
            VAULT_AGENT_REQUEST_EVENT,
            json!({ "requestId": request_id, "op": op, "params": params }),
        );
        let wait = Duration::from_millis(timeout_ms.unwrap_or(VAULT_AGENT_TIMEOUT_MS));
        match tokio::time::timeout(wait, rx).await {
            Ok(Ok(result)) => result,
            _ => {
                self.pending.lock().remove(&request_id);
                json!({ "ok": false, "error": "Vault agent bridge timed out waiting for renderer." })
            }
        }
    }
}

pub(crate) fn uuid_v4() -> String {
    let b: [u8; 16] = rand::random();
    let mut b = b;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}
