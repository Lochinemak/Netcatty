//! Bridges interactive SSH prompts (host key, keyboard-interactive,
//! passphrase) to the renderer: emit a request event, park a oneshot, and
//! resolve it when the renderer calls the matching `ssh_respond_*` command.
//!
//! Requests time out (default 5 minutes) so an abandoned dialog cannot leak
//! a pending connection forever; on timeout the connection attempt fails
//! with `Cancelled`.

use netcatty_core::ipc::{
    HostKeyVerifyRequest, HostKeyVerifyResponse, KeyboardInteractivePrompt, KeyboardInteractiveRequest,
    KeyboardInteractiveResponse, PassphraseRequest, PassphraseResponse,
};
use netcatty_ssh::{HostKeyDecision, HostKeyInfo, SshCallbacks};
use std::sync::Arc;
use std::time::Duration;
use tauri::AppHandle;
use tokio::sync::oneshot;

pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(300);

pub struct PromptBroker {
    pub app: AppHandle,
    pub(crate) host_key: dashmap::DashMap<String, oneshot::Sender<HostKeyVerifyResponse>>,
    pub(crate) keyboard_interactive: dashmap::DashMap<String, oneshot::Sender<KeyboardInteractiveResponse>>,
    pub(crate) passphrase: dashmap::DashMap<String, oneshot::Sender<PassphraseResponse>>,
}

impl PromptBroker {
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            host_key: dashmap::DashMap::new(),
            keyboard_interactive: dashmap::DashMap::new(),
            passphrase: dashmap::DashMap::new(),
        }
    }

    /// Callbacks bound to one session (so events carry `sessionId`).
    pub fn callbacks_for(self: &Arc<Self>, session_id: String, host_id: Option<String>, saved_password: Option<String>, totp_uri: Option<String>) -> Arc<dyn SshCallbacks> {
        Arc::new(SessionCallbacks { broker: self.clone(), session_id, host_id, saved_password, totp_uri })
    }

    pub fn resolve_host_key(&self, response: HostKeyVerifyResponse) -> bool {
        match self.host_key.remove(&response.request_id) {
            Some((_, tx)) => tx.send(response).is_ok(),
            None => false,
        }
    }

    pub fn resolve_keyboard_interactive(&self, response: KeyboardInteractiveResponse) -> bool {
        match self.keyboard_interactive.remove(&response.request_id) {
            Some((_, tx)) => tx.send(response).is_ok(),
            None => false,
        }
    }

    pub fn resolve_passphrase(&self, response: PassphraseResponse) -> bool {
        match self.passphrase.remove(&response.request_id) {
            Some((_, tx)) => tx.send(response).is_ok(),
            None => false,
        }
    }

    /// Cancel every pending prompt for a session (session closed / aborted).
    pub fn cancel_session(&self, session_id: &str) {
        let _ = session_id;
        todo!("drop pending senders whose request belongs to session_id and emit *-cancelled events (tauri agent task)")
    }
}

pub struct SessionCallbacks {
    pub broker: Arc<PromptBroker>,
    pub session_id: String,
    pub host_id: Option<String>,
    pub saved_password: Option<String>,
    pub totp_uri: Option<String>,
}

#[async_trait::async_trait]
impl SshCallbacks for SessionCallbacks {
    async fn verify_host_key(&self, info: HostKeyInfo) -> HostKeyDecision {
        let _ = info;
        todo!("emit HostKeyVerifyRequest, await response with PROMPT_TIMEOUT (tauri agent task)")
    }

    async fn keyboard_interactive(
        &self,
        name: String,
        instructions: String,
        prompts: Vec<KeyboardInteractivePrompt>,
    ) -> Option<Vec<String>> {
        let _ = (name, instructions, prompts);
        todo!("emit KeyboardInteractiveRequest, await response (tauri agent task)")
    }

    async fn request_passphrase(&self, key_name: String, invalid: bool) -> Option<String> {
        let _ = (key_name, invalid);
        todo!("emit PassphraseRequest, await response (tauri agent task)")
    }
}

// Keep the request types referenced so the contract stays visible here.
#[allow(dead_code)]
fn _contract(_: HostKeyVerifyRequest, _: KeyboardInteractiveRequest, _: PassphraseRequest) {}
