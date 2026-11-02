//! Bridges interactive SSH prompts (host key, keyboard-interactive,
//! passphrase) to the renderer: emit a request event, park a oneshot, and
//! resolve it when the renderer calls the matching `ssh_respond_*` command.
//!
//! Requests time out (default 5 minutes) so an abandoned dialog cannot leak
//! a pending connection forever; on timeout the connection attempt fails
//! (host key rejected / keyboard-interactive cancelled / key skipped).
//! [`PromptBroker::cancel_session`] drops every pending request of a session
//! (session closed, test connection aborted, tunnel stopped) and notifies the
//! renderer with `*-cancelled` events carrying `reason: "session-closed"`.

use crate::events;
use netcatty_core::ipc::{
    events as ev, HostKeyStatus, HostKeyVerifyRequest, HostKeyVerifyResponse,
    KeyboardInteractivePrompt, KeyboardInteractiveRequest, KeyboardInteractiveResponse,
    PassphraseRequest, PassphraseResponse,
};
use netcatty_ssh::{HostKeyDecision, HostKeyInfo, SshCallbacks};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tauri::AppHandle;
use tokio::sync::oneshot;

pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(300);

/// Payload of `netcatty:keyboard-interactive-cancelled`,
/// `netcatty:passphrase-cancelled` and `netcatty:passphrase-timeout`
/// (`{ requestId, sessionId?, reason? }`, see `rust/docs/ipc-contract.md`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptCancelledEvent {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    HostKey,
    KeyboardInteractive,
    Passphrase,
}

pub struct PromptBroker {
    pub app: AppHandle,
    pub(crate) host_key: dashmap::DashMap<String, oneshot::Sender<HostKeyVerifyResponse>>,
    pub(crate) keyboard_interactive:
        dashmap::DashMap<String, oneshot::Sender<KeyboardInteractiveResponse>>,
    pub(crate) passphrase: dashmap::DashMap<String, oneshot::Sender<PassphraseResponse>>,
    /// `requestId → (kind, sessionId)` so a session can cancel its prompts.
    pub(crate) owners: dashmap::DashMap<String, (PromptKind, String)>,
}

/// How a parked request ended.
enum Outcome<T> {
    Answered(T),
    /// Sender dropped by `cancel_session` (event already emitted there).
    Cancelled,
    TimedOut,
}

impl PromptBroker {
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            host_key: dashmap::DashMap::new(),
            keyboard_interactive: dashmap::DashMap::new(),
            passphrase: dashmap::DashMap::new(),
            owners: dashmap::DashMap::new(),
        }
    }

    /// Callbacks bound to one session (so events carry `sessionId`).
    pub fn callbacks_for(
        self: &Arc<Self>,
        session_id: String,
        hostname: String,
        host_id: Option<String>,
        saved_password: Option<String>,
        totp_uri: Option<String>,
    ) -> Arc<dyn SshCallbacks> {
        Arc::new(SessionCallbacks {
            broker: self.clone(),
            session_id,
            hostname,
            host_id,
            saved_password,
            totp_uri,
        })
    }

    pub fn resolve_host_key(&self, response: HostKeyVerifyResponse) -> bool {
        self.owners.remove(&response.request_id);
        match self.host_key.remove(&response.request_id) {
            Some((_, tx)) => tx.send(response).is_ok(),
            None => false,
        }
    }

    pub fn resolve_keyboard_interactive(&self, response: KeyboardInteractiveResponse) -> bool {
        self.owners.remove(&response.request_id);
        match self.keyboard_interactive.remove(&response.request_id) {
            Some((_, tx)) => tx.send(response).is_ok(),
            None => false,
        }
    }

    pub fn resolve_passphrase(&self, response: PassphraseResponse) -> bool {
        self.owners.remove(&response.request_id);
        match self.passphrase.remove(&response.request_id) {
            Some((_, tx)) => tx.send(response).is_ok(),
            None => false,
        }
    }

    /// Number of prompts currently waiting for the renderer.
    pub fn pending_count(&self) -> usize {
        self.owners.len()
    }

    /// Cancel every pending prompt for a session (session closed / aborted).
    pub fn cancel_session(&self, session_id: &str) {
        self.cancel_session_with_reason(session_id, "session-closed");
    }

    pub fn cancel_session_with_reason(&self, session_id: &str, reason: &str) {
        let ids: Vec<(String, PromptKind)> = self
            .owners
            .iter()
            .filter(|e| e.value().1 == session_id)
            .map(|e| (e.key().clone(), e.value().0))
            .collect();
        for (request_id, kind) in ids {
            self.owners.remove(&request_id);
            let payload = PromptCancelledEvent {
                request_id: request_id.clone(),
                session_id: Some(session_id.to_string()),
                reason: Some(reason.to_string()),
            };
            match kind {
                PromptKind::HostKey => {
                    // Dropping the sender makes the awaiting callback reject.
                    self.host_key.remove(&request_id);
                }
                PromptKind::KeyboardInteractive => {
                    if self.keyboard_interactive.remove(&request_id).is_some() {
                        events::emit(&self.app, ev::KEYBOARD_INTERACTIVE_CANCELLED, payload);
                    }
                }
                PromptKind::Passphrase => {
                    if self.passphrase.remove(&request_id).is_some() {
                        events::emit(&self.app, ev::PASSPHRASE_CANCELLED, payload);
                    }
                }
            }
        }
    }

    fn register<T>(
        &self,
        map: &dashmap::DashMap<String, oneshot::Sender<T>>,
        kind: PromptKind,
        session_id: &str,
    ) -> (String, oneshot::Receiver<T>) {
        let request_id = netcatty_core::new_id();
        let (tx, rx) = oneshot::channel();
        map.insert(request_id.clone(), tx);
        self.owners
            .insert(request_id.clone(), (kind, session_id.to_string()));
        (request_id, rx)
    }

    async fn await_response<T>(
        &self,
        map: &dashmap::DashMap<String, oneshot::Sender<T>>,
        request_id: &str,
        rx: oneshot::Receiver<T>,
    ) -> Outcome<T> {
        match tokio::time::timeout(PROMPT_TIMEOUT, rx).await {
            Ok(Ok(value)) => {
                self.owners.remove(request_id);
                Outcome::Answered(value)
            }
            Ok(Err(_)) => {
                self.owners.remove(request_id);
                Outcome::Cancelled
            }
            Err(_) => {
                map.remove(request_id);
                self.owners.remove(request_id);
                Outcome::TimedOut
            }
        }
    }
}

pub struct SessionCallbacks {
    pub broker: Arc<PromptBroker>,
    pub session_id: String,
    pub hostname: String,
    pub host_id: Option<String>,
    pub saved_password: Option<String>,
    pub totp_uri: Option<String>,
}

#[async_trait::async_trait]
impl SshCallbacks for SessionCallbacks {
    async fn verify_host_key(&self, info: HostKeyInfo) -> HostKeyDecision {
        let broker = &self.broker;
        let (request_id, rx) =
            broker.register(&broker.host_key, PromptKind::HostKey, &self.session_id);
        let request = HostKeyVerifyRequest {
            request_id: request_id.clone(),
            session_id: self.session_id.clone(),
            hostname: info.hostname.clone(),
            port: info.port,
            status: if info.is_changed() {
                HostKeyStatus::Changed
            } else {
                HostKeyStatus::Unknown
            },
            key_type: info.key_type.clone(),
            fingerprint: info.fingerprint.clone(),
            public_key: Some(info.public_key.clone()),
            known_host_id: info.known_host_id.clone(),
            known_fingerprint: info.known_fingerprint.clone(),
            boot_epoch: None,
        };
        events::emit(&broker.app, ev::HOST_KEY_VERIFY, request);
        match broker
            .await_response(&broker.host_key, &request_id, rx)
            .await
        {
            Outcome::Answered(resp) if resp.accept => HostKeyDecision::Accept {
                remember: resp.add_to_known_hosts,
            },
            Outcome::Answered(_) => HostKeyDecision::Reject,
            Outcome::Cancelled => HostKeyDecision::Reject,
            Outcome::TimedOut => {
                tracing::warn!(session_id = %self.session_id, "host key verification timed out");
                HostKeyDecision::Reject
            }
        }
    }

    async fn keyboard_interactive(
        &self,
        name: String,
        instructions: String,
        prompts: Vec<KeyboardInteractivePrompt>,
    ) -> Option<Vec<String>> {
        let broker = &self.broker;
        let (request_id, rx) = broker.register(
            &broker.keyboard_interactive,
            PromptKind::KeyboardInteractive,
            &self.session_id,
        );
        let request = KeyboardInteractiveRequest {
            request_id: request_id.clone(),
            session_id: self.session_id.clone(),
            host_id: self.host_id.clone(),
            name,
            instructions,
            prompts,
            hostname: self.hostname.clone(),
            saved_password: self.saved_password.clone(),
            allow_save_password: Some(true),
            totp_uri: self.totp_uri.clone(),
            scope: None,
            boot_epoch: None,
        };
        events::emit(&broker.app, ev::KEYBOARD_INTERACTIVE, request);
        match broker
            .await_response(&broker.keyboard_interactive, &request_id, rx)
            .await
        {
            Outcome::Answered(resp) if resp.cancelled => None,
            Outcome::Answered(resp) => Some(resp.responses),
            Outcome::Cancelled => None,
            Outcome::TimedOut => {
                tracing::warn!(session_id = %self.session_id, "keyboard-interactive prompt timed out");
                events::emit(
                    &broker.app,
                    ev::KEYBOARD_INTERACTIVE_CANCELLED,
                    PromptCancelledEvent {
                        request_id,
                        session_id: Some(self.session_id.clone()),
                        reason: Some("timeout".to_string()),
                    },
                );
                None
            }
        }
    }

    async fn request_passphrase(&self, key_name: String, invalid: bool) -> Option<String> {
        let broker = &self.broker;
        let (request_id, rx) =
            broker.register(&broker.passphrase, PromptKind::Passphrase, &self.session_id);
        let request = PassphraseRequest {
            request_id: request_id.clone(),
            key_path: key_name.clone(),
            key_name,
            hostname: Some(self.hostname.clone()),
            passphrase_invalid: Some(invalid),
            session_id: Some(self.session_id.clone()),
            boot_epoch: None,
        };
        events::emit(&broker.app, ev::PASSPHRASE_REQUEST, request);
        match broker
            .await_response(&broker.passphrase, &request_id, rx)
            .await
        {
            Outcome::Answered(resp) if resp.cancelled || resp.skip => None,
            Outcome::Answered(resp) => resp.passphrase,
            Outcome::Cancelled => None,
            Outcome::TimedOut => {
                tracing::warn!(session_id = %self.session_id, "passphrase prompt timed out");
                events::emit(
                    &broker.app,
                    ev::PASSPHRASE_TIMEOUT,
                    PromptCancelledEvent {
                        request_id,
                        session_id: Some(self.session_id.clone()),
                        reason: Some("timeout".to_string()),
                    },
                );
                None
            }
        }
    }
}
