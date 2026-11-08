//! FIDO2 PIN / touch / recovery prompts (Electron `fidoPromptHandler.cjs`).
//!
//! A request is emitted as `netcatty:fido-prompt-request` and parked until
//! the renderer answers with `respondFidoPrompt`, the 3-minute TTL expires
//! (`netcatty:fido-prompt-timeout`) or it is cancelled
//! (`netcatty:fido-prompt-cancelled`, e.g. the askpass helper exited because
//! the key was touched).

use parking_lot::Mutex;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, watch};

pub const EVENT_REQUEST: &str = "netcatty:fido-prompt-request";
pub const EVENT_TIMEOUT: &str = "netcatty:fido-prompt-timeout";
pub const EVENT_CANCELLED: &str = "netcatty:fido-prompt-cancelled";
pub const REQUEST_TTL: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PromptKind {
    Pin,
    Touch,
    Confirm,
    Recovery,
}

impl PromptKind {
    fn prefix(self) -> &'static str {
        match self {
            PromptKind::Pin => "pin",
            PromptKind::Touch => "touch",
            PromptKind::Confirm => "confirm",
            PromptKind::Recovery => "recovery",
        }
    }
}

/// `netcatty:fido-prompt-request` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptRequest {
    pub request_id: String,
    pub kind: PromptKind,
    pub message: String,
    pub title: String,
    pub key_name: String,
    pub notification_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub allow_password_fallback: bool,
}

/// `{ requestId }` (timeout) / `{ requestId, reason }` (cancelled).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptEnded {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Where prompt events go (the desktop app emits them to the windows).
pub trait PromptSink: Send + Sync + 'static {
    fn emit(&self, event: &str, payload: serde_json::Value);
}

/// What a caller asks for.
#[derive(Debug, Clone, Default)]
pub struct PromptOptions {
    pub kind: Option<PromptKind>,
    pub message: String,
    pub title: String,
    pub key_name: String,
    pub notification_only: bool,
    pub reason: Option<String>,
    pub allow_password_fallback: bool,
    /// Owner (askpass lease / signing attempt) for bulk cancellation.
    pub lease_id: String,
}

/// How a prompt ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptOutcome {
    Answered(String),
    Cancelled,
}

struct Pending {
    tx: oneshot::Sender<PromptOutcome>,
    lease_id: String,
    notification_only: bool,
}

/// Cancellation signal shared between a prompt and the operation it
/// belongs to (helper process exit, signing attempt finished).
#[derive(Debug, Clone)]
pub struct Signal(watch::Sender<bool>);

impl Default for Signal {
    fn default() -> Self {
        Self(watch::channel(false).0)
    }
}

impl Signal {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn abort(&self) {
        self.0.send_replace(true);
    }
    pub fn is_aborted(&self) -> bool {
        *self.0.borrow()
    }
    pub async fn aborted(&self) {
        let mut rx = self.0.subscribe();
        let _ = rx.wait_for(|v| *v).await;
    }
}

pub struct PromptBroker {
    sink: Arc<dyn PromptSink>,
    pending: Mutex<HashMap<String, Pending>>,
}

impl PromptBroker {
    pub fn new(sink: Arc<dyn PromptSink>) -> Arc<Self> {
        Arc::new(Self {
            sink,
            pending: Mutex::new(HashMap::new()),
        })
    }

    fn settle(&self, request_id: &str, outcome: PromptOutcome, event: Option<(&str, Option<&str>)>) -> bool {
        let Some(pending) = self.pending.lock().remove(request_id) else {
            return false;
        };
        if let Some((name, reason)) = event {
            let payload = PromptEnded {
                request_id: request_id.to_string(),
                reason: reason.map(str::to_string),
            };
            self.sink.emit(name, serde_json::to_value(payload).unwrap_or_default());
        }
        let _ = pending.tx.send(outcome);
        true
    }

    pub fn cancel(&self, request_id: &str, reason: &str) -> bool {
        self.settle(request_id, PromptOutcome::Cancelled, Some((EVENT_CANCELLED, Some(reason))))
    }

    /// Cancel prompts owned by `lease_id` (only notifications when asked).
    pub fn cancel_lease(&self, lease_id: &str, reason: &str, notifications_only: bool) -> usize {
        if lease_id.is_empty() {
            return 0;
        }
        let ids: Vec<String> = self
            .pending
            .lock()
            .iter()
            .filter(|(_, p)| p.lease_id == lease_id && (!notifications_only || p.notification_only))
            .map(|(id, _)| id.clone())
            .collect();
        ids.iter().filter(|id| self.cancel(id, reason)).count()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }

    /// `respondFidoPrompt(requestId, response, cancelled)`.
    pub fn respond(&self, request_id: &str, response: Option<String>, cancelled: bool) -> Result<(), &'static str> {
        let outcome = if cancelled {
            PromptOutcome::Cancelled
        } else {
            PromptOutcome::Answered(response.unwrap_or_default())
        };
        if self.settle(request_id, outcome, None) {
            Ok(())
        } else {
            Err("Request not found")
        }
    }

    /// Emit a request and wait for the answer. `signal` cancels it (event
    /// `cancelled` with reason `helper-exited`).
    pub async fn request(&self, options: PromptOptions, signal: Option<Signal>) -> PromptOutcome {
        let kind = options.kind.unwrap_or(PromptKind::Pin);
        let request_id = format!("{}-{}", kind.prefix(), uuid::Uuid::new_v4());
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(
            request_id.clone(),
            Pending {
                tx,
                lease_id: options.lease_id.clone(),
                notification_only: options.notification_only,
            },
        );
        if signal.as_ref().is_some_and(Signal::is_aborted) {
            self.cancel(&request_id, "helper-exited");
            return PromptOutcome::Cancelled;
        }
        let request = PromptRequest {
            request_id: request_id.clone(),
            kind,
            message: options.message,
            title: options.title,
            key_name: options.key_name,
            notification_only: options.notification_only,
            reason: options.reason,
            allow_password_fallback: options.allow_password_fallback,
        };
        self.sink
            .emit(EVENT_REQUEST, serde_json::to_value(request).unwrap_or_default());

        let aborted = async {
            match &signal {
                Some(signal) => signal.aborted().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            outcome = rx => outcome.unwrap_or(PromptOutcome::Cancelled),
            _ = tokio::time::sleep(REQUEST_TTL) => {
                self.settle(&request_id, PromptOutcome::Cancelled, Some((EVENT_TIMEOUT, None)));
                PromptOutcome::Cancelled
            }
            _ = aborted => {
                self.cancel(&request_id, "helper-exited");
                PromptOutcome::Cancelled
            }
        }
    }
}

/// Classify OpenSSH / `ssh-sk-helper` askpass text. Unknown prompts are
/// PIN-style secret entry (an empty answer to a PIN request would silently
/// fail the operation).
pub fn classify_askpass_prompt(prompt: &str) -> PromptKind {
    use regex::Regex;
    use std::sync::OnceLock;
    static PIN: OnceLock<Regex> = OnceLock::new();
    static TOUCH: OnceLock<Regex> = OnceLock::new();
    let p = prompt.to_lowercase();
    let pin = PIN.get_or_init(|| Regex::new(r"\bpin\b|密码|密碼|口令").unwrap());
    if pin.is_match(&p) {
        return PromptKind::Pin;
    }
    let touch = TOUCH.get_or_init(|| {
        Regex::new(r"confirm user presence|touch (your |the )?(security )?key|tap (your |the )?(security )?key|user presence|请触摸|請觸摸|请轻触").unwrap()
    });
    if touch.is_match(&p) {
        return PromptKind::Touch;
    }
    PromptKind::Pin
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    pub(crate) struct Captured(pub Mutex<Vec<(String, serde_json::Value)>>);

    impl PromptSink for Captured {
        fn emit(&self, event: &str, payload: serde_json::Value) {
            self.0.lock().push((event.to_string(), payload));
        }
    }

    impl Captured {
        fn last_request_id(&self) -> String {
            self.0
                .lock()
                .iter()
                .rev()
                .find(|(e, _)| e == EVENT_REQUEST)
                .map(|(_, p)| p["requestId"].as_str().unwrap().to_string())
                .unwrap()
        }
    }

    #[test]
    fn classifies_prompts() {
        assert_eq!(classify_askpass_prompt("Enter PIN for ED25519-SK key /x:"), PromptKind::Pin);
        assert_eq!(
            classify_askpass_prompt("Enter PIN and confirm user presence for key"),
            PromptKind::Pin
        );
        assert_eq!(classify_askpass_prompt("Confirm user presence for key ED25519-SK"), PromptKind::Touch);
        assert_eq!(classify_askpass_prompt("Touch your security key"), PromptKind::Touch);
        assert_eq!(classify_askpass_prompt("请触摸安全密钥"), PromptKind::Touch);
        assert_eq!(classify_askpass_prompt("请输入密码"), PromptKind::Pin);
        assert_eq!(classify_askpass_prompt("Something else"), PromptKind::Pin);
    }

    #[tokio::test]
    async fn answered_prompt_resolves_and_emits_request() {
        let sink = Arc::new(Captured::default());
        let broker = PromptBroker::new(sink.clone());
        let b = broker.clone();
        let task = tokio::spawn(async move {
            b.request(
                PromptOptions {
                    kind: Some(PromptKind::Pin),
                    message: "Enter PIN".into(),
                    key_name: "yubikey".into(),
                    ..Default::default()
                },
                None,
            )
            .await
        });
        tokio::task::yield_now().await;
        while sink.0.lock().is_empty() {
            tokio::task::yield_now().await;
        }
        let id = sink.last_request_id();
        assert!(id.starts_with("pin-"));
        let payload = sink.0.lock()[0].1.clone();
        assert_eq!(payload["kind"], "pin");
        assert_eq!(payload["keyName"], "yubikey");
        assert_eq!(payload["notificationOnly"], false);
        assert_eq!(payload["allowPasswordFallback"], false);
        assert!(payload.get("reason").is_none());
        broker.respond(&id, Some("1234".into()), false).unwrap();
        assert_eq!(task.await.unwrap(), PromptOutcome::Answered("1234".into()));
        assert_eq!(broker.respond(&id, None, false), Err("Request not found"));
        assert_eq!(broker.pending_count(), 0);
    }

    #[tokio::test]
    async fn signal_cancels_with_helper_exited() {
        let sink = Arc::new(Captured::default());
        let broker = PromptBroker::new(sink.clone());
        let signal = Signal::new();
        let b = broker.clone();
        let s = signal.clone();
        let task = tokio::spawn(async move {
            b.request(
                PromptOptions {
                    kind: Some(PromptKind::Touch),
                    notification_only: true,
                    ..Default::default()
                },
                Some(s),
            )
            .await
        });
        while sink.0.lock().is_empty() {
            tokio::task::yield_now().await;
        }
        signal.abort();
        assert_eq!(task.await.unwrap(), PromptOutcome::Cancelled);
        let events = sink.0.lock().clone();
        assert_eq!(events.last().unwrap().0, EVENT_CANCELLED);
        assert_eq!(events.last().unwrap().1["reason"], "helper-exited");
    }

    #[tokio::test(start_paused = true)]
    async fn ttl_expiry_emits_timeout() {
        let sink = Arc::new(Captured::default());
        let broker = PromptBroker::new(sink.clone());
        let outcome = broker.request(PromptOptions::default(), None).await;
        assert_eq!(outcome, PromptOutcome::Cancelled);
        let events = sink.0.lock().clone();
        assert_eq!(events.last().unwrap().0, EVENT_TIMEOUT);
        assert!(events.last().unwrap().1.get("reason").is_none());
    }

    #[tokio::test]
    async fn lease_cancellation_targets_owned_prompts() {
        let sink = Arc::new(Captured::default());
        let broker = PromptBroker::new(sink.clone());
        let mut tasks = Vec::new();
        for (lease, notification) in [("a", true), ("a", false), ("b", true)] {
            let b = broker.clone();
            tasks.push(tokio::spawn(async move {
                b.request(
                    PromptOptions {
                        lease_id: lease.into(),
                        notification_only: notification,
                        ..Default::default()
                    },
                    None,
                )
                .await
            }));
        }
        while broker.pending_count() < 3 {
            tokio::task::yield_now().await;
        }
        assert_eq!(broker.cancel_lease("a", "pin-requested", true), 1);
        assert_eq!(broker.pending_count(), 2);
        assert_eq!(broker.cancel_lease("a", "lease-released", false), 1);
        assert_eq!(broker.cancel_lease("", "x", false), 0);
        assert_eq!(broker.cancel_lease("b", "x", false), 1);
        for t in tasks {
            assert_eq!(t.await.unwrap(), PromptOutcome::Cancelled);
        }
    }
}
