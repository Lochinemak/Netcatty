//! Request / response round trips with one window's renderer (Electron:
//! `invokeWebContents` in `editorWindow.cjs`, the pending snapshot maps in
//! `terminalBridge.cjs`).
//!
//! Rust emits `send_event` to the target window with a `requestId`; the
//! renderer answers through `windows_report(channel, payload)`. Only a reply
//! from the queried window, on the expected channel, with the same
//! `requestId` settles the request (Electron: `evt.sender` check). A window
//! that is destroyed fails its pending requests immediately.

use parking_lot::Mutex;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::sync::oneshot;

/// Why a round trip produced no reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyError {
    /// The target window does not exist or was destroyed while waiting.
    Gone,
    /// No reply within the timeout.
    Timeout,
    /// The event could not be emitted.
    SendFailed,
}

struct Pending {
    label: String,
    channel: String,
    tx: oneshot::Sender<Value>,
}

/// Pending requests keyed by `requestId`.
#[derive(Default)]
pub struct ReplyBroker {
    pending: Mutex<HashMap<String, Pending>>,
}

impl ReplyBroker {
    /// Register a pending request; the receiver resolves with the reply
    /// payload, or errors when the request is dropped ([`Self::fail_window`]).
    pub fn register(
        &self,
        request_id: &str,
        label: &str,
        channel: &str,
    ) -> oneshot::Receiver<Value> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(
            request_id.to_owned(),
            Pending {
                label: label.to_owned(),
                channel: channel.to_owned(),
                tx,
            },
        );
        rx
    }

    /// Deliver a reply. Returns `false` when it matches no pending request of
    /// that window on that channel (unknown id, wrong window, settled).
    pub fn resolve(&self, sender_label: &str, channel: &str, payload: Value) -> bool {
        let Some(request_id) = payload
            .get("requestId")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return false;
        };
        let mut pending = self.pending.lock();
        let matches = pending
            .get(&request_id)
            .is_some_and(|p| p.label == sender_label && p.channel == channel);
        if !matches {
            return false;
        }
        let entry = pending.remove(&request_id).expect("checked above");
        drop(pending);
        entry.tx.send(payload).is_ok()
    }

    pub fn cancel(&self, request_id: &str) {
        self.pending.lock().remove(request_id);
    }

    /// Fail every request waiting on `label` (its window was destroyed).
    pub fn fail_window(&self, label: &str) {
        self.pending.lock().retain(|_, p| p.label != label);
    }

    #[cfg(test)]
    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }

    /// Emit `send_event` to `label` with `payload` (+ a generated `requestId`
    /// unless the payload carries one) and wait for the matching reply.
    pub async fn request<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        label: &str,
        send_event: &str,
        reply_channel: &str,
        mut payload: Map<String, Value>,
        timeout: Duration,
    ) -> Result<Value, ReplyError> {
        if app.get_webview_window(label).is_none() {
            return Err(ReplyError::Gone);
        }
        let request_id = match payload.get("requestId").and_then(Value::as_str) {
            Some(id) if !id.is_empty() => id.to_owned(),
            _ => {
                let id = uuid::Uuid::new_v4().to_string();
                payload.insert("requestId".into(), Value::String(id.clone()));
                id
            }
        };
        let rx = self.register(&request_id, label, reply_channel);
        if app
            .emit_to(label, send_event, Value::Object(payload))
            .is_err()
        {
            self.cancel(&request_id);
            return Err(ReplyError::SendFailed);
        }
        let outcome = tokio::time::timeout(timeout, rx).await;
        self.cancel(&request_id);
        match outcome {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(ReplyError::Gone),
            Err(_) => Err(ReplyError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_the_queried_window_on_the_expected_channel_resolves() {
        let broker = ReplyBroker::default();
        let mut rx = broker.register("r1", "editor", "netcatty:window:editorOpenTabResult");
        // Wrong window, wrong channel, missing / unknown id: ignored.
        assert!(!broker.resolve(
            "main",
            "netcatty:window:editorOpenTabResult",
            json!({ "requestId": "r1" })
        ));
        assert!(!broker.resolve(
            "editor",
            "netcatty:window:editorDockResult",
            json!({ "requestId": "r1" })
        ));
        assert!(!broker.resolve("editor", "netcatty:window:editorOpenTabResult", json!({})));
        assert!(!broker.resolve(
            "editor",
            "netcatty:window:editorOpenTabResult",
            json!({ "requestId": "r2" })
        ));
        assert!(rx.try_recv().is_err());
        assert!(broker.resolve(
            "editor",
            "netcatty:window:editorOpenTabResult",
            json!({ "requestId": "r1", "ok": true })
        ));
        assert_eq!(rx.try_recv().unwrap()["ok"], json!(true));
        // Settled: a duplicate reply matches nothing.
        assert!(!broker.resolve(
            "editor",
            "netcatty:window:editorOpenTabResult",
            json!({ "requestId": "r1" })
        ));
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn destroyed_window_fails_only_its_requests() {
        let broker = ReplyBroker::default();
        let mut gone = broker.register("a", "editor", "c");
        let mut alive = broker.register("b", "main", "c");
        broker.fail_window("editor");
        assert!(matches!(
            gone.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert!(matches!(
            alive.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(broker.pending_count(), 1);
    }
}
