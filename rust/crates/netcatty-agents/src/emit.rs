//! Stream emitter: forwards translated agent events to the renderer over the
//! SDK agent channels consumed by `sdkAgentAdapter.ts` (Electron: `sdk/emit.cjs`).
//!
//! Canonical event shapes:
//! ```text
//! { type: 'text-delta', textDelta }
//! { type: 'reasoning-delta', delta }
//! { type: 'reasoning-end' }
//! { type: 'tool-call', toolName, args, toolCallId }
//! { type: 'tool-result', toolCallId, output, toolName }
//! { type: 'file-change', itemId, changes, status }
//! { type: 'web-search', itemId, query, status }
//! { type: 'plan-update', itemId, items, status }
//! { type: 'warning', itemId, message }
//! { type: 'usage', inputTokens, cachedInputTokens, outputTokens, reasoningTokens, totalTokens }
//! { type: 'status', message }
//! { type: 'session-id', sessionId }
//! { type: 'error', error }
//! ```

use crate::events;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

/// Destination of renderer events (`safeSend(sender, channel, payload)`).
pub trait EventSink: Send + Sync {
    fn send(&self, channel: &str, payload: Value);
}

/// Collects events in memory (tests).
#[derive(Default)]
pub struct RecordingSink {
    pub events: Mutex<Vec<(String, Value)>>,
}

impl RecordingSink {
    pub fn take(&self) -> Vec<(String, Value)> {
        std::mem::take(&mut *self.events.lock())
    }

    /// Events on `netcatty:ai:sdk-agent:event` (the `event` field only).
    pub fn stream_events(&self) -> Vec<Value> {
        self.events
            .lock()
            .iter()
            .filter(|(c, _)| c == events::SDK_AGENT_EVENT)
            .map(|(_, p)| p["event"].clone())
            .collect()
    }

    pub fn done_count(&self) -> usize {
        self.events.lock().iter().filter(|(c, _)| c == events::SDK_AGENT_DONE).count()
    }

    pub fn errors(&self) -> Vec<String> {
        self.events
            .lock()
            .iter()
            .filter(|(c, _)| c == events::SDK_AGENT_ERROR)
            .map(|(_, p)| p["error"].as_str().unwrap_or("").to_string())
            .collect()
    }
}

impl EventSink for RecordingSink {
    fn send(&self, channel: &str, payload: Value) {
        self.events.lock().push((channel.to_string(), payload));
    }
}

/// Usage tokens for the `usage` event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
    pub reasoning_tokens: u64,
    pub total_tokens: u64,
}

/// Per-request emitter. Cheap to clone (shared sink + request id).
#[derive(Clone)]
pub struct Emitter {
    sink: Arc<dyn EventSink>,
    request_id: String,
    /// Extra fields merged into every `session-id` event (backend, binPath, runtime...).
    session_id_extra: Arc<Mutex<Value>>,
    /// Observer for native session ids (the runtime records them for resume).
    on_session_id: Arc<Mutex<Option<Arc<dyn Fn(&str) + Send + Sync>>>>,
}

impl Emitter {
    pub fn new(sink: Arc<dyn EventSink>, request_id: &str) -> Self {
        Self {
            sink,
            request_id: request_id.to_string(),
            session_id_extra: Arc::new(Mutex::new(json!({}))),
            on_session_id: Arc::new(Mutex::new(None)),
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Decorate `session-id` events (`sdkBackend`, `binPath`, `runtime`, ...).
    pub fn set_session_id_extra(&self, extra: Value) {
        *self.session_id_extra.lock() = extra;
    }

    pub fn set_on_session_id(&self, f: Arc<dyn Fn(&str) + Send + Sync>) {
        *self.on_session_id.lock() = Some(f);
    }

    pub fn emit_event(&self, event: Value) {
        self.sink.send(events::SDK_AGENT_EVENT, json!({ "requestId": self.request_id, "event": event }));
    }

    pub fn emit_done(&self) {
        self.sink.send(events::SDK_AGENT_DONE, json!({ "requestId": self.request_id }));
    }

    pub fn emit_error(&self, error: impl Into<String>) {
        let error: String = error.into();
        self.sink.send(events::SDK_AGENT_ERROR, json!({ "requestId": self.request_id, "error": error }));
    }

    pub fn text(&self, delta: &str) {
        if !delta.is_empty() {
            self.emit_event(json!({ "type": "text-delta", "textDelta": delta }));
        }
    }

    pub fn reasoning(&self, delta: &str) {
        if !delta.is_empty() {
            self.emit_event(json!({ "type": "reasoning-delta", "delta": delta }));
        }
    }

    pub fn reasoning_end(&self) {
        self.emit_event(json!({ "type": "reasoning-end" }));
    }

    pub fn tool_call(&self, tool_name: &str, args: Value, tool_call_id: &str) {
        let name = if tool_name.is_empty() { "unknown" } else { tool_name };
        let args = if args.is_null() { json!({}) } else { args };
        self.emit_event(json!({ "type": "tool-call", "toolName": name, "args": args, "toolCallId": tool_call_id }));
    }

    pub fn tool_result(&self, tool_call_id: &str, output: &str, tool_name: Option<&str>) {
        self.emit_event(json!({ "type": "tool-result", "toolCallId": tool_call_id, "output": output, "toolName": tool_name }));
    }

    pub fn file_change(&self, item_id: &str, changes: Value, status: &str) {
        let changes = if changes.is_array() { changes } else { json!([]) };
        self.emit_event(json!({ "type": "file-change", "itemId": item_id, "changes": changes, "status": status }));
    }

    pub fn web_search(&self, item_id: &str, query: &str, status: &str) {
        self.emit_event(json!({ "type": "web-search", "itemId": item_id, "query": query, "status": status }));
    }

    pub fn plan_update(&self, item_id: &str, items: Value, status: &str) {
        let items = if items.is_array() { items } else { json!([]) };
        self.emit_event(json!({ "type": "plan-update", "itemId": item_id, "items": items, "status": status }));
    }

    pub fn warning(&self, item_id: &str, message: &str) {
        if !message.is_empty() {
            self.emit_event(json!({ "type": "warning", "itemId": item_id, "message": message }));
        }
    }

    pub fn usage(&self, usage: Usage) {
        self.emit_event(json!({
            "type": "usage",
            "inputTokens": usage.input_tokens,
            "cachedInputTokens": usage.cached_input_tokens,
            "outputTokens": usage.output_tokens,
            "reasoningTokens": usage.reasoning_tokens,
            "totalTokens": usage.total_tokens,
        }));
    }

    pub fn status(&self, message: &str) {
        if !message.is_empty() {
            self.emit_event(json!({ "type": "status", "message": message }));
        }
    }

    pub fn session_id(&self, session_id: &str) {
        if session_id.is_empty() {
            return;
        }
        if let Some(cb) = self.on_session_id.lock().clone() {
            cb(session_id);
        }
        let mut event = json!({ "type": "session-id", "sessionId": session_id });
        if let (Some(target), Value::Object(extra)) = (event.as_object_mut(), &*self.session_id_extra.lock()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
        self.emit_event(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emitter() -> (Arc<RecordingSink>, Emitter) {
        let sink = Arc::new(RecordingSink::default());
        let emitter = Emitter::new(sink.clone(), "req-1");
        (sink, emitter)
    }

    #[test]
    fn canonical_shapes() {
        let (sink, e) = emitter();
        e.text("hi");
        e.text("");
        e.reasoning("think");
        e.reasoning_end();
        e.tool_call("", Value::Null, "c1");
        e.tool_result("c1", "out", Some("Bash"));
        e.file_change("f", json!("bad"), "completed");
        e.web_search("w", "q", "running");
        e.plan_update("p", json!([{ "text": "a", "completed": false }]), "running");
        e.warning("x", "");
        e.warning("x", "careful");
        e.usage(Usage { input_tokens: 1, cached_input_tokens: 2, output_tokens: 3, reasoning_tokens: 4, total_tokens: 4 });
        e.status("ok");
        let events = sink.stream_events();
        assert_eq!(events[0], json!({ "type": "text-delta", "textDelta": "hi" }));
        assert_eq!(events[1], json!({ "type": "reasoning-delta", "delta": "think" }));
        assert_eq!(events[2], json!({ "type": "reasoning-end" }));
        assert_eq!(events[3], json!({ "type": "tool-call", "toolName": "unknown", "args": {}, "toolCallId": "c1" }));
        assert_eq!(events[4], json!({ "type": "tool-result", "toolCallId": "c1", "output": "out", "toolName": "Bash" }));
        assert_eq!(events[5]["changes"], json!([]));
        assert_eq!(events[6]["type"], "web-search");
        assert_eq!(events[7]["items"][0]["text"], "a");
        assert_eq!(events[8], json!({ "type": "warning", "itemId": "x", "message": "careful" }));
        assert_eq!(events[9]["cachedInputTokens"], 2);
        assert_eq!(events[10], json!({ "type": "status", "message": "ok" }));
        assert_eq!(events.len(), 11);
    }

    #[test]
    fn done_error_and_session_id_envelopes() {
        let (sink, e) = emitter();
        e.set_session_id_extra(json!({ "sdkBackend": "claude", "binPath": "/x", "runtime": "sdk" }));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        e.set_on_session_id(Arc::new(move |id| seen2.lock().push(id.to_string())));
        e.session_id("");
        e.session_id("s-1");
        e.emit_done();
        e.emit_error("boom");
        let all = sink.take();
        assert_eq!(all[0].0, events::SDK_AGENT_EVENT);
        assert_eq!(all[0].1, json!({ "requestId": "req-1", "event": { "type": "session-id", "sessionId": "s-1", "sdkBackend": "claude", "binPath": "/x", "runtime": "sdk" } }));
        assert_eq!(all[1], (events::SDK_AGENT_DONE.to_string(), json!({ "requestId": "req-1" })));
        assert_eq!(all[2], (events::SDK_AGENT_ERROR.to_string(), json!({ "requestId": "req-1", "error": "boom" })));
        assert_eq!(*seen.lock(), vec!["s-1".to_string()]);
    }
}
