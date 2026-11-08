//! Host side of the plugin JSON-RPC transport (ports of `rpcRouter.cjs` and
//! `streamRouter.cjs`).
//!
//! One router per runtime. Every inbound envelope passes the JSON budget and
//! the committed contract schema before correlation or dispatch. Requests
//! carry deadlines and cancellation IDs; a timed-out or cancelled outbound
//! request leaves one bounded tombstone so exactly one late response is
//! tolerated. Streams use sequence numbers and byte credit.
//!
//! Wire adaptation for non-MessagePort transports (webview relay, Node
//! stdio): a stream chunk whose payload was an `ArrayBuffer` transfer arrives
//! as `{ frame, transferBase64 }`; the host only ever *sends* `json` or
//! `base64` chunks, so it never needs transfers outbound.

use crate::constants::{PLUGIN_RPC_DEFAULT_TIMEOUT_MS, PLUGIN_RPC_MAX_PENDING};
use crate::contract;
use crate::error::{codes, PluginError, PluginResult};
use base64::Engine;
use futures::future::BoxFuture;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// Transport-level context of one inbound call.
#[derive(Clone)]
pub struct TransportContext {
    pub plugin_id: String,
    pub signal: CancellationToken,
    pub cancellation_id: Option<String>,
    pub deadline_ms: u64,
    pub request_id: Option<Value>,
    pub notification: bool,
}

pub type Handler = Arc<dyn Fn(Value, TransportContext) -> BoxFuture<'static, PluginResult<Value>> + Send + Sync>;

/// One materialized stream chunk.
#[derive(Debug, Clone)]
pub enum StreamChunk {
    Json(Value),
    Bytes(Vec<u8>),
}

/// Handlers bound to an accepted incoming stream. `on_chunk` receives the
/// chunk and a `release` closure that returns receive credit.
pub struct IncomingHandlers {
    pub on_chunk: Box<dyn FnMut(StreamChunk, Box<dyn FnOnce() + Send>) + Send>,
    pub on_close: Option<Box<dyn FnOnce(Value) + Send>>,
}

/// An incoming stream offered to the host.
pub struct IncomingStream {
    pub stream_id: String,
    pub window_bytes: u64,
    pub signal: CancellationToken,
    router: Arc<RpcRouter>,
}

impl IncomingStream {
    pub fn bind(&self, handlers: IncomingHandlers) -> PluginResult<()> {
        let mut state = self.router.state.lock();
        let incoming = state
            .incoming
            .get_mut(&self.stream_id)
            .filter(|s| !s.closed)
            .ok_or_else(|| PluginError::host(format!("Unknown incoming plugin stream: {}", self.stream_id)))?;
        incoming.handlers = Some(handlers);
        Ok(())
    }
}

pub type IncomingStreamHandler = Arc<dyn Fn(&IncomingStream) -> bool + Send + Sync>;

/// Request / notification handlers of one runtime.
#[derive(Clone, Default)]
pub struct Routes {
    pub requests: HashMap<String, Handler>,
    pub notifications: HashMap<String, Handler>,
    pub on_incoming_stream: Option<IncomingStreamHandler>,
    pub on_progress: Option<Arc<dyn Fn(Value) + Send + Sync>>,
    /// Synchronous transport guard (quota) run before schema traversal.
    pub on_before_message: Option<Arc<dyn Fn(&Value) -> PluginResult<()> + Send + Sync>>,
}

pub type Outbound = Arc<dyn Fn(Value) -> PluginResult<()> + Send + Sync>;

struct PendingRequest {
    method: String,
    cancellation_id: String,
    tx: oneshot::Sender<PluginResult<Value>>,
}

struct IncomingState {
    next_sequence: u64,
    available: u64,
    window: u64,
    update_sequence: i64,
    closed: bool,
    signal: CancellationToken,
    handlers: Option<IncomingHandlers>,
}

struct OutgoingState {
    next_sequence: u64,
    available: u64,
    max_credit: u64,
    last_update_sequence: i64,
    queue: VecDeque<(Value, u64, oneshot::Sender<PluginResult<()>>)>,
    queued_bytes: u64,
    closed: bool,
    terminal: Option<&'static str>,
    on_close: Option<Box<dyn FnOnce(Value) + Send>>,
}

#[derive(Default)]
struct RouterState {
    pending: HashMap<String, PendingRequest>,
    pending_cancellation_ids: HashSet<String>,
    retired: VecDeque<String>,
    inflight: HashMap<String, CancellationToken>,
    inflight_ids: HashSet<String>,
    inflight_notifications: usize,
    next_id: u64,
    closed: bool,
    incoming: HashMap<String, IncomingState>,
    outgoing: HashMap<String, OutgoingState>,
}

pub struct RpcRouter {
    pub plugin_id: String,
    send: Outbound,
    routes: Routes,
    state: Mutex<RouterState>,
    max_pending: usize,
    default_timeout_ms: u64,
    on_protocol_error: Mutex<Option<Box<dyn FnOnce(PluginError) + Send>>>,
    closed_token: CancellationToken,
}

fn id_key(id: &Value) -> String {
    match id {
        Value::String(s) => format!("string:{s}"),
        other => format!("number:{other}"),
    }
}

fn protocol(message: impl Into<String>) -> PluginError {
    PluginError::host(message)
}

impl RpcRouter {
    pub fn new(
        plugin_id: impl Into<String>,
        send: Outbound,
        routes: Routes,
        on_protocol_error: Option<Box<dyn FnOnce(PluginError) + Send>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            plugin_id: plugin_id.into(),
            send,
            routes,
            state: Mutex::new(RouterState::default()),
            max_pending: PLUGIN_RPC_MAX_PENDING,
            default_timeout_ms: PLUGIN_RPC_DEFAULT_TIMEOUT_MS,
            on_protocol_error: Mutex::new(on_protocol_error),
            closed_token: CancellationToken::new(),
        })
    }

    pub fn is_closed(&self) -> bool {
        self.state.lock().closed
    }

    /// Cancelled when the router closes.
    pub fn closed_token(&self) -> CancellationToken {
        self.closed_token.clone()
    }

    fn send_rpc(&self, message: Value) -> PluginResult<()> {
        contract::assert_rpc_message(&message)?;
        (self.send)(message)
    }

    fn send_failure(&self, id: Value, error: &PluginError) {
        let wire = json!({ "jsonrpc": "2.0", "id": id, "error": error.to_wire() });
        if self.send_rpc(wire).is_err() {
            let _ = self.send_rpc(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": codes::INTERNAL, "message": "Plugin host request failed" }
            }));
        }
    }

    /// Accept one inbound transport message. Protocol violations close the
    /// router and report through `on_protocol_error`.
    pub fn accept(self: &Arc<Self>, message: Value) {
        if self.is_closed() {
            return;
        }
        if let Err(error) = self.accept_inner(message) {
            if self.is_closed() {
                return;
            }
            let report = self.on_protocol_error.lock().take();
            if let Some(report) = report {
                report(error.clone());
            }
            self.close(error);
        }
    }

    fn accept_inner(self: &Arc<Self>, mut message: Value) -> PluginResult<()> {
        if let Some(guard) = &self.routes.on_before_message {
            guard(&message)?;
        }
        if message.get("frame").is_some() {
            let transfer = match message.as_object_mut().and_then(|m| m.remove("transferBase64")) {
                Some(Value::String(b64)) => Some(
                    base64::engine::general_purpose::STANDARD
                        .decode(b64)
                        .map_err(|_| protocol("Invalid stream transfer payload"))?,
                ),
                Some(_) => return Err(protocol("Invalid stream transfer payload")),
                None => None,
            };
            let object = message.as_object().ok_or_else(|| protocol("Invalid plugin stream envelope"))?;
            if object.keys().any(|k| k != "frame" && k != "transfer") {
                return Err(protocol("Plugin stream envelope contains unknown properties"));
            }
            let frame = message["frame"].clone();
            contract::assert_stream_frame(&frame)?;
            return self.accept_stream(frame, transfer);
        }
        contract::assert_rpc_message(&message)?;
        let has_id = message.get("id").is_some();
        if has_id && (message.get("result").is_some() || message.get("error").is_some()) {
            return self.accept_response(message);
        }
        let method = message.get("method").and_then(Value::as_str).unwrap_or("").to_string();
        if method == "$/progress" {
            if let Some(on_progress) = &self.routes.on_progress {
                on_progress(message.get("params").cloned().unwrap_or(Value::Null));
            }
            return Ok(());
        }
        if method == "$/cancelRequest" {
            let id = message["params"]["cancellationId"].as_str().unwrap_or("");
            let token = self.state.lock().inflight.get(id).cloned();
            if let Some(token) = token {
                token.cancel();
            }
            return Ok(());
        }
        if has_id {
            self.accept_request(method, message);
            return Ok(());
        }
        self.accept_notification(method, message)
    }

    fn accept_response(&self, message: Value) -> PluginResult<()> {
        let key = id_key(&message["id"]);
        let pending = {
            let mut state = self.state.lock();
            match state.pending.remove(&key) {
                Some(p) => {
                    state.pending_cancellation_ids.remove(&p.cancellation_id);
                    p
                }
                None => {
                    if let Some(pos) = state.retired.iter().position(|k| k == &key) {
                        state.retired.remove(pos);
                        return Ok(());
                    }
                    return Err(protocol(format!("Plugin returned an unknown RPC response ID: {}", message["id"])));
                }
            }
        };
        let result = if let Some(error) = message.get("error") {
            Err(PluginError::from_wire(error))
        } else {
            let result = message.get("result").cloned().unwrap_or(Value::Null);
            if pending.method == "plugin.initialize" {
                contract::assert_initialize_result(&result).map(|_| result)
            } else {
                Ok(result)
            }
        };
        let _ = pending.tx.send(result);
        Ok(())
    }

    fn accept_request(self: &Arc<Self>, method: String, message: Value) {
        let id = message["id"].clone();
        let key = id_key(&id);
        let handler = self.routes.requests.get(&method).cloned();
        let (cancellation_id, token) = {
            let mut state = self.state.lock();
            if state.inflight.len() >= self.max_pending {
                drop(state);
                let _ = self.send_rpc(json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": codes::RESOURCE_EXHAUSTED, "message": "Too many in-flight plugin requests" } }));
                return;
            }
            if handler.is_none() {
                drop(state);
                let _ = self.send_rpc(json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": codes::METHOD_NOT_FOUND, "message": format!("Unsupported plugin method: {method}") } }));
                return;
            }
            if state.inflight_ids.contains(&key) {
                drop(state);
                self.send_failure(id, &PluginError::rpc(codes::INVALID_PARAMS, "Duplicate in-flight plugin request ID"));
                return;
            }
            let requested = message.get("cancellationId").and_then(Value::as_str).map(str::to_string);
            if let Some(cid) = &requested {
                if state.inflight.contains_key(cid) {
                    drop(state);
                    self.send_failure(id, &PluginError::rpc(codes::INVALID_PARAMS, "Duplicate in-flight plugin cancellation ID"));
                    return;
                }
            }
            let cid = requested.unwrap_or_else(|| format!("host-{}", uuid::Uuid::new_v4()));
            let token = self.closed_token.child_token();
            state.inflight.insert(cid.clone(), token.clone());
            state.inflight_ids.insert(key.clone());
            (cid, token)
        };
        let handler = handler.expect("checked");
        let timeout_ms = message.get("deadlineMs").and_then(Value::as_u64).unwrap_or(self.default_timeout_ms);
        let ctx = TransportContext {
            plugin_id: self.plugin_id.clone(),
            signal: token.clone(),
            cancellation_id: Some(cancellation_id.clone()),
            deadline_ms: timeout_ms,
            request_id: Some(id.clone()),
            notification: false,
        };
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let router = self.clone();
        tokio::spawn(async move {
            let outcome = tokio::select! {
                result = handler(params, ctx) => result,
                _ = token.cancelled() => Err(if router.is_closed() {
                    PluginError::unavailable("Plugin runtime closed")
                } else {
                    PluginError::cancelled()
                }),
                _ = tokio::time::sleep(Duration::from_millis(timeout_ms)) => {
                    token.cancel();
                    Err(PluginError::deadline("Plugin request deadline exceeded"))
                }
            };
            if !router.is_closed() {
                match outcome {
                    Ok(result) => {
                        if let Err(err) = router.send_rpc(json!({ "jsonrpc": "2.0", "id": id, "result": result })) {
                            router.send_failure(id, &err);
                        }
                    }
                    Err(err) => router.send_failure(id, &err),
                }
            }
            let mut state = router.state.lock();
            state.inflight.remove(&cancellation_id);
            state.inflight_ids.remove(&key);
        });
    }

    fn accept_notification(self: &Arc<Self>, method: String, message: Value) -> PluginResult<()> {
        let Some(handler) = self.routes.notifications.get(&method).cloned() else { return Ok(()) };
        {
            let mut state = self.state.lock();
            if state.inflight_notifications >= self.max_pending {
                return Err(PluginError::exhausted("Too many in-flight plugin notifications"));
            }
            state.inflight_notifications += 1;
        }
        let token = self.closed_token.child_token();
        let ctx = TransportContext {
            plugin_id: self.plugin_id.clone(),
            signal: token.clone(),
            cancellation_id: None,
            deadline_ms: self.default_timeout_ms,
            request_id: None,
            notification: true,
        };
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let router = self.clone();
        let timeout = self.default_timeout_ms;
        tokio::spawn(async move {
            tokio::select! {
                _ = handler(params, ctx) => {}
                _ = token.cancelled() => {}
                _ = tokio::time::sleep(Duration::from_millis(timeout)) => token.cancel(),
            }
            router.state.lock().inflight_notifications -= 1;
        });
        Ok(())
    }

    /// Host → plugin request.
    pub async fn request(
        self: &Arc<Self>,
        method: &str,
        params: Option<Value>,
        timeout: Option<Duration>,
        signal: Option<CancellationToken>,
    ) -> PluginResult<Value> {
        let timeout = timeout.unwrap_or(Duration::from_millis(self.default_timeout_ms));
        let (id, cancellation_id, rx) = {
            let mut state = self.state.lock();
            if state.closed {
                return Err(PluginError::unavailable("Plugin runtime is closed"));
            }
            if signal.as_ref().is_some_and(CancellationToken::is_cancelled) {
                return Err(PluginError::cancelled());
            }
            if state.pending.len() >= self.max_pending {
                return Err(PluginError::exhausted("Too many pending plugin requests"));
            }
            let mut id = None;
            for _ in 0..=(self.max_pending + state.retired.len()) {
                let candidate = state.next_id;
                state.next_id = if candidate >= (1u64 << 53) - 1 { 0 } else { candidate + 1 };
                let key = id_key(&json!(candidate));
                if !state.pending.contains_key(&key) && !state.retired.contains(&key) {
                    id = Some(candidate);
                    break;
                }
            }
            let id = id.ok_or_else(|| PluginError::exhausted("No RPC correlation ID is available"))?;
            let cancellation_id = loop {
                let candidate = format!("host-{}", uuid::Uuid::new_v4());
                if !state.pending_cancellation_ids.contains(&candidate) {
                    break candidate;
                }
            };
            let (tx, rx) = oneshot::channel();
            state.pending.insert(
                id_key(&json!(id)),
                PendingRequest { method: method.to_string(), cancellation_id: cancellation_id.clone(), tx },
            );
            state.pending_cancellation_ids.insert(cancellation_id.clone());
            (id, cancellation_id, rx)
        };
        let mut message = json!({
            "jsonrpc": "2.0", "id": id, "method": method,
            "deadlineMs": timeout.as_millis() as u64, "cancellationId": cancellation_id,
        });
        if let Some(params) = params {
            message["params"] = params;
        }
        if let Err(err) = self.send_rpc(message) {
            self.forget_pending(id, false);
            return Err(err);
        }
        let signal = signal.unwrap_or_default();
        tokio::select! {
            result = rx => result.unwrap_or_else(|_| Err(PluginError::unavailable("Plugin runtime closed"))),
            _ = tokio::time::sleep(timeout) => {
                self.forget_pending(id, true);
                let _ = self.send_rpc(json!({ "jsonrpc": "2.0", "method": "$/cancelRequest", "params": { "cancellationId": cancellation_id } }));
                Err(PluginError::deadline(format!("Plugin request timed out: {method}")))
            }
            _ = signal.cancelled() => {
                self.forget_pending(id, true);
                let _ = self.send_rpc(json!({ "jsonrpc": "2.0", "method": "$/cancelRequest", "params": { "cancellationId": cancellation_id } }));
                Err(PluginError::cancelled())
            }
        }
    }

    fn forget_pending(&self, id: u64, retire: bool) {
        let key = id_key(&json!(id));
        let mut state = self.state.lock();
        if let Some(pending) = state.pending.remove(&key) {
            state.pending_cancellation_ids.remove(&pending.cancellation_id);
            if retire {
                state.retired.retain(|k| k != &key);
                state.retired.push_back(key);
                while state.retired.len() > self.max_pending {
                    state.retired.pop_front();
                }
            }
        }
    }

    pub fn notify(&self, method: &str, params: Option<Value>) -> PluginResult<()> {
        if self.is_closed() {
            return Err(PluginError::unavailable("Plugin runtime is closed"));
        }
        let mut message = json!({ "jsonrpc": "2.0", "method": method });
        if let Some(params) = params {
            message["params"] = params;
        }
        self.send_rpc(message)
    }

    /// Close: reject pending work, cancel in-flight handlers and streams.
    pub fn close(&self, error: PluginError) {
        let (pending, incoming, outgoing) = {
            let mut state = self.state.lock();
            if state.closed {
                return;
            }
            state.closed = true;
            state.pending_cancellation_ids.clear();
            state.retired.clear();
            state.inflight.clear();
            state.inflight_ids.clear();
            (
                std::mem::take(&mut state.pending),
                std::mem::take(&mut state.incoming),
                std::mem::take(&mut state.outgoing),
            )
        };
        self.closed_token.cancel();
        for (_, p) in pending {
            let _ = p.tx.send(Err(error.clone()));
        }
        let reason = json!(error.message());
        for (_, mut s) in outgoing {
            for (_, _, tx) in s.queue.drain(..) {
                let _ = tx.send(Err(error.clone()));
            }
            if let Some(on_close) = s.on_close.take() {
                on_close(reason.clone());
            }
        }
        for (_, mut s) in incoming {
            s.signal.cancel();
            if let Some(on_close) = s.handlers.take().and_then(|h| h.on_close) {
                on_close(reason.clone());
            }
        }
    }

    // ---- streams -----------------------------------------------------------

    fn send_frame(&self, frame: Value) -> PluginResult<()> {
        contract::assert_stream_frame(&frame)?;
        (self.send)(json!({ "frame": frame }))
    }

    fn accept_stream(self: &Arc<Self>, frame: Value, transfer: Option<Vec<u8>>) -> PluginResult<()> {
        let stream_id = frame["streamId"].as_str().unwrap_or("").to_string();
        let kind = frame["kind"].as_str().unwrap_or("").to_string();
        let sequence = frame["sequence"].as_u64().unwrap_or(0);
        if kind == "open" {
            let window = frame["windowBytes"].as_u64().unwrap_or(0);
            {
                let mut state = self.state.lock();
                if state.incoming.contains_key(&stream_id)
                    || state.outgoing.contains_key(&stream_id)
                    || state.incoming.len() + state.outgoing.len() >= self.max_pending
                {
                    return Err(protocol(format!("Plugin stream cannot be opened: {stream_id}")));
                }
                state.incoming.insert(
                    stream_id.clone(),
                    IncomingState {
                        next_sequence: 1,
                        available: window,
                        window,
                        update_sequence: -1,
                        closed: false,
                        signal: self.closed_token.child_token(),
                        handlers: None,
                    },
                );
            }
            let signal = self.state.lock().incoming[&stream_id].signal.clone();
            let offer = IncomingStream { stream_id: stream_id.clone(), window_bytes: window, signal, router: self.clone() };
            let accepted = self.routes.on_incoming_stream.as_ref().is_some_and(|h| h(&offer));
            if !accepted {
                self.cancel_incoming(&stream_id, json!("Plugin stream was not accepted"))?;
            }
            return Ok(());
        }
        if kind == "windowUpdate" {
            let credit = frame["creditBytes"].as_u64().unwrap_or(0);
            let mut state = self.state.lock();
            let outgoing = state
                .outgoing
                .get_mut(&stream_id)
                .ok_or_else(|| protocol(format!("Unknown outgoing plugin stream: {stream_id}")))?;
            if sequence as i64 != outgoing.last_update_sequence + 1 {
                return Err(protocol(format!("Out-of-order stream credit update: {stream_id}")));
            }
            outgoing.last_update_sequence = sequence as i64;
            outgoing.available += credit;
            if outgoing.available > outgoing.max_credit {
                return Err(protocol(format!("Plugin stream credit exceeds its negotiated window: {stream_id}")));
            }
            if matches!(outgoing.terminal, Some("end" | "cancel")) {
                if outgoing.available == outgoing.max_credit {
                    state.outgoing.remove(&stream_id);
                }
                return Ok(());
            }
            if outgoing.closed {
                return Err(protocol(format!("Unknown outgoing plugin stream: {stream_id}")));
            }
            drop(state);
            return self.flush_outgoing(&stream_id);
        }
        if kind == "cancel" {
            let mut state = self.state.lock();
            if let Some(outgoing) = state.outgoing.get(&stream_id) {
                if sequence as i64 != (outgoing.last_update_sequence + 1).max(1) {
                    return Err(protocol(format!("Out-of-order stream cancellation: {stream_id}")));
                }
                let mut outgoing = state.outgoing.remove(&stream_id).expect("present");
                drop(state);
                outgoing.closed = true;
                for (_, _, tx) in outgoing.queue.drain(..) {
                    let _ = tx.send(Err(PluginError::host(format!("Plugin stream cancelled: {stream_id}"))));
                }
                if let Some(on_close) = outgoing.on_close.take() {
                    on_close(json!("cancel"));
                }
                return Ok(());
            }
        }
        // Incoming chunk / end / error / cancel.
        let mut state = self.state.lock();
        let incoming = state
            .incoming
            .get_mut(&stream_id)
            .filter(|s| !s.closed)
            .ok_or_else(|| protocol(format!("Unknown incoming plugin stream: {stream_id}")))?;
        if sequence != incoming.next_sequence {
            return Err(protocol(format!("Out-of-order plugin stream frame: {stream_id}")));
        }
        incoming.next_sequence += 1;
        if kind == "chunk" {
            let data = &frame["data"];
            let credit = data["byteLength"].as_u64().unwrap_or(0);
            if credit > incoming.available {
                return Err(protocol(format!("Plugin stream exceeded receive credit: {stream_id}")));
            }
            incoming.available -= credit;
            let chunk = match data["encoding"].as_str() {
                Some("json") => {
                    if transfer.is_some() {
                        return Err(protocol("JSON stream chunks must not include a transferable buffer"));
                    }
                    StreamChunk::Json(data["value"].clone())
                }
                Some("base64") => {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(data["value"].as_str().unwrap_or(""))
                        .map_err(|_| protocol("Invalid base64 stream chunk"))?;
                    if bytes.len() as u64 != credit {
                        return Err(protocol("Stream chunk byteLength mismatch"));
                    }
                    StreamChunk::Bytes(bytes)
                }
                Some("transfer") => {
                    let bytes = transfer.ok_or_else(|| protocol("Transfer stream chunk is missing its buffer"))?;
                    if bytes.len() as u64 != credit {
                        return Err(protocol("Stream transfer byteLength mismatch"));
                    }
                    StreamChunk::Bytes(bytes)
                }
                _ => return Err(protocol("Invalid stream chunk encoding")),
            };
            let Some(mut handlers) = incoming.handlers.take() else {
                drop(state);
                return self.cancel_incoming(&stream_id, json!("Plugin stream has no consumer"));
            };
            drop(state);
            let router = self.clone();
            let sid = stream_id.clone();
            let release: Box<dyn FnOnce() + Send> = Box::new(move || router.release_credit(&sid, credit));
            (handlers.on_chunk)(chunk, release);
            if let Some(s) = self.state.lock().incoming.get_mut(&stream_id) {
                s.handlers = Some(handlers);
            }
            return Ok(());
        }
        let mut incoming = state.incoming.remove(&stream_id).expect("present");
        drop(state);
        incoming.closed = true;
        incoming.signal.cancel();
        let reason = if kind == "error" { frame["error"].clone() } else { json!(kind) };
        let result = if kind == "cancel" && incoming.available < incoming.window {
            incoming.update_sequence += 1;
            self.send_frame(json!({
                "streamId": stream_id, "sequence": incoming.update_sequence,
                "kind": "windowUpdate", "creditBytes": incoming.window - incoming.available,
            }))
        } else {
            Ok(())
        };
        if let Some(on_close) = incoming.handlers.take().and_then(|h| h.on_close) {
            on_close(reason);
        }
        result
    }

    fn release_credit(&self, stream_id: &str, credit: u64) {
        let frame = {
            let mut state = self.state.lock();
            let Some(incoming) = state.incoming.get_mut(stream_id).filter(|s| !s.closed) else { return };
            incoming.available += credit;
            incoming.update_sequence += 1;
            json!({ "streamId": stream_id, "sequence": incoming.update_sequence, "kind": "windowUpdate", "creditBytes": credit })
        };
        if let Err(err) = self.send_frame(frame) {
            let removed = self.state.lock().incoming.remove(stream_id);
            if let Some(mut incoming) = removed {
                incoming.signal.cancel();
                if let Some(on_close) = incoming.handlers.take().and_then(|h| h.on_close) {
                    on_close(json!(err.message()));
                }
            }
        }
    }

    /// Cancel an incoming stream (host-side consumer gave up).
    pub fn cancel_incoming(&self, stream_id: &str, reason: Value) -> PluginResult<()> {
        let Some(mut incoming) = self.state.lock().incoming.remove(stream_id) else { return Ok(()) };
        incoming.closed = true;
        incoming.signal.cancel();
        incoming.update_sequence = (incoming.update_sequence + 1).max(1);
        let sent = self.send_frame(json!({ "streamId": stream_id, "sequence": incoming.update_sequence, "kind": "cancel" }));
        if let Some(on_close) = incoming.handlers.take().and_then(|h| h.on_close) {
            on_close(reason);
        }
        sent
    }

    /// Open a host → plugin stream.
    pub fn open_outgoing(
        self: &Arc<Self>,
        stream_id: &str,
        window_bytes: u64,
        on_close: Option<Box<dyn FnOnce(Value) + Send>>,
    ) -> PluginResult<OutgoingStream> {
        {
            let mut state = self.state.lock();
            if state.closed
                || state.outgoing.contains_key(stream_id)
                || state.incoming.contains_key(stream_id)
                || state.incoming.len() + state.outgoing.len() >= self.max_pending
            {
                return Err(PluginError::host(format!("Plugin stream cannot be opened: {stream_id}")));
            }
            state.outgoing.insert(
                stream_id.to_string(),
                OutgoingState {
                    next_sequence: 1,
                    available: window_bytes,
                    max_credit: window_bytes,
                    last_update_sequence: -1,
                    queue: VecDeque::new(),
                    queued_bytes: 0,
                    closed: false,
                    terminal: None,
                    on_close,
                },
            );
        }
        if let Err(err) = self.send_frame(json!({ "streamId": stream_id, "sequence": 0, "kind": "open", "windowBytes": window_bytes })) {
            self.state.lock().outgoing.remove(stream_id);
            return Err(err);
        }
        Ok(OutgoingStream { router: self.clone(), stream_id: stream_id.to_string() })
    }

    fn flush_outgoing(&self, stream_id: &str) -> PluginResult<()> {
        loop {
            let (frame, tx) = {
                let mut state = self.state.lock();
                let Some(outgoing) = state.outgoing.get_mut(stream_id) else { return Ok(()) };
                if outgoing.closed {
                    return Ok(());
                }
                let Some((_, bytes, _)) = outgoing.queue.front() else { return Ok(()) };
                if *bytes > outgoing.available {
                    return Ok(());
                }
                let (data, bytes, tx) = outgoing.queue.pop_front().expect("front");
                outgoing.queued_bytes -= bytes;
                outgoing.available -= bytes;
                let frame = json!({ "streamId": stream_id, "sequence": outgoing.next_sequence, "kind": "chunk", "data": data });
                outgoing.next_sequence += 1;
                (frame, tx)
            };
            match self.send_frame(frame) {
                Ok(()) => {
                    let _ = tx.send(Ok(()));
                }
                Err(err) => {
                    let _ = tx.send(Err(err.clone()));
                    let removed = self.state.lock().outgoing.remove(stream_id);
                    if let Some(mut outgoing) = removed {
                        for (_, _, tx) in outgoing.queue.drain(..) {
                            let _ = tx.send(Err(err.clone()));
                        }
                        if let Some(on_close) = outgoing.on_close.take() {
                            on_close(json!(err.message()));
                        }
                    }
                    return Err(err);
                }
            }
        }
    }
}

pub const PLUGIN_STREAM_MAX_CHUNK_BYTES: usize = 16 * 1024 * 1024;

/// Writer half of a host → plugin stream.
pub struct OutgoingStream {
    router: Arc<RpcRouter>,
    pub stream_id: String,
}

impl OutgoingStream {
    /// Queue bytes (sent as a base64 chunk); resolves once sent under credit.
    pub async fn write_bytes(&self, bytes: &[u8]) -> PluginResult<()> {
        if bytes.len() > PLUGIN_STREAM_MAX_CHUNK_BYTES {
            return Err(PluginError::invalid("Plugin stream chunk is too large"));
        }
        let data = json!({
            "encoding": "base64",
            "value": base64::engine::general_purpose::STANDARD.encode(bytes),
            "byteLength": bytes.len(),
        });
        self.queue(data, bytes.len() as u64).await
    }

    /// Queue a JSON chunk.
    pub async fn write_json(&self, value: Value) -> PluginResult<()> {
        let byte_length = serde_json::to_string(&value)?.len() as u64;
        self.queue(json!({ "encoding": "json", "value": value, "byteLength": byte_length }), byte_length).await
    }

    async fn queue(&self, data: Value, bytes: u64) -> PluginResult<()> {
        let rx = {
            let mut state = self.router.state.lock();
            let outgoing = state
                .outgoing
                .get_mut(&self.stream_id)
                .filter(|s| !s.closed)
                .ok_or_else(|| PluginError::host(format!("Plugin stream is closed: {}", self.stream_id)))?;
            if outgoing.queued_bytes + bytes > outgoing.max_credit {
                return Err(PluginError::host(format!(
                    "Plugin stream pending queue exceeds its negotiated window: {}",
                    self.stream_id
                )));
            }
            let (tx, rx) = oneshot::channel();
            outgoing.queue.push_back((data, bytes, tx));
            outgoing.queued_bytes += bytes;
            rx
        };
        self.router.flush_outgoing(&self.stream_id)?;
        rx.await.unwrap_or_else(|_| Err(PluginError::host("Plugin stream closed")))
    }

    fn finish(&self, kind: &'static str) -> PluginResult<()> {
        let (frame, on_close) = {
            let mut state = self.router.state.lock();
            let Some(outgoing) = state.outgoing.get_mut(&self.stream_id) else { return Ok(()) };
            if outgoing.closed {
                return Ok(());
            }
            if kind == "end" && !outgoing.queue.is_empty() {
                return Err(PluginError::host("Cannot end a plugin stream with pending backpressure"));
            }
            outgoing.closed = true;
            outgoing.terminal = Some(kind);
            for (_, _, tx) in outgoing.queue.drain(..) {
                let _ = tx.send(Err(PluginError::host(format!("Plugin stream {kind}"))));
            }
            outgoing.queued_bytes = 0;
            let frame = json!({ "streamId": self.stream_id, "sequence": outgoing.next_sequence, "kind": kind });
            let on_close = outgoing.on_close.take();
            if outgoing.available == outgoing.max_credit {
                state.outgoing.remove(&self.stream_id);
            }
            (frame, on_close)
        };
        let result = self.router.send_frame(frame);
        if result.is_err() {
            self.router.state.lock().outgoing.remove(&self.stream_id);
        }
        if let Some(on_close) = on_close {
            on_close(json!(kind));
        }
        result
    }

    pub fn end(&self) -> PluginResult<()> {
        self.finish("end")
    }

    pub fn cancel(&self) -> PluginResult<()> {
        self.finish("cancel")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn router_with(routes: Routes) -> (Arc<RpcRouter>, mpsc::UnboundedReceiver<Value>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let send: Outbound = Arc::new(move |m| {
            tx.send(m).map_err(|_| PluginError::host("closed"))
        });
        (RpcRouter::new("com.example.a", send, routes, None), rx)
    }

    #[tokio::test]
    async fn dispatches_requests_and_unknown_methods() {
        let mut routes = Routes::default();
        let handler: Handler = Arc::new(|params, _ctx| Box::pin(async move { Ok(json!({ "echo": params })) }));
        routes.requests.insert("storage.get".into(), handler);
        let (router, mut rx) = router_with(routes);
        router.accept(json!({ "jsonrpc": "2.0", "id": 1, "method": "storage.get", "params": { "key": "k" } }));
        let reply = rx.recv().await.unwrap();
        assert_eq!(reply["result"]["echo"]["key"], json!("k"));
        router.accept(json!({ "jsonrpc": "2.0", "id": 2, "method": "nope.method", "params": {} }));
        let reply = rx.recv().await.unwrap();
        assert_eq!(reply["error"]["code"], json!(codes::METHOD_NOT_FOUND));
    }

    #[tokio::test]
    async fn outbound_request_timeout_leaves_one_tombstone() {
        let (router, mut rx) = router_with(Routes::default());
        let r = router.clone();
        let task = tokio::spawn(async move { r.request("plugin.command.execute", Some(json!({})), Some(Duration::from_millis(20)), None).await });
        let sent = rx.recv().await.unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err.code(), Some(codes::DEADLINE_EXCEEDED));
        let cancel = rx.recv().await.unwrap();
        assert_eq!(cancel["method"], json!("$/cancelRequest"));
        // One late response is tolerated…
        router.accept(json!({ "jsonrpc": "2.0", "id": sent["id"], "result": null }));
        assert!(!router.is_closed());
        // …a second one is a protocol violation.
        router.accept(json!({ "jsonrpc": "2.0", "id": sent["id"], "result": null }));
        assert!(router.is_closed());
    }

    #[tokio::test]
    async fn rejects_schema_violations() {
        let (router, _rx) = router_with(Routes::default());
        router.accept(json!({ "jsonrpc": "1.0", "id": 1, "method": "x" }));
        assert!(router.is_closed());
    }

    #[tokio::test]
    #[allow(clippy::field_reassign_with_default)]
    async fn incoming_stream_credit_and_ordering() {
        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let sink = received.clone();
        let mut routes = Routes::default();
        routes.on_incoming_stream = Some(Arc::new(move |stream: &IncomingStream| {
            let sink = sink.clone();
            stream
                .bind(IncomingHandlers {
                    on_chunk: Box::new(move |chunk, release| {
                        if let StreamChunk::Bytes(b) = chunk {
                            sink.lock().push(b);
                        }
                        release();
                    }),
                    on_close: None,
                })
                .is_ok()
        }));
        let (router, mut rx) = router_with(routes);
        router.accept(json!({ "frame": { "streamId": "s1", "sequence": 0, "kind": "open", "windowBytes": 1024 } }));
        router.accept(json!({ "frame": { "streamId": "s1", "sequence": 1, "kind": "chunk",
            "data": { "encoding": "transfer", "byteLength": 3 } }, "transferBase64": "AQID" }));
        let update = rx.recv().await.unwrap();
        assert_eq!(update["frame"]["kind"], json!("windowUpdate"));
        assert_eq!(received.lock()[0], vec![1, 2, 3]);
        // Out-of-order sequence closes the router.
        router.accept(json!({ "frame": { "streamId": "s1", "sequence": 5, "kind": "end" } }));
        assert!(router.is_closed());
    }

    #[tokio::test]
    async fn outgoing_stream_respects_credit() {
        let (router, mut rx) = router_with(Routes::default());
        let stream = router.open_outgoing("out-1", 1024, None).unwrap();
        assert_eq!(rx.recv().await.unwrap()["frame"]["kind"], json!("open"));
        stream.write_bytes(&[7u8; 1024]).await.unwrap();
        assert_eq!(rx.recv().await.unwrap()["frame"]["data"]["encoding"], json!("base64"));
        let r = router.clone();
        let pending = tokio::spawn(async move {
            let s = OutgoingStream { router: r, stream_id: "out-1".into() };
            s.write_bytes(&[5]).await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(rx.try_recv().is_err(), "no credit yet");
        router.accept(json!({ "frame": { "streamId": "out-1", "sequence": 0, "kind": "windowUpdate", "creditBytes": 1024 } }));
        pending.await.unwrap().unwrap();
        assert_eq!(rx.recv().await.unwrap()["frame"]["sequence"], json!(2));
    }
}
