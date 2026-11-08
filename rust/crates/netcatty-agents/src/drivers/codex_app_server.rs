//! Codex App Server runtime (Electron: `aiBridge/codexAppServer/{connection,runtime,probe}.cjs`).
//!
//! `codex app-server --stdio` speaks newline-delimited JSON-RPC (no `jsonrpc`
//! field). One warm connection per (binary, env fingerprint) is kept; turns run
//! `thread/start|resume` + `turn/start`, stream notifications, support
//! `turn/steer` and `turn/interrupt`, and route the server's approval / user
//! input requests to the renderer as `netcatty:ai:codex-app-server:interaction-*`.

use super::codex_exec::{parse_codex_model_selection, to_codex_mcp_config};
use super::{TurnContext, TurnResult};
use crate::emit::{Emitter, EventSink, Usage};
use crate::events;
use crate::process::{build_command, Stdin, StderrTail};
use crate::EnvMap;
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const INITIALIZE_TIMEOUT: Duration = Duration::from_secs(10);
pub const INTERACTION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const INTERRUPT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const INTERRUPT_GRACE: Duration = Duration::from_secs(2);
const CLOSE_KILL_GRACE: Duration = Duration::from_millis(750);
const MAX_JSONL_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAX_STREAMED_PREFIX_CHARS: usize = 256 * 1024;
const MAX_TOOL_OUTPUT_CHARS: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: Option<i64>,
    pub message: String,
    pub data: Value,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl RpcError {
    fn msg(message: impl Into<String>) -> Self {
        Self { code: None, message: message.into(), data: Value::Null }
    }
}

/// `buildCodexAppServerLaunch`.
pub fn build_launch(bin_path: &str, args: &[&str]) -> Result<(String, Vec<String>), String> {
    let exe = bin_path.trim();
    if exe.is_empty() {
        return Err("Codex binary not found. Configure Codex in Settings -> AI.".into());
    }
    let lower = exe.to_ascii_lowercase();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    if lower.ends_with(".js") || lower.ends_with(".cjs") || lower.ends_with(".mjs") {
        let mut full = vec![exe.to_string()];
        full.extend(args);
        return Ok(("node".into(), full));
    }
    if lower.ends_with(".cmd") || lower.ends_with(".bat") || lower.ends_with(".ps1") {
        return Err(format!("Codex App Server cannot launch the shell shim {exe}. Configure the native Codex executable or reinstall the Codex CLI."));
    }
    Ok((exe.to_string(), args))
}

/// `buildCodexAppServerKey`: binary + sha256(sorted env).
pub fn connection_key(bin_path: &str, env: &EnvMap) -> String {
    let fingerprint = hex::encode(Sha256::digest(serde_json::to_string(env).unwrap_or_default().as_bytes()));
    format!("{bin_path}\0{fingerprint}")
}

/// `probeCodexAppServer`: `codex app-server --help` advertises the server.
pub async fn probe(bin_path: &str, env: &EnvMap) -> Value {
    let (command, args) = match build_launch(bin_path, &["app-server", "--help"]) {
        Ok(l) => l,
        Err(error) => return json!({ "available": false, "error": error }),
    };
    match crate::cli::run_command(&command, &args, env, None, Some(Duration::from_secs(5))).await {
        Ok(result) => {
            let output = format!("{}\n{}", result.stdout, result.stderr);
            if regex::Regex::new(r"(?i)Run the app server|--listen|--stdio").unwrap().is_match(&output) {
                json!({ "available": true })
            } else {
                json!({ "available": false, "error": "This Codex CLI does not advertise App Server support." })
            }
        }
        Err(error) => json!({ "available": false, "error": error.to_string() }),
    }
}

enum ConnEvent {
    Notification(String, Value),
    ServerRequest(String, Value),
    Fatal(String, String),
}

/// One `codex app-server` process.
type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, RpcError>>>>>;

pub struct Connection {
    key: String,
    stdin_tx: Mutex<Option<mpsc::UnboundedSender<String>>>,
    pending: PendingMap,
    next_id: AtomicU64,
    closed: Arc<AtomicBool>,
    pid: Option<u32>,
    child: Arc<tokio::sync::Mutex<Option<tokio::process::Child>>>,
    stderr: StderrTail,
}

impl Connection {
    async fn start(bin: &str, env: &EnvMap, app_version: &str, key: &str, events_tx: mpsc::UnboundedSender<ConnEvent>) -> Result<Arc<Self>, String> {
        let (command, args) = build_launch(bin, &["app-server", "--stdio"])?;
        let spec = crate::cli::SpawnSpec { command, args, shell: false };
        let mut cmd = build_command(&spec, env, std::env::current_dir().ok().as_deref(), Stdin::Piped);
        let mut child = cmd.spawn().map_err(|e| e.to_string())?;
        let stdout = child.stdout.take().ok_or("Codex App Server stdout is unavailable")?;
        let mut stdin = child.stdin.take().ok_or("Codex App Server stdin is unavailable")?;
        let stderr = StderrTail::spawn(child.stderr.take(), 32_000);
        let pid = child.id();
        let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(line) = stdin_rx.recv().await {
                if stdin.write_all(line.as_bytes()).await.is_err() || stdin.flush().await.is_err() {
                    break;
                }
            }
            let _ = stdin.shutdown().await;
        });
        let conn = Arc::new(Self {
            key: key.to_string(),
            stdin_tx: Mutex::new(Some(stdin_tx)),
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            closed: Arc::new(AtomicBool::new(false)),
            pid,
            child: Arc::new(tokio::sync::Mutex::new(Some(child))),
            stderr,
        });
        let reader_conn = conn.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::with_capacity(64 * 1024, stdout);
            let mut buf = Vec::new();
            let fatal = loop {
                buf.clear();
                match reader.read_until(b'\n', &mut buf).await {
                    Ok(0) => break None,
                    Ok(_) if buf.len() > MAX_JSONL_LINE_BYTES => break Some(format!("Codex App Server message exceeded {MAX_JSONL_LINE_BYTES} bytes")),
                    Ok(_) => {
                        let line = String::from_utf8_lossy(&buf).trim().to_string();
                        if line.is_empty() {
                            continue;
                        }
                        let Ok(message) = serde_json::from_str::<Value>(&line) else {
                            break Some(format!("Codex App Server emitted invalid JSON: {}", line.chars().take(500).collect::<String>()));
                        };
                        let has_id = message.get("id").is_some();
                        let method = message.get("method").and_then(|m| m.as_str()).is_some();
                        if has_id && !method {
                            let id = message["id"].as_u64().unwrap_or(0);
                            if let Some(tx) = reader_conn.pending.lock().remove(&id) {
                                let result = match message.get("error") {
                                    Some(err) if !err.is_null() => Err(RpcError {
                                        code: err["code"].as_i64(),
                                        message: err["message"].as_str().unwrap_or("Codex App Server request failed").to_string(),
                                        data: err.get("data").cloned().unwrap_or(Value::Null),
                                    }),
                                    _ => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
                                };
                                let _ = tx.send(result);
                            }
                        } else if method && has_id {
                            let _ = events_tx.send(ConnEvent::ServerRequest(reader_conn.key.clone(), message));
                        } else if method {
                            let _ = events_tx.send(ConnEvent::Notification(reader_conn.key.clone(), message));
                        }
                    }
                    Err(e) => break Some(e.to_string()),
                }
            };
            if reader_conn.closed.load(Ordering::SeqCst) {
                return;
            }
            let message = match fatal {
                Some(m) => m,
                None => {
                    let status = match reader_conn.child.lock().await.as_mut() {
                        Some(child) => tokio::time::timeout(Duration::from_secs(2), child.wait()).await.ok().and_then(|s| s.ok()),
                        None => None,
                    };
                    let code = status.and_then(|s| s.code()).map(|c| c.to_string()).unwrap_or_else(|| "null".into());
                    let detail = reader_conn.stderr.text().trim().to_string();
                    let suffix = if detail.is_empty() { String::new() } else { format!("\n{detail}") };
                    format!("Codex App Server exited unexpectedly (code {code}, signal none).{suffix}")
                }
            };
            reader_conn.fail_pending(&message);
            let _ = events_tx.send(ConnEvent::Fatal(reader_conn.key.clone(), message));
            reader_conn.close();
        });
        let init = conn
            .request(
                "initialize",
                json!({
                    "clientInfo": { "name": "netcatty", "title": "Netcatty", "version": app_version },
                    "capabilities": { "experimentalApi": true, "requestAttestation": false, "mcpServerOpenaiFormElicitation": false },
                }),
                INITIALIZE_TIMEOUT,
            )
            .await;
        if let Err(error) = init {
            conn.close();
            let detail = conn.stderr.text().trim().to_string();
            return Err(if detail.is_empty() || error.message.contains(&detail) { error.message } else { format!("{}\n{detail}", error.message) });
        }
        conn.notify("initialized", json!({}));
        Ok(conn)
    }

    fn fail_pending(&self, message: &str) {
        for (_, tx) in self.pending.lock().drain() {
            let _ = tx.send(Err(RpcError::msg(message)));
        }
    }

    fn write(&self, message: &Value) -> Result<(), RpcError> {
        match self.stdin_tx.lock().as_ref() {
            Some(tx) if tx.send(format!("{message}\n")).is_ok() => Ok(()),
            _ => Err(RpcError::msg("Codex App Server stdin is unavailable")),
        }
    }

    pub async fn request(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, RpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(id, tx);
        if let Err(e) = self.write(&json!({ "id": id, "method": method, "params": params })) {
            self.pending.lock().remove(&id);
            return Err(e);
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(RpcError::msg("Codex App Server connection closed")),
            Err(_) => {
                self.pending.lock().remove(&id);
                Err(RpcError::msg(format!("Codex App Server request timed out: {method}")))
            }
        }
    }

    pub fn notify(&self, method: &str, params: Value) {
        let _ = self.write(&json!({ "method": method, "params": params }));
    }

    pub fn respond(&self, id: &Value, result: Value) {
        let _ = self.write(&json!({ "id": id, "result": result }));
    }

    pub fn respond_error(&self, id: &Value, code: i64, message: &str) {
        let _ = self.write(&json!({ "id": id, "error": { "code": code, "message": message } }));
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// End stdin, SIGTERM, SIGKILL after the grace period.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.stdin_tx.lock().take();
        self.fail_pending("Codex App Server connection closed");
        crate::process::signal_process_tree(self.pid, false);
        let child = self.child.clone();
        let pid = self.pid;
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            crate::process::signal_process_tree(pid, true);
            return;
        };
        handle.spawn(async move {
            let mut guard = child.lock().await;
            if let Some(c) = guard.as_mut() {
                if tokio::time::timeout(CLOSE_KILL_GRACE, c.wait()).await.is_err() {
                    crate::process::signal_process_tree(pid, true);
                    let _ = c.wait().await;
                }
            }
            guard.take();
        });
    }
}

#[derive(Default)]
struct StreamState {
    prefix: String,
    length: usize,
}

fn append_stream(map: &mut HashMap<String, StreamState>, id: &str, delta: &str) {
    let entry = map.entry(id.to_string()).or_default();
    let remaining = MAX_STREAMED_PREFIX_CHARS.saturating_sub(entry.prefix.chars().count());
    entry.prefix.extend(delta.chars().take(remaining));
    entry.length += delta.chars().count();
}

#[derive(Default)]
struct OutputState {
    text: String,
    total: usize,
}

fn format_bounded_tool_output(value: &str, total: usize) -> String {
    let len = value.chars().count();
    if len <= MAX_TOOL_OUTPUT_CHARS && total <= MAX_TOOL_OUTPUT_CHARS {
        return value.to_string();
    }
    let kept: String = value.chars().take(MAX_TOOL_OUTPUT_CHARS).collect();
    format!("{kept}\n[output truncated: {} characters total]", total.max(len))
}

/// `stringifyMcpContent`.
pub fn stringify_mcp_content(result: &Value) -> String {
    if result.is_null() {
        return String::new();
    }
    let mut text = String::new();
    let mut total = 0usize;
    for item in result["content"].as_array().cloned().unwrap_or_default() {
        let part = match &item {
            Value::String(s) => s.clone(),
            Value::Object(o) if o.get("text").map(|t| t.is_string()).unwrap_or(false) => o["text"].as_str().unwrap().to_string(),
            other => other.to_string(),
        };
        total += part.chars().count();
        if text.chars().count() < MAX_TOOL_OUTPUT_CHARS {
            let room = MAX_TOOL_OUTPUT_CHARS - text.chars().count();
            text.extend(part.chars().take(room));
        }
    }
    if !text.is_empty() || total > 0 {
        return format_bounded_tool_output(&text, total);
    }
    match result.get("structuredContent") {
        Some(v) if !v.is_null() => {
            let s = v.to_string();
            let n = s.chars().count();
            format_bounded_tool_output(&s, n)
        }
        _ => String::new(),
    }
}

/// `resolveCodexPermissionConfig`.
pub fn permission_config(permission_mode: &str) -> Value {
    match permission_mode {
        "observer" => json!({ "approvalPolicy": "never", "approvalsReviewer": "user", "sandbox": "read-only", "sandboxPolicy": { "type": "readOnly", "networkAccess": false } }),
        "auto" => json!({ "approvalPolicy": "never", "approvalsReviewer": "user", "sandbox": "danger-full-access", "sandboxPolicy": { "type": "dangerFullAccess" } }),
        _ => json!({ "approvalPolicy": "on-request", "approvalsReviewer": "user", "sandbox": "read-only", "sandboxPolicy": { "type": "readOnly", "networkAccess": false } }),
    }
}

pub fn build_turn_input(prompt: &str, attachments: &[crate::session::StagedAttachment]) -> Value {
    let mut input = vec![json!({ "type": "text", "text": prompt, "text_elements": [] })];
    for a in attachments.iter().filter(|a| !a.file_path.is_empty() && a.media_type.to_ascii_lowercase().starts_with("image/")) {
        input.push(json!({ "type": "localImage", "path": a.file_path }));
    }
    Value::Array(input)
}

pub fn normalize_file_changes(changes: &Value) -> Value {
    Value::Array(
        changes
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter(|c| c["path"].is_string())
                    .map(|c| {
                        let kind = match c.pointer("/kind/type").and_then(|k| k.as_str()) {
                            Some("add") => "add",
                            Some("delete") => "delete",
                            _ => "update",
                        };
                        json!({ "path": c["path"], "kind": kind })
                    })
                    .collect()
            })
            .unwrap_or_default(),
    )
}

pub fn map_app_server_models(raw: &[Value]) -> Vec<Value> {
    raw.iter()
        .filter(|m| m["id"].is_string() && m["hidden"] != true)
        .map(|m| {
            let levels: Vec<Value> = m["supportedReasoningEfforts"].as_array().map(|o| o.iter().filter_map(|x| x.get("reasoningEffort").filter(|v| !v.is_null()).cloned()).collect()).unwrap_or_default();
            let mut preset = json!({
                "id": m["id"],
                "name": m.get("displayName").filter(|v| v.is_string()).unwrap_or(&m["id"]),
                "thinkingLevels": levels,
                "isDefault": m["isDefault"] == true,
            });
            if let Some(d) = m.get("description").filter(|d| d.as_str().map(|s| !s.is_empty()).unwrap_or(false)) {
                preset["description"] = d.clone();
            }
            if let Some(d) = m.get("defaultReasoningEffort").filter(|d| d.is_string()) {
                preset["defaultThinkingLevel"] = d.clone();
            }
            preset
        })
        .collect()
}

pub fn resolve_model_selection(model: &Value) -> Option<String> {
    let id = model["id"].as_str()?;
    if let Some(level) = model["defaultThinkingLevel"].as_str() {
        if model["thinkingLevels"].as_array().map(|l| l.iter().any(|x| x == level)).unwrap_or(false) {
            return Some(format!("{id}/{level}"));
        }
    }
    Some(id.to_string())
}

fn not_steerable_kind(error: &RpcError) -> Option<String> {
    let kind = error.data.pointer("/activeTurnNotSteerable/turnKind").or_else(|| error.data.pointer("/codexErrorInfo/activeTurnNotSteerable/turnKind"))?.as_str()?;
    (kind == "review" || kind == "compact").then(|| kind.to_string())
}

#[derive(Default)]
struct CtxState {
    turn_id: Option<String>,
    settled: bool,
    cancel_requested: bool,
    reasoning_open: bool,
    steering: bool,
    interrupting: bool,
    last_error: Option<String>,
    streamed_text: HashMap<String, StreamState>,
    streamed_reasoning: HashMap<String, StreamState>,
    command_output: HashMap<String, OutputState>,
    tool_calls: HashSet<String>,
    tool_results: HashSet<String>,
    force_timer: Option<tokio::task::AbortHandle>,
}

struct TurnCtx {
    request_id: String,
    chat_session_id: String,
    conn: Arc<Connection>,
    conn_key: String,
    thread_id: String,
    emitter: Emitter,
    state: Mutex<CtxState>,
    done: Mutex<Option<oneshot::Sender<Result<(), String>>>>,
}

impl TurnCtx {
    fn close_reasoning(&self, st: &mut CtxState) {
        if st.reasoning_open {
            self.emitter.reasoning_end();
            st.reasoning_open = false;
        }
    }

    fn finish(&self, result: Result<(), String>) {
        if let Some(tx) = self.done.lock().take() {
            let _ = tx.send(result);
        }
    }
}

struct PendingInteraction {
    conn: Arc<Connection>,
    rpc_id: Value,
    kind: &'static str,
    params: Value,
    ctx: Arc<TurnCtx>,
    timer: Option<tokio::task::AbortHandle>,
    absolute_expires_at: Instant,
    idle_cancelled: bool,
}

struct Inner {
    app_version: String,
    sink: Arc<dyn EventSink>,
    events_tx: mpsc::UnboundedSender<ConnEvent>,
    connections: Mutex<HashMap<String, Arc<Connection>>>,
    preferred: Mutex<Option<String>>,
    active: Mutex<HashMap<String, Arc<TurnCtx>>>,
    by_thread: Mutex<HashMap<String, Arc<TurnCtx>>>,
    by_turn: Mutex<HashMap<String, Arc<TurnCtx>>>,
    interactions: Mutex<HashMap<String, PendingInteraction>>,
    interaction_counter: AtomicU64,
    event_counter: AtomicU64,
    connecting: tokio::sync::Mutex<()>,
}

/// The App Server runtime shared by every chat.
#[derive(Clone)]
pub struct CodexAppServerRuntime {
    inner: Arc<Inner>,
}

fn scoped(key: &str, id: &str) -> String {
    format!("{key}\0{id}")
}

impl CodexAppServerRuntime {
    pub fn new(app_version: &str, sink: Arc<dyn EventSink>) -> Self {
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            app_version: app_version.to_string(),
            sink,
            events_tx,
            connections: Mutex::new(HashMap::new()),
            preferred: Mutex::new(None),
            active: Mutex::new(HashMap::new()),
            by_thread: Mutex::new(HashMap::new()),
            by_turn: Mutex::new(HashMap::new()),
            interactions: Mutex::new(HashMap::new()),
            interaction_counter: AtomicU64::new(0),
            event_counter: AtomicU64::new(0),
            connecting: tokio::sync::Mutex::new(()),
        });
        let weak = Arc::downgrade(&inner);
        let spawn = || -> bool { tokio::runtime::Handle::try_current().is_ok() };
        if spawn() {
            tokio::spawn(async move {
                while let Some(event) = events_rx.recv().await {
                    let Some(inner) = weak.upgrade() else { break };
                    let rt = CodexAppServerRuntime { inner };
                    match event {
                        ConnEvent::Notification(key, msg) => rt.handle_notification(&key, &msg),
                        ConnEvent::ServerRequest(key, msg) => rt.handle_server_request(&key, msg),
                        ConnEvent::Fatal(key, message) => rt.handle_fatal(&key, &message),
                    }
                }
            });
        }
        Self { inner }
    }

    fn close_idle_connections(&self, keep: Option<&str>) {
        let active: HashSet<String> = self.inner.active.lock().values().map(|c| c.conn_key.clone()).collect();
        let mut conns = self.inner.connections.lock();
        let drop_keys: Vec<String> = conns.keys().filter(|k| Some(k.as_str()) != keep && !active.contains(*k)).cloned().collect();
        for k in drop_keys {
            if let Some(c) = conns.remove(&k) {
                c.close();
            }
        }
    }

    async fn get_connection(&self, bin: &str, env: &EnvMap) -> Result<Arc<Connection>, String> {
        let key = connection_key(bin, env);
        let _guard = self.inner.connecting.lock().await;
        *self.inner.preferred.lock() = Some(key.clone());
        self.close_idle_connections(Some(&key));
        if let Some(existing) = self.inner.connections.lock().get(&key).cloned() {
            if !existing.is_closed() {
                return Ok(existing);
            }
        }
        let conn = Connection::start(bin, env, &self.inner.app_version, &key, self.inner.events_tx.clone()).await?;
        self.inner.connections.lock().insert(key, conn.clone());
        Ok(conn)
    }

    fn find_ctx(&self, key: &str, params: &Value) -> Option<Arc<TurnCtx>> {
        if let Some(turn) = params["turnId"].as_str() {
            if let Some(c) = self.inner.by_turn.lock().get(&scoped(key, turn)) {
                return Some(c.clone());
            }
        }
        params["threadId"].as_str().and_then(|t| self.inner.by_thread.lock().get(&scoped(key, t)).cloned())
    }

    fn assign_turn_id(&self, ctx: &Arc<TurnCtx>, turn_id: &str) {
        let cancel_now = {
            let mut st = ctx.state.lock();
            if st.turn_id.as_deref() == Some(turn_id) {
                return;
            }
            if let Some(old) = st.turn_id.take() {
                self.inner.by_turn.lock().remove(&scoped(&ctx.conn_key, &old));
            }
            st.turn_id = Some(turn_id.to_string());
            st.cancel_requested
        };
        self.inner.by_turn.lock().insert(scoped(&ctx.conn_key, turn_id), ctx.clone());
        if cancel_now {
            let rt = self.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move { rt.interrupt_and_schedule(&ctx).await });
        }
    }

    /// Run one turn on the App Server.
    pub async fn run_turn(&self, ctx: &TurnContext) -> Result<TurnResult, String> {
        let bin = ctx.bin_path.clone().filter(|b| !b.is_empty()).ok_or("Codex binary not found. Configure Codex in Settings -> AI.")?;
        if ctx.aborted() {
            return Err("Codex App Server turn was interrupted before it started".into());
        }
        let conn = self.get_connection(&bin, &ctx.env).await?;
        if ctx.aborted() {
            return Err("Codex App Server turn was interrupted before it started".into());
        }
        let permission = permission_config(&ctx.permission_mode);
        let (model, effort) = parse_codex_model_selection(ctx.model.as_deref());
        let cwd = ctx.cwd.to_string_lossy().into_owned();
        let mut thread_params = json!({
            "model": model,
            "cwd": cwd,
            "approvalPolicy": permission["approvalPolicy"],
            "approvalsReviewer": permission["approvalsReviewer"],
            "sandbox": permission["sandbox"],
            "config": {
                "mcp_servers": to_codex_mcp_config(&ctx.injected_mcp_servers, Some("approve")),
                "model_reasoning_summary": "concise",
            },
        });
        let thread_result = match ctx.resume_session_id.as_deref() {
            Some(resume) => {
                thread_params["threadId"] = json!(resume);
                conn.request("thread/resume", thread_params, DEFAULT_REQUEST_TIMEOUT).await
            }
            None => conn.request("thread/start", thread_params, DEFAULT_REQUEST_TIMEOUT).await,
        }
        .map_err(|e| e.message)?;
        if ctx.aborted() {
            return Err("Codex App Server turn was interrupted before it started".into());
        }
        let thread_id = thread_result.pointer("/thread/id").and_then(|v| v.as_str()).map(str::to_string).or(ctx.resume_session_id.clone()).ok_or("Codex App Server did not return a thread id")?;
        ctx.emitter.session_id(&thread_id);
        let (done_tx, done_rx) = oneshot::channel();
        let turn = Arc::new(TurnCtx {
            request_id: ctx.request_id.clone(),
            chat_session_id: ctx.chat_session_id.clone(),
            conn: conn.clone(),
            conn_key: conn.key.clone(),
            thread_id: thread_id.clone(),
            emitter: ctx.emitter.clone(),
            state: Mutex::new(CtxState::default()),
            done: Mutex::new(Some(done_tx)),
        });
        self.inner.active.lock().insert(ctx.request_id.clone(), turn.clone());
        self.inner.by_thread.lock().insert(scoped(&turn.conn_key, &thread_id), turn.clone());
        let cancel = ctx.cancel.clone();
        let rt = self.clone();
        let request_id = ctx.request_id.clone();
        let watcher = tokio::spawn(async move {
            cancel.cancelled().await;
            rt.cancel_turn(&request_id).await;
        });
        let start = conn
            .request(
                "turn/start",
                json!({
                    "threadId": thread_id,
                    "input": build_turn_input(&ctx.prompt, &ctx.attachments),
                    "cwd": cwd,
                    "approvalPolicy": permission["approvalPolicy"],
                    "approvalsReviewer": permission["approvalsReviewer"],
                    "sandboxPolicy": permission["sandboxPolicy"],
                    "model": model,
                    "effort": effort,
                    "summary": "concise",
                }),
                DEFAULT_REQUEST_TIMEOUT,
            )
            .await;
        let outcome = match start {
            Ok(result) => {
                if let Some(turn_id) = result.pointer("/turn/id").and_then(|v| v.as_str()) {
                    self.assign_turn_id(&turn, turn_id);
                }
                done_rx.await.unwrap_or_else(|_| Err("Codex App Server shut down".into()))
            }
            Err(error) => Err(error.message),
        };
        watcher.abort();
        self.remove_ctx(&turn);
        outcome.map(|_| TurnResult { session_id: Some(thread_id) })
    }

    fn remove_ctx(&self, ctx: &Arc<TurnCtx>) {
        let turn_id = {
            let mut st = ctx.state.lock();
            if let Some(t) = st.force_timer.take() {
                t.abort();
            }
            st.turn_id.clone()
        };
        self.inner.active.lock().remove(&ctx.request_id);
        self.inner.by_thread.lock().remove(&scoped(&ctx.conn_key, &ctx.thread_id));
        if let Some(t) = turn_id {
            self.inner.by_turn.lock().remove(&scoped(&ctx.conn_key, &t));
        }
        let keep = self.inner.preferred.lock().clone();
        self.close_idle_connections(keep.as_deref());
    }

    /// Live `model/list` catalog.
    pub async fn list_models(&self, bin: &str, env: &EnvMap) -> Result<crate::catalog::ModelCatalog, String> {
        let conn = self.get_connection(bin, env).await?;
        let mut all = Vec::new();
        let mut cursor = Value::Null;
        loop {
            let response = conn.request("model/list", json!({ "cursor": cursor, "limit": 100 }), Duration::from_secs(10)).await.map_err(|e| e.message)?;
            all.extend(response["data"].as_array().cloned().unwrap_or_default());
            cursor = response.get("nextCursor").cloned().unwrap_or(Value::Null);
            if cursor.is_null() || cursor == "" {
                break;
            }
        }
        let models = map_app_server_models(&all);
        let current = models.iter().find(|m| m["isDefault"] == true).and_then(resolve_model_selection);
        Ok(crate::catalog::ModelCatalog { current_model_id: current, models })
    }

    /// `turn/steer` for an active turn.
    pub async fn steer_turn(&self, request_id: &str, chat_session_id: &str, prompt: &str, attachments: &[crate::session::StagedAttachment], client_user_message_id: &str) -> Value {
        let Some(ctx) = self.inner.active.lock().get(request_id).cloned() else { return json!({ "status": "inactive" }) };
        let turn_id = {
            let mut st = ctx.state.lock();
            if st.settled || ctx.chat_session_id != chat_session_id {
                return json!({ "status": "inactive" });
            }
            if st.cancel_requested {
                return json!({ "status": "cancelled" });
            }
            let Some(turn_id) = st.turn_id.clone() else { return json!({ "status": "busy", "message": "Codex turn is still starting" }) };
            if st.steering {
                return json!({ "status": "busy", "message": "A Codex instruction is already being sent" });
            }
            st.steering = true;
            turn_id
        };
        let response = ctx
            .conn
            .request(
                "turn/steer",
                json!({ "threadId": ctx.thread_id, "expectedTurnId": turn_id, "input": build_turn_input(prompt, attachments), "clientUserMessageId": if client_user_message_id.is_empty() { Value::Null } else { json!(client_user_message_id) } }),
                DEFAULT_REQUEST_TIMEOUT,
            )
            .await;
        let mut st = ctx.state.lock();
        st.steering = false;
        let cancelled = st.cancel_requested || st.settled;
        match response {
            Ok(_) if cancelled => json!({ "status": "cancelled" }),
            Ok(r) if r["turnId"].as_str().map(|t| t != turn_id).unwrap_or(false) => json!({ "status": "failed", "message": "Codex App Server returned a different turn id while steering" }),
            Ok(_) => json!({ "status": "accepted" }),
            Err(e) => match not_steerable_kind(&e) {
                Some(kind) => json!({ "status": "not-steerable", "turnKind": kind, "message": e.message }),
                None if cancelled => json!({ "status": "cancelled" }),
                None => json!({ "status": "failed", "message": e.message }),
            },
        }
    }

    pub fn has_active(&self, request_id: &str) -> bool {
        self.inner.active.lock().contains_key(request_id)
    }

    /// Interrupt an active turn; force-complete it if Codex does not settle.
    pub async fn cancel_turn(&self, request_id: &str) -> bool {
        let Some(ctx) = self.inner.active.lock().get(request_id).cloned() else { return false };
        ctx.state.lock().cancel_requested = true;
        self.clear_interactions_for(&ctx, "cancel");
        self.interrupt_and_schedule(&ctx).await;
        true
    }

    async fn interrupt_and_schedule(&self, ctx: &Arc<TurnCtx>) {
        let turn_id = {
            let mut st = ctx.state.lock();
            if st.settled || st.interrupting {
                return;
            }
            match st.turn_id.clone() {
                Some(t) => {
                    st.interrupting = true;
                    Some(t)
                }
                None => None,
            }
        };
        let Some(turn_id) = turn_id else {
            self.schedule_force_cancel(ctx, INTERRUPT_REQUEST_TIMEOUT + INTERRUPT_GRACE);
            return;
        };
        let ok = ctx.conn.request("turn/interrupt", json!({ "threadId": ctx.thread_id, "turnId": turn_id }), INTERRUPT_REQUEST_TIMEOUT).await.is_ok();
        if ctx.state.lock().settled {
            return;
        }
        if ok {
            self.schedule_force_cancel(ctx, INTERRUPT_GRACE);
        } else {
            self.force_cancel(ctx, "Codex App Server could not interrupt the turn");
        }
    }

    fn schedule_force_cancel(&self, ctx: &Arc<TurnCtx>, delay: Duration) {
        let rt = self.clone();
        let c = ctx.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            rt.force_cancel(&c, "Codex App Server did not complete the interrupted turn");
        });
        let mut st = ctx.state.lock();
        if let Some(old) = st.force_timer.replace(handle.abort_handle()) {
            old.abort();
        }
    }

    fn force_cancel(&self, ctx: &Arc<TurnCtx>, reason: &str) {
        {
            let mut st = ctx.state.lock();
            if st.settled {
                return;
            }
            st.settled = true;
            ctx.close_reasoning(&mut st);
        }
        self.clear_interactions_for(ctx, "cancel");
        ctx.emitter.emit_done();
        ctx.finish(Ok(()));
        let mut conns = self.inner.connections.lock();
        if conns.get(&ctx.conn_key).map(|c| Arc::ptr_eq(c, &ctx.conn)).unwrap_or(false) {
            conns.remove(&ctx.conn_key);
            ctx.conn.close();
        }
        drop(conns);
        let others: Vec<Arc<TurnCtx>> = self.inner.active.lock().values().filter(|c| c.conn_key == ctx.conn_key && !Arc::ptr_eq(c, ctx)).cloned().collect();
        for other in others {
            let settle = {
                let mut st = other.state.lock();
                !std::mem::replace(&mut st.settled, true)
            };
            if settle {
                self.clear_interactions_for(&other, "cancel");
                other.finish(Err(reason.to_string()));
            }
        }
    }

    pub async fn cleanup_chat_session(&self, chat_session_id: &str) {
        let ids: Vec<String> = self.inner.active.lock().values().filter(|c| c.chat_session_id == chat_session_id).map(|c| c.request_id.clone()).collect();
        for id in ids {
            self.cancel_turn(&id).await;
        }
    }

    fn handle_fatal(&self, key: &str, message: &str) {
        self.inner.connections.lock().remove(key);
        let contexts: Vec<Arc<TurnCtx>> = self.inner.active.lock().values().filter(|c| c.conn_key == key).cloned().collect();
        for ctx in contexts {
            let settle = !std::mem::replace(&mut ctx.state.lock().settled, true);
            if settle {
                self.clear_interactions_for(&ctx, "cancel");
                ctx.finish(Err(message.to_string()));
            }
        }
    }

    fn handle_notification(&self, key: &str, message: &Value) {
        let params = message.get("params").cloned().unwrap_or(json!({}));
        let method = message["method"].as_str().unwrap_or("");
        let Some(ctx) = self.find_ctx(key, &params) else {
            if method == "warning" {
                let contexts: Vec<Arc<TurnCtx>> = self.inner.active.lock().values().filter(|c| c.conn_key == key).cloned().collect();
                for c in contexts {
                    let n = self.inner.event_counter.fetch_add(1, Ordering::Relaxed) + 1;
                    c.emitter.warning(&format!("codex-warning:connection:{n}"), params["message"].as_str().unwrap_or("Codex warning"));
                }
            }
            return;
        };
        let e = &ctx.emitter;
        let item_id = params["itemId"].as_str().unwrap_or("").to_string();
        match method {
            "turn/started" => {
                if let Some(id) = params.pointer("/turn/id").and_then(|v| v.as_str()) {
                    self.assign_turn_id(&ctx, id);
                }
            }
            "item/agentMessage/delta" => {
                let delta = params["delta"].as_str().unwrap_or("");
                append_stream(&mut ctx.state.lock().streamed_text, &item_id, delta);
                e.text(delta);
            }
            "item/reasoning/summaryTextDelta" => {
                let delta = params["delta"].as_str().unwrap_or("");
                let mut st = ctx.state.lock();
                append_stream(&mut st.streamed_reasoning, &item_id, delta);
                e.reasoning(delta);
                st.reasoning_open = true;
            }
            "item/commandExecution/outputDelta" => {
                let delta = params["delta"].as_str().unwrap_or("");
                let mut st = ctx.state.lock();
                let out = st.command_output.entry(item_id).or_default();
                let room = MAX_TOOL_OUTPUT_CHARS.saturating_sub(out.text.chars().count());
                out.text.extend(delta.chars().take(room));
                out.total += delta.chars().count();
            }
            "item/started" => self.handle_item(&ctx, &params["item"], false),
            "item/completed" => self.handle_item(&ctx, &params["item"], true),
            "turn/plan/updated" => {
                let plan = params["plan"].as_array().cloned().unwrap_or_default();
                let items: Vec<Value> = plan.iter().map(|i| json!({ "text": i["step"].as_str().unwrap_or(""), "completed": i["status"] == "completed" })).collect();
                let status = if plan.iter().all(|i| i["status"] == "completed") { "completed" } else { "running" };
                e.plan_update(&format!("codex-plan:{}", params["turnId"].as_str().unwrap_or("")), Value::Array(items), status);
            }
            "thread/tokenUsage/updated" => {
                let u = &params["tokenUsage"]["last"];
                if u.is_object() {
                    e.usage(Usage {
                        input_tokens: u["inputTokens"].as_u64().unwrap_or(0),
                        cached_input_tokens: u["cachedInputTokens"].as_u64().unwrap_or(0),
                        output_tokens: u["outputTokens"].as_u64().unwrap_or(0),
                        reasoning_tokens: u["reasoningOutputTokens"].as_u64().unwrap_or(0),
                        total_tokens: u["totalTokens"].as_u64().unwrap_or(0),
                    });
                }
            }
            "warning" => {
                let n = self.inner.event_counter.fetch_add(1, Ordering::Relaxed) + 1;
                let turn = params["turnId"].as_str().map(str::to_string).or(ctx.state.lock().turn_id.clone()).unwrap_or_default();
                e.warning(&format!("codex-warning:{turn}:{n}"), params["message"].as_str().unwrap_or("Codex warning"));
            }
            "error" => {
                let message = params.pointer("/error/message").and_then(|m| m.as_str()).unwrap_or("Codex App Server error").to_string();
                let turn = {
                    let mut st = ctx.state.lock();
                    st.last_error = Some(message.clone());
                    params["turnId"].as_str().map(str::to_string).or(st.turn_id.clone()).unwrap_or_default()
                };
                let n = self.inner.event_counter.fetch_add(1, Ordering::Relaxed) + 1;
                let text = if params["willRetry"] == true { format!("{message} (retrying)") } else { message };
                e.warning(&format!("codex-error:{turn}:{n}"), &text);
            }
            "turn/completed" => self.complete_turn(&ctx, &params["turn"]),
            _ => {}
        }
    }

    fn handle_item(&self, ctx: &Arc<TurnCtx>, item: &Value, completed: bool) {
        if !item.is_object() {
            return;
        }
        let e = &ctx.emitter;
        let id = item["id"].as_str().unwrap_or("").to_string();
        let mut st = ctx.state.lock();
        let tool_call = |st: &mut CtxState, name: &str, args: Value| {
            if !id.is_empty() && st.tool_calls.insert(id.clone()) {
                ctx.close_reasoning(st);
                e.tool_call(name, args, &id);
            }
        };
        match item["type"].as_str().unwrap_or("") {
            "agentMessage" => {
                if !completed {
                    return;
                }
                ctx.close_reasoning(&mut st);
                let text = item["text"].as_str().unwrap_or("");
                match st.streamed_text.remove(&id) {
                    Some(streamed) if !text.is_empty() && text.starts_with(&streamed.prefix) => {
                        let len = text.chars().count();
                        if len > streamed.length {
                            e.text(&text.chars().skip(streamed.length).collect::<String>());
                        }
                    }
                    None if !text.is_empty() => e.text(text),
                    _ => {}
                }
            }
            "reasoning" => {
                if !completed {
                    return;
                }
                let final_text = item["summary"].as_array().map(|s| s.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("\n")).unwrap_or_default();
                match st.streamed_reasoning.remove(&id) {
                    Some(streamed) if !final_text.is_empty() && final_text.starts_with(&streamed.prefix) => {
                        if final_text.chars().count() > streamed.length {
                            e.reasoning(&final_text.chars().skip(streamed.length).collect::<String>());
                        }
                    }
                    None if !final_text.is_empty() => e.reasoning(&final_text),
                    _ => {}
                }
                st.reasoning_open = true;
                ctx.close_reasoning(&mut st);
            }
            "commandExecution" => {
                let name = "codex.command";
                tool_call(&mut st, name, json!({ "command": item["command"], "cwd": item["cwd"] }));
                if completed && !id.is_empty() && st.tool_results.insert(id.clone()) {
                    let streamed = st.command_output.remove(&id).unwrap_or_default();
                    let output = match item["aggregatedOutput"].as_str() {
                        Some(agg) => format_bounded_tool_output(agg, agg.chars().count()),
                        None => format_bounded_tool_output(&streamed.text, streamed.total),
                    };
                    let suffix = item["exitCode"].as_i64().map(|c| format!("\n[exit code: {c}]")).unwrap_or_default();
                    e.tool_result(&id, &format!("{output}{suffix}"), Some(name));
                }
            }
            "mcpToolCall" => {
                let name = format!("{}.{}", item["server"].as_str().unwrap_or("mcp"), item["tool"].as_str().unwrap_or("tool"));
                let args = if item["arguments"].is_object() { item["arguments"].clone() } else { json!({}) };
                tool_call(&mut st, &name, args);
                if completed && !id.is_empty() && st.tool_results.insert(id.clone()) {
                    let output = item.pointer("/error/message").and_then(|m| m.as_str()).map(str::to_string).unwrap_or_else(|| stringify_mcp_content(&item["result"]));
                    e.tool_result(&id, &output, Some(&name));
                }
            }
            "fileChange" => {
                if completed {
                    e.file_change(&id, normalize_file_changes(&item["changes"]), if item["status"] == "completed" { "completed" } else { "failed" });
                }
            }
            "webSearch" => e.web_search(&id, item["query"].as_str().unwrap_or(""), if completed { "completed" } else { "running" }),
            _ => {}
        }
    }

    fn complete_turn(&self, ctx: &Arc<TurnCtx>, turn: &Value) {
        let last_error = {
            let mut st = ctx.state.lock();
            if st.settled {
                return;
            }
            st.settled = true;
            if let Some(t) = st.force_timer.take() {
                t.abort();
            }
            ctx.close_reasoning(&mut st);
            st.last_error.clone()
        };
        self.clear_interactions_for(ctx, "cancel");
        if turn["status"] == "failed" {
            let message = turn.pointer("/error/message").and_then(|m| m.as_str()).map(str::to_string).or(last_error).unwrap_or_else(|| "Codex turn failed".into());
            ctx.finish(Err(message));
            return;
        }
        ctx.emitter.emit_done();
        ctx.finish(Ok(()));
    }

    fn handle_server_request(&self, key: &str, message: Value) {
        let params = message.get("params").cloned().unwrap_or(json!({}));
        let method = message["method"].as_str().unwrap_or("").to_string();
        let rpc_id = message["id"].clone();
        let Some(conn) = self.inner.connections.lock().get(key).cloned() else { return };
        let ctx = self.find_ctx(key, &params);
        let kind = match method.as_str() {
            "item/commandExecution/requestApproval" => "command",
            "item/fileChange/requestApproval" => "file-change",
            "item/permissions/requestApproval" => "permissions",
            "item/tool/requestUserInput" => "user-input",
            _ => {
                conn.respond_error(&rpc_id, -32601, &format!("Unsupported Codex App Server request: {method}"));
                if let Some(ctx) = ctx {
                    let n = self.inner.event_counter.fetch_add(1, Ordering::Relaxed) + 1;
                    ctx.emitter.warning(&format!("codex-unsupported-request:{n}"), &format!("Unsupported Codex request: {method}"));
                }
                return;
            }
        };
        let Some(ctx) = ctx else {
            conn.respond(&rpc_id, safe_interaction_response(kind, &params, "reject"));
            return;
        };
        let n = self.inner.interaction_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let interaction_id = format!("codex_interaction_{n}_{}", chrono::Utc::now().timestamp_millis());
        let timeout = if kind == "user-input" && params["autoResolutionMs"].as_f64().map(|v| v > 0.0).unwrap_or(false) {
            Duration::from_millis(params["autoResolutionMs"].as_f64().unwrap() as u64)
        } else {
            INTERACTION_TIMEOUT
        };
        self.inner.interactions.lock().insert(
            interaction_id.clone(),
            PendingInteraction { conn, rpc_id, kind, params: params.clone(), ctx: ctx.clone(), timer: None, absolute_expires_at: Instant::now() + timeout, idle_cancelled: false },
        );
        self.arm_timer(&interaction_id, timeout);
        let tool_name = match kind {
            "command" => json!("codex.command"),
            "file-change" => json!("codex.file_change"),
            "permissions" => json!("codex.permissions"),
            _ => Value::Null,
        };
        let args = match kind {
            "command" => json!({ "command": params["command"], "cwd": params["cwd"], "reason": params["reason"], "commandActions": params["commandActions"] }),
            "file-change" => json!({ "reason": params["reason"], "grantRoot": params["grantRoot"], "itemId": params["itemId"] }),
            "permissions" => json!({ "cwd": params["cwd"], "reason": params["reason"], "permissions": params["permissions"] }),
            _ => Value::Null,
        };
        let mut payload = json!({
            "interactionId": interaction_id,
            "source": "codex-app-server",
            "kind": kind,
            "requestId": ctx.request_id,
            "chatSessionId": ctx.chat_session_id,
            "itemId": params["itemId"],
        });
        let obj = payload.as_object_mut().unwrap();
        if !tool_name.is_null() {
            obj.insert("toolName".into(), tool_name);
            obj.insert("args".into(), args);
        }
        if kind == "command" && params["availableDecisions"].is_array() {
            obj.insert("availableDecisions".into(), params["availableDecisions"].clone());
        }
        if kind == "user-input" {
            obj.insert("questions".into(), params.get("questions").cloned().filter(|q| !q.is_null()).unwrap_or(json!([])));
            obj.insert("autoResolutionMs".into(), params["autoResolutionMs"].clone());
        }
        self.inner.sink.send(events::CODEX_APP_SERVER_INTERACTION_REQUEST, payload);
    }

    fn arm_timer(&self, id: &str, after: Duration) {
        let rt = self.clone();
        let owned = id.to_string();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(after).await;
            rt.resolve_default(&owned);
        });
        if let Some(p) = self.inner.interactions.lock().get_mut(id) {
            if let Some(old) = p.timer.replace(handle.abort_handle()) {
                old.abort();
            }
        } else {
            handle.abort();
        }
    }

    fn resolve_default(&self, id: &str) {
        let kind = self.inner.interactions.lock().get(id).map(|p| p.kind);
        if let Some(kind) = kind {
            let response = if kind == "user-input" { json!({ "answers": {} }) } else { json!({ "decision": "reject" }) };
            self.resolve_interaction(id, &response);
        }
    }

    fn resolve_interaction(&self, id: &str, response: &Value) -> bool {
        let Some(pending) = self.inner.interactions.lock().remove(id) else { return false };
        if let Some(t) = pending.timer {
            t.abort();
        }
        let result = if pending.kind == "user-input" {
            json!({ "answers": response.get("answers").cloned().filter(|a| a.is_object()).unwrap_or(json!({})) })
        } else {
            safe_interaction_response(pending.kind, &pending.params, response["decision"].as_str().unwrap_or("reject"))
        };
        pending.conn.respond(&pending.rpc_id, result);
        self.inner.sink.send(events::CODEX_APP_SERVER_INTERACTION_CLEARED, json!({ "interactionIds": [id], "chatSessionId": pending.ctx.chat_session_id }));
        true
    }

    /// `netcatty:ai:codex-app-server:interaction-response`.
    pub fn respond_interaction(&self, payload: &Value) -> bool {
        let id = payload["interactionId"].as_str().unwrap_or("");
        self.resolve_interaction(id, payload)
    }

    /// Drop the idle auto-reject timer, keeping the absolute deadline.
    pub fn cancel_interaction_timeout(&self, id: &str) -> bool {
        let remaining = {
            let mut guard = self.inner.interactions.lock();
            let Some(p) = guard.get_mut(id) else { return false };
            if p.idle_cancelled {
                return false;
            }
            p.idle_cancelled = true;
            if let Some(t) = p.timer.take() {
                t.abort();
            }
            p.absolute_expires_at.saturating_duration_since(Instant::now())
        };
        if remaining.is_zero() {
            self.resolve_default(id);
        } else {
            self.arm_timer(id, remaining);
        }
        true
    }

    fn clear_interactions_for(&self, ctx: &Arc<TurnCtx>, decision: &str) {
        let ids: Vec<(String, &'static str)> = self.inner.interactions.lock().iter().filter(|(_, p)| Arc::ptr_eq(&p.ctx, ctx)).map(|(k, p)| (k.clone(), p.kind)).collect();
        for (id, kind) in ids {
            let response = if kind == "user-input" { json!({ "answers": {} }) } else { json!({ "decision": decision }) };
            self.resolve_interaction(&id, &response);
        }
    }

    /// Close everything (app shutdown).
    pub fn close(&self) {
        let ids: Vec<String> = self.inner.interactions.lock().keys().cloned().collect();
        for id in ids {
            self.resolve_interaction(&id, &json!({ "decision": "cancel", "answers": {} }));
        }
        for (_, c) in self.inner.connections.lock().drain() {
            c.close();
        }
        for (_, ctx) in self.inner.active.lock().drain() {
            if !std::mem::replace(&mut ctx.state.lock().settled, true) {
                ctx.finish(Err("Codex App Server shut down".into()));
            }
        }
        self.inner.by_thread.lock().clear();
        self.inner.by_turn.lock().clear();
    }
}

fn normalize_granted_permissions(requested: &Value) -> Value {
    let mut granted = serde_json::Map::new();
    for key in ["network", "fileSystem"] {
        if let Some(v) = requested.get(key).filter(|v| !v.is_null()) {
            granted.insert(key.into(), v.clone());
        }
    }
    Value::Object(granted)
}

/// `#safeInteractionResponse`.
pub fn safe_interaction_response(kind: &str, params: &Value, decision: &str) -> Value {
    match kind {
        "user-input" => json!({ "answers": {} }),
        "permissions" => {
            let granted = if decision == "once" || decision == "session" { normalize_granted_permissions(&params["permissions"]) } else { json!({}) };
            json!({ "permissions": granted, "scope": if decision == "session" { "session" } else { "turn" } })
        }
        _ => {
            let mapped = match decision {
                "once" => "accept",
                "session" => "acceptForSession",
                "cancel" => "cancel",
                _ => "decline",
            };
            json!({ "decision": mapped })
        }
    }
}

/// Signals a cancelled request (used by the steer/cancel bridge).
pub fn new_cancel() -> CancellationToken {
    CancellationToken::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::RecordingSink;

    #[test]
    fn launch_rules() {
        assert_eq!(build_launch("/x/codex", &["app-server", "--stdio"]).unwrap(), ("/x/codex".into(), vec!["app-server".into(), "--stdio".into()]));
        assert_eq!(build_launch("/x/codex.js", &["a"]).unwrap().0, "node");
        assert!(build_launch("C:\\x\\codex.cmd", &[]).is_err());
        assert!(build_launch(" ", &[]).is_err());
    }

    #[test]
    fn interaction_responses() {
        assert_eq!(safe_interaction_response("command", &Value::Null, "once"), json!({ "decision": "accept" }));
        assert_eq!(safe_interaction_response("file-change", &Value::Null, "session"), json!({ "decision": "acceptForSession" }));
        assert_eq!(safe_interaction_response("command", &Value::Null, "reject"), json!({ "decision": "decline" }));
        assert_eq!(safe_interaction_response("command", &Value::Null, "cancel"), json!({ "decision": "cancel" }));
        let params = json!({ "permissions": { "network": { "enabled": true }, "other": 1 } });
        assert_eq!(safe_interaction_response("permissions", &params, "session"), json!({ "permissions": { "network": { "enabled": true } }, "scope": "session" }));
        assert_eq!(safe_interaction_response("permissions", &params, "reject"), json!({ "permissions": {}, "scope": "turn" }));
    }

    #[test]
    fn model_mapping_and_mcp_content() {
        let models = map_app_server_models(&[
            json!({ "id": "gpt-5.5", "displayName": "GPT 5.5", "supportedReasoningEfforts": [{ "reasoningEffort": "low" }, { "reasoningEffort": "high" }], "defaultReasoningEffort": "high", "isDefault": true }),
            json!({ "id": "hidden", "hidden": true }),
        ]);
        assert_eq!(models.len(), 1);
        assert_eq!(resolve_model_selection(&models[0]).as_deref(), Some("gpt-5.5/high"));
        assert_eq!(stringify_mcp_content(&json!({ "content": [{ "type": "text", "text": "a" }, "b"] })), "ab");
        assert_eq!(stringify_mcp_content(&json!({ "content": [], "structuredContent": { "x": 1 } })), "{\"x\":1}");
        assert_eq!(normalize_file_changes(&json!([{ "path": "a", "kind": { "type": "add" } }, { "nope": 1 }])), json!([{ "path": "a", "kind": "add" }]));
    }

    /// Fake app-server: answers initialize / thread/start / turn/start, streams a
    /// delta, asks for a command approval and completes after the answer.
    #[cfg(unix)]
    #[tokio::test]
    async fn turn_with_approval_round_trip() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("codex");
        std::fs::write(&script, r#"#!/usr/bin/env python3
import sys, json
def send(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    m = json.loads(line)
    method = m.get("method")
    if method == "initialize":
        send({"id": m["id"], "result": {}})
    elif method == "thread/start":
        send({"id": m["id"], "result": {"thread": {"id": "th-1"}}})
    elif method == "turn/start":
        send({"id": m["id"], "result": {"turn": {"id": "tu-1"}}})
        send({"method": "item/agentMessage/delta", "params": {"threadId": "th-1", "turnId": "tu-1", "itemId": "a1", "delta": "Hel"}})
        send({"id": 900, "method": "item/commandExecution/requestApproval", "params": {"threadId": "th-1", "turnId": "tu-1", "itemId": "c1", "command": "rm -rf x"}})
    elif m.get("id") == 900:
        send({"method": "item/completed", "params": {"threadId": "th-1", "turnId": "tu-1", "item": {"id": "a1", "type": "agentMessage", "text": "Hello " + m["result"]["decision"]}}})
        send({"method": "turn/completed", "params": {"threadId": "th-1", "turnId": "tu-1", "turn": {"status": "completed"}}})
"#).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sink = Arc::new(RecordingSink::default());
        let rt = CodexAppServerRuntime::new("1.0.0", sink.clone());
        let env: EnvMap = [("PATH".to_string(), "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin".to_string())].into_iter().collect();
        let emitter = Emitter::new(sink.clone(), "req-1");
        let ctx = crate::drivers::test_turn_context(emitter, Some(script.to_string_lossy().into_owned()), env);
        let rt2 = rt.clone();
        let sink2 = sink.clone();
        tokio::spawn(async move {
            for _ in 0..200 {
                let req = sink2.events.lock().iter().find(|(c, _)| c == events::CODEX_APP_SERVER_INTERACTION_REQUEST).map(|(_, p)| p.clone());
                if let Some(req) = req {
                    assert_eq!(req["kind"], "command");
                    assert_eq!(req["toolName"], "codex.command");
                    assert_eq!(req["args"]["command"], "rm -rf x");
                    assert!(rt2.respond_interaction(&json!({ "interactionId": req["interactionId"], "decision": "once" })));
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        let result = tokio::time::timeout(Duration::from_secs(10), rt.run_turn(&ctx)).await.unwrap().unwrap();
        assert_eq!(result.session_id.as_deref(), Some("th-1"));
        let ev = sink.stream_events();
        let text: String = ev.iter().filter(|e| e["type"] == "text-delta").map(|e| e["textDelta"].as_str().unwrap().to_string()).collect();
        assert_eq!(text, "Hello accept");
        assert_eq!(sink.done_count(), 1);
        assert!(sink.events.lock().iter().any(|(c, _)| c == events::CODEX_APP_SERVER_INTERACTION_CLEARED));
        rt.close();
    }
}
