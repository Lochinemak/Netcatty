//! The script worker: a QuickJS runtime on its own thread. Port of
//! `electron/scripts/scriptExecutionWorker.cjs` (the JavaScript shim that
//! exposes `nct` to the user's script and forwards every call to the host as
//! an RPC) plus the worker-side half of `executeInScriptWorker` in
//! `scriptRuntime.cjs` (start, heartbeat watchdog, limits, teardown).
//!
//! Protocol (one channel each way):
//!
//! * engine → host ([`EngineEvent`]): `Rpc { request_id, method, args }` for
//!   every `nct.*` call that returns a promise, `Notify { method, args }` for
//!   `nct.log`, `console.log` and `nct.progress.*`, then exactly one
//!   `Completed` / `Failed`.
//! * host → engine ([`EngineInbound`]): `RpcResult` settles the pending
//!   promise (and refreshes the `nct.session` / `nct.screen` snapshot),
//!   `Snapshot` refreshes it on its own, `Stop` tears the worker down.
//!
//! Synchronous execution is bounded like Electron's heartbeat watchdog: a
//! QuickJS interrupt handler fails the script when one JavaScript slice
//! (everything that runs without yielding to a host result) exceeds
//! `sync_execution_timeout_ms`, and stops it as soon as the abort flag is
//! set. QuickJS is also capped at [`EngineLimits::memory_limit_bytes`] and a
//! 4 MiB JS stack, the counterparts of the worker's `resourceLimits`.
//!
//! Why QuickJS (`rquickjs`): it is small, has native promises / async
//! functions, a periodic interrupt callback (synchronous loops *and*
//! catastrophic regexes can be stopped), a memory limit, and `RegExp`
//! objects with ECMAScript semantics that user scripts pass to
//! `waitFor`; `boa_engine` is larger, slower to start, and its interrupt
//! support is coarser.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

pub const SCRIPT_SYNC_EXECUTION_TIMEOUT_MS: u64 = 1_000;
pub const SCRIPT_WORKER_MAX_PENDING_HOST_REQUESTS: usize = 128;
pub const SCRIPT_WORKER_MAX_LOG_NOTIFICATIONS: usize = 512;
pub const SCRIPT_WORKER_MAX_TOTAL_NOTIFICATIONS: usize = 20_000;
/// Electron: 64 MiB old generation + 16 MiB young generation.
pub const SCRIPT_WORKER_MEMORY_LIMIT_BYTES: usize = 80 * 1024 * 1024;
pub const SCRIPT_WORKER_STACK_SIZE_BYTES: usize = 4 * 1024 * 1024;
const IDLE_TICK: Duration = Duration::from_millis(25);

/// What the script sees as `nct.session` / `nct.screen` properties.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSnapshot {
    pub session: SessionSnapshot,
    pub screen: ScreenSnapshotMeta,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSnapshot {
    pub connected: bool,
    pub name: String,
    pub hostname: String,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenSnapshotMeta {
    pub current_row: i64,
    pub rows: i64,
    pub cols: i64,
}

impl Default for ScreenSnapshotMeta {
    fn default() -> Self {
        Self {
            current_row: 0,
            rows: 24,
            cols: 80,
        }
    }
}

/// A JavaScript error crossing the engine boundary (`serializeError`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptError {
    pub name: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
}

impl ScriptError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            name: "Error".into(),
            message: message.into(),
            stack: None,
        }
    }
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ScriptError {}

#[derive(Debug, Clone)]
pub struct EngineLimits {
    pub max_pending_host_requests: usize,
    pub max_log_notifications: usize,
    pub max_total_notifications: usize,
    pub sync_execution_timeout_ms: u64,
    pub memory_limit_bytes: usize,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            max_pending_host_requests: SCRIPT_WORKER_MAX_PENDING_HOST_REQUESTS,
            max_log_notifications: SCRIPT_WORKER_MAX_LOG_NOTIFICATIONS,
            max_total_notifications: SCRIPT_WORKER_MAX_TOTAL_NOTIFICATIONS,
            sync_execution_timeout_ms: SCRIPT_SYNC_EXECUTION_TIMEOUT_MS,
            memory_limit_bytes: SCRIPT_WORKER_MEMORY_LIMIT_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Already wrapped (see [`crate::source::wrap_script_source`]).
    pub source: String,
    pub filename: String,
    /// `nct.version`.
    pub version: String,
    pub snapshot: RuntimeSnapshot,
    pub limits: EngineLimits,
}

/// Engine → host.
#[derive(Debug, Clone, PartialEq)]
pub enum EngineEvent {
    Rpc {
        request_id: u64,
        method: String,
        args: Vec<Value>,
    },
    Notify {
        method: String,
        args: Vec<Value>,
    },
    Completed,
    Failed(ScriptError),
}

/// Host → engine.
#[derive(Debug, Clone)]
pub enum EngineInbound {
    RpcResult {
        request_id: u64,
        /// `Ok(None)` resolves with `undefined`.
        result: Result<Option<Value>, ScriptError>,
        snapshot: RuntimeSnapshot,
    },
    Snapshot(RuntimeSnapshot),
    Stop,
}

/// Handle to a running engine thread.
pub struct EngineHandle {
    inbound: mpsc::Sender<EngineInbound>,
    abort: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl EngineHandle {
    /// Deliver a message; ignored once the engine is gone.
    pub fn send(&self, message: EngineInbound) {
        let _ = self.inbound.send(message);
    }

    /// Interrupt whatever runs and tear the worker down.
    pub fn stop(&self) {
        self.abort.store(true, Ordering::SeqCst);
        let _ = self.inbound.send(EngineInbound::Stop);
    }

    /// Wait for the engine thread to exit (blocking).
    pub fn join(mut self) {
        self.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The JavaScript shim: `nct`, `console`, request / notification plumbing
/// (`scriptExecutionWorker.cjs`).
const PRELUDE: &str = r#"
(function (global) {
  "use strict";
  const config = JSON.parse(global.__nctConfigJson);
  const hostCall = global.__nctHostCall;
  const hostNotify = global.__nctHostNotify;
  delete global.__nctConfigJson;
  delete global.__nctHostCall;
  delete global.__nctHostNotify;

  const pendingRequests = new Map();
  let finished = false;
  const runtimeSnapshot = {
    session: {
      connected: Boolean(config.snapshot?.session?.connected),
      name: String(config.snapshot?.session?.name || ""),
      hostname: String(config.snapshot?.session?.hostname || ""),
      username: String(config.snapshot?.session?.username || ""),
    },
    screen: {
      currentRow: Number(config.snapshot?.screen?.currentRow) || 0,
      rows: Number(config.snapshot?.screen?.rows) || 24,
      cols: Number(config.snapshot?.screen?.cols) || 80,
    },
  };

  function updateSnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== "object") return;
    if (snapshot.session && typeof snapshot.session === "object") {
      Object.assign(runtimeSnapshot.session, snapshot.session);
    }
    if (snapshot.screen && typeof snapshot.screen === "object") {
      Object.assign(runtimeSnapshot.screen, snapshot.screen);
    }
  }

  function reviveError(value) {
    const error = new Error(value?.message || "Script API request failed");
    error.name = value?.name || "Error";
    if (typeof value?.stack === "string") error.stack = value.stack;
    return error;
  }

  function replacer(_key, value) {
    if (value instanceof RegExp) {
      return { __nctRegExp: true, source: value.source, flags: value.flags };
    }
    return value;
  }

  function callHost(method, args = []) {
    if (finished) return Promise.reject(new Error("Script execution finished"));
    const requestId = hostCall(method, JSON.stringify(args, replacer));
    return new Promise((resolve, reject) => {
      pendingRequests.set(requestId, { resolve, reject });
    });
  }

  function notifyHost(method, args = []) {
    if (finished) return;
    hostNotify(method, JSON.stringify(args, replacer));
  }

  global.__nctSettle = function (requestId, ok, valueJson, errorJson, snapshotJson) {
    const pending = pendingRequests.get(requestId);
    if (!pending) return;
    pendingRequests.delete(requestId);
    if (snapshotJson) updateSnapshot(JSON.parse(snapshotJson));
    if (ok) {
      pending.resolve(valueJson === "" ? undefined : JSON.parse(valueJson));
    } else {
      pending.reject(reviveError(JSON.parse(errorJson)));
    }
  };
  global.__nctUpdateSnapshot = function (snapshotJson) {
    updateSnapshot(JSON.parse(snapshotJson));
  };
  global.__nctFinish = function () {
    finished = true;
  };

  const sessionApi = {
    get connected() { return runtimeSnapshot.session.connected; },
    get name() { return runtimeSnapshot.session.name; },
    get hostname() { return runtimeSnapshot.session.hostname; },
    get username() { return runtimeSnapshot.session.username; },
    sleep: (ms) => callHost("session.sleep", [ms]),
    startLog: (path) => callHost("session.startLog", [path == null ? path : String(path)]),
    stopLog: () => callHost("session.stopLog"),
    disconnect: () => callHost("session.disconnect"),
  };

  const screenApi = {
    send: (text, options) => callHost("screen.send", [
      String(text ?? ""),
      { sensitive: options?.sensitive === true },
    ]),
    sendLine: (text, options) => callHost("screen.sendLine", [
      String(text ?? ""),
      { sensitive: options?.sensitive === true },
    ]),
    waitFor: (pattern, timeoutMs) => callHost("screen.waitFor", [pattern, timeoutMs]),
    waitForText: (text, timeoutMs) => callHost("screen.waitForText", [text, timeoutMs]),
    waitForRegex: (pattern, timeoutMs) => callHost("screen.waitForRegex", [pattern, timeoutMs]),
    waitForPrompt: (timeoutMs) => callHost("screen.waitForPrompt", [timeoutMs]),
    waitForAny: (patterns, timeoutMs) => callHost("screen.waitForAny", [patterns, timeoutMs]),
    getText: (startRow, endRow) => callHost("screen.getText", [startRow, endRow]),
    get currentRow() { return runtimeSnapshot.screen.currentRow; },
    get rows() { return runtimeSnapshot.screen.rows; },
    get cols() { return runtimeSnapshot.screen.cols; },
    clear: () => callHost("screen.clear"),
  };

  const dialogApi = {
    alert: (message) => callHost("dialog.alert", [String(message ?? "")]),
    confirm: (message) => callHost("dialog.confirm", [String(message ?? "")]),
    prompt: (message, defaultValue, options) => callHost("dialog.prompt", [
      String(message ?? ""),
      String(defaultValue ?? ""),
      { sensitive: options?.sensitive === true },
    ]),
    form: (spec) => callHost("dialog.form", [spec]),
    select: (message, options, defaultValue) => callHost("dialog.select", [message, options, defaultValue]),
    radio: (message, options, defaultValue) => callHost("dialog.radio", [message, options, defaultValue]),
    checkbox: (message, defaultChecked) => callHost("dialog.checkbox", [message, defaultChecked]),
  };

  const progressApi = {
    start(label, total) { notifyHost("progress.start", [label, total]); },
    set(current, detail) { notifyHost("progress.set", [current, detail]); },
    step(detail) { notifyHost("progress.step", [detail]); },
    done() { notifyHost("progress.done"); },
  };

  global.nct = {
    session: sessionApi,
    screen: screenApi,
    dialog: dialogApi,
    progress: progressApi,
    version: String(config.version || "0.0.0"),
    sleep: sessionApi.sleep,
    log(message) { notifyHost("log", [String(message ?? "")]); },
  };
  global.console = {
    log: (...args) => notifyHost("console.log", [args.map((arg) => String(arg)).join(" ")]),
  };

  // Electron's sandbox: no SharedArrayBuffer, no code generation from strings.
  global.SharedArrayBuffer = undefined;
  const codeGenerationError = () => {
    throw new EvalError("Code generation from strings disallowed for this context");
  };
  global.eval = codeGenerationError;
  const FunctionCtor = function Function() { codeGenerationError(); };
  FunctionCtor.prototype = Function.prototype;
  global.Function = FunctionCtor;
  Object.defineProperty(Function.prototype, "constructor", { value: FunctionCtor, writable: true, configurable: true });
})(globalThis);
"#;

/// Start the engine thread. Events arrive on `events`; the user's script
/// runs as soon as the thread is up.
pub fn spawn_engine(
    config: EngineConfig,
    events: tokio::sync::mpsc::UnboundedSender<EngineEvent>,
) -> EngineHandle {
    let (inbound_tx, inbound_rx) = mpsc::channel();
    let abort = Arc::new(AtomicBool::new(false));
    let abort_for_thread = abort.clone();
    let events_for_thread = events.clone();
    let thread = std::thread::Builder::new()
        .name("netcatty-script".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let outcome = run_engine(config, &events_for_thread, inbound_rx, abort_for_thread);
            if let Err(error) = outcome {
                let _ = events_for_thread.send(EngineEvent::Failed(error));
            }
        });
    let thread = match thread {
        Ok(handle) => Some(handle),
        Err(err) => {
            let _ = events.send(EngineEvent::Failed(ScriptError::new(format!(
                "Script worker failed to start: {err}"
            ))));
            None
        }
    };
    EngineHandle {
        inbound: inbound_tx,
        abort,
        thread,
    }
}

struct Shared {
    events: tokio::sync::mpsc::UnboundedSender<EngineEvent>,
    pending: AtomicUsize,
    next_request_id: AtomicUsize,
    log_notifications: AtomicUsize,
    total_notifications: AtomicUsize,
    limits: EngineLimits,
}

fn exception_to_error<'js>(ctx: &rquickjs::Ctx<'js>, value: rquickjs::Value<'js>) -> ScriptError {
    if let Some(object) = value.as_object() {
        let name: Option<String> = object.get::<_, Option<rquickjs::Coerced<String>>>("name").ok().flatten().map(|c| c.0);
        let message: Option<String> = object.get::<_, Option<rquickjs::Coerced<String>>>("message").ok().flatten().map(|c| c.0);
        let stack: Option<String> = object.get::<_, Option<rquickjs::Coerced<String>>>("stack").ok().flatten().map(|c| c.0);
        if message.is_some() || name.is_some() {
            return ScriptError {
                name: name.filter(|n| !n.is_empty()).unwrap_or_else(|| "Error".into()),
                message: message.unwrap_or_default(),
                stack: stack.filter(|s| !s.is_empty()),
            };
        }
    }
    let text = <rquickjs::Coerced<String> as rquickjs::FromJs>::from_js(ctx, value)
        .map(|c| c.0)
        .unwrap_or_else(|_| "Script worker failed".into());
    ScriptError::new(text)
}

/// Translate an interrupted / thrown execution into the error the host
/// reports.
fn execution_failure<'js>(
    ctx: &rquickjs::Ctx<'js>,
    abort: &AtomicBool,
    timed_out: &AtomicBool,
    limits: &EngineLimits,
) -> Option<ScriptError> {
    let value = ctx.catch();
    if abort.load(Ordering::SeqCst) {
        return None;
    }
    if timed_out.load(Ordering::SeqCst) {
        return Some(ScriptError::new(format!(
            "Script execution timed out after {}ms",
            limits.sync_execution_timeout_ms
        )));
    }
    Some(exception_to_error(ctx, value))
}

fn run_engine(
    config: EngineConfig,
    events: &tokio::sync::mpsc::UnboundedSender<EngineEvent>,
    inbound: mpsc::Receiver<EngineInbound>,
    abort: Arc<AtomicBool>,
) -> Result<(), ScriptError> {
    use rquickjs::{Context, Function, Runtime};

    let limits = config.limits.clone();
    let runtime = Runtime::new().map_err(|e| ScriptError::new(format!("Script worker failed to start: {e}")))?;
    runtime.set_memory_limit(limits.memory_limit_bytes);
    runtime.set_max_stack_size(SCRIPT_WORKER_STACK_SIZE_BYTES);

    let timed_out = Arc::new(AtomicBool::new(false));
    let slice_started = Arc::new(parking_lot::Mutex::new(Instant::now()));
    {
        let abort = abort.clone();
        let timed_out = timed_out.clone();
        let slice_started = slice_started.clone();
        let timeout = Duration::from_millis(limits.sync_execution_timeout_ms);
        runtime.set_interrupt_handler(Some(Box::new(move || {
            if abort.load(Ordering::SeqCst) {
                return true;
            }
            if slice_started.lock().elapsed() > timeout {
                timed_out.store(true, Ordering::SeqCst);
                return true;
            }
            false
        })));
    }

    let context = Context::full(&runtime).map_err(|e| ScriptError::new(format!("Script worker failed to start: {e}")))?;
    let shared = Arc::new(Shared {
        events: events.clone(),
        pending: AtomicUsize::new(0),
        next_request_id: AtomicUsize::new(1),
        log_notifications: AtomicUsize::new(0),
        total_notifications: AtomicUsize::new(0),
        limits: limits.clone(),
    });

    // Install the host natives, the shim and the user's script.
    let start: Result<Option<rquickjs::Persistent<rquickjs::Promise<'static>>>, ScriptError> = context.with(|ctx| {
        let globals = ctx.globals();
        let host_call = {
            let shared = shared.clone();
            Function::new(ctx.clone(), move |ctx: rquickjs::Ctx<'_>, method: String, args_json: String| -> rquickjs::Result<f64> {
                if shared.pending.load(Ordering::SeqCst) >= shared.limits.max_pending_host_requests {
                    return Err(rquickjs::Exception::throw_message(
                        &ctx,
                        &format!(
                            "Script exceeded the {} pending host request limit",
                            shared.limits.max_pending_host_requests
                        ),
                    ));
                }
                let args: Vec<Value> = serde_json::from_str(&args_json).unwrap_or_default();
                let request_id = shared.next_request_id.fetch_add(1, Ordering::SeqCst) as u64;
                shared.pending.fetch_add(1, Ordering::SeqCst);
                let _ = shared.events.send(EngineEvent::Rpc {
                    request_id,
                    method,
                    args,
                });
                Ok(request_id as f64)
            })
        }
        .map_err(|e| ScriptError::new(e.to_string()))?;
        let host_notify = {
            let shared = shared.clone();
            Function::new(ctx.clone(), move |ctx: rquickjs::Ctx<'_>, method: String, args_json: String| -> rquickjs::Result<()> {
                let total = shared.total_notifications.fetch_add(1, Ordering::SeqCst) + 1;
                if total > shared.limits.max_total_notifications {
                    return Err(rquickjs::Exception::throw_message(
                        &ctx,
                        &format!(
                            "Script exceeded the {} notification limit",
                            shared.limits.max_total_notifications
                        ),
                    ));
                }
                if method == "log" || method == "console.log" {
                    let logs = shared.log_notifications.fetch_add(1, Ordering::SeqCst) + 1;
                    if logs > shared.limits.max_log_notifications {
                        return Err(rquickjs::Exception::throw_message(
                            &ctx,
                            &format!(
                                "Script exceeded the {} log notification limit",
                                shared.limits.max_log_notifications
                            ),
                        ));
                    }
                }
                let args: Vec<Value> = serde_json::from_str(&args_json).unwrap_or_default();
                let _ = shared.events.send(EngineEvent::Notify { method, args });
                Ok(())
            })
        }
        .map_err(|e| ScriptError::new(e.to_string()))?;
        let config_json = serde_json::json!({
            "version": config.version,
            "snapshot": config.snapshot,
        })
        .to_string();
        globals
            .set("__nctHostCall", host_call)
            .and_then(|_| globals.set("__nctHostNotify", host_notify))
            .and_then(|_| globals.set("__nctConfigJson", config_json))
            .map_err(|e| ScriptError::new(e.to_string()))?;
        if let Err(err) = ctx.eval::<(), _>(PRELUDE) {
            let value = ctx.catch();
            return Err(match err {
                rquickjs::Error::Exception => exception_to_error(&ctx, value),
                other => ScriptError::new(other.to_string()),
            });
        }

        *slice_started.lock() = Instant::now();
        let mut options = rquickjs::context::EvalOptions::default();
        options.global = true;
        options.strict = false;
        options.backtrace_barrier = false;
        options.promise = false;
        options.filename = Some(config.filename.clone());
        match ctx.eval_with_options::<rquickjs::Value, _>(config.source.as_bytes().to_vec(), options) {
            Ok(value) => Ok(value
                .into_promise()
                .map(|p| rquickjs::Persistent::save(&ctx, p))),
            Err(rquickjs::Error::Exception) => {
                match execution_failure(&ctx, &abort, &timed_out, &limits) {
                    Some(error) => Err(error),
                    None => Ok(None),
                }
            }
            Err(other) => Err(ScriptError::new(other.to_string())),
        }
    });

    let main_promise = match start {
        Ok(promise) => promise,
        Err(error) => {
            finish(&context);
            return Err(error);
        }
    };

    // Event loop.
    let outcome: Result<(), ScriptError> = loop {
        if abort.load(Ordering::SeqCst) {
            break Ok(());
        }
        // Drain the job queue (microtasks).
        let drained: Result<(), Option<ScriptError>> = loop {
            match runtime.execute_pending_job() {
                Ok(true) => {
                    if abort.load(Ordering::SeqCst) {
                        break Err(None);
                    }
                }
                Ok(false) => break Ok(()),
                Err(job_error) => {
                    let failure = job_error
                        .0
                        .with(|ctx| execution_failure(&ctx, &abort, &timed_out, &limits));
                    break Err(failure);
                }
            }
        };
        match drained {
            Ok(()) => {}
            Err(None) => break Ok(()),
            Err(Some(error)) => break Err(error),
        }

        // Settled?
        let settled: Option<Result<(), ScriptError>> = context.with(|ctx| {
            let Some(persistent) = &main_promise else {
                return Some(Ok(()));
            };
            let promise = persistent.clone().restore(&ctx).ok()?;
            match promise.state() {
                rquickjs::promise::PromiseState::Pending => None,
                rquickjs::promise::PromiseState::Resolved => Some(Ok(())),
                rquickjs::promise::PromiseState::Rejected => {
                    let _ = promise.result::<rquickjs::Value>();
                    let value = ctx.catch();
                    Some(Err(exception_to_error(&ctx, value)))
                }
            }
        });
        if let Some(result) = settled {
            break result;
        }

        // Idle: wait for the host.
        *slice_started.lock() = Instant::now();
        match inbound.recv_timeout(IDLE_TICK) {
            Ok(EngineInbound::RpcResult {
                request_id,
                result,
                snapshot,
            }) => {
                shared.pending.fetch_sub(1, Ordering::SeqCst);
                *slice_started.lock() = Instant::now();
                let delivered: Result<(), Option<ScriptError>> = context.with(|ctx| {
                    let settle: Function = ctx
                        .globals()
                        .get("__nctSettle")
                        .map_err(|e| Some(ScriptError::new(e.to_string())))?;
                    let (ok, value_json, error_json) = match result {
                        Ok(Some(value)) => (true, value.to_string(), String::new()),
                        Ok(None) => (true, String::new(), String::new()),
                        Err(error) => (
                            false,
                            String::new(),
                            serde_json::to_string(&error).unwrap_or_default(),
                        ),
                    };
                    let snapshot_json = serde_json::to_string(&snapshot).unwrap_or_default();
                    match settle.call::<_, ()>((request_id as f64, ok, value_json, error_json, snapshot_json)) {
                        Ok(()) => Ok(()),
                        Err(rquickjs::Error::Exception) => {
                            Err(execution_failure(&ctx, &abort, &timed_out, &limits))
                        }
                        Err(other) => Err(Some(ScriptError::new(other.to_string()))),
                    }
                });
                match delivered {
                    Ok(()) => {}
                    Err(None) => break Ok(()),
                    Err(Some(error)) => break Err(error),
                }
            }
            Ok(EngineInbound::Snapshot(snapshot)) => {
                context.with(|ctx| {
                    if let Ok(update) = ctx.globals().get::<_, Function>("__nctUpdateSnapshot") {
                        let snapshot_json = serde_json::to_string(&snapshot).unwrap_or_default();
                        let _ = update.call::<_, ()>((snapshot_json,));
                    }
                });
            }
            Ok(EngineInbound::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };

    finish(&context);
    match outcome {
        Ok(()) => {
            if !abort.load(Ordering::SeqCst) {
                let _ = events.send(EngineEvent::Completed);
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Mark the shim finished so late settlements are ignored.
fn finish(context: &rquickjs::Context) {
    context.with(|ctx| {
        if let Ok(done) = ctx.globals().get::<_, rquickjs::Function>("__nctFinish") {
            let _ = done.call::<_, ()>(());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn config(source: &str, timeout_ms: u64) -> EngineConfig {
        EngineConfig {
            source: crate::source::wrap_script_source(source).unwrap(),
            filename: "test.js".into(),
            version: "1.2.3".into(),
            snapshot: RuntimeSnapshot {
                session: SessionSnapshot {
                    connected: true,
                    name: "box".into(),
                    hostname: "host".into(),
                    username: "user".into(),
                },
                screen: ScreenSnapshotMeta::default(),
            },
            limits: EngineLimits {
                sync_execution_timeout_ms: timeout_ms,
                ..Default::default()
            },
        }
    }

    /// Run a script, answering every RPC with `answer`.
    async fn run_script(
        source: &str,
        timeout_ms: u64,
        mut answer: impl FnMut(&str, &[Value]) -> Result<Option<Value>, ScriptError>,
    ) -> (Result<(), ScriptError>, Vec<(String, Vec<Value>)>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let handle = spawn_engine(config(source, timeout_ms), tx);
        let mut notifications = Vec::new();
        let result = loop {
            match rx.recv().await {
                Some(EngineEvent::Rpc {
                    request_id,
                    method,
                    args,
                }) => {
                    let result = answer(&method, &args);
                    handle.send(EngineInbound::RpcResult {
                        request_id,
                        result,
                        snapshot: RuntimeSnapshot::default(),
                    });
                }
                Some(EngineEvent::Notify { method, args }) => notifications.push((method, args)),
                Some(EngineEvent::Completed) => break Ok(()),
                Some(EngineEvent::Failed(error)) => break Err(error),
                None => break Err(ScriptError::new("engine gone")),
            }
        };
        tokio::task::spawn_blocking(move || handle.join()).await.unwrap();
        (result, notifications)
    }

    #[tokio::test]
    async fn executes_async_main_script_and_exposes_session_name() {
        let (result, notifications) = run_script(
            "async function main() { nct.log(nct.session.name + '/' + nct.session.hostname + '/' + nct.version); console.log('a', 1); }\nawait main();",
            1000,
            |_, _| Ok(None),
        )
        .await;
        assert_eq!(result, Ok(()));
        assert_eq!(notifications[0].0, "log");
        assert_eq!(notifications[0].1[0], "box/host/1.2.3");
        assert_eq!(notifications[1], ("console.log".into(), vec![Value::String("a 1".into())]));
    }

    #[tokio::test]
    async fn rpc_round_trip_resolves_values_and_errors() {
        let (result, notifications) = run_script(
            r#"
              const v = await nct.screen.waitFor(/READY$/m, 5);
              const u = await nct.screen.send('x');
              nct.log(v + ':' + String(u));
              try { await nct.dialog.confirm('q'); } catch (e) { nct.log(e.name + ':' + e.message); }
            "#,
            1000,
            |method, args| match method {
                "screen.waitFor" => {
                    assert_eq!(args[0]["__nctRegExp"], true);
                    assert_eq!(args[0]["source"], "READY$");
                    assert_eq!(args[0]["flags"], "m");
                    assert_eq!(args[1], 5);
                    Ok(Some(Value::String("READY".into())))
                }
                "screen.send" => Ok(None),
                "dialog.confirm" => Err(ScriptError {
                    name: "TypeError".into(),
                    message: "nope".into(),
                    stack: None,
                }),
                other => panic!("unexpected {other}"),
            },
        )
        .await;
        assert_eq!(result, Ok(()));
        assert_eq!(notifications[0].1[0], "READY:undefined");
        assert_eq!(notifications[1].1[0], "TypeError:nope");
    }

    #[tokio::test]
    async fn script_errors_are_reported_with_name_and_message() {
        let (result, _) = run_script("throw new RangeError('bad');", 1000, |_, _| Ok(None)).await;
        let error = result.unwrap_err();
        assert_eq!(error.name, "RangeError");
        assert_eq!(error.message, "bad");
        let (result, _) = run_script("this is not js", 1000, |_, _| Ok(None)).await;
        assert_eq!(result.unwrap_err().name, "SyntaxError");
    }

    #[tokio::test]
    async fn stops_a_synchronous_infinite_loop() {
        let (result, _) = run_script("while (true) {}", 20, |_, _| Ok(None)).await;
        assert_eq!(
            result.unwrap_err().message,
            "Script execution timed out after 20ms"
        );
    }

    #[tokio::test]
    async fn enforces_the_deadline_across_promise_continuations() {
        let (result, _) =
            run_script("await Promise.resolve(); while (true) {}", 20, |_, _| Ok(None)).await;
        assert!(result.unwrap_err().message.contains("timed out"));
        let (result, _) = run_script("await nct.sleep(1); while (true) {}", 20, |_, _| Ok(None)).await;
        assert!(result.unwrap_err().message.contains("timed out"));
        let (result, _) = run_script(
            "await nct.sleep(1); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);",
            20,
            |_, _| Ok(None),
        )
        .await;
        assert!(result.unwrap_err().message.to_lowercase().contains("sharedarraybuffer"));
        let started = Instant::now();
        let (result, _) = run_script(
            "await nct.sleep(1); /^(a+)+$/.test('a'.repeat(28) + '!');",
            20,
            |_, _| Ok(None),
        )
        .await;
        assert!(result.unwrap_err().message.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn drains_normal_host_backed_promise_continuations() {
        let (result, notifications) = run_script(
            "await nct.sleep(1); nct.log('first'); await Promise.resolve(); await nct.sleep(1); nct.log(nct.session.connected ? 'second' : 'disconnected');",
            20,
            |_, _| Ok(None),
        )
        .await;
        assert_eq!(result, Ok(()));
        let logs: Vec<&Value> = notifications.iter().map(|n| &n.1[0]).collect();
        assert_eq!(logs, vec!["first", "second"]);
    }

    #[tokio::test]
    async fn explicit_stop_terminates_a_blocked_worker() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let handle = spawn_engine(
            config("await nct.sleep(1); /^(a+)+$/.test('a'.repeat(30) + '!');", 5_000),
            tx,
        );
        let started = Instant::now();
        let Some(EngineEvent::Rpc { request_id, .. }) = rx.recv().await else {
            panic!("expected sleep rpc");
        };
        handle.send(EngineInbound::RpcResult {
            request_id,
            result: Ok(None),
            snapshot: RuntimeSnapshot::default(),
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::task::spawn_blocking(move || handle.join()).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        // No completion is reported after an abort.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn fan_out_stops_at_the_pending_limit() {
        let started = Instant::now();
        let (result, _) = run_script(
            "for (let i = 0; i < 20000; i += 1) void nct.sleep(60000);",
            5_000,
            |_, _| unreachable!("the engine must not answer during the fan-out"),
        )
        .await;
        assert_eq!(
            result.unwrap_err().message,
            format!("Script exceeded the {SCRIPT_WORKER_MAX_PENDING_HOST_REQUESTS} pending host request limit")
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn sequential_host_requests_are_fine() {
        let (result, notifications) = run_script(
            "for (let i = 0; i < 5; i += 1) await nct.sleep(0); nct.log('done');",
            1000,
            |_, _| Ok(None),
        )
        .await;
        assert_eq!(result, Ok(()));
        assert_eq!(notifications.len(), 1);
    }

    #[tokio::test]
    async fn bounds_log_notification_floods() {
        let (result, notifications) = run_script(
            "for (let i = 0; i < 200000; i += 1) nct.log('x');",
            5_000,
            |_, _| Ok(None),
        )
        .await;
        assert_eq!(
            result.unwrap_err().message,
            format!("Script exceeded the {SCRIPT_WORKER_MAX_LOG_NOTIFICATIONS} log notification limit")
        );
        assert_eq!(notifications.len(), SCRIPT_WORKER_MAX_LOG_NOTIFICATIONS);
    }

    #[tokio::test]
    async fn code_generation_from_strings_is_disabled() {
        let (result, notifications) = run_script(
            "try { eval('1'); } catch (e) { nct.log(e.name); } try { new Function('return 1')(); } catch (e) { nct.log(e.name); } nct.log(String(typeof SharedArrayBuffer));",
            1000,
            |_, _| Ok(None),
        )
        .await;
        assert_eq!(result, Ok(()));
        let logs: Vec<&Value> = notifications.iter().map(|n| &n.1[0]).collect();
        assert_eq!(logs, vec!["EvalError", "EvalError", "undefined"]);
    }
}
