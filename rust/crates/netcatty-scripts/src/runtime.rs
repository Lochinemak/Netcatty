//! Host side of the script API: the port of `createScriptRuntime` and the
//! host half of `executeInScriptWorker` in `electron/scripts/scriptRuntime.cjs`.
//!
//! A [`ScriptRuntime`] owns one run: it starts the QuickJS worker
//! ([`crate::engine`]), answers its RPCs (`screen.send`, `screen.waitFor`,
//! `dialog.*`, ...) against a [`RuntimeHost`] (the bridge: session writes,
//! dialogs, logs), tracks steps / progress for the run status, and enforces
//! pause / abort. Error messages are the ones Electron scripts see
//! (`"Script stopped"`, `"Observer mode: screen.send is disabled. ..."`,
//! `"waitFor timed out after 30000ms"`, ...).

use crate::buffer::{AbortCheck, OutputBuffer, WaitError};
use crate::dialog::{js_number, js_string, js_truthy, normalize_dialog_form_spec};
use crate::engine::{
    spawn_engine, EngineConfig, EngineEvent, EngineHandle, EngineInbound, EngineLimits,
    RuntimeSnapshot, ScreenSnapshotMeta, ScriptError, SessionSnapshot,
};
use crate::pattern::{PatternError, WaitPattern};
use crate::prompt_patterns::shell_prompt_patterns;
use crate::run::{now_ms, ProgressMode, RunStatus, StatusPatch};
use crate::source::{format_script_input_for_log, truncate_activity_label, wrap_script_source};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const SCRIPT_WORKER_IMMEDIATE_PROGRESS_NOTIFICATIONS: usize = 64;
pub const SCRIPT_WORKER_PROGRESS_THROTTLE_MS: u64 = 50;
const WATCHDOG_TICK: Duration = Duration::from_millis(25);
const SCRIPT_STOPPED: &str = "Script stopped";

/// `permissionMode` of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionMode {
    Observer,
    Confirm,
    #[default]
    Auto,
}

impl PermissionMode {
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            Some("observer") => PermissionMode::Observer,
            Some("confirm") => PermissionMode::Confirm,
            _ => PermissionMode::Auto,
        }
    }
}

/// The renderer's `ScriptScreenSnapshot` (`source: "buffer-fallback"` marks
/// the synthetic snapshot built from the output buffer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenSnapshot {
    #[serde(default = "default_rows")]
    pub rows: i64,
    #[serde(default = "default_cols")]
    pub cols: i64,
    #[serde(default)]
    pub current_row: i64,
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

fn default_rows() -> i64 {
    24
}
fn default_cols() -> i64 {
    80
}

impl Default for ScreenSnapshot {
    fn default() -> Self {
        Self {
            rows: 24,
            cols: 80,
            current_row: 0,
            lines: Vec::new(),
            source: None,
        }
    }
}

impl ScreenSnapshot {
    /// `bufferFallbackSnapshot`: the output buffer split into lines.
    pub fn buffer_fallback(buffer_text: &str) -> Self {
        Self {
            rows: 24,
            cols: 80,
            current_row: 0,
            lines: buffer_text.split('\n').map(str::to_string).collect(),
            source: Some("buffer-fallback".into()),
        }
    }

    pub fn is_viewport(&self) -> bool {
        self.source.as_deref() != Some("buffer-fallback")
    }
}

/// Options of a session write issued by the script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteOptions {
    pub automated: bool,
    pub sensitive: bool,
    /// `false` for the two writes of `sendLine` (see #1960).
    pub invalidate_startup_seed: bool,
}

/// A dialog the runtime asks the renderer to show.
#[derive(Debug, Clone, PartialEq)]
pub struct DialogRequest {
    /// `alert` | `confirm` | `prompt` | `form` | `waitForTimeout`.
    pub dialog_type: String,
    pub message: String,
    pub default_value: Option<String>,
    /// Extra payload fields (`sensitive`, `form`, `pattern`, `timeoutMs`).
    pub extras: serde_json::Map<String, Value>,
}

/// What a runtime needs from its bridge (the `deps` of `createScriptRuntime`).
#[async_trait::async_trait]
pub trait RuntimeHost: Send + Sync {
    fn append_log(&self, message: &str);
    fn write_to_session(&self, data: &str, options: &WriteOptions);
    fn output_buffer(&self) -> OutputBuffer;
    /// `getScreenSnapshot`: `Err` falls back to the output buffer text.
    async fn screen_snapshot(&self) -> Result<ScreenSnapshot, String>;
    fn session_meta(&self) -> SessionSnapshot;
    /// `showDialog`: `Ok(None)` is `undefined` (alerts).
    async fn show_dialog(&self, request: DialogRequest) -> Result<Option<Value>, String>;
    /// `showWaitForTimeoutDialog`: `retry` | `skip` | `abort`.
    async fn show_wait_for_timeout_dialog(
        &self,
        pattern: &str,
        timeout_ms: u64,
    ) -> Result<String, String>;
    async fn disconnect_session(&self) -> Result<(), String>;
    async fn start_session_log(&self, path: Option<String>) -> Result<(), String>;
    async fn stop_session_log(&self) -> Result<(), String>;
    fn is_paused(&self) -> bool;
    fn is_aborted(&self) -> bool;
    fn on_status_change(&self, patch: StatusPatch);
}

#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    pub session_id: String,
    pub run_id: String,
    pub app_version: String,
    pub permission_mode: PermissionMode,
    pub started_at: i64,
    pub limits: EngineLimits,
}

struct RuntimeState {
    step_index: u64,
    progress_mode: ProgressMode,
    progress_label: Option<String>,
    progress_current: f64,
    progress_total: f64,
    screen_snapshot: ScreenSnapshot,
}

struct Inner {
    host: Arc<dyn RuntimeHost>,
    options: RuntimeOptions,
    state: Mutex<RuntimeState>,
    /// `executionToken.closed`: set when the worker is torn down.
    closed: AtomicBool,
    engine: Mutex<Option<Arc<EngineHandle>>>,
    stop_reason: Mutex<Option<String>>,
    stop_signal: tokio::sync::Notify,
}

/// The `nct` host implementation for one run.
#[derive(Clone)]
pub struct ScriptRuntime {
    inner: Arc<Inner>,
}

/// A host request that failed; `name` keeps the JS error class.
fn js_error(name: &str, message: impl Into<String>) -> ScriptError {
    ScriptError {
        name: name.into(),
        message: message.into(),
        stack: None,
    }
}

fn plain_error(message: impl Into<String>) -> ScriptError {
    js_error("Error", message)
}

fn stopped() -> ScriptError {
    plain_error(SCRIPT_STOPPED)
}

impl From<WaitError> for ScriptError {
    fn from(error: WaitError) -> Self {
        match error {
            WaitError::Pattern(PatternError::Type(message)) => js_error("TypeError", message),
            WaitError::Pattern(err @ PatternError::Syntax { .. }) => {
                js_error("SyntaxError", err.to_string())
            }
            other => plain_error(other.message()),
        }
    }
}

/// `undefined` marker the worker shim emits for missing arguments.
fn is_undefined_marker(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("__nctUndefined") == Some(&Value::Bool(true)))
}

/// Replace nested `undefined` markers like `JSON.stringify` would have
/// (object keys dropped, array items `null`).
fn strip_undefined(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, v)| !is_undefined_marker(v))
                .map(|(k, v)| (k, strip_undefined(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|v| {
                    if is_undefined_marker(&v) {
                        Value::Null
                    } else {
                        strip_undefined(v)
                    }
                })
                .collect(),
        ),
        other => other,
    }
}

/// Arguments of one RPC with JavaScript argument semantics (`undefined`
/// for missing ones).
struct Args(Vec<Option<Value>>);

impl Args {
    fn new(raw: Vec<Value>) -> Self {
        Args(
            raw.into_iter()
                .map(|v| {
                    if is_undefined_marker(&v) {
                        None
                    } else {
                        Some(strip_undefined(v))
                    }
                })
                .collect(),
        )
    }

    fn get(&self, index: usize) -> Option<&Value> {
        self.0.get(index).and_then(|v| v.as_ref())
    }

    /// `String(value ?? "")`.
    fn string(&self, index: usize) -> String {
        match self.get(index) {
            None | Some(Value::Null) => String::new(),
            Some(v) => js_string(v),
        }
    }

    /// A `timeoutMs = <default>` parameter: the default for `undefined`,
    /// otherwise `Number(value)` (NaN → 0, like `setTimeout`).
    fn timeout(&self, index: usize, default: u64) -> u64 {
        match self.get(index) {
            None => default,
            Some(v) => js_number(v)
                .filter(|n| n.is_finite() && *n > 0.0)
                .map(|n| n as u64)
                .unwrap_or(0),
        }
    }

    fn sensitive_option(&self, index: usize) -> bool {
        self.get(index)
            .and_then(|v| v.get("sensitive"))
            .is_some_and(|v| v == &Value::Bool(true))
    }
}

impl ScriptRuntime {
    pub fn new(host: Arc<dyn RuntimeHost>, options: RuntimeOptions) -> Self {
        Self {
            inner: Arc::new(Inner {
                host,
                options,
                state: Mutex::new(RuntimeState {
                    step_index: 0,
                    progress_mode: ProgressMode::Activity,
                    progress_label: None,
                    progress_current: 0.0,
                    progress_total: 0.0,
                    screen_snapshot: ScreenSnapshot::default(),
                }),
                closed: AtomicBool::new(false),
                engine: Mutex::new(None),
                stop_reason: Mutex::new(None),
                stop_signal: tokio::sync::Notify::new(),
            }),
        }
    }

    /// `runtime.stop(reason)`: tear the worker down; `execute` rejects with
    /// `reason`.
    pub fn stop(&self, reason: &str) {
        {
            let mut slot = self.inner.stop_reason.lock();
            if slot.is_none() {
                *slot = Some(reason.to_string());
            }
        }
        self.inner.closed.store(true, Ordering::SeqCst);
        if let Some(engine) = self.inner.engine.lock().as_ref() {
            engine.stop();
        }
        self.inner.stop_signal.notify_waiters();
        self.inner.stop_signal.notify_one();
    }

    fn is_execution_aborted(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst) || self.inner.host.is_aborted()
    }

    fn abort_check(&self) -> AbortCheck {
        let runtime = self.clone();
        Arc::new(move || runtime.is_execution_aborted())
    }

    fn assert_not_aborted(&self) -> Result<(), ScriptError> {
        if self.is_execution_aborted() {
            Err(stopped())
        } else {
            Ok(())
        }
    }

    /// `abortable(promise)`: race `future` with the abort flag (polled every
    /// 50 ms); a result that lands after an abort is dropped.
    async fn abortable<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, ScriptError>>,
    ) -> Result<T, ScriptError> {
        self.assert_not_aborted()?;
        tokio::pin!(future);
        loop {
            tokio::select! {
                result = &mut future => {
                    if self.is_execution_aborted() {
                        return Err(stopped());
                    }
                    return result;
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    if self.is_execution_aborted() {
                        return Err(stopped());
                    }
                }
            }
        }
    }

    /// `interruptibleSleep`.
    async fn interruptible_sleep(&self, ms: u64) -> Result<(), ScriptError> {
        let started = Instant::now();
        let delay = Duration::from_millis(ms);
        loop {
            if self.is_execution_aborted() {
                return Err(stopped());
            }
            if started.elapsed() >= delay {
                return Ok(());
            }
            let remaining = delay.saturating_sub(started.elapsed());
            tokio::time::sleep(remaining.min(Duration::from_millis(50))).await;
        }
    }

    /// `ignoreIfStopped`: a `"Script stopped"` failure after an abort is a
    /// silent `undefined`.
    fn ignore_if_stopped(&self, result: Result<(), ScriptError>) -> Result<Option<Value>, ScriptError> {
        match result {
            Ok(()) => Ok(None),
            Err(err) if self.is_execution_aborted() && err.message == SCRIPT_STOPPED => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn emit_status(&self, patch: StatusPatch) {
        let base = {
            let state = self.inner.state.lock();
            let determinate = state.progress_mode == ProgressMode::Determinate;
            StatusPatch {
                status: Some(RunStatus::Running),
                progress_mode: Some(state.progress_mode),
                progress_label: Some(if determinate {
                    state.progress_label.clone()
                } else {
                    None
                }),
                progress_current: Some(if determinate {
                    Some(state.progress_current)
                } else {
                    None
                }),
                progress_total: Some(if determinate {
                    Some(state.progress_total)
                } else {
                    None
                }),
                step_index: Some(state.step_index),
                activity_label: None,
                current_step: None,
                waiting_for: None,
            }
        };
        let merged = StatusPatch {
            status: patch.status.or(base.status),
            progress_mode: patch.progress_mode.or(base.progress_mode),
            progress_label: patch.progress_label.or(base.progress_label),
            progress_current: patch.progress_current.or(base.progress_current),
            progress_total: patch.progress_total.or(base.progress_total),
            step_index: patch.step_index.or(base.step_index),
            activity_label: patch.activity_label,
            current_step: patch.current_step,
            waiting_for: patch.waiting_for,
        };
        self.inner.host.on_status_change(merged);
    }

    fn status_change(&self, patch: StatusPatch) {
        self.inner.host.on_status_change(patch);
    }

    fn assert_write_allowed(&self, operation: &str) -> Result<(), ScriptError> {
        if self.inner.options.permission_mode != PermissionMode::Observer {
            return Ok(());
        }
        Err(plain_error(format!(
            "Observer mode: {operation} is disabled. Switch to Confirm or Auto mode."
        )))
    }

    fn track_step(&self, label: &str) -> Result<(), ScriptError> {
        self.assert_not_aborted()?;
        let activity_label = truncate_activity_label(label, 80);
        self.inner.state.lock().step_index += 1;
        self.emit_status(StatusPatch {
            activity_label: Some(Some(activity_label.clone())),
            current_step: Some(Some(activity_label)),
            ..Default::default()
        });
        Ok(())
    }

    async fn refresh_screen_snapshot(&self) -> Result<ScreenSnapshot, ScriptError> {
        self.assert_not_aborted()?;
        let host = self.inner.host.clone();
        let fetched = self
            .abortable(async move { host.screen_snapshot().await.map_err(plain_error) })
            .await;
        if let Ok(snapshot) = fetched {
            self.inner.state.lock().screen_snapshot = snapshot;
        }
        self.assert_not_aborted()?;
        Ok(self.inner.state.lock().screen_snapshot.clone())
    }

    async fn wait_if_paused(&self) -> Result<(), ScriptError> {
        self.assert_not_aborted()?;
        while self.inner.host.is_paused() {
            self.assert_not_aborted()?;
            self.status_change(StatusPatch::status(RunStatus::Paused));
            self.interruptible_sleep(100).await?;
        }
        self.assert_not_aborted()?;
        self.status_change(StatusPatch::status(RunStatus::Running));
        Ok(())
    }

    /// Shared timeout-recovery loop of the `waitFor*` methods.
    async fn wait_with_recovery<T: Clone>(
        &self,
        step_label: &str,
        waiting_label: &str,
        timeout_ms: u64,
        skip_value: T,
        mut wait: impl FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, WaitError>> + Send>>,
    ) -> Result<T, ScriptError> {
        let mut step_tracked = false;
        loop {
            if self.is_execution_aborted() {
                return Err(stopped());
            }
            if !step_tracked {
                self.track_step(step_label)?;
                step_tracked = true;
            }
            self.status_change(StatusPatch::waiting(
                RunStatus::Running,
                Some(waiting_label.to_string()),
            ));
            let outcome = wait().await;
            let result = match outcome {
                Ok(value) => Some(Ok(value)),
                Err(err) if !err.is_timeout() => Some(Err(ScriptError::from(err))),
                Err(_) => {
                    self.status_change(StatusPatch::waiting(
                        RunStatus::Paused,
                        Some(waiting_label.to_string()),
                    ));
                    let action = match self.assert_not_aborted() {
                        Ok(()) => {
                            let host = self.inner.host.clone();
                            let label = waiting_label.to_string();
                            self.abortable(async move {
                                host.show_wait_for_timeout_dialog(&label, timeout_ms)
                                    .await
                                    .map_err(plain_error)
                            })
                            .await
                        }
                        Err(err) => Err(err),
                    };
                    match action {
                        Err(err) => Some(Err(err)),
                        Ok(action) => {
                            self.status_change(StatusPatch::status(RunStatus::Running));
                            match action.as_str() {
                                "retry" => None,
                                "skip" => Some(Ok(skip_value.clone())),
                                _ => Some(Err(plain_error("Script stopped by user"))),
                            }
                        }
                    }
                }
            };
            // `finally`
            self.status_change(StatusPatch::waiting(RunStatus::Running, None));
            if let Some(result) = result {
                return result;
            }
        }
    }

    async fn wait_for_pattern(
        &self,
        method: &str,
        pattern: WaitPattern,
        timeout_ms: u64,
    ) -> Result<Option<Value>, ScriptError> {
        let pattern_label = pattern.label();
        let step_label = format!(
            "{method} {}",
            truncate_activity_label(&pattern_label, 60)
        );
        let buffer = self.inner.host.output_buffer();
        let abort = self.abort_check();
        let method_name = method.to_string();
        let value = self
            .wait_with_recovery(&step_label, &pattern_label, timeout_ms, SkipValue::Text, move || {
                let buffer = buffer.clone();
                let pattern = pattern.clone();
                let abort = abort.clone();
                let method_name = method_name.clone();
                Box::pin(async move {
                    match method_name.as_str() {
                        "waitForText" => buffer.wait_for_text(&pattern, timeout_ms, Some(abort)).await,
                        "waitForRegex" => buffer.wait_for_regex(&pattern, timeout_ms, Some(abort)).await,
                        _ => buffer.wait_for(&pattern, timeout_ms, Some(abort)).await,
                    }
                    .map(SkipValue::Matched)
                })
            })
            .await?;
        Ok(Some(value.into_json()))
    }

    async fn wait_for_prompt(&self, timeout_ms: u64) -> Result<Option<Value>, ScriptError> {
        let buffer = self.inner.host.output_buffer();
        let abort = self.abort_check();
        let patterns = shell_prompt_patterns();
        let value = self
            .wait_with_recovery("waitForPrompt", "shell prompt", timeout_ms, SkipValue::Index, move || {
                let buffer = buffer.clone();
                let patterns = patterns.clone();
                let abort = abort.clone();
                Box::pin(async move {
                    buffer
                        .wait_for_any(&patterns, timeout_ms, Some(abort), true)
                        .await
                        .map(SkipValue::Found)
                })
            })
            .await?;
        Ok(Some(value.into_json()))
    }

    async fn wait_for_any(
        &self,
        patterns: Vec<WaitPattern>,
        timeout_ms: u64,
    ) -> Result<Option<Value>, ScriptError> {
        let label = patterns
            .iter()
            .map(WaitPattern::label)
            .collect::<Vec<_>>()
            .join(" | ");
        let step_label = format!("waitForAny {}", truncate_activity_label(&label, 60));
        let buffer = self.inner.host.output_buffer();
        let abort = self.abort_check();
        let value = self
            .wait_with_recovery(&step_label, &label, timeout_ms, SkipValue::Index, move || {
                let buffer = buffer.clone();
                let patterns = patterns.clone();
                let abort = abort.clone();
                Box::pin(async move {
                    buffer
                        .wait_for_any(&patterns, timeout_ms, Some(abort), false)
                        .await
                        .map(SkipValue::Found)
                })
            })
            .await?;
        Ok(Some(value.into_json()))
    }

    async fn show_dialog(
        &self,
        dialog_type: &str,
        message: String,
        default_value: Option<String>,
        extras: serde_json::Map<String, Value>,
    ) -> Result<Option<Value>, ScriptError> {
        self.assert_not_aborted()?;
        let host = self.inner.host.clone();
        let request = DialogRequest {
            dialog_type: dialog_type.to_string(),
            message,
            default_value,
            extras,
        };
        self.abortable(async move { host.show_dialog(request).await.map_err(plain_error) })
            .await
    }

    async fn dialog_form(&self, spec: Option<&Value>) -> Result<Option<Value>, ScriptError> {
        self.assert_not_aborted()?;
        let form = normalize_dialog_form_spec(spec.unwrap_or(&Value::Null)).map_err(plain_error)?;
        let message = form["message"].as_str().unwrap_or("").to_string();
        let mut extras = serde_json::Map::new();
        extras.insert("form".into(), form);
        self.show_dialog("form", message, None, extras).await
    }

    async fn dialog_single_field(
        &self,
        field_type: &str,
        message: Option<&Value>,
        extra: Value,
    ) -> Result<Option<Value>, ScriptError> {
        let mut field = json!({
            "type": field_type,
            "name": "value",
        });
        if let Some(message) = message {
            field["label"] = message.clone();
        }
        if let Value::Object(extra) = extra {
            for (key, value) in extra {
                field[key] = value;
            }
        }
        let mut spec = json!({ "fields": [field] });
        if let Some(message) = message {
            spec["message"] = message.clone();
        }
        let values = self.dialog_form(Some(&spec)).await?;
        Ok(Some(
            values
                .and_then(|v| v.get("value").cloned())
                .unwrap_or(Value::Null),
        ))
    }

    /// `invokeWorkerRpc`.
    async fn invoke_rpc(&self, method: &str, args: Args) -> Result<Option<Value>, ScriptError> {
        match method {
            "session.sleep" => {
                let delay = args
                    .get(0)
                    .and_then(js_number)
                    .filter(|n| n.is_finite() && *n > 0.0)
                    .unwrap_or(0.0) as u64;
                self.track_step(&format!("sleep {delay}ms"))?;
                self.interruptible_sleep(delay).await?;
                Ok(None)
            }
            "session.startLog" => {
                let result = async {
                    if self.is_execution_aborted() {
                        return Ok(());
                    }
                    self.assert_write_allowed("session.startLog")?;
                    self.track_step("startLog")?;
                    if self.is_execution_aborted() {
                        return Ok(());
                    }
                    let path = match args.get(0) {
                        None | Some(Value::Null) => None,
                        Some(v) => Some(js_string(v)),
                    };
                    self.inner
                        .host
                        .start_session_log(path)
                        .await
                        .map_err(plain_error)
                }
                .await;
                self.ignore_if_stopped(result)
            }
            "session.stopLog" => {
                self.inner
                    .host
                    .stop_session_log()
                    .await
                    .map_err(plain_error)?;
                Ok(None)
            }
            "session.disconnect" => {
                let result = async {
                    if self.is_execution_aborted() {
                        return Ok(());
                    }
                    self.assert_write_allowed("session.disconnect")?;
                    self.track_step("disconnect")?;
                    if self.is_execution_aborted() {
                        return Ok(());
                    }
                    self.inner
                        .host
                        .disconnect_session()
                        .await
                        .map_err(plain_error)
                }
                .await;
                self.ignore_if_stopped(result)
            }
            "screen.send" => {
                let result = async {
                    if self.is_execution_aborted() {
                        return Ok(());
                    }
                    self.assert_write_allowed("screen.send")?;
                    self.wait_if_paused().await?;
                    let payload = args.string(0);
                    let sensitive = args.sensitive_option(1);
                    let visible = if sensitive {
                        "[sensitive]".to_string()
                    } else {
                        format_script_input_for_log(&payload)
                    };
                    self.track_step(&format!("send: {}", truncate_activity_label(&visible, 60)))?;
                    if self.is_execution_aborted() {
                        return Ok(());
                    }
                    self.inner.host.append_log(&format!("→ {visible}"));
                    self.inner.host.write_to_session(
                        &payload,
                        &WriteOptions {
                            automated: true,
                            sensitive,
                            invalidate_startup_seed: true,
                        },
                    );
                    Ok(())
                }
                .await;
                self.ignore_if_stopped(result)
            }
            "screen.sendLine" => {
                let result = async {
                    if self.is_execution_aborted() {
                        return Ok(());
                    }
                    self.assert_write_allowed("screen.sendLine")?;
                    self.wait_if_paused().await?;
                    let line = args.string(0);
                    let sensitive = args.sensitive_option(1);
                    let visible = if sensitive {
                        "[sensitive]".to_string()
                    } else {
                        line.clone()
                    };
                    self.track_step(&format!(
                        "sendLine: {}",
                        truncate_activity_label(&visible, 60)
                    ))?;
                    if self.is_execution_aborted() {
                        return Ok(());
                    }
                    self.inner.host.append_log(&format!("→ {visible}"));
                    // Bastion menus can ignore a single "line\r" packet. Match
                    // xterm: body, then Enter (#1960). Consume only the
                    // pre-send buffer length so prompts that arrive between
                    // body and CR stay waitable for the next step.
                    let buffer = self.inner.host.output_buffer();
                    let length_before_send = buffer.text_len();
                    let options = WriteOptions {
                        automated: true,
                        sensitive,
                        invalidate_startup_seed: false,
                    };
                    if !line.is_empty() {
                        self.inner.host.write_to_session(&line, &options);
                        self.interruptible_sleep(30).await?;
                        if self.is_execution_aborted() {
                            return Ok(());
                        }
                    }
                    self.inner.host.write_to_session("\r", &options);
                    buffer.consume_through_absolute(length_before_send);
                    Ok(())
                }
                .await;
                self.ignore_if_stopped(result)
            }
            "screen.waitFor" | "screen.waitForText" | "screen.waitForRegex" => {
                let name = &method["screen.".len()..];
                let pattern = match args.get(0).and_then(WaitPattern::from_json) {
                    Some(pattern) => pattern,
                    None => {
                        return Err(js_error(
                            "TypeError",
                            match name {
                                "waitForText" => "waitForText pattern must be a string",
                                "waitForRegex" => "waitForRegex pattern must be a string or RegExp",
                                _ => "waitFor pattern must be a string or RegExp",
                            },
                        ))
                    }
                };
                let timeout_ms = args.timeout(1, 30_000);
                self.wait_for_pattern(name, pattern, timeout_ms).await
            }
            "screen.waitForPrompt" => {
                let timeout_ms = args.timeout(0, 60_000);
                self.wait_for_prompt(timeout_ms).await
            }
            "screen.waitForAny" => {
                let patterns = match args.get(0) {
                    Some(Value::Array(items)) if !items.is_empty() => items
                        .iter()
                        .map(|item| {
                            WaitPattern::from_json(item).ok_or_else(|| {
                                js_error("TypeError", "waitFor pattern must be a string or RegExp")
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => {
                        return Err(js_error(
                            "TypeError",
                            "waitForAny requires a non-empty patterns array",
                        ))
                    }
                };
                let timeout_ms = args.timeout(1, 30_000);
                self.wait_for_any(patterns, timeout_ms).await
            }
            "screen.getText" => {
                let snapshot = self.refresh_screen_snapshot().await?;
                self.assert_not_aborted()?;
                let lines = &snapshot.lines;
                if lines.is_empty() {
                    return Ok(Some(Value::String(self.inner.host.output_buffer().text())));
                }
                let as_row = |value: Option<&Value>| value.and_then(|v| v.as_f64()).map(|n| n.trunc() as i64);
                let start = as_row(args.get(0)).map_or(0, |n| n.max(0));
                let end = as_row(args.get(1)).map_or(lines.len() as i64 - 1, |n| {
                    n.min(lines.len() as i64 - 1)
                });
                let start = (start as usize).min(lines.len());
                let end_exclusive = if end < 0 { 0 } else { (end as usize + 1).min(lines.len()) };
                let text = if end_exclusive > start {
                    lines[start..end_exclusive].join("\n")
                } else {
                    String::new()
                };
                Ok(Some(Value::String(text)))
            }
            "screen.clear" => {
                let result = async {
                    if self.is_execution_aborted() {
                        return Ok(());
                    }
                    self.assert_write_allowed("screen.clear")?;
                    self.track_step("clear")?;
                    if self.is_execution_aborted() {
                        return Ok(());
                    }
                    self.inner.host.write_to_session(
                        "\x1b[2J\x1b[H",
                        &WriteOptions {
                            automated: true,
                            sensitive: false,
                            invalidate_startup_seed: true,
                        },
                    );
                    Ok(())
                }
                .await;
                self.ignore_if_stopped(result)
            }
            "dialog.alert" => {
                self.show_dialog("alert", args.string(0), None, serde_json::Map::new())
                    .await
            }
            "dialog.confirm" => {
                self.show_dialog("confirm", args.string(0), None, serde_json::Map::new())
                    .await
            }
            "dialog.prompt" => {
                let mut extras = serde_json::Map::new();
                extras.insert("sensitive".into(), Value::Bool(args.sensitive_option(2)));
                self.show_dialog("prompt", args.string(0), Some(args.string(1)), extras)
                    .await
            }
            "dialog.form" => self.dialog_form(args.get(0)).await,
            "dialog.select" | "dialog.radio" => {
                let field_type = &method["dialog.".len()..];
                let mut extra = serde_json::Map::new();
                if let Some(options) = args.get(1) {
                    extra.insert("options".into(), options.clone());
                }
                if let Some(default_value) = args.get(2) {
                    extra.insert("defaultValue".into(), default_value.clone());
                }
                let value = self
                    .dialog_single_field(field_type, args.get(0), Value::Object(extra))
                    .await?;
                let text = match value {
                    None | Some(Value::Null) => String::new(),
                    Some(v) => js_string(&v),
                };
                Ok(Some(Value::String(text)))
            }
            "dialog.checkbox" => {
                let mut extra = serde_json::Map::new();
                extra.insert(
                    "defaultValue".into(),
                    args.get(1).cloned().unwrap_or(Value::Bool(false)),
                );
                let value = self
                    .dialog_single_field("checkbox", args.get(0), Value::Object(extra))
                    .await?;
                Ok(Some(Value::Bool(value.as_ref().is_some_and(js_truthy))))
            }
            other => Err(plain_error(format!("Unsupported script API method: {other}"))),
        }
    }

    /// `nct.log` (host side): a step plus a log line.
    fn log(&self, message: &str) {
        if self.is_execution_aborted() {
            return;
        }
        self.inner.state.lock().step_index += 1;
        self.emit_status(StatusPatch {
            activity_label: Some(Some("log".into())),
            current_step: Some(Some("log".into())),
            ..Default::default()
        });
        self.inner.host.append_log(message);
    }

    fn progress_start(&self, label: Option<&Value>, total: Option<&Value>) {
        let label = match label {
            None | Some(Value::Null) => String::new(),
            Some(v) => js_string(v),
        };
        let label = truncate_activity_label(
            if label.is_empty() { "Progress" } else { &label },
            60,
        );
        let total = total
            .and_then(js_number)
            .filter(|n| n.is_finite() && *n != 0.0)
            .unwrap_or(1.0)
            .max(1.0);
        {
            let mut state = self.inner.state.lock();
            state.progress_mode = ProgressMode::Determinate;
            state.progress_label = Some(label.clone());
            state.progress_total = total;
            state.progress_current = 0.0;
        }
        self.emit_status(StatusPatch {
            progress_mode: Some(ProgressMode::Determinate),
            progress_label: Some(Some(label.clone())),
            progress_current: Some(Some(0.0)),
            progress_total: Some(Some(total)),
            activity_label: Some(Some(label)),
            ..Default::default()
        });
    }

    fn progress_update(&self, current: Option<f64>, detail: Option<&Value>) {
        let (progress_current, progress_total, progress_label) = {
            let mut state = self.inner.state.lock();
            if state.progress_mode != ProgressMode::Determinate {
                return;
            }
            state.progress_current = match current {
                Some(value) => value.max(0.0).min(state.progress_total),
                None => (state.progress_current + 1.0).min(state.progress_total),
            };
            (
                state.progress_current,
                state.progress_total,
                state.progress_label.clone(),
            )
        };
        let mut patch = StatusPatch {
            progress_current: Some(Some(progress_current)),
            progress_total: Some(Some(progress_total)),
            progress_label: Some(progress_label),
            ..Default::default()
        };
        if let Some(detail) = detail {
            let text = js_string(detail);
            if !matches!(detail, Value::Null) && !text.is_empty() {
                patch.activity_label = Some(Some(truncate_activity_label(&text, 80)));
            }
        }
        self.emit_status(patch);
    }

    fn progress_done(&self) {
        let (current, total, label) = {
            let mut state = self.inner.state.lock();
            if state.progress_mode != ProgressMode::Determinate {
                return;
            }
            state.progress_current = state.progress_total;
            (
                state.progress_current,
                state.progress_total,
                state.progress_label.clone(),
            )
        };
        self.emit_status(StatusPatch {
            progress_current: Some(Some(current)),
            progress_total: Some(Some(total)),
            progress_label: Some(label),
            ..Default::default()
        });
        {
            let mut state = self.inner.state.lock();
            state.progress_mode = ProgressMode::Activity;
            state.progress_label = None;
            state.progress_current = 0.0;
            state.progress_total = 0.0;
        }
        self.emit_status(StatusPatch {
            progress_mode: Some(ProgressMode::Activity),
            progress_label: Some(None),
            progress_current: Some(None),
            progress_total: Some(None),
            ..Default::default()
        });
    }

    /// `handleWorkerNotification`.
    fn handle_notification(&self, method: &str, args: &[Value]) -> Result<(), ScriptError> {
        let args = Args::new(args.to_vec());
        match method {
            "log" => {
                self.log(&args.string(0));
                Ok(())
            }
            "console.log" => {
                self.inner.host.append_log(&args.string(0));
                Ok(())
            }
            "progress.start" => {
                self.progress_start(args.get(0), args.get(1));
                Ok(())
            }
            "progress.set" => {
                let current = Some(
                    args.get(0)
                        .and_then(js_number)
                        .filter(|n| n.is_finite())
                        .unwrap_or(0.0),
                );
                self.progress_update(current, args.get(1));
                Ok(())
            }
            "progress.step" => {
                self.progress_update(None, args.get(0));
                Ok(())
            }
            "progress.done" => {
                self.progress_done();
                Ok(())
            }
            other => Err(plain_error(format!("Unsupported script notification: {other}"))),
        }
    }

    /// `readRuntimeSnapshot(nct)`.
    pub fn snapshot(&self) -> RuntimeSnapshot {
        let session = self.inner.host.session_meta();
        let screen = {
            let state = self.inner.state.lock();
            let s = &state.screen_snapshot;
            ScreenSnapshotMeta {
                current_row: s.current_row,
                rows: if s.rows == 0 { 24 } else { s.rows },
                cols: if s.cols == 0 { 80 } else { s.cols },
            }
        };
        RuntimeSnapshot { session, screen }
    }

    /// Run `source` to completion (the host half of `executeInScriptWorker`).
    pub async fn execute(&self, source: &str) -> Result<(), ScriptError> {
        self.assert_not_aborted()?;
        let wrapped = wrap_script_source(source).map_err(plain_error)?;
        let config = EngineConfig {
            source: wrapped,
            filename: format!("script-{}.js", self.inner.options.run_id),
            version: self.inner.options.app_version.clone(),
            snapshot: self.snapshot(),
            limits: self.inner.options.limits.clone(),
        };
        let (events_tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let engine = Arc::new(spawn_engine(config, events_tx));
        *self.inner.engine.lock() = Some(engine.clone());
        if let Some(reason) = self.inner.stop_reason.lock().clone() {
            // Stopped before the worker came up.
            engine.stop();
            return Err(plain_error(reason));
        }

        let mut tasks = tokio::task::JoinSet::new();
        let mut pending_requests = 0usize;
        let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let max_pending = self.inner.options.limits.max_pending_host_requests;

        // Progress coalescing (`handleProgressNotification`).
        let mut progress_notifications = 0usize;
        let mut progress_current = 0.0f64;
        let mut progress_total = 1.0f64;
        let mut pending_progress: Option<(String, Vec<Value>)> = None;
        let mut progress_flush_at: Option<Instant> = None;

        let mut watchdog = tokio::time::interval(WATCHDOG_TICK);
        watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let outcome: Result<(), ScriptError> = loop {
            let flush_sleep = async {
                match progress_flush_at {
                    Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                event = events.recv() => match event {
                    Some(EngineEvent::Rpc { request_id, method, args }) => {
                        if pending_requests >= max_pending {
                            break Err(plain_error(format!(
                                "Script exceeded the {max_pending} pending host request limit"
                            )));
                        }
                        pending_requests += 1;
                        let runtime = self.clone();
                        let engine = engine.clone();
                        let done = done_tx.clone();
                        tasks.spawn(async move {
                            let result = runtime.invoke_rpc(&method, Args::new(args)).await;
                            if !runtime.inner.closed.load(Ordering::SeqCst) {
                                engine.send(EngineInbound::RpcResult {
                                    request_id,
                                    result,
                                    snapshot: runtime.snapshot(),
                                });
                            }
                            let _ = done.send(());
                        });
                    }
                    Some(EngineEvent::Notify { method, args }) => {
                        let handled: Result<(), ScriptError> = (|| {
                            if method == "log" || method == "console.log" {
                                if let Some((m, a)) = pending_progress.take() {
                                    progress_flush_at = None;
                                    self.handle_notification(&m, &a)?;
                                }
                                return self.handle_notification(&method, &args);
                            }
                            if let Some(name) = method.strip_prefix("progress.") {
                                match name {
                                    "start" => {
                                        if let Some((m, a)) = pending_progress.take() {
                                            progress_flush_at = None;
                                            self.handle_notification(&m, &a)?;
                                        }
                                        progress_current = 0.0;
                                        progress_total = args
                                            .get(1)
                                            .and_then(js_number)
                                            .filter(|n| n.is_finite() && *n != 0.0)
                                            .unwrap_or(1.0)
                                            .max(1.0);
                                    }
                                    "set" => {
                                        let current = args
                                            .get(0)
                                            .and_then(js_number)
                                            .filter(|n| n.is_finite())
                                            .unwrap_or(0.0);
                                        progress_current = current.max(0.0).min(progress_total);
                                    }
                                    "step" => {
                                        progress_current = (progress_current + 1.0).min(progress_total);
                                    }
                                    "done" => {
                                        if let Some((m, a)) = pending_progress.take() {
                                            progress_flush_at = None;
                                            self.handle_notification(&m, &a)?;
                                        }
                                    }
                                    _ => {}
                                }
                                progress_notifications += 1;
                                if progress_notifications <= SCRIPT_WORKER_IMMEDIATE_PROGRESS_NOTIFICATIONS
                                    || name == "start"
                                    || name == "done"
                                {
                                    return self.handle_notification(&method, &args);
                                }
                                let detail = args.get(1).or(args.get(0)).cloned().unwrap_or(Value::Null);
                                pending_progress = Some((
                                    "progress.set".into(),
                                    vec![json!(progress_current), detail],
                                ));
                                if progress_flush_at.is_none() {
                                    progress_flush_at = Some(
                                        Instant::now()
                                            + Duration::from_millis(SCRIPT_WORKER_PROGRESS_THROTTLE_MS),
                                    );
                                }
                                return Ok(());
                            }
                            if let Some((m, a)) = pending_progress.take() {
                                progress_flush_at = None;
                                self.handle_notification(&m, &a)?;
                            }
                            self.handle_notification(&method, &args)
                        })();
                        if let Err(err) = handled {
                            break Err(err);
                        }
                    }
                    Some(EngineEvent::Completed) => {
                        if let Some((m, a)) = pending_progress.take() {
                            if let Err(err) = self.handle_notification(&m, &a) {
                                break Err(err);
                            }
                        }
                        break Ok(());
                    }
                    Some(EngineEvent::Failed(error)) => break Err(error),
                    None => break Err(plain_error("Script worker exited before completion")),
                },
                Some(()) = done_rx.recv() => {
                    pending_requests = pending_requests.saturating_sub(1);
                }
                _ = flush_sleep => {
                    progress_flush_at = None;
                    if let Some((m, a)) = pending_progress.take() {
                        if let Err(err) = self.handle_notification(&m, &a) {
                            break Err(err);
                        }
                    }
                }
                _ = watchdog.tick() => {
                    if self.is_execution_aborted() {
                        let reason = self
                            .inner
                            .stop_reason
                            .lock()
                            .clone()
                            .unwrap_or_else(|| SCRIPT_STOPPED.to_string());
                        break Err(plain_error(reason));
                    }
                    engine.send(EngineInbound::Snapshot(self.snapshot()));
                }
                _ = self.inner.stop_signal.notified() => {
                    let reason = self
                        .inner
                        .stop_reason
                        .lock()
                        .clone()
                        .unwrap_or_else(|| SCRIPT_STOPPED.to_string());
                    break Err(plain_error(reason));
                }
            }
        };

        // Teardown: close the execution token, terminate the worker and let
        // in-flight host requests observe the closed token.
        self.inner.closed.store(true, Ordering::SeqCst);
        engine.stop();
        tasks.shutdown().await;
        *self.inner.engine.lock() = None;
        if let Ok(engine) = Arc::try_unwrap(engine) {
            let _ = tokio::task::spawn_blocking(move || engine.join()).await;
        }
        drop(events);
        outcome?;
        self.assert_not_aborted()
    }

    pub fn step_index(&self) -> u64 {
        self.inner.state.lock().step_index
    }
}

/// Result of a wait: a matched string, a found index, or the `skip`
/// placeholder of either kind.
#[derive(Debug, Clone)]
enum SkipValue {
    Text,
    Index,
    Matched(String),
    Found(usize),
}

impl SkipValue {
    fn into_json(self) -> Value {
        match self {
            SkipValue::Text => Value::String(String::new()),
            SkipValue::Index => json!(-1),
            SkipValue::Matched(text) => Value::String(text),
            SkipValue::Found(index) => json!(index),
        }
    }
}

/// Shared defaults for the `elapsedMs` the status patches carried in
/// Electron (the manager recomputes it from `startedAt`).
pub fn elapsed_ms(started_at: i64) -> i64 {
    (now_ms() - started_at).max(0)
}
