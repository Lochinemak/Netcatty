//! Run bookkeeping and the IPC handlers of `electron/bridges/scriptBridge.cjs`:
//! `run` / `stop` / `pause` / `resume` / `getRuns`, dialog and screen
//! snapshot round trips, the per-session run queue, script session logs and
//! recordings.
//!
//! The manager is independent of Tauri: everything it needs from the app
//! (session writes, events, session metadata, log streams) goes through
//! [`ManagerHost`], so the bridge tests run against a fake session.

use crate::buffer::{strip_trailing_blank_lines, BufferRegistry, OutputBuffer};
use crate::codegen::steps_to_javascript;
use crate::dialog::default_dialog_value;
use crate::engine::{EngineLimits, ScriptError, SessionSnapshot};
use crate::retention::{
    append_retained_run_log, prune_completed_runs, MAX_RETAINED_COMPLETED_RUNS,
    MAX_RETAINED_LOGS_PER_RUN,
};
use crate::run::{now_ms, RunLogEntry, RunStatus, ScriptRun, SerializedRun, StatusPatch};
use crate::runtime::{
    DialogRequest, PermissionMode, RuntimeHost, RuntimeOptions, ScreenSnapshot, ScriptRuntime,
    WriteOptions,
};
use crate::source::seed_buffer_from_screen;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

pub const MAX_SCRIPT_RECORDING_STEPS: usize = 10_000;
pub const MAX_SCRIPT_RECORDING_BYTES: usize = 2 * 1024 * 1024;
pub const SCRIPT_RECORDING_LIMIT_ERROR: &str =
    "Recording stopped because it reached the safety limit";
pub const DIALOG_TIMEOUT: Duration = Duration::from_secs(120);
pub const SCREEN_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(3);

/// Event channel names (Electron's).
pub mod events {
    pub const RUNS_UPDATED: &str = "netcatty:script:runs-updated";
    pub const DIALOG_REQUEST: &str = "netcatty:script:dialog-request";
    pub const SCREEN_SNAPSHOT_REQUEST: &str = "netcatty:script:screen-snapshot-request";
    pub const SESSION_INPUT: &str = "netcatty:script:session-input";
}

/// What the app knows about a live terminal session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostSessionInfo {
    pub label: String,
    pub hostname: String,
    pub username: String,
}

/// The app side of the manager.
pub trait ManagerHost: Send + Sync + 'static {
    /// Write automated input to a session (in order).
    fn write_to_session(&self, session_id: &str, data: &str, automated: bool, sensitive: bool);
    /// Close a session (`nct.session.disconnect()`).
    fn close_session(&self, session_id: &str);
    /// Emit a renderer event.
    fn emit(&self, event: &str, payload: Value);
    /// Is there a renderer to show dialogs / answer snapshots
    /// (Electron: `getMainWindow()?.webContents`)?
    fn has_renderer(&self) -> bool;
    /// A live session of the session registry.
    fn session_info(&self, session_id: &str) -> Option<HostSessionInfo>;
    /// Start a raw log stream of the session into `file_path`; returns an
    /// opaque token for [`ManagerHost::stop_session_log`].
    fn start_session_log(&self, session_id: &str, file_path: PathBuf, host_label: &str)
        -> Result<u64, String>;
    /// Stop the stream started with `token` (blocking is fine).
    fn stop_session_log(&self, session_id: &str, token: u64);
    /// Directory for `session.startLog()` without a path (Electron:
    /// `app.getPath("documents")`).
    fn default_log_dir(&self) -> PathBuf;
    fn app_version(&self) -> String;
}

/// `ScriptRunParams`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunParams {
    #[serde(default)]
    pub run_id: Option<Value>,
    #[serde(default)]
    pub return_when_queued: bool,
    #[serde(default)]
    pub script_id: Option<String>,
    #[serde(default)]
    pub script_label: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub session_ids: Option<Vec<String>>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub permission_mode: Option<String>,
    #[serde(default)]
    pub session_meta: Option<RendererSessionMeta>,
}

/// `sessionMeta` sent by the renderer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RendererSessionMeta {
    #[serde(default)]
    pub connected: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

impl RendererSessionMeta {
    fn merge(&mut self, other: RendererSessionMeta) {
        if other.connected.is_some() {
            self.connected = other.connected;
        }
        if other.name.is_some() {
            self.name = other.name;
        }
        if other.hostname.is_some() {
            self.hostname = other.hostname;
        }
        if other.username.is_some() {
            self.username = other.username;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunResult {
    pub run_ids: Vec<String>,
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OkResult {
    pub ok: bool,
}

/// `scriptRecordingStop` result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RecordingResult {
    pub steps: Vec<Value>,
    pub code: String,
}

/// `scriptRecordingAppendStep` result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AppendStepResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steps: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl AppendStepResult {
    fn ok() -> Self {
        Self {
            ok: true,
            stopped: None,
            reason: None,
            error: None,
            steps: None,
            code: None,
        }
    }

    fn error(message: &str) -> Self {
        Self {
            ok: false,
            error: Some(message.to_string()),
            ..Self::ok()
        }
    }
}

struct Recording {
    started_at: i64,
    steps: Vec<Value>,
    total_bytes: usize,
    last_timestamp: i64,
}

struct PendingDialog {
    dialog_type: String,
    run_id: String,
    tx: oneshot::Sender<Result<Option<Value>, String>>,
}

struct PendingSnapshot {
    session_id: String,
    run_id: String,
    tx: oneshot::Sender<Result<ScreenSnapshot, String>>,
}

struct RunControl {
    runtime: Option<ScriptRuntime>,
    cancel: CancellationToken,
}

#[derive(Default)]
struct State {
    runs: HashMap<String, ScriptRun>,
    /// Creation order of runs (Electron serializes in `Map` order).
    run_order: HashMap<String, u64>,
    next_order: u64,
    recordings: HashMap<String, Recording>,
    pending_dialogs: HashMap<String, PendingDialog>,
    pending_snapshots: HashMap<String, PendingSnapshot>,
    /// sessionId → (runId, log token).
    script_log_tokens: HashMap<String, (String, u64)>,
    queued_runs: HashSet<String>,
    cancelled_queued_runs: HashSet<String>,
    run_controls: HashMap<String, RunControl>,
    renderer_meta: HashMap<String, RendererSessionMeta>,
    /// Per-session run chain (Electron's `sessionRunChains`): the receiver
    /// completes when the last queued run of the session has finished.
    session_tails: HashMap<String, (u64, oneshot::Receiver<()>)>,
    next_chain_id: u64,
}

pub(crate) struct Inner<H: ManagerHost> {
    host: H,
    state: Mutex<State>,
    buffers: BufferRegistry,
    limits: Mutex<EngineLimits>,
}

/// The script automation service (one per app).
pub struct ScriptManager<H: ManagerHost> {
    inner: Arc<Inner<H>>,
}

impl<H: ManagerHost> Clone for ScriptManager<H> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

fn new_request_id() -> String {
    netcatty_core::new_id()
}

/// `new Date(ms).toISOString()`.
fn iso_string(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

impl<H: ManagerHost> ScriptManager<H> {
    pub fn new(host: H) -> Self {
        Self {
            inner: Arc::new(Inner {
                host,
                state: Mutex::new(State::default()),
                buffers: BufferRegistry::new(),
                limits: Mutex::new(EngineLimits::default()),
            }),
        }
    }

    pub fn host(&self) -> &H {
        &self.inner.host
    }

    /// Override the engine limits (tests use short sync timeouts).
    pub fn set_engine_limits(&self, limits: EngineLimits) {
        *self.inner.limits.lock() = limits;
    }

    // -----------------------------------------------------------------
    // Session hooks
    // -----------------------------------------------------------------

    /// Session output tap (`appendSessionOutput`).
    pub fn append_session_output(&self, session_id: &str, data: &str) {
        self.inner.buffers.append(session_id, data);
    }

    /// The session ended (`releaseSessionResources`).
    pub fn session_closed(&self, session_id: &str) {
        self.inner.buffers.remove(session_id);
        let mut state = self.inner.state.lock();
        state.renderer_meta.remove(session_id);
        state.recordings.remove(session_id);
    }

    pub fn buffer(&self, session_id: &str) -> OutputBuffer {
        self.inner.buffers.get_or_create(session_id)
    }

    pub fn has_buffer(&self, session_id: &str) -> bool {
        self.inner.buffers.contains(session_id)
    }

    pub fn remove_buffer(&self, session_id: &str) {
        self.inner.buffers.remove(session_id);
    }

    // -----------------------------------------------------------------
    // Runs
    // -----------------------------------------------------------------

    fn serialized_runs(&self) -> Vec<SerializedRun> {
        let state = self.inner.state.lock();
        let now = now_ms();
        let mut runs: Vec<(&u64, &ScriptRun)> = state
            .runs
            .values()
            .map(|run| (state.run_order.get(&run.run_id).unwrap_or(&0), run))
            .collect();
        runs.sort_by_key(|(order, _)| **order);
        runs.into_iter().map(|(_, run)| run.serialize(now)).collect()
    }

    fn broadcast_runs(&self) {
        if !self.inner.host.has_renderer() {
            return;
        }
        let runs = self.serialized_runs();
        self.inner
            .host
            .emit(events::RUNS_UPDATED, json!({ "runs": runs }));
    }

    /// `scriptGetRuns`.
    pub fn get_runs(&self, session_id: Option<&str>) -> Vec<SerializedRun> {
        let all = self.serialized_runs();
        match session_id.filter(|s| !s.is_empty()) {
            Some(sid) => all.into_iter().filter(|r| r.session_id == sid).collect(),
            None => all,
        }
    }

    /// `scriptRun`.
    pub async fn run(&self, params: RunParams) -> Result<RunResult, String> {
        let targets: Vec<String> = match &params.session_ids {
            Some(ids) if !ids.is_empty() => ids.clone(),
            _ => params
                .session_id
                .clone()
                .filter(|s| !s.is_empty())
                .into_iter()
                .collect(),
        };
        if targets.is_empty() {
            return Err("No target session for script run".into());
        }
        let content = params.content.clone().unwrap_or_default();
        if content.trim().is_empty() {
            return Err("Script content is empty".into());
        }
        let requested_run_id = params.run_id.as_ref().filter(|v| !v.is_null());
        if requested_run_id.is_some() && targets.len() != 1 {
            return Err("A caller-provided runId requires exactly one target session".into());
        }
        if params.return_when_queued && targets.len() != 1 {
            return Err("returnWhenQueued requires exactly one target session".into());
        }
        let permission_mode = PermissionMode::parse(params.permission_mode.as_deref());

        let mut run_ids = Vec::new();
        let mut queued = Vec::new();
        for sid in &targets {
            let run_id = match requested_run_id {
                None => netcatty_core::new_id(),
                Some(value) => crate::dialog::js_string(value).trim().to_string(),
            };
            if run_id.is_empty() || run_id.chars().count() > 128 {
                return Err("Invalid script run id".into());
            }
            {
                let mut state = self.inner.state.lock();
                if state.runs.contains_key(&run_id) || state.queued_runs.contains(&run_id) {
                    return Err(format!("Script run id already exists: {run_id}"));
                }
                state.queued_runs.insert(run_id.clone());
            }
            run_ids.push(run_id.clone());
            queued.push((sid.clone(), run_id));
        }

        let spawn_queued = |sid: String, run_id: String| {
            let manager = self.clone();
            let params = params.clone();
            let content = content.clone();
            // Join the session chain synchronously so runs start in call order.
            let (previous, done, chain_id) = self.enqueue_session_run(&sid);
            tokio::spawn(async move {
                if let Some(previous) = previous {
                    let _ = previous.await;
                }
                manager
                    .run_queued(sid.clone(), run_id, params, content, permission_mode)
                    .await;
                drop(done);
                manager.release_session_chain(&sid, chain_id);
            })
        };

        if params.return_when_queued {
            let (sid, run_id) = queued.remove(0);
            let _ = spawn_queued(sid, run_id);
            return Ok(RunResult {
                run_id: run_ids.first().cloned(),
                run_ids,
            });
        }

        if params.mode.as_deref() == Some("sequential") {
            for (sid, run_id) in queued {
                let _ = spawn_queued(sid, run_id).await;
            }
        } else {
            let handles: Vec<_> = queued
                .into_iter()
                .map(|(sid, run_id)| spawn_queued(sid, run_id))
                .collect();
            for handle in handles {
                let _ = handle.await;
            }
        }
        Ok(RunResult {
            run_id: run_ids.first().cloned(),
            run_ids,
        })
    }

    fn enqueue_session_run(
        &self,
        session_id: &str,
    ) -> (Option<oneshot::Receiver<()>>, oneshot::Sender<()>, u64) {
        let mut state = self.inner.state.lock();
        let (tx, rx) = oneshot::channel();
        state.next_chain_id += 1;
        let chain_id = state.next_chain_id;
        let previous = state
            .session_tails
            .insert(session_id.to_string(), (chain_id, rx))
            .map(|(_, rx)| rx);
        (previous, tx, chain_id)
    }

    fn release_session_chain(&self, session_id: &str, chain_id: u64) {
        let mut state = self.inner.state.lock();
        if state
            .session_tails
            .get(session_id)
            .is_some_and(|(id, _)| *id == chain_id)
        {
            state.session_tails.remove(session_id);
        }
    }

    async fn run_queued(
        &self,
        session_id: String,
        run_id: String,
        params: RunParams,
        content: String,
        permission_mode: PermissionMode,
    ) {
        {
            let mut state = self.inner.state.lock();
            state.queued_runs.remove(&run_id);
            if state.cancelled_queued_runs.remove(&run_id) {
                return;
            }
        }
        self.run_script_on_session(
            &run_id,
            params.script_id.clone(),
            params.script_label.clone(),
            &session_id,
            &content,
            permission_mode,
            params.session_meta.clone(),
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_script_on_session(
        &self,
        run_id: &str,
        script_id: Option<String>,
        script_label: Option<String>,
        session_id: &str,
        content: &str,
        permission_mode: PermissionMode,
        session_meta: Option<RendererSessionMeta>,
    ) {
        if let Some(meta) = session_meta {
            self.remember_renderer_meta(session_id, meta);
        }
        let started_at = now_ms();
        let cancel = CancellationToken::new();
        {
            let mut state = self.inner.state.lock();
            let order = state.next_order;
            state.next_order += 1;
            state.run_order.insert(run_id.to_string(), order);
            state.runs.insert(
                run_id.to_string(),
                ScriptRun::new(run_id, script_id, script_label, session_id, started_at),
            );
            state.run_controls.insert(
                run_id.to_string(),
                RunControl {
                    runtime: None,
                    cancel: cancel.clone(),
                },
            );
        }
        self.broadcast_runs();

        let host = Arc::new(RunHost {
            manager: self.clone(),
            run_id: run_id.to_string(),
            session_id: session_id.to_string(),
        });
        let runtime = ScriptRuntime::new(
            host,
            RuntimeOptions {
                session_id: session_id.to_string(),
                run_id: run_id.to_string(),
                app_version: self.inner.host.app_version(),
                permission_mode,
                started_at,
                limits: self.inner.limits.lock().clone(),
            },
        );
        if let Some(control) = self.inner.state.lock().run_controls.get_mut(run_id) {
            control.runtime = Some(runtime.clone());
        }

        let operation = async {
            self.sync_output_buffer_from_snapshot(session_id, run_id).await;
            runtime.execute(content).await
        };
        // Biased: a stop settles the run with its reason even when the
        // operation fails at the same moment (Electron's `Promise.race` sees
        // the abort first because `handleScriptStop` rejects synchronously).
        let outcome: Result<(), ScriptError> = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ScriptError::new(
                self.run_error(run_id).unwrap_or_else(|| "Script stopped".into()),
            )),
            result = operation => result,
        };
        // The runtime may still be tearing down its worker after a stop.
        runtime.stop("Script stopped");

        let aborted = {
            let mut state = self.inner.state.lock();
            let mut aborted = false;
            if let Some(run) = state.runs.get_mut(run_id) {
                aborted = run.aborted;
                match &outcome {
                    Ok(()) => {
                        if run.aborted {
                            run.status = RunStatus::Failed;
                            if run.error.is_none() {
                                run.error = Some("Stopped by user".into());
                            }
                        } else {
                            run.status = RunStatus::Completed;
                        }
                        run.ended_at = Some(now_ms());
                        run.clear_progress();
                    }
                    Err(err) => {
                        run.status = RunStatus::Failed;
                        run.ended_at = Some(now_ms());
                        run.clear_progress();
                        run.error = Some(err.message.clone());
                        append_retained_run_log(
                            run,
                            RunLogEntry {
                                at: now_ms(),
                                message: err.message.clone(),
                            },
                            MAX_RETAINED_LOGS_PER_RUN,
                        );
                    }
                }
            }
            aborted
        };
        self.settle_pending_run_requests(run_id, aborted, "Stopped by user");
        self.stop_script_session_log(session_id, Some(run_id)).await;
        {
            let mut state = self.inner.state.lock();
            state.run_controls.remove(run_id);
            prune_completed_runs(&mut state.runs, MAX_RETAINED_COMPLETED_RUNS);
            let live: HashSet<String> = state.runs.keys().cloned().collect();
            state.run_order.retain(|id, _| live.contains(id));
        }
        self.broadcast_runs();
    }

    fn run_error(&self, run_id: &str) -> Option<String> {
        self.inner
            .state
            .lock()
            .runs
            .get(run_id)
            .and_then(|r| r.error.clone())
    }

    /// `scriptStop`.
    pub fn stop(&self, run_id: &str) -> OkResult {
        let (session_id, control) = {
            let mut state = self.inner.state.lock();
            let Some(run) = state.runs.get_mut(run_id) else {
                if state.queued_runs.contains(run_id) {
                    state.cancelled_queued_runs.insert(run_id.to_string());
                    return OkResult { ok: true };
                }
                return OkResult { ok: false };
            };
            run.aborted = true;
            run.paused = false;
            run.status = RunStatus::Failed;
            run.error = Some("Stopped by user".into());
            run.ended_at = Some(now_ms());
            run.waiting_for = None;
            let session_id = run.session_id.clone();
            let control = state
                .run_controls
                .get(run_id)
                .map(|c| (c.runtime.clone(), c.cancel.clone()));
            (session_id, control)
        };
        // Cancel first: settling the pending requests below wakes the run,
        // which must already see the stop.
        if let Some((runtime, cancel)) = control {
            cancel.cancel();
            if let Some(runtime) = runtime {
                runtime.stop("Stopped by user");
            }
        }
        if let Some(buffer) = self.inner.buffers.get(&session_id) {
            buffer.abort_waiters("Stopped by user");
        }
        self.settle_pending_run_requests(run_id, false, "Stopped by user");
        self.broadcast_runs();
        OkResult { ok: true }
    }

    /// `scriptPause`.
    pub fn pause(&self, run_id: &str) -> OkResult {
        {
            let mut state = self.inner.state.lock();
            let Some(run) = state.runs.get_mut(run_id) else {
                return OkResult { ok: false };
            };
            run.paused = true;
            run.status = RunStatus::Paused;
        }
        self.broadcast_runs();
        OkResult { ok: true }
    }

    /// `scriptResume`.
    pub fn resume(&self, run_id: &str) -> OkResult {
        {
            let mut state = self.inner.state.lock();
            let Some(run) = state.runs.get_mut(run_id) else {
                return OkResult { ok: false };
            };
            run.paused = false;
            run.status = RunStatus::Running;
        }
        self.broadcast_runs();
        OkResult { ok: true }
    }

    fn settle_pending_run_requests(&self, run_id: &str, reject: bool, reason: &str) {
        let (snapshots, dialogs) = {
            let mut state = self.inner.state.lock();
            let snapshot_ids: Vec<String> = state
                .pending_snapshots
                .iter()
                .filter(|(_, p)| p.run_id == run_id)
                .map(|(id, _)| id.clone())
                .collect();
            let dialog_ids: Vec<String> = state
                .pending_dialogs
                .iter()
                .filter(|(_, p)| p.run_id == run_id)
                .map(|(id, _)| id.clone())
                .collect();
            let snapshots: Vec<PendingSnapshot> = snapshot_ids
                .iter()
                .filter_map(|id| state.pending_snapshots.remove(id))
                .collect();
            let dialogs: Vec<PendingDialog> = dialog_ids
                .iter()
                .filter_map(|id| state.pending_dialogs.remove(id))
                .collect();
            (snapshots, dialogs)
        };
        for pending in snapshots {
            let value = if reject {
                Err(reason.to_string())
            } else {
                Ok(self.buffer_fallback_snapshot(&pending.session_id))
            };
            let _ = pending.tx.send(value);
        }
        for pending in dialogs {
            let value = if reject {
                Err(reason.to_string())
            } else {
                Ok(Some(default_dialog_value(&pending.dialog_type)).filter(|v| !v.is_null()))
            };
            let _ = pending.tx.send(value);
        }
    }

    // -----------------------------------------------------------------
    // Session metadata / writes
    // -----------------------------------------------------------------

    fn remember_renderer_meta(&self, session_id: &str, meta: RendererSessionMeta) {
        self.inner
            .state
            .lock()
            .renderer_meta
            .entry(session_id.to_string())
            .or_default()
            .merge(meta);
    }

    fn has_active_output_buffer(&self, session_id: &str) -> bool {
        self.inner
            .buffers
            .get(session_id)
            .is_some_and(|b| !b.text().trim().is_empty())
    }

    /// `getSessionMeta`.
    pub fn session_meta(&self, session_id: &str) -> SessionSnapshot {
        let renderer = self
            .inner
            .state
            .lock()
            .renderer_meta
            .get(session_id)
            .cloned();
        let non_empty = |v: &Option<String>| v.clone().filter(|s| !s.is_empty());
        if let Some(info) = self.inner.host.session_info(session_id) {
            let renderer = renderer.unwrap_or_default();
            return SessionSnapshot {
                connected: true,
                name: non_empty(&renderer.name).unwrap_or(info.label),
                hostname: if info.hostname.is_empty() {
                    renderer.hostname.unwrap_or_default()
                } else {
                    info.hostname
                },
                username: if info.username.is_empty() {
                    renderer.username.unwrap_or_default()
                } else {
                    info.username
                },
            };
        }
        let connected = renderer.as_ref().and_then(|r| r.connected).unwrap_or(false)
            || self.has_active_output_buffer(session_id);
        if connected {
            let renderer = renderer.unwrap_or_default();
            return SessionSnapshot {
                connected: true,
                name: renderer.name.unwrap_or_default(),
                hostname: renderer.hostname.unwrap_or_default(),
                username: renderer.username.unwrap_or_default(),
            };
        }
        SessionSnapshot::default()
    }

    fn write_to_session(&self, session_id: &str, data: &str, options: &WriteOptions) {
        self.inner
            .host
            .write_to_session(session_id, data, options.automated, options.sensitive);
        // sendLine may emit body and CR as two writes: only the final write
        // invalidates the startup seed (#1960).
        if options.automated && !data.is_empty() && data != "\x03" {
            if options.invalidate_startup_seed {
                self.buffer(session_id).invalidate_startup_seed();
            }
            self.inner.host.emit(
                events::SESSION_INPUT,
                json!({ "sessionId": session_id, "data": data }),
            );
        }
    }

    // -----------------------------------------------------------------
    // Screen snapshots
    // -----------------------------------------------------------------

    fn buffer_fallback_snapshot(&self, session_id: &str) -> ScreenSnapshot {
        ScreenSnapshot::buffer_fallback(&self.buffer(session_id).text())
    }

    /// `requestScreenSnapshot`: ask the renderer for the visible terminal
    /// screen; the buffer text after 3 s or without a renderer.
    pub async fn request_screen_snapshot(
        &self,
        session_id: &str,
        run_id: &str,
    ) -> Result<ScreenSnapshot, String> {
        if !self.inner.host.has_renderer() {
            return Ok(self.buffer_fallback_snapshot(session_id));
        }
        let request_id = new_request_id();
        let (tx, rx) = oneshot::channel();
        self.inner.state.lock().pending_snapshots.insert(
            request_id.clone(),
            PendingSnapshot {
                session_id: session_id.to_string(),
                run_id: run_id.to_string(),
                tx,
            },
        );
        self.inner.host.emit(
            events::SCREEN_SNAPSHOT_REQUEST,
            json!({ "requestId": request_id, "sessionId": session_id }),
        );
        match tokio::time::timeout(SCREEN_SNAPSHOT_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Ok(self.buffer_fallback_snapshot(session_id)),
            Err(_) => {
                self.inner.state.lock().pending_snapshots.remove(&request_id);
                Ok(self.buffer_fallback_snapshot(session_id))
            }
        }
    }

    /// `scriptScreenSnapshotResponse`.
    pub fn screen_snapshot_response(&self, request_id: &str, snapshot: Option<Value>) -> OkResult {
        let Some(pending) = self.inner.state.lock().pending_snapshots.remove(request_id) else {
            return OkResult { ok: false };
        };
        let snapshot = snapshot
            .filter(|v| !v.is_null())
            .and_then(|v| serde_json::from_value::<ScreenSnapshot>(v).ok())
            .unwrap_or_else(|| self.buffer_fallback_snapshot(&pending.session_id));
        let _ = pending.tx.send(Ok(snapshot));
        OkResult { ok: true }
    }

    /// `syncOutputBufferFromSnapshot`: seed the buffer with the screen that
    /// is visible when the script starts (#1821, #1960).
    async fn sync_output_buffer_from_snapshot(&self, session_id: &str, run_id: &str) {
        let buffer = self.buffer(session_id);
        let sync_start_text = buffer.text();
        let is_aborted = || {
            self.inner
                .state
                .lock()
                .runs
                .get(run_id)
                .is_none_or(|r| r.aborted)
        };
        match self.request_screen_snapshot(session_id, run_id).await {
            Ok(snapshot) => {
                if is_aborted() {
                    return;
                }
                let screen_text = snapshot.lines.join("\n");
                if snapshot.is_viewport() && !strip_trailing_blank_lines(&screen_text).is_empty() {
                    seed_buffer_from_screen(&buffer, &screen_text, &sync_start_text);
                } else {
                    seed_buffer_from_screen(&buffer, &sync_start_text, &sync_start_text);
                }
            }
            Err(_) => {
                if is_aborted() {
                    return;
                }
                if !sync_start_text.is_empty() {
                    seed_buffer_from_screen(&buffer, "", &sync_start_text);
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Dialogs
    // -----------------------------------------------------------------

    /// `showDialog`.
    pub async fn show_dialog(
        &self,
        run_id: &str,
        request: DialogRequest,
    ) -> Result<Option<Value>, String> {
        if !self.inner.host.has_renderer() {
            return Ok(match request.dialog_type.as_str() {
                "prompt" => Some(Value::String(request.default_value.unwrap_or_default())),
                other => Some(default_dialog_value(other)).filter(|v| !v.is_null()),
            });
        }
        let request_id = new_request_id();
        let (tx, rx) = oneshot::channel();
        self.inner.state.lock().pending_dialogs.insert(
            request_id.clone(),
            PendingDialog {
                dialog_type: request.dialog_type.clone(),
                run_id: run_id.to_string(),
                tx,
            },
        );
        let mut payload = serde_json::Map::new();
        payload.insert("requestId".into(), Value::String(request_id.clone()));
        payload.insert("type".into(), Value::String(request.dialog_type.clone()));
        payload.insert("message".into(), Value::String(request.message.clone()));
        if let Some(default_value) = &request.default_value {
            payload.insert("defaultValue".into(), Value::String(default_value.clone()));
        }
        for (key, value) in request.extras {
            payload.insert(key, value);
        }
        self.inner
            .host
            .emit(events::DIALOG_REQUEST, Value::Object(payload));
        match tokio::time::timeout(DIALOG_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("Dialog cancelled".into()),
            Err(_) => {
                self.inner.state.lock().pending_dialogs.remove(&request_id);
                Err("Dialog timed out".into())
            }
        }
    }

    /// `scriptDialogResponse`.
    pub fn dialog_response(
        &self,
        request_id: &str,
        value: Option<Value>,
        cancelled: bool,
    ) -> OkResult {
        let Some(pending) = self.inner.state.lock().pending_dialogs.remove(request_id) else {
            return OkResult { ok: false };
        };
        if cancelled {
            let _ = pending.tx.send(Err("Dialog cancelled".into()));
            return OkResult { ok: true };
        }
        let resolved = match pending.dialog_type.as_str() {
            "confirm" => Some(Value::Bool(
                value.as_ref().is_some_and(crate::dialog::js_truthy),
            )),
            "prompt" => Some(match value {
                Some(Value::String(s)) => Value::String(s),
                _ => Value::String(String::new()),
            }),
            "form" => Some(match value {
                Some(v @ Value::Object(_)) | Some(v @ Value::Array(_)) => v,
                _ => json!({}),
            }),
            "waitForTimeout" => Some(match value {
                Some(Value::String(s)) => Value::String(s),
                _ => Value::String("abort".into()),
            }),
            _ => None,
        };
        let _ = pending.tx.send(Ok(resolved));
        OkResult { ok: true }
    }

    // -----------------------------------------------------------------
    // Script session logs
    // -----------------------------------------------------------------

    async fn start_script_session_log(
        &self,
        session_id: &str,
        run_id: &str,
        log_path: Option<String>,
    ) -> Result<(), String> {
        let file_path = match log_path.filter(|p| !p.is_empty()) {
            Some(path) => {
                let path = PathBuf::from(path);
                if path.is_absolute() {
                    path
                } else {
                    std::env::current_dir().unwrap_or_default().join(path)
                }
            }
            None => self
                .inner
                .host
                .default_log_dir()
                .join(format!("netcatty-script-{}.log", now_ms())),
        };
        let host_label = self
            .inner
            .host
            .session_info(session_id)
            .map(|info| {
                if info.hostname.is_empty() {
                    info.label
                } else {
                    info.hostname
                }
            })
            .filter(|label| !label.is_empty())
            .unwrap_or_else(|| "script".into());
        let token = self
            .inner
            .host
            .start_session_log(session_id, file_path, &host_label)
            .map_err(|err| {
                if err.is_empty() {
                    "Failed to start script log".to_string()
                } else {
                    err
                }
            })?;
        self.inner
            .state
            .lock()
            .script_log_tokens
            .insert(session_id.to_string(), (run_id.to_string(), token));
        Ok(())
    }

    async fn stop_script_session_log(&self, session_id: &str, run_id: Option<&str>) {
        let token = {
            let mut state = self.inner.state.lock();
            match state.script_log_tokens.get(session_id) {
                Some((owner, _)) if run_id.is_some_and(|r| r != owner) => return,
                Some(_) => state.script_log_tokens.remove(session_id).map(|(_, t)| t),
                None => None,
            }
        };
        if let Some(token) = token {
            let manager = self.clone();
            let session_id = session_id.to_string();
            let _ = tokio::task::spawn_blocking(move || {
                manager.inner.host.stop_session_log(&session_id, token);
            })
            .await;
        }
    }

    // -----------------------------------------------------------------
    // Recording
    // -----------------------------------------------------------------

    /// `scriptRecordingStart`.
    pub fn recording_start(&self, session_id: &str) -> Result<OkResult, String> {
        if session_id.is_empty() {
            return Err("sessionId required".into());
        }
        let now = now_ms();
        self.inner.state.lock().recordings.insert(
            session_id.to_string(),
            Recording {
                started_at: now,
                steps: Vec::new(),
                total_bytes: 0,
                last_timestamp: now,
            },
        );
        Ok(OkResult { ok: true })
    }

    /// `scriptRecordingStop`.
    pub fn recording_stop(&self, session_id: &str) -> RecordingResult {
        let Some(recording) = self.inner.state.lock().recordings.remove(session_id) else {
            return RecordingResult {
                steps: Vec::new(),
                code: String::new(),
            };
        };
        let code = steps_to_javascript(&recording.steps, Some(&iso_string(recording.started_at)));
        RecordingResult {
            steps: recording.steps,
            code,
        }
    }

    /// `scriptRecordingAppendStep`.
    pub fn recording_append_step(&self, session_id: &str, step: Option<Value>) -> AppendStepResult {
        let mut state = self.inner.state.lock();
        let Some(recording) = state.recordings.get_mut(session_id) else {
            return AppendStepResult::error("Recording not started");
        };
        let Some(step) = step.filter(|s| !s.is_null()) else {
            return AppendStepResult::error("Recording step is required");
        };
        let now = now_ms();
        let gap = now - recording.last_timestamp;
        let mut additions = Vec::new();
        if gap > 1000 && step.get("type").and_then(|t| t.as_str()) == Some("send") {
            additions.push(json!({ "type": "sleep", "value": gap }));
        }
        additions.push(step);
        let addition_bytes: usize = additions
            .iter()
            .map(|a| serde_json::to_string(a).map(|s| s.len()).unwrap_or(0))
            .sum();
        let next_count = recording.steps.len() + additions.len();
        let next_bytes = recording.total_bytes + addition_bytes;
        let exceeds = next_count > MAX_SCRIPT_RECORDING_STEPS || next_bytes > MAX_SCRIPT_RECORDING_BYTES;
        if !exceeds {
            recording.steps.extend(additions);
            recording.total_bytes = next_bytes;
            recording.last_timestamp = now;
        }
        if exceeds
            || recording.steps.len() >= MAX_SCRIPT_RECORDING_STEPS
            || recording.total_bytes >= MAX_SCRIPT_RECORDING_BYTES
        {
            let recording = state.recordings.remove(session_id).expect("present");
            let code = if recording.steps.is_empty() {
                String::new()
            } else {
                steps_to_javascript(&recording.steps, Some(&iso_string(recording.started_at)))
            };
            return AppendStepResult {
                ok: false,
                stopped: Some(true),
                reason: Some("limit"),
                error: Some(SCRIPT_RECORDING_LIMIT_ERROR.into()),
                steps: Some(recording.steps),
                code: Some(code),
            };
        }
        AppendStepResult::ok()
    }
}

/// The [`RuntimeHost`] of one run (the `deps` passed to
/// `createScriptRuntime` by `runScriptOnSession`).
struct RunHost<H: ManagerHost> {
    manager: ScriptManager<H>,
    run_id: String,
    session_id: String,
}

impl<H: ManagerHost> RunHost<H> {
    fn with_run<T>(&self, f: impl FnOnce(&mut ScriptRun) -> T) -> Option<T> {
        self.manager
            .inner
            .state
            .lock()
            .runs
            .get_mut(&self.run_id)
            .map(f)
    }

    fn run_finished(&self) -> bool {
        self.with_run(|r| r.is_finished()).unwrap_or(true)
    }
}

#[async_trait::async_trait]
impl<H: ManagerHost> RuntimeHost for RunHost<H> {
    fn append_log(&self, message: &str) {
        let appended = self
            .with_run(|run| {
                if run.is_finished() {
                    return false;
                }
                append_retained_run_log(
                    run,
                    RunLogEntry {
                        at: now_ms(),
                        message: message.to_string(),
                    },
                    MAX_RETAINED_LOGS_PER_RUN,
                );
                true
            })
            .unwrap_or(false);
        if appended {
            self.manager.broadcast_runs();
        }
    }

    fn write_to_session(&self, data: &str, options: &WriteOptions) {
        if self.run_finished() {
            return;
        }
        self.manager.write_to_session(&self.session_id, data, options);
    }

    fn output_buffer(&self) -> OutputBuffer {
        self.manager.buffer(&self.session_id)
    }

    async fn screen_snapshot(&self) -> Result<ScreenSnapshot, String> {
        self.manager
            .request_screen_snapshot(&self.session_id, &self.run_id)
            .await
    }

    fn session_meta(&self) -> SessionSnapshot {
        self.manager.session_meta(&self.session_id)
    }

    async fn show_dialog(&self, request: DialogRequest) -> Result<Option<Value>, String> {
        self.manager.show_dialog(&self.run_id, request).await
    }

    async fn show_wait_for_timeout_dialog(
        &self,
        pattern: &str,
        timeout_ms: u64,
    ) -> Result<String, String> {
        let mut extras = serde_json::Map::new();
        extras.insert("pattern".into(), Value::String(pattern.to_string()));
        extras.insert("timeoutMs".into(), json!(timeout_ms));
        let value = self
            .manager
            .show_dialog(
                &self.run_id,
                DialogRequest {
                    dialog_type: "waitForTimeout".into(),
                    message: format!("Timed out waiting for \"{pattern}\" after {timeout_ms}ms"),
                    default_value: None,
                    extras,
                },
            )
            .await?;
        Ok(match value {
            Some(Value::String(s)) => s,
            _ => "abort".into(),
        })
    }

    async fn disconnect_session(&self) -> Result<(), String> {
        self.manager.inner.host.close_session(&self.session_id);
        Ok(())
    }

    async fn start_session_log(&self, path: Option<String>) -> Result<(), String> {
        self.manager
            .start_script_session_log(&self.session_id, &self.run_id, path)
            .await
    }

    async fn stop_session_log(&self) -> Result<(), String> {
        self.manager
            .stop_script_session_log(&self.session_id, Some(&self.run_id))
            .await;
        Ok(())
    }

    fn is_paused(&self) -> bool {
        self.with_run(|r| r.paused).unwrap_or(false)
    }

    fn is_aborted(&self) -> bool {
        self.run_finished()
    }

    fn on_status_change(&self, patch: StatusPatch) {
        let applied = self
            .with_run(|run| {
                if run.is_finished() {
                    return false;
                }
                run.apply(&patch);
                true
            })
            .unwrap_or(false);
        if applied {
            self.manager.broadcast_runs();
        }
    }
}
