//! Transfer features and existing-protocol gaps (`rust/docs/ipc-transfers.md`):
//!
//! * Global transfer queue: admission of renderer transfers
//!   ([`admit`], used by `sftp::run_transfer`), `transfer_prioritize`,
//!   `transfer_set_concurrency`, queued pause / cancel, and
//!   `transfer_cleanup` (Electron `transferBridge.cjs`).
//! * Compressed folder upload `compress_*` (Electron
//!   `compressUploadBridge.cjs`).
//! * Native drag of local files out of the app `local_drag_start` /
//!   `local_drag_cancel` (Electron `localFileDragBridge.cjs`).
//! * X11 forwarding proxy for SSH shells ([`start_x11_forwarding`]).
//! * Mosh / ET host-stats companion SSH connection ([`companion_connection`],
//!   Electron `moshStatsConnection.cjs`).
//! * Real cwd discovery of SSH terminals ([`ssh_session_cwd`], Electron
//!   `getSessionPwd`).

use super::session::SuccessResult;
use super::CmdResult;
use crate::events;
use crate::state::{AppState, Ctx};
use dashmap::DashMap;
use netcatty_core::ipc::{
    events as ev, EndpointType, SshSessionOptions, StreamTransferOptions, StreamTransferResult,
};
use netcatty_core::CoreError;
use netcatty_sftp::transfer::{start_transfer, TransferEndpoints, TransferOutcome};
use netcatty_sftp::{SftpClient, TransferHandle, TransferRequest};
use netcatty_ssh::SshConnection;
use netcatty_transfers::admission::{resource_keys, Admission, AdmissionQueue, Slot};
use netcatty_transfers::compress;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager, Runtime};
use tokio_util::sync::CancellationToken;

/// Interval of the sweep that forgets state of ended sessions.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Managed state of this module.
#[derive(Default)]
pub struct Transfers2State {
    pub queue: AdmissionQueue,
    compressions: DashMap<String, Arc<Compression>>,
    support_cache: parking_lot::Mutex<Vec<(String, Instant, Support)>>,
    target_locks: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
    /// Terminal session id → login shell pid found by the cwd probe.
    shell_pids: DashMap<String, String>,
    /// Mosh / ET session id → stats companion.
    companions: DashMap<String, Arc<Companion>>,
    /// Window label → pending native drag request id.
    drags: parking_lot::Mutex<HashMap<String, String>>,
}

/// Register the managed state and the stale-session sweep.
pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    app.manage(Transfers2State::default());
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            sweep(&handle).await;
        }
    });
}

/// Forget cwd pids and disconnect companions of sessions that ended.
async fn sweep<R: Runtime>(app: &AppHandle<R>) {
    let (Some(t2), Some(state)) = (
        app.try_state::<Transfers2State>(),
        app.try_state::<AppState<R>>(),
    ) else {
        return;
    };
    t2.shell_pids.retain(|id, _| state.sessions.contains(id));
    let gone: Vec<String> = t2
        .companions
        .iter()
        .filter(|c| !state.sessions.contains(c.key()))
        .map(|c| c.key().clone())
        .collect();
    for id in gone {
        if let Some((_, companion)) = t2.companions.remove(&id) {
            companion.shutdown().await;
        }
    }
}

fn emit_transfer<R: Runtime>(app: &AppHandle<R>, payload: Value) {
    events::emit(app, ev::SFTP_GLOBAL_TRANSFER, payload);
}

// ===========================================================================
// Transfer queue
// ===========================================================================

/// Result of [`admit`].
pub(crate) enum AdmitOutcome {
    /// Run now; keep the slot (if any) alive until the transfer ends.
    Run(Option<Slot>),
    /// Ended while queued (cancelled / paused); return this result.
    Done(StreamTransferResult),
}

fn extra_bool(payload: &StreamTransferOptions, key: &str) -> bool {
    payload.extra.get(key).and_then(Value::as_bool) == Some(true)
}

/// Electron `buildTransferLifecycleEvent("queued", payload)`, shaped like
/// the `started` event `run_transfer` emits next.
fn queued_event(payload: &StreamTransferOptions) -> Value {
    let mut event = serde_json::to_value(super::sftp::started_event(
        payload,
        netcatty_core::ids::now_ms(),
    ))
    .unwrap_or_else(|_| json!({ "transferId": payload.transfer_id }));
    if let Some(obj) = event.as_object_mut() {
        obj.insert("type".into(), json!("queued"));
        obj.insert("controlKind".into(), json!("stream"));
        obj.insert("lifecycleState".into(), json!("queued"));
        obj.remove("phase");
        if let Some(epoch) = payload.extra.get("lifecycleEpoch").filter(|v| v.is_number()) {
            obj.insert("lifecycleEpoch".into(), epoch.clone());
        }
    }
    event
}

/// Queue a renderer transfer behind the global admission limit. Internal
/// transfers (`emit_events == false`) and `skipAdmission` payloads run at
/// once. `globalConcurrency` in the payload updates the limit first.
pub(crate) async fn admit<R: Runtime>(
    state: &AppState<R>,
    payload: &StreamTransferOptions,
    emit_events: bool,
) -> CmdResult<AdmitOutcome> {
    let Some(t2) = state.app.try_state::<Transfers2State>() else {
        return Ok(AdmitOutcome::Run(None));
    };
    if !emit_events || extra_bool(payload, "skipAdmission") {
        return Ok(AdmitOutcome::Run(None));
    }
    if t2.queue.is_queued(&payload.transfer_id) {
        return Err(CoreError::invalid(format!(
            "transfer {} is already queued",
            payload.transfer_id
        )));
    }
    if let Some(limit) = payload.extra.get("globalConcurrency").and_then(Value::as_f64) {
        t2.queue.set_limit(limit);
    }
    let keys = resource_keys(
        payload.source_host_id.as_deref(),
        payload.source_sftp_id.as_deref(),
        payload.target_host_id.as_deref(),
        payload.target_sftp_id.as_deref(),
    );
    let ticket = t2.queue.enqueue(&payload.transfer_id, keys);
    emit_transfer(&state.app, queued_event(payload));
    let id = payload.transfer_id.clone();
    match ticket.wait().await {
        Admission::Run(slot) => Ok(AdmitOutcome::Run(Some(slot))),
        Admission::Cancelled => {
            emit_transfer(
                &state.app,
                json!({ "type": "cancelled", "transferId": id, "endedAt": netcatty_core::ids::now_ms() }),
            );
            Ok(AdmitOutcome::Done(StreamTransferResult {
                transfer_id: id,
                error: Some("Transfer cancelled".into()),
                cancelled: Some(true),
                ..Default::default()
            }))
        }
        Admission::Paused => {
            // Never report 0 when the payload carries a real checkpoint.
            let checkpoint = ["downloadCheckpointBytes", "uploadCheckpointBytes"]
                .iter()
                .filter_map(|k| payload.extra.get(*k).and_then(Value::as_u64))
                .chain(payload.checkpoint_bytes)
                .max()
                .unwrap_or(0);
            let resume_stage = payload
                .extra
                .get("resumeStage")
                .and_then(Value::as_str)
                .unwrap_or("direct")
                .to_string();
            let mut event = json!({
                "type": "paused",
                "transferId": id,
                "checkpointBytes": checkpoint,
                "resumeStage": resume_stage,
            });
            if let Some(epoch) = payload.extra.get("lifecycleEpoch").and_then(Value::as_u64) {
                event["lifecycleEpoch"] = json!(epoch + 1);
            }
            emit_transfer(&state.app, event);
            Ok(AdmitOutcome::Done(StreamTransferResult {
                transfer_id: id,
                cancelled: Some(true),
                warning: Some("paused".into()),
                ..Default::default()
            }))
        }
    }
}

/// `transfer_cancel` on a transfer that is still queued.
pub(crate) fn cancel_queued<R: Runtime>(app: &AppHandle<R>, transfer_id: &str) -> bool {
    app.try_state::<Transfers2State>()
        .is_some_and(|t2| t2.queue.cancel_queued(transfer_id))
}

/// `transfer_pause` on a transfer that is still queued.
pub(crate) fn pause_queued<R: Runtime>(app: &AppHandle<R>, transfer_id: &str) -> bool {
    app.try_state::<Transfers2State>()
        .is_some_and(|t2| t2.queue.pause_queued(transfer_id))
}

/// `prioritizeTransfer`: move a queued transfer to the front.
#[tauri::command]
pub fn transfer_prioritize<R: Runtime>(state: Ctx<'_, R>, transfer_id: String) -> SuccessResult {
    let moved = state
        .app
        .try_state::<Transfers2State>()
        .is_some_and(|t2| t2.queue.prioritize(&transfer_id));
    SuccessResult {
        success: moved,
        error: None,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ConcurrencyResult {
    pub success: bool,
    pub limit: usize,
}

/// `setGlobalTransferConcurrency`: integers 1..=16, otherwise unchanged.
#[tauri::command]
pub fn transfer_set_concurrency<R: Runtime>(state: Ctx<'_, R>, limit: Value) -> ConcurrencyResult {
    let Some(t2) = state.app.try_state::<Transfers2State>() else {
        return ConcurrencyResult {
            success: false,
            limit: netcatty_transfers::admission::DEFAULT_LIMIT,
        };
    };
    let limit = match limit.as_f64() {
        Some(value) => t2.queue.set_limit(value),
        None => t2.queue.limit(),
    };
    ConcurrencyResult {
        success: true,
        limit,
    }
}

/// `cleanupTransferArtifacts` payload.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupPayload {
    #[serde(default)]
    pub transfer_id: String,
    #[serde(default)]
    pub source_path: String,
    #[serde(default)]
    pub target_path: String,
    #[serde(default)]
    pub target_sftp_id: Option<String>,
    #[serde(default)]
    pub target_encoding: Option<netcatty_core::models::SftpFilenameEncoding>,
    #[serde(default)]
    pub staged_target_path: Option<String>,
}

/// Remove a task's transfer artifacts (best effort). Running transfers and
/// stages of other running transfers to the same target are left alone.
#[tauri::command]
pub async fn transfer_cleanup<R: Runtime>(
    state: Ctx<'_, R>,
    payload: CleanupPayload,
) -> CmdResult<SuccessResult> {
    use netcatty_transfers::cleanup::{replace_stage_is_owned, stage_file_name};
    if payload.transfer_id.is_empty() {
        return Ok(SuccessResult::fail("transferId is required"));
    }
    if state.transfers.contains_key(&payload.transfer_id) {
        return Ok(SuccessResult::ok());
    }
    let temp = super::tempdir::current(&state.app);
    let mut names = vec![stage_file_name(&payload.target_path)];
    let source_name = stage_file_name(&payload.source_path);
    if !names.contains(&source_name) {
        names.push(source_name);
    }
    for name in names {
        let stage = super::temp::transfer_temp_file_path(&temp, &payload.transfer_id, &name);
        let _ = tokio::fs::remove_file(&stage).await;
    }
    let client = payload
        .target_sftp_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|id| state.sftp_client(id).ok());
    if !payload.target_path.is_empty() {
        match &client {
            Some(client) => {
                let stage = netcatty_sftp::remote_staging_path(&payload.target_path);
                let _ = client
                    .delete(
                        &stage,
                        Some(netcatty_core::models::FileEntryType::File),
                        payload.target_encoding,
                    )
                    .await;
            }
            None if payload.target_sftp_id.is_none() => {
                let stage = netcatty_sftp::staging_path(&payload.target_path);
                if tokio::fs::symlink_metadata(&stage)
                    .await
                    .is_ok_and(|m| m.is_file())
                {
                    let _ = tokio::fs::remove_file(&stage).await;
                }
            }
            None => {}
        }
    }
    if let Some(staged) = payload.staged_target_path.as_deref().filter(|s| !s.is_empty()) {
        if replace_stage_is_owned(staged, &payload.target_path, &payload.transfer_id) {
            match &client {
                Some(client) => {
                    let _ = client.delete(staged, None, payload.target_encoding).await;
                }
                None if payload.target_sftp_id.is_none() => {
                    let _ = tokio::fs::remove_dir_all(staged).await;
                    let _ = tokio::fs::remove_file(staged).await;
                }
                None => {}
            }
        } else {
            tracing::warn!("cleanup refused a staged target path that is not this task's stage");
        }
    }
    Ok(SuccessResult::ok())
}

// ===========================================================================
// Remote exec with cancellation (compressed upload)
// ===========================================================================

#[derive(Debug, Default)]
struct RemoteOutput {
    code: Option<u32>,
    has_output: bool,
    stderr: String,
}

#[derive(Debug, PartialEq, Eq)]
enum RemoteError {
    Timeout(u64),
    Cancelled,
    Failed(String),
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout(ms) => write!(f, "Remote command timed out after {} seconds", ms / 1000),
            Self::Cancelled => f.write_str("Upload cancelled"),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

/// Run `command` on a new exec channel; a timeout or cancellation sends
/// SIGKILL to the remote command and closes the channel (never the
/// connection).
async fn run_remote(
    conn: &SshConnection,
    command: &str,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<RemoteOutput, RemoteError> {
    use russh::ChannelMsg;
    let timeout_ms = timeout.as_millis() as u64;
    let deadline = tokio::time::Instant::now() + timeout;
    if conn.is_closed() {
        return Err(RemoteError::Failed("Not connected".into()));
    }
    let open = tokio::select! {
        r = conn.handle.channel_open_session() => r,
        _ = cancel.cancelled() => return Err(RemoteError::Cancelled),
        _ = tokio::time::sleep_until(deadline) => return Err(RemoteError::Timeout(timeout_ms)),
    };
    let mut channel = open.map_err(|e| RemoteError::Failed(e.to_string()))?;
    let mut stderr = compress::BoundedUtf8::new(compress::MAX_STDERR_BYTES);
    let mut out = RemoteOutput::default();
    let outcome: Result<(), RemoteError> = async {
        tokio::select! {
            r = channel.exec(true, command.as_bytes().to_vec()) => {
                r.map_err(|e| RemoteError::Failed(format!("Unable to exec: {e}")))?
            }
            _ = cancel.cancelled() => return Err(RemoteError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => return Err(RemoteError::Timeout(timeout_ms)),
        }
        loop {
            let msg = tokio::select! {
                m = channel.wait() => m,
                _ = cancel.cancelled() => return Err(RemoteError::Cancelled),
                _ = tokio::time::sleep_until(deadline) => return Err(RemoteError::Timeout(timeout_ms)),
            };
            match msg {
                Some(ChannelMsg::Failure) => {
                    return Err(RemoteError::Failed("Unable to exec: request rejected".into()))
                }
                Some(ChannelMsg::Data { data }) => out.has_output |= !data.is_empty(),
                Some(ChannelMsg::ExtendedData { data, .. }) => stderr.append(&data),
                Some(ChannelMsg::ExitStatus { exit_status }) => out.code = Some(exit_status),
                Some(ChannelMsg::Close) | None => return Ok(()),
                Some(_) => {}
            }
        }
    }
    .await;
    if outcome.is_err() {
        let _ = channel.signal(russh::Sig::KILL).await;
        let _ = channel.close().await;
    }
    outcome?;
    out.stderr = stderr.finish();
    Ok(out)
}

// ===========================================================================
// Compressed folder upload
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Support {
    pub supported: bool,
    pub local_tar: bool,
    pub remote_tar: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompressStartPayload {
    pub compression_id: String,
    pub folder_path: String,
    pub target_path: String,
    pub sftp_id: String,
    pub folder_name: String,
    #[serde(default)]
    pub total_bytes: Option<f64>,
    #[serde(default)]
    pub lifecycle_epoch: Option<f64>,
}

struct CompressionState {
    phase: &'static str,
    paused: bool,
    lifecycle_epoch: u64,
    lifecycle_state: &'static str,
    terminal: Option<&'static str>,
    tar_pid: Option<u32>,
}

struct Compression {
    id: String,
    total_bytes: u64,
    cancelled: AtomicBool,
    cancel: CancellationToken,
    state: parking_lot::Mutex<CompressionState>,
    resume: tokio::sync::Notify,
    upload: parking_lot::Mutex<Option<TransferHandle>>,
}

impl Compression {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn lifecycle(&self) -> (u64, &'static str) {
        let s = self.state.lock();
        (s.lifecycle_epoch, s.lifecycle_state)
    }
}

/// Send a signal to the local tar (pause / resume / terminate).
#[cfg(unix)]
fn signal_pid(pid: u32, signal: i32) {
    // SAFETY: plain kill(2) on a child pid we spawned.
    unsafe {
        libc::kill(pid as libc::pid_t, signal);
    }
}

fn compress_event<R: Runtime>(app: &AppHandle<R>, comp: &Compression, kind: &str, mut extra: Value) {
    let (epoch, lifecycle_state) = comp.lifecycle();
    if let Some(obj) = extra.as_object_mut() {
        obj.insert("type".into(), json!(kind));
        obj.insert("transferId".into(), json!(comp.id));
        obj.entry("lifecycleEpoch").or_insert(json!(epoch));
        obj.entry("lifecycleState").or_insert(json!(lifecycle_state));
    }
    emit_transfer(app, extra);
}

fn compress_progress<R: Runtime>(app: &AppHandle<R>, comp: &Compression, phase: &str, percent: f64) {
    if comp.is_cancelled() {
        return;
    }
    let transferred = compress::transferred_bytes(percent, 100.0, comp.total_bytes);
    compress_event(
        app,
        comp,
        "progress",
        json!({
            "transferred": transferred,
            "totalBytes": comp.total_bytes,
            "speed": 0,
            "phase": phase,
        }),
    );
}

/// Publish the terminal event once.
fn settle<R: Runtime>(app: &AppHandle<R>, comp: &Compression, kind: &'static str, extra: Value) -> bool {
    {
        let mut s = comp.state.lock();
        if s.terminal.is_some() {
            return false;
        }
        s.terminal = Some(kind);
    }
    let mut extra = extra;
    if let Some(obj) = extra.as_object_mut() {
        obj.insert("endedAt".into(), json!(netcatty_core::ids::now_ms()));
    }
    compress_event(app, comp, kind, extra);
    true
}

async fn wait_while_paused<R: Runtime>(app: &AppHandle<R>, comp: &Compression) {
    loop {
        let notified = comp.resume.notified();
        let phase = {
            let s = comp.state.lock();
            if !s.paused || comp.is_cancelled() {
                return;
            }
            s.phase
        };
        compress_event(
            app,
            comp,
            "paused",
            json!({ "phase": phase, "lifecycleState": "paused" }),
        );
        tokio::select! {
            _ = notified => {}
            _ = comp.cancel.cancelled() => return,
        }
    }
}

fn release_paused(comp: &Compression) {
    comp.state.lock().paused = false;
    comp.resume.notify_waiters();
}

fn cancelled_error() -> String {
    "Upload cancelled".to_string()
}

/// `tar --version` locally (10 s bound).
async fn local_tar_available(cancel: &CancellationToken) -> bool {
    let mut cmd = tokio::process::Command::new(compress::local_tar_command());
    cmd.arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    tokio::select! {
        status = child.wait() => status.is_ok_and(|s| s.success()),
        _ = tokio::time::sleep(Duration::from_millis(compress::LOCAL_TAR_PROBE_TIMEOUT_MS)) => false,
        _ = cancel.cancelled() => false,
    }
}

/// `tar --version` on the remote host. Single-channel servers never get a
/// second channel (the renderer then uploads file by file).
async fn remote_tar_available(client: &SftpClient, cancel: &CancellationToken) -> bool {
    if super::system::single_channel_banner(&client.connection) {
        return false;
    }
    match run_remote(
        &client.connection,
        "tar --version",
        Duration::from_millis(compress::REMOTE_TAR_PROBE_TIMEOUT_MS),
        cancel,
    )
    .await
    {
        Ok(out) => out.code == Some(0) && out.has_output,
        Err(_) => false,
    }
}

async fn resolve_support<R: Runtime>(
    state: &AppState<R>,
    t2: &Transfers2State,
    sftp_id: &str,
    cancel: &CancellationToken,
) -> Result<Support, String> {
    let ttl = Duration::from_millis(compress::SUPPORT_CACHE_TTL_MS);
    {
        let mut cache = t2.support_cache.lock();
        cache.retain(|(_, at, _)| at.elapsed() < ttl);
        if let Some((_, _, support)) = cache.iter().find(|(id, _, _)| id == sftp_id) {
            return Ok(support.clone());
        }
    }
    let client = state.sftp_client(sftp_id).map_err(|e| e.message)?;
    let local_tar = local_tar_available(cancel).await;
    if cancel.is_cancelled() {
        return Err(cancelled_error());
    }
    let remote_tar = local_tar && remote_tar_available(&client, cancel).await;
    if cancel.is_cancelled() {
        return Err(cancelled_error());
    }
    let support = Support {
        supported: local_tar && remote_tar,
        local_tar,
        remote_tar,
        error: None,
    };
    let mut cache = t2.support_cache.lock();
    cache.retain(|(id, _, _)| id != sftp_id);
    cache.push((sftp_id.to_string(), Instant::now(), support.clone()));
    let overflow = cache.len().saturating_sub(compress::SUPPORT_CACHE_MAX_ENTRIES);
    cache.drain(..overflow);
    Ok(support)
}

/// `checkCompressedUploadSupport(sftpId)`.
#[tauri::command]
pub async fn compress_check_support<R: Runtime>(state: Ctx<'_, R>, sftp_id: String) -> CmdResult<Support> {
    let t2 = state.app.state::<Transfers2State>();
    Ok(
        match resolve_support(&state, &t2, &sftp_id, &CancellationToken::new()).await {
            Ok(support) => support,
            Err(error) => Support {
                supported: false,
                local_tar: false,
                remote_tar: false,
                error: Some(error),
            },
        },
    )
}

/// Run the local compressor; progress from the archive size every 500 ms.
async fn compress_folder<R: Runtime>(
    app: &AppHandle<R>,
    comp: &Compression,
    folder: &Path,
    archive: &Path,
) -> Result<(), String> {
    let invocation = compress::local_tar_invocation(folder, archive)?;
    let file = std::fs::File::create(archive)
        .map_err(|e| format!("Failed to create tar archive: {e}"))?;
    let mut cmd = tokio::process::Command::new(compress::local_tar_command());
    cmd.args(&invocation.args)
        .current_dir(&invocation.cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(file))
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    let mut child = cmd.spawn().map_err(|e| format!("Failed to start tar: {e}"))?;
    comp.state.lock().tar_pid = child.id();
    let stderr_task = child.stderr.take().map(|mut stderr| {
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut collector = compress::BoundedUtf8::new(compress::MAX_STDERR_BYTES);
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                collector.append(&buf[..n]);
            }
            collector.finish()
        })
    });
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    let status = loop {
        tokio::select! {
            status = child.wait() => break status,
            _ = ticker.tick() => {
                if let Ok(meta) = tokio::fs::metadata(archive).await {
                    compress_progress(app, comp, "compressing", compress::compressing_percent(meta.len()));
                }
            }
            _ = comp.cancel.cancelled() => {
                #[cfg(unix)]
                if let Some(pid) = child.id() {
                    signal_pid(pid, libc::SIGTERM);
                    signal_pid(pid, libc::SIGCONT);
                }
                let grace = Duration::from_millis(compress::LOCAL_TAR_KILL_GRACE_MS);
                if tokio::time::timeout(grace, child.wait()).await.is_err() {
                    let _ = child.kill().await;
                }
                comp.state.lock().tar_pid = None;
                let _ = tokio::fs::remove_file(archive).await;
                return Err("Compression cancelled".into());
            }
        }
    };
    comp.state.lock().tar_pid = None;
    let stderr = match stderr_task {
        Some(task) => task.await.unwrap_or_default(),
        None => String::new(),
    };
    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => Err(format!("Tar compression failed: {stderr}")),
        Err(err) => Err(format!("Failed to start tar: {err}")),
    }
}

/// Upload the archive (30–90 %), restarting from the checkpoint after a
/// pause. Queued behind the global admission limit like Electron's
/// internal transfer.
async fn upload_archive<R: Runtime>(
    state: &AppState<R>,
    t2: &Transfers2State,
    comp: &Compression,
    client: &Arc<SftpClient>,
    sftp_id: &str,
    local_archive: &Path,
    remote_archive: &str,
    size: u64,
) -> Result<(), String> {
    let transfer_id = format!("compress-{}", comp.id);
    let mut checkpoint = 0u64;
    loop {
        let ticket = t2
            .queue
            .enqueue(&transfer_id, resource_keys(None, None, None, Some(sftp_id)));
        let slot = tokio::select! {
            admission = ticket.wait() => match admission {
                Admission::Run(slot) => slot,
                _ => return Err(cancelled_error()),
            },
            _ = comp.cancel.cancelled() => {
                t2.queue.cancel_queued(&transfer_id);
                return Err(cancelled_error());
            }
        };
        let request = TransferRequest {
            transfer_id: transfer_id.clone(),
            source_type: EndpointType::Local,
            target_type: EndpointType::Sftp,
            source_path: local_archive.to_string_lossy().into_owned(),
            target_path: remote_archive.to_string(),
            total_bytes: Some(size),
            checkpoint_bytes: checkpoint,
            stage_target: true,
        };
        let endpoints = TransferEndpoints {
            source: None,
            target: Some(client.clone()),
        };
        let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut handle = start_transfer(request, endpoints, Some(progress_tx)).map_err(|e| e.to_string())?;
        let (_tx, dummy) = tokio::sync::oneshot::channel();
        let done = std::mem::replace(&mut handle.done, dummy);
        *comp.upload.lock() = Some(handle);
        if comp.is_cancelled() {
            if let Some(h) = comp.upload.lock().as_ref() {
                h.cancel();
            }
        }
        tokio::pin!(done);
        let outcome = loop {
            tokio::select! {
                outcome = &mut done => break outcome,
                progress = progress_rx.recv() => match progress {
                    Some((_, progress)) => {
                        let progress: netcatty_sftp::TransferProgress = progress;
                        compress_progress(
                            &state.app,
                            comp,
                            "uploading",
                            compress::uploading_percent(progress.transferred, size),
                        );
                    }
                    None => break (&mut done).await,
                },
            }
        };
        comp.upload.lock().take();
        drop(slot);
        match outcome {
            Ok(TransferOutcome::Completed { .. }) => return Ok(()),
            Ok(TransferOutcome::Paused { checkpoint_bytes }) => {
                checkpoint = checkpoint_bytes;
                wait_while_paused(&state.app, comp).await;
                if comp.is_cancelled() {
                    return Err(cancelled_error());
                }
            }
            Ok(TransferOutcome::Cancelled { .. }) => return Err(cancelled_error()),
            Ok(TransferOutcome::Failed { error, .. }) => return Err(error),
            Err(_) => return Err("transfer task ended unexpectedly".into()),
        }
    }
}

/// Serialize commits to one remote destination (Electron
/// `runWithCompressionTargetLock`); waiting is cancellable.
async fn with_target_lock<T, F>(
    t2: &Transfers2State,
    key: &str,
    cancel: &CancellationToken,
    op: F,
) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>>,
{
    let lock = t2
        .target_locks
        .entry(key.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let result = {
        let guard = tokio::select! {
            g = lock.lock() => Some(g),
            _ = cancel.cancelled() => None,
        };
        match guard {
            Some(_guard) => op.await,
            None => Err(cancelled_error()),
        }
    };
    drop(lock);
    t2.target_locks
        .remove_if(key, |_, v| Arc::strong_count(v) == 1);
    result
}

async fn run_compression<R: Runtime>(
    state: &AppState<R>,
    t2: &Transfers2State,
    comp: &Compression,
    payload: &CompressStartPayload,
    archive_slot: &mut Option<PathBuf>,
) -> Result<bool, String> {
    let app = &state.app;
    // Holding the client keeps the SFTP session (and its connection) alive
    // through extraction and cleanup even if the browser tab closes.
    let client = state.sftp_client(&payload.sftp_id).map_err(|e| e.message)?;
    let support = resolve_support(state, t2, &payload.sftp_id, &comp.cancel).await?;
    if !support.local_tar {
        return Err("tar command not available on local system. Please install tar.".into());
    }
    if !support.remote_tar {
        return Err(
            "tar command not available on remote server. Please install tar on the remote system."
                .into(),
        );
    }

    // Phase 1: compression (0–30 %).
    comp.state.lock().phase = "compressing";
    wait_while_paused(app, comp).await;
    compress_progress(app, comp, "compressing", 0.0);
    let archive = super::tempdir::temp_file_path(app, &format!("{}.tar.gz", payload.folder_name));
    *archive_slot = Some(archive.clone());
    compress_folder(app, comp, Path::new(&payload.folder_path), &archive).await?;
    if comp.is_cancelled() {
        return Err(cancelled_error());
    }
    let size = tokio::fs::metadata(&archive)
        .await
        .map_err(|e| e.to_string())?
        .len();
    compress_progress(app, comp, "compressing", 30.0);

    // Phase 2: upload (30–90 %).
    comp.state.lock().phase = "uploading";
    wait_while_paused(app, comp).await;
    compress_progress(app, comp, "uploading", 30.0);
    let remote_archive = compress::build_remote_archive_path(
        &payload.target_path,
        &payload.folder_name,
        &payload.compression_id,
    );
    upload_archive(
        state,
        t2,
        comp,
        &client,
        &payload.sftp_id,
        &archive,
        &remote_archive,
        size,
    )
    .await?;
    if comp.is_cancelled() {
        return Err(cancelled_error());
    }
    compress_progress(app, comp, "uploading", 90.0);

    // Phase 3: atomic extraction (90–100 %).
    comp.state.lock().phase = "extracting";
    wait_while_paused(app, comp).await;
    compress_progress(app, comp, "extracting", 90.0);
    let key = compress::compression_target_key(
        &client.connection.describe(),
        &payload.target_path,
        &payload.folder_name,
    )?;
    let command = compress::build_atomic_remote_extraction_command(
        &remote_archive,
        &payload.target_path,
        &payload.folder_name,
    )?;
    let timeout_ms = compress::extraction_timeout_ms(size);
    with_target_lock(t2, &key, &comp.cancel, async {
        if super::system::single_channel_banner(&client.connection) {
            return Err("This host is configured for single-channel SSH. Compressed extraction cannot open a shell on the file-transfer login.".to_string());
        }
        match run_remote(
            &client.connection,
            &command,
            Duration::from_millis(timeout_ms),
            &comp.cancel,
        )
        .await
        {
            Ok(out) if out.code == Some(0) => Ok(()),
            Ok(out) => Err(format!(
                "Remote extraction failed: {}",
                if out.stderr.is_empty() {
                    format!("exit code {}", out.code.map(|c| c.to_string()).unwrap_or_else(|| "null".into()))
                } else {
                    out.stderr
                }
            )),
            Err(RemoteError::Timeout(_)) => Err(format!(
                "Remote extraction timed out after {} seconds",
                timeout_ms / 1000
            )),
            Err(RemoteError::Cancelled) => Err(cancelled_error()),
            Err(err) => Err(format!("Remote extraction failed: {err}")),
        }
    })
    .await?;
    // A pause requested during extraction takes effect here.
    wait_while_paused(app, comp).await;
    compress_progress(app, comp, "extracting", 95.0);
    // Best-effort archive removal (the script already removed it on success).
    let _ = run_remote(
        &client.connection,
        &format!("rm -f {}", compress::escape_shell_arg(&remote_archive)),
        Duration::from_millis(compress::REMOTE_CLEANUP_TIMEOUT_MS),
        &comp.cancel,
    )
    .await;
    Ok(!comp.is_cancelled())
}

/// `startCompressedUpload(options)`: resolves when the upload finished,
/// failed or was cancelled. Progress and the terminal state arrive on
/// `netcatty:sftp:global-transfer` under `transferId = compressionId`.
#[tauri::command]
pub async fn compress_start<R: Runtime>(state: Ctx<'_, R>, payload: CompressStartPayload) -> CmdResult<Value> {
    let t2 = state.app.state::<Transfers2State>();
    let id = payload.compression_id.clone();
    if id.trim().is_empty() {
        return Err(CoreError::invalid("compressionId is required"));
    }
    if t2.compressions.contains_key(&id) {
        return Err(CoreError::invalid(format!(
            "Compressed upload is already active: {id}"
        )));
    }
    let total_bytes = payload.total_bytes.filter(|v| v.is_finite() && *v > 0.0).unwrap_or(0.0) as u64;
    let comp = Arc::new(Compression {
        id: id.clone(),
        total_bytes,
        cancelled: AtomicBool::new(false),
        cancel: CancellationToken::new(),
        state: parking_lot::Mutex::new(CompressionState {
            phase: "preparing",
            paused: false,
            lifecycle_epoch: payload
                .lifecycle_epoch
                .filter(|v| v.is_finite() && *v > 0.0)
                .unwrap_or(0.0) as u64,
            lifecycle_state: "transferring",
            terminal: None,
            tar_pid: None,
        }),
        resume: tokio::sync::Notify::new(),
        upload: parking_lot::Mutex::new(None),
    });
    t2.compressions.insert(id.clone(), comp.clone());
    let display_name = format!("{} (compressed)", payload.folder_name);
    compress_event(
        &state.app,
        &comp,
        "started",
        json!({
            "direction": "upload",
            "fileName": display_name,
            "sourcePath": payload.folder_path,
            "targetPath": format!("{}/{}", payload.target_path, payload.folder_name),
            "totalBytes": total_bytes,
            "isDirectory": true,
            "controlKind": "compressed-upload",
            "phase": "compressing",
            "startedAt": netcatty_core::ids::now_ms(),
        }),
    );

    let mut archive: Option<PathBuf> = None;
    let outcome = run_compression(&state, &t2, &comp, &payload, &mut archive).await;
    if let Some(path) = &archive {
        let _ = tokio::fs::remove_file(path).await;
    }
    let result = match outcome {
        Ok(true) => {
            compress_progress(&state.app, &comp, "extracting", 100.0);
            settle(
                &state.app,
                &comp,
                "completed",
                json!({ "transferred": total_bytes, "totalBytes": total_bytes }),
            );
            json!({ "compressionId": id, "success": true })
        }
        Ok(false) => {
            settle(&state.app, &comp, "cancelled", json!({}));
            json!({ "compressionId": id, "cancelled": true })
        }
        Err(error) => {
            let cancelled = comp.is_cancelled()
                || matches!(error.as_str(), "Upload cancelled" | "Compression cancelled" | "Transfer cancelled");
            if cancelled {
                settle(&state.app, &comp, "cancelled", json!({}));
            } else {
                settle(&state.app, &comp, "failed", json!({ "error": error }));
            }
            json!({ "compressionId": id, "error": error })
        }
    };
    comp.cancel.cancel();
    t2.compressions.remove_if(&id, |_, v| Arc::ptr_eq(v, &comp));
    Ok(result)
}

/// `cancelCompressedUpload(compressionId)`; idempotent.
#[tauri::command]
pub fn compress_cancel<R: Runtime>(state: Ctx<'_, R>, compression_id: String) -> Value {
    let t2 = state.app.state::<Transfers2State>();
    let Some(comp) = t2.compressions.get(&compression_id).map(|c| c.clone()) else {
        return json!({ "success": true, "inactive": true });
    };
    if comp.state.lock().terminal.is_none() {
        comp.cancelled.store(true, Ordering::SeqCst);
        settle(&state.app, &comp, "cancelled", json!({}));
        release_paused(&comp);
        comp.cancel.cancel();
        if let Some(handle) = comp.upload.lock().as_ref() {
            handle.cancel();
        }
    }
    json!({ "success": true })
}

/// `pauseCompressedUpload(compressionId)`.
#[tauri::command]
pub fn compress_pause<R: Runtime>(state: Ctx<'_, R>, compression_id: String) -> Value {
    let t2 = state.app.state::<Transfers2State>();
    let Some(comp) = t2.compressions.get(&compression_id).map(|c| c.clone()) else {
        return json!({ "success": false, "reason": "Compression is not active" });
    };
    if comp.is_cancelled() {
        return json!({ "success": false, "reason": "Compression is not active" });
    }
    let (phase, epoch, deferred) = {
        let mut s = comp.state.lock();
        if s.paused {
            return json!({ "success": true, "deferred": s.phase == "extracting" });
        }
        s.paused = true;
        s.lifecycle_epoch += 1;
        let deferred = s.phase == "extracting" || (s.phase == "compressing" && cfg!(windows));
        #[cfg(unix)]
        if s.phase == "compressing" {
            if let Some(pid) = s.tar_pid {
                signal_pid(pid, libc::SIGSTOP);
            }
        }
        s.lifecycle_state = if deferred { "pausing" } else { "paused" };
        (s.phase, s.lifecycle_epoch, deferred)
    };
    if phase == "uploading" {
        if let Some(handle) = comp.upload.lock().as_ref() {
            handle.pause();
        }
    }
    compress_event(
        &state.app,
        &comp,
        if deferred { "pausing" } else { "paused" },
        json!({ "phase": phase }),
    );
    json!({ "success": true, "deferred": deferred, "lifecycleEpoch": epoch })
}

/// `resumeCompressedUpload(compressionId)`.
#[tauri::command]
pub fn compress_resume<R: Runtime>(state: Ctx<'_, R>, compression_id: String) -> Value {
    let t2 = state.app.state::<Transfers2State>();
    let Some(comp) = t2.compressions.get(&compression_id).map(|c| c.clone()) else {
        return json!({ "success": false, "reason": "Compression is not active" });
    };
    if comp.is_cancelled() {
        return json!({ "success": false, "reason": "Compression is not active" });
    }
    let (phase, epoch) = {
        let mut s = comp.state.lock();
        #[cfg(unix)]
        if s.phase == "compressing" {
            if let Some(pid) = s.tar_pid {
                signal_pid(pid, libc::SIGCONT);
            }
        }
        s.lifecycle_epoch += 1;
        s.lifecycle_state = "transferring";
        (s.phase, s.lifecycle_epoch)
    };
    release_paused(&comp);
    compress_event(&state.app, &comp, "resumed", json!({ "phase": phase }));
    json!({ "success": true, "lifecycleEpoch": epoch })
}

// ===========================================================================
// Native drag of local files
// ===========================================================================

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DragStartPayload {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub paths: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DragStartResult {
    pub started: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl DragStartResult {
    fn failed(error: impl Into<String>) -> Self {
        Self {
            started: false,
            error: Some(error.into()),
        }
    }
}

/// Validate a drag request and inspect only metadata (symlinks followed);
/// files and directories are accepted, anything else is refused.
pub fn prepare_drag(payload: &DragStartPayload) -> Result<Vec<String>, String> {
    use netcatty_transfers::drag::{validate_drag_request, PathFlavor};
    let mut paths = Vec::with_capacity(payload.paths.len());
    for value in &payload.paths {
        match value.as_str() {
            Some(path) => paths.push(path.to_string()),
            None => return Err("Drag paths must be absolute filesystem paths".into()),
        }
    }
    let paths = validate_drag_request(&payload.request_id, &paths, PathFlavor::current())?;
    for path in &paths {
        let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
        if !meta.is_file() && !meta.is_dir() {
            return Err("Only files and folders can be dragged".into());
        }
    }
    Ok(paths)
}

/// 16×16 orange PNG used as the drag image (Electron's bitmap icon).
fn drag_icon_png() -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, 16, 16);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        if let Ok(mut writer) = encoder.write_header() {
            let pixels: Vec<u8> = (0..16 * 16).flat_map(|_| [220u8, 140, 40, 255]).collect();
            let _ = writer.write_image_data(&pixels);
        }
    }
    out
}

/// `startLocalFileDrag({ requestId, paths })`: hand real local files to the
/// OS drag session of the calling window. The reply never means the drop
/// was accepted.
#[tauri::command]
pub async fn local_drag_start<R: Runtime>(
    window: tauri::WebviewWindow<R>,
    payload: DragStartPayload,
) -> DragStartResult {
    let app = window.app_handle().clone();
    let Some(t2) = app.try_state::<Transfers2State>() else {
        return DragStartResult::failed("Native file drag is unavailable");
    };
    let label = window.label().to_string();
    t2.drags
        .lock()
        .insert(label.clone(), payload.request_id.clone());
    let request_id = payload.request_id.clone();
    let prepared = tokio::task::spawn_blocking({
        let payload = payload.clone();
        move || prepare_drag(&payload)
    })
    .await
    .unwrap_or_else(|_| Err("Unable to drag files".into()));
    let still_pending = {
        let mut drags = t2.drags.lock();
        let pending = drags.get(&label) == Some(&request_id);
        if pending {
            drags.remove(&label);
        }
        pending
    };
    let paths = match prepared {
        Ok(paths) => paths,
        Err(error) => return DragStartResult::failed(error),
    };
    if !still_pending {
        return DragStartResult {
            started: false,
            error: None,
        };
    }
    native_drag(window, paths).await
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn native_drag<R: Runtime>(window: tauri::WebviewWindow<R>, paths: Vec<String>) -> DragStartResult {
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
    let target = window.clone();
    let icon = drag_icon_png();
    let scheduled = window.run_on_main_thread(move || {
        let item = drag::DragItem::Files(paths.into_iter().map(PathBuf::from).collect());
        let image = drag::Image::Raw(icon);
        #[cfg(target_os = "linux")]
        let result = match target.gtk_window() {
            Ok(gtk_window) => {
                drag::start_drag(&gtk_window, item, image, |_, _| {}, drag::Options::default())
            }
            Err(err) => {
                let _ = tx.send(Err(err.to_string()));
                return;
            }
        };
        #[cfg(not(target_os = "linux"))]
        let result = drag::start_drag(&target, item, image, |_, _| {}, drag::Options::default());
        let _ = tx.send(result.map_err(|e| e.to_string()));
    });
    if let Err(err) = scheduled {
        return DragStartResult::failed(err.to_string());
    }
    match rx.await {
        Ok(Ok(())) => DragStartResult {
            started: true,
            error: None,
        },
        Ok(Err(error)) => DragStartResult::failed(error),
        Err(_) => DragStartResult::failed("Unable to drag files"),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
async fn native_drag<R: Runtime>(_window: tauri::WebviewWindow<R>, _paths: Vec<String>) -> DragStartResult {
    DragStartResult::failed("Native file drag is not supported on this platform")
}

/// `cancelLocalFileDrag(requestId)`: drop a pending request of this window.
#[tauri::command]
pub fn local_drag_cancel<R: Runtime>(window: tauri::WebviewWindow<R>, request_id: String) {
    if let Some(t2) = window.app_handle().try_state::<Transfers2State>() {
        let mut drags = t2.drags.lock();
        if drags.get(window.label()) == Some(&request_id) {
            drags.remove(window.label());
        }
    }
}

// ===========================================================================
// X11 forwarding
// ===========================================================================

/// Start the local X11 proxy for a freshly opened X11 shell on
/// `connection` (dialed for this session only). Connection failures are
/// written into the terminal like Electron's `sendTerminalMessage`.
pub(crate) async fn start_x11_forwarding<R: Runtime>(
    app: &AppHandle<R>,
    session_id: &str,
    connection: &Arc<SshConnection>,
    display: Option<String>,
    fake_cookie: String,
) {
    use netcatty_ssh::x11::{spawn_x11_forwarder, X11ForwardConfig, X11Platform};
    let rx = {
        let mut channels = connection.channels.lock().await;
        channels.as_mut().and_then(|c| c.x11_rx.take())
    };
    let Some(rx) = rx else {
        tracing::debug!(session_id, "x11 channel receiver unavailable on this connection");
        return;
    };
    let app = app.clone();
    let id = session_id.to_string();
    let notify: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |message: String| {
        events::emit(
            &app,
            ev::SESSION_DATA,
            netcatty_core::ipc::SessionDataEvent {
                session_id: id.clone(),
                data: message,
                meta: None,
            },
        );
    });
    spawn_x11_forwarder(
        rx,
        X11ForwardConfig {
            display,
            fake_cookie,
            platform: X11Platform::current(),
        },
        notify,
    );
}

// ===========================================================================
// Mosh / ET host-stats companion connection
// ===========================================================================

#[derive(Default)]
struct CompanionConn {
    conn: Option<Arc<SshConnection>>,
    failed: bool,
}

struct Companion {
    options: SshSessionOptions,
    /// Mosh: set once the handshake succeeded (`netcatty:mosh:ready`).
    ready: AtomicBool,
    state: tokio::sync::Mutex<CompanionConn>,
}

impl Companion {
    async fn shutdown(&self) {
        let conn = self.state.lock().await.conn.take();
        if let Some(conn) = conn {
            let _ = conn.disconnect().await;
        }
    }
}

/// Companion login options from the Mosh / ET start options: the same SSH
/// endpoint and stored credentials, no jump hosts, 10 s bounds, no
/// keepalive, the local agent unless explicitly disabled or a key is given.
pub fn companion_options(o: &super::mosh::ExternalSessionOptions) -> SshSessionOptions {
    let explicit_key = o
        .private_key
        .as_deref()
        .is_some_and(|k| !k.trim().is_empty());
    SshSessionOptions {
        hostname: o.hostname.trim().to_string(),
        username: o
            .username
            .clone()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "root".to_string()),
        port: Some(o.port.unwrap_or(22)),
        host_id: o.host_id.clone(),
        auth_method: o.auth_method,
        password: o.password.clone().filter(|p| !p.is_empty()),
        private_key: o.private_key.clone(),
        certificate: o.certificate.clone(),
        key_id: o.key_id.clone(),
        passphrase: o.passphrase.clone(),
        identity_file_paths: o.identity_file_paths.clone(),
        use_ssh_agent: Some(o.use_ssh_agent != Some(false) && !explicit_key),
        identity_agent: o.identity_agent.clone(),
        identities_only: o.identities_only,
        known_hosts: o.known_hosts.clone(),
        verify_host_keys: o.verify_host_keys,
        legacy_algorithms: o.legacy_algorithms,
        keepalive_interval: Some(0),
        ssh_tcp_connect_timeout_ms: Some(10_000),
        ssh_auth_ready_timeout_ms: Some(10_000),
        ..Default::default()
    }
}

/// Record the companion credentials of a Mosh / ET session (`protocol`).
/// A Mosh companion waits for [`companion_ready`]: the handshake has not
/// vetted the host yet.
pub fn remember_companion<R: Runtime>(
    app: &AppHandle<R>,
    session_id: &str,
    options: &super::mosh::ExternalSessionOptions,
    protocol: &str,
) {
    // ET through a jump host: Electron runs those stats through ET's own ssh
    // environment; a direct companion would bypass the jump.
    if protocol == "et" && options.jump_hosts.as_ref().is_some_and(|j| !j.is_empty()) {
        return;
    }
    let ready = protocol != "mosh";
    if let Some(t2) = app.try_state::<Transfers2State>() {
        if let Some((_, old)) = t2.companions.remove(session_id) {
            tauri::async_runtime::spawn(async move { old.shutdown().await });
        }
        t2.companions.insert(
            session_id.to_string(),
            Arc::new(Companion {
                options: companion_options(options),
                ready: AtomicBool::new(ready),
                state: tokio::sync::Mutex::new(CompanionConn::default()),
            }),
        );
    }
}

/// The Mosh handshake succeeded: the companion may connect now.
pub fn companion_ready<R: Runtime>(app: &AppHandle<R>, session_id: &str) {
    if let Some(t2) = app.try_state::<Transfers2State>() {
        if let Some(c) = t2.companions.get(session_id) {
            c.ready.store(true, Ordering::SeqCst);
        }
    }
}

/// Never prompts: an unknown / changed host key is accepted only when the
/// user's OpenSSH `known_hosts` holds that exact key (Mosh / ET vet keys
/// through the system ssh); everything else rejects the transport.
struct CompanionCallbacks;

/// Is `fingerprint` (SHA256, no prefix) trusted for `host:port` by the
/// user's `~/.ssh/known_hosts`?
fn system_known_hosts_trust(hostname: &str, port: u16, fingerprint: &str) -> bool {
    let Some(home) = dirs::home_dir() else {
        return false;
    };
    let Ok(text) = std::fs::read_to_string(home.join(".ssh").join("known_hosts")) else {
        return false;
    };
    netcatty_ssh::known_hosts::parse_openssh_known_hosts(&text)
        .iter()
        .any(|kh| {
            kh.matches(hostname, port)
                && kh
                    .fingerprint
                    .as_deref()
                    .is_some_and(|f| f.trim_start_matches("SHA256:") == fingerprint)
        })
}

#[async_trait::async_trait]
impl netcatty_ssh::SshCallbacks for CompanionCallbacks {
    async fn verify_host_key(&self, info: netcatty_ssh::HostKeyInfo) -> netcatty_ssh::HostKeyDecision {
        let trusted = tokio::task::spawn_blocking(move || {
            system_known_hosts_trust(&info.hostname, info.port, &info.fingerprint)
        })
        .await
        .unwrap_or(false);
        if trusted {
            netcatty_ssh::HostKeyDecision::Accept { remember: false }
        } else {
            netcatty_ssh::HostKeyDecision::Reject
        }
    }

    async fn keyboard_interactive(
        &self,
        _name: String,
        _instructions: String,
        _prompts: Vec<netcatty_core::ipc::KeyboardInteractivePrompt>,
    ) -> Option<Vec<String>> {
        None
    }

    async fn request_passphrase(&self, _key_name: String, _invalid: bool) -> Option<String> {
        None
    }
}

/// The stats companion of a Mosh / ET session: reused while alive, dialed
/// lazily (concurrent callers share one attempt), and never retried after
/// an authentication or host-key rejection.
pub(crate) async fn companion_connection<R: Runtime>(
    state: &AppState<R>,
    session_id: &str,
) -> Option<Arc<SshConnection>> {
    let t2 = state.app.try_state::<Transfers2State>()?;
    let companion = t2.companions.get(session_id).map(|c| c.clone())?;
    if !companion.ready.load(Ordering::SeqCst) {
        return None;
    }
    let mut guard = companion.state.lock().await;
    if let Some(conn) = guard.conn.as_ref().filter(|c| !c.is_closed()) {
        return Some(conn.clone());
    }
    guard.conn = None;
    if guard.failed {
        return None;
    }
    let mut options = netcatty_ssh::ConnectOptions::from(&companion.options);
    options.session_id = Some(format!("{session_id}-stats"));
    match netcatty_ssh::connect(options, Arc::new(CompanionCallbacks)).await {
        Ok(conn) => {
            let conn = Arc::new(conn);
            if !state.sessions.contains(session_id) {
                let _ = conn.disconnect().await;
                return None;
            }
            guard.conn = Some(conn.clone());
            Some(conn)
        }
        Err(err) => {
            let permanent = matches!(
                err,
                netcatty_ssh::SshError::AuthFailed(_) | netcatty_ssh::SshError::HostKeyRejected(_)
            );
            tracing::debug!(session_id, permanent, "stats companion connection failed");
            guard.failed |= permanent;
            None
        }
    }
}

// ===========================================================================
// SSH terminal cwd
// ===========================================================================

/// Electron `getSessionPwd` for an SSH terminal: the probe runs on a
/// sibling exec channel; the login shell pid it reports is remembered so
/// later probes target that tab's shell. Without a known pid a connection
/// shared by several terminals is ambiguous and fails closed.
pub(crate) async fn ssh_session_cwd<R: Runtime>(
    state: &AppState<R>,
    session_id: &str,
    connection: &Arc<SshConnection>,
    options: netcatty_sysmgr::cwd::CwdProbeOptions,
) -> Result<String, String> {
    use super::system::exec::{bounded_exec, BoundedError};
    if state.system.is_single_channel(session_id) || super::system::single_channel_banner(connection) {
        return Err(super::system::SINGLE_CHANNEL_ERROR.to_string());
    }
    let t2 = state.app.try_state::<Transfers2State>();
    let known_pid = t2
        .as_ref()
        .and_then(|t| t.shell_pids.get(session_id).map(|p| p.clone()));
    let shared = state
        .sessions
        .session_ids()
        .into_iter()
        .filter(|id| {
            state
                .sessions
                .connection_of(id)
                .is_some_and(|c| Arc::ptr_eq(&c, connection))
        })
        .count();
    if shared > 1 && known_pid.is_none() {
        return Err("Current directory is ambiguous across shared terminal channels".into());
    }
    let command = netcatty_sysmgr::cwd::probe_command(known_pid.as_deref(), &options);
    let result = bounded_exec(
        connection,
        &command,
        None,
        Duration::from_secs(5),
        Duration::from_millis(options.timeout_ms),
        256 * 1024,
    )
    .await;
    let still_owner = state
        .sessions
        .connection_of(session_id)
        .is_some_and(|c| Arc::ptr_eq(&c, connection));
    if !still_owner {
        return Err("Session changed during cwd probe".into());
    }
    let out = match result {
        Ok(out) => out,
        Err(BoundedError::OpenTimeout(_) | BoundedError::RunTimeout(_)) => {
            return Err("Timeout getting pwd".into())
        }
        Err(err) => return Err(err.to_string()),
    };
    let parsed = netcatty_sysmgr::cwd::parse_probe_output(
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
    );
    if let (Some(pid), Some(t2)) = (parsed.login_pid, t2.as_ref()) {
        t2.shell_pids.insert(session_id.to_string(), pid);
    }
    parsed.cwd.ok_or_else(|| "Could not determine cwd".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> StreamTransferOptions {
        serde_json::from_value(json!({
            "transferId": "t1",
            "sourcePath": "/local/a.bin",
            "targetPath": "/srv/a.bin",
            "sourceType": "local",
            "targetType": "sftp",
            "targetSftpId": "s1",
            "totalBytes": 10,
            "lifecycleEpoch": 3
        }))
        .unwrap()
    }

    #[test]
    fn queued_event_mirrors_started_with_queue_state() {
        let ev = queued_event(&options());
        assert_eq!(ev["type"], "queued");
        assert_eq!(ev["transferId"], "t1");
        assert_eq!(ev["lifecycleState"], "queued");
        assert_eq!(ev["controlKind"], "stream");
        assert_eq!(ev["lifecycleEpoch"], 3);
        assert_eq!(ev["totalBytes"], 10);
        assert_eq!(ev["direction"], "upload");
        assert!(ev.get("phase").is_none());
    }

    #[test]
    fn remote_errors_use_electron_wording() {
        assert_eq!(
            RemoteError::Timeout(15_000).to_string(),
            "Remote command timed out after 15 seconds"
        );
        assert_eq!(RemoteError::Cancelled.to_string(), "Upload cancelled");
    }

    #[test]
    fn drag_preparation_checks_metadata() {
        let dir = std::env::temp_dir().join(format!("nc-drag-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f.txt");
        std::fs::write(&file, "original").unwrap();
        let p = |paths: Vec<Value>| DragStartPayload {
            request_id: "r".into(),
            paths,
        };
        let f = file.to_string_lossy().into_owned();
        let d = dir.to_string_lossy().into_owned();
        assert_eq!(
            prepare_drag(&p(vec![json!(f), json!(d), json!(f)])).unwrap(),
            vec![f.clone(), d.clone()]
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "original");
        assert!(prepare_drag(&p(vec![json!(dir.join("missing").to_string_lossy())])).is_err());
        assert!(prepare_drag(&p(vec![json!(42)])).is_err());
        assert!(prepare_drag(&p(vec![json!("relative")])).is_err());
        #[cfg(unix)]
        {
            let link = dir.join("link");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&file, &link).unwrap();
            let l = link.to_string_lossy().into_owned();
            assert_eq!(prepare_drag(&p(vec![json!(l.clone())])).unwrap(), vec![l]);
            std::fs::remove_file(&file).unwrap();
            assert!(prepare_drag(&p(vec![json!(link.to_string_lossy())])).is_err(), "broken link");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn drag_icon_is_a_png() {
        let png = drag_icon_png();
        assert!(png.starts_with(&[0x89, b'P', b'N', b'G']));
    }

    #[test]
    fn companion_options_reuse_the_ssh_endpoint_without_jumps() {
        let o: super::super::mosh::ExternalSessionOptions = serde_json::from_value(json!({
            "hostname": " mosh.example ",
            "username": "alice",
            "password": "pw",
            "port": 2200,
            "etPort": 2022,
            "jumpHosts": [{ "hostname": "jump", "port": 22, "username": "j" }],
            "useSshAgent": true
        }))
        .unwrap();
        let c = companion_options(&o);
        assert_eq!(c.hostname, "mosh.example");
        assert_eq!(c.port, Some(2200));
        assert_eq!(c.username, "alice");
        assert_eq!(c.password.as_deref(), Some("pw"));
        assert!(c.jump_hosts.is_none());
        assert_eq!(c.use_ssh_agent, Some(true));
        assert_eq!(c.ssh_auth_ready_timeout_ms, Some(10_000));
        let with_key: super::super::mosh::ExternalSessionOptions = serde_json::from_value(json!({
            "hostname": "h", "privateKey": "-----BEGIN-----", "useSshAgent": true
        }))
        .unwrap();
        let c = companion_options(&with_key);
        assert_eq!(c.use_ssh_agent, Some(false), "an explicit key suppresses the agent");
        assert_eq!(c.username, "root");
        assert_eq!(c.port, Some(22));
    }
}
