//! ZMODEM (`rz` / `sz`) and serial YMODEM transfers for terminal sessions.
//!
//! Port of `electron/bridges/zmodemHelper.cjs` (+ the wiring in
//! `terminalBridge.cjs`, `sshBridge/startSession.cjs`,
//! `main/registerBridges.cjs`) and `ymodemTransfer.cjs`. See
//! `rust/docs/ipc-zmodem.md`.
//!
//! Hooks into the session pump (`sessions.rs`):
//! * [`filter_output`] sees every raw output chunk before it is decoded and
//!   shown. A per-session [`Sentry`] detects transfers, feeds protocol bytes
//!   to the active session and returns only displayable bytes, so nothing of
//!   a running transfer reaches `netcatty:data`. A YMODEM transfer takes the
//!   raw stream entirely.
//! * [`poll_flush`] releases a withheld partial hex header once its short
//!   deadline passed (the pump is woken through its flow-control `Notify`).
//! * [`session_ended`] cancels whatever was running when a session ends.
//!
//! `session_write` / `session_interrupt` call [`intercept_input`]: during a
//! transfer terminal input is swallowed and Ctrl+C cancels the transfer.
//!
//! Protocol replies and upload data go through one ordered writer task per
//! session (`SessionRegistry::write_input` with raw bytes), which counts
//! outstanding bytes so uploads honour transport backpressure and report
//! delivered (not queued) progress.

use super::CmdResult;
use crate::events;
use crate::state::{AppState, Ctx};
use crate::stream::{InputMeta, SessionInput};
use bytes::Bytes;
use netcatty_zmodem::sentry::{ConsumeResult, Role, Sentry};
use netcatty_zmodem::session::{FileInfo, ReceiveEvent, SendEvent};
use netcatty_zmodem::ymodem::{self, YResult, YmodemError, YmodemIo};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_util::sync::CancellationToken;

/// Renderer events (Electron channel names).
pub mod channels {
    pub const DETECT: &str = "netcatty:zmodem:detect";
    pub const PROGRESS: &str = "netcatty:zmodem:progress";
    pub const COMPLETE: &str = "netcatty:zmodem:complete";
    pub const ERROR: &str = "netcatty:zmodem:error";
    pub const OVERWRITE_REQUEST: &str = "netcatty:zmodem:overwrite-request";
}

const TRANSFER_CANCELLED: &str = "Transfer cancelled";
/// Upload read / send chunk.
const UPLOAD_CHUNK_SIZE: usize = 64 * 1024;
/// Outstanding (queued, not yet written) bytes before the upload pauses.
const UPLOAD_HIGH_WATER: usize = 1024 * 1024;
const UPLOAD_FILE_END_TIMEOUT: Duration = Duration::from_secs(45);
const UPLOAD_BACKPRESSURE_FILE_END_TIMEOUT: Duration = Duration::from_secs(120);
const UPLOAD_SESSION_CLOSE_TIMEOUT: Duration = Duration::from_secs(15);
/// A transport drain without progress for this long fails the upload.
const UPLOAD_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);
const PROGRESS_THROTTLE: Duration = Duration::from_millis(100);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const DRAG_DROP_START_TIMEOUT: Duration = Duration::from_secs(15);
const OVERWRITE_DECISION_TIMEOUT: Duration = Duration::from_secs(120);
const REMOTE_EXEC_TIMEOUT: Duration = Duration::from_secs(10);
const COMMIT_TOKEN: &str = "NETCATTY_ZMODEM_COMMIT";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Managed state: per-session transfer state and pending overwrite prompts.
#[derive(Default)]
pub struct ZmodemState {
    sessions: dashmap::DashMap<String, Arc<SessionZ>>,
    overwrite: dashmap::DashMap<String, oneshot::Sender<OverwriteDecision>>,
    next_id: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OverwriteAction {
    Overwrite,
    Skip,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverwriteDecision {
    pub action: OverwriteAction,
    pub apply_to_rest: bool,
}

enum TransferEvent {
    Rx(ReceiveEvent),
    Tx(SendEvent),
    /// The protocol session ended normally.
    Ended,
    /// The protocol session failed (already aborted by the sentry).
    Failed(String),
}

struct TransferCtl {
    id: u64,
    events: mpsc::UnboundedSender<TransferEvent>,
    cancel: CancellationToken,
}

struct DragDropUpload {
    paths: Vec<PathBuf>,
    names: Vec<String>,
    temp_paths: Vec<PathBuf>,
    timer: CancellationToken,
}

fn remove_temp_files(paths: &[PathBuf]) {
    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

/// Transfer state of one terminal session.
struct SessionZ {
    session_id: String,
    sentry: parking_lot::Mutex<Sentry>,
    writer: mpsc::UnboundedSender<Bytes>,
    outstanding: Arc<AtomicUsize>,
    drained: Arc<Notify>,
    write_failed: Arc<AtomicBool>,
    transfer: parking_lot::Mutex<Option<TransferCtl>>,
    drag_drop: parking_lot::Mutex<Option<DragDropUpload>>,
    /// Raw output sink of a running YMODEM transfer.
    ymodem: parking_lot::Mutex<Option<(mpsc::UnboundedSender<Vec<u8>>, CancellationToken)>>,
    flush_armed: AtomicBool,
}

impl SessionZ {
    fn write(&self, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        self.outstanding.fetch_add(bytes.len(), Ordering::SeqCst);
        if self.writer.send(Bytes::from(bytes)).is_err() {
            self.write_failed.store(true, Ordering::SeqCst);
        }
    }

    fn flush_writes(&self, writes: Vec<Vec<u8>>) {
        for w in writes {
            self.write(w);
        }
    }

    /// Run `f` on the sentry and send whatever it queued.
    fn with_sentry<T>(&self, f: impl FnOnce(&mut Sentry, Instant) -> T) -> T {
        let mut sentry = self.sentry.lock();
        let value = f(&mut sentry, Instant::now());
        let writes = sentry.take_outgoing();
        // Queue while holding the lock so wire order matches call order.
        self.flush_writes(writes);
        value
    }

    fn transfer_active(&self) -> bool {
        self.sentry.lock().is_active() || self.ymodem.lock().is_some()
    }

    /// Ctrl+C after `delay` (stuck `rz` / `sz` after CAN).
    fn schedule_ctrl_c(self: &Arc<Self>, delay: Duration) {
        let entry = self.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(delay).await;
            entry.write(vec![0x03]);
        });
    }

    /// CAN ×8 now and Ctrl+C shortly (`abortRemoteProcess`).
    fn abort_remote_process(self: &Arc<Self>) {
        self.write(netcatty_zmodem::EXTRA_ABORT_BYTES.to_vec());
        self.schedule_ctrl_c(Duration::from_millis(150));
    }

    /// Wait until fewer than `limit` bytes are queued. Fails when the
    /// writer made no progress for [`UPLOAD_DRAIN_TIMEOUT`] or on cancel.
    async fn wait_drain(&self, limit: usize, cancel: &CancellationToken) -> Result<(), String> {
        let mut last = self.outstanding.load(Ordering::SeqCst);
        let mut last_progress = Instant::now();
        loop {
            if self.write_failed.load(Ordering::SeqCst) {
                return Err("Transport closed during upload".into());
            }
            let now_outstanding = self.outstanding.load(Ordering::SeqCst);
            if now_outstanding < limit {
                return Ok(());
            }
            if now_outstanding != last {
                last = now_outstanding;
                last_progress = Instant::now();
            } else if last_progress.elapsed() >= UPLOAD_DRAIN_TIMEOUT {
                return Err("Transport drain timeout".into());
            }
            let notified = self.drained.notified();
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep(PROGRESS_THROTTLE) => {}
                _ = cancel.cancelled() => return Err(TRANSFER_CANCELLED.into()),
            }
        }
    }

    fn take_drag_drop(&self) -> Option<DragDropUpload> {
        let upload = self.drag_drop.lock().take();
        if let Some(u) = &upload {
            u.timer.cancel();
        }
        upload
    }

    fn clear_drag_drop(&self) {
        if let Some(upload) = self.take_drag_drop() {
            remove_temp_files(&upload.temp_paths);
        }
        self.sentry.lock().clear_suppression();
    }
}

impl ZmodemState {
    fn get(&self, session_id: &str) -> Option<Arc<SessionZ>> {
        self.sessions.get(session_id).map(|e| e.clone())
    }

    fn get_or_create<R: Runtime>(&self, app: &AppHandle<R>, session_id: &str) -> Arc<SessionZ> {
        if let Some(entry) = self.get(session_id) {
            return entry;
        }
        let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
        let entry = Arc::new(SessionZ {
            session_id: session_id.to_string(),
            sentry: parking_lot::Mutex::new(Sentry::default()),
            writer: tx,
            outstanding: Arc::new(AtomicUsize::new(0)),
            drained: Arc::new(Notify::new()),
            write_failed: Arc::new(AtomicBool::new(false)),
            transfer: parking_lot::Mutex::new(None),
            drag_drop: parking_lot::Mutex::new(None),
            ymodem: parking_lot::Mutex::new(None),
            flush_armed: AtomicBool::new(false),
        });
        let entry = self
            .sessions
            .entry(session_id.to_string())
            .or_insert(entry)
            .clone();
        // Ordered writer: protocol replies and upload data, in queue order.
        if let Some(state) = app.try_state::<AppState<R>>() {
            let registry = state.sessions.clone();
            let sid = session_id.to_string();
            let outstanding = entry.outstanding.clone();
            let drained = entry.drained.clone();
            let failed = entry.write_failed.clone();
            tauri::async_runtime::spawn(async move {
                while let Some(bytes) = rx.recv().await {
                    let len = bytes.len();
                    if failed.load(Ordering::SeqCst) {
                        outstanding.fetch_sub(len, Ordering::SeqCst);
                        drained.notify_waiters();
                        continue;
                    }
                    let result = registry
                        .write_input(&sid, SessionInput::Bytes(bytes), &InputMeta::automated())
                        .await;
                    if result.is_err() {
                        failed.store(true, Ordering::SeqCst);
                    }
                    outstanding.fetch_sub(len, Ordering::SeqCst);
                    drained.notify_waiters();
                }
            });
        }
        entry
    }
}

// ---------------------------------------------------------------------------
// Event payloads
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DetectEvent<'a> {
    session_id: &'a str,
    transfer_type: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressEvent<'a> {
    session_id: &'a str,
    filename: &'a str,
    transferred: u64,
    total: u64,
    file_index: usize,
    /// `-1` while a download's file count is unknown.
    file_count: i64,
    transfer_type: &'static str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    finalizing: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionOnlyEvent<'a> {
    session_id: &'a str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorEvent<'a> {
    session_id: &'a str,
    error: &'a str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OverwriteRequestEvent<'a> {
    session_id: &'a str,
    request_id: &'a str,
    filename: &'a str,
}

fn emit_error<R: Runtime>(app: &AppHandle<R>, session_id: &str, error: &str) {
    events::emit(app, channels::ERROR, ErrorEvent { session_id, error });
}

// ---------------------------------------------------------------------------
// Pump hooks
// ---------------------------------------------------------------------------

/// Can this chunk start (or be part of the start of) a transfer? Without a
/// sentry for the session, chunks failing this test skip it entirely.
fn might_start_transfer(raw: &[u8]) -> bool {
    raw.contains(&netcatty_zmodem::ZDLE) || raw.last() == Some(&b'*')
}

/// Session-pump hook: replace `raw` with the bytes that may be shown.
pub fn filter_output<R: Runtime>(app: &AppHandle<R>, session_id: &str, raw: &mut Vec<u8>) {
    let Some(state) = app.try_state::<ZmodemState>() else {
        return;
    };
    let entry = match state.get(session_id) {
        Some(entry) => entry,
        None if might_start_transfer(raw) => state.get_or_create(app, session_id),
        None => return,
    };
    if let Some((tx, _)) = entry.ymodem.lock().as_ref() {
        let _ = tx.send(std::mem::take(raw));
        return;
    }
    let (result, deadline) = {
        let mut sentry = entry.sentry.lock();
        let result = sentry.consume(raw, Instant::now());
        let writes = sentry.take_outgoing();
        entry.flush_writes(writes);
        (result, sentry.next_deadline())
    };
    let ConsumeResult {
        terminal,
        detected,
        rx_events,
        tx_events,
        ended,
        error,
        interrupt,
    } = result;
    *raw = terminal;

    if let Some(role) = detected {
        start_transfer(app, &state, &entry, role);
    }
    let sender = entry.transfer.lock().as_ref().map(|t| t.events.clone());
    if let Some(tx) = sender {
        for e in rx_events {
            let _ = tx.send(TransferEvent::Rx(e));
        }
        for e in tx_events {
            let _ = tx.send(TransferEvent::Tx(e));
        }
        if ended {
            let _ = tx.send(TransferEvent::Ended);
        }
        if let Some(message) = &error {
            let _ = tx.send(TransferEvent::Failed(message.clone()));
        }
    } else if let Some(message) = &error {
        tracing::debug!(session_id, %message, "zmodem detection rejected");
    }
    if interrupt {
        entry.schedule_ctrl_c(Duration::from_millis(150));
    }
    if let Some(deadline) = deadline {
        arm_flush(app, &entry, deadline);
    }
}

/// Wake the session pump at `deadline` so [`poll_flush`] can release a
/// withheld fragment.
fn arm_flush<R: Runtime>(app: &AppHandle<R>, entry: &Arc<SessionZ>, deadline: Instant) {
    if entry.flush_armed.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    let entry = entry.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        entry.flush_armed.store(false, Ordering::SeqCst);
        if let Some(state) = app.try_state::<AppState<R>>() {
            if let Some(flags) = state.sessions.flags_of(&entry.session_id) {
                flags.wake.notify_one();
            }
        }
    });
}

/// Session-pump hook (wake branch): bytes of an expired withheld fragment.
pub fn poll_flush<R: Runtime>(app: &AppHandle<R>, session_id: &str) -> Vec<u8> {
    let Some(state) = app.try_state::<ZmodemState>() else {
        return Vec::new();
    };
    let Some(entry) = state.get(session_id) else {
        return Vec::new();
    };
    let (bytes, deadline) = {
        let mut sentry = entry.sentry.lock();
        (sentry.flush_expired(Instant::now()), sentry.next_deadline())
    };
    if let Some(deadline) = deadline {
        arm_flush(app, &entry, deadline);
    }
    bytes
}

/// Session-registry hook: the session is gone; stop everything silently
/// (the renderer already received `netcatty:exit`).
pub fn session_ended<R: Runtime>(app: &AppHandle<R>, session_id: &str) {
    let Some(state) = app.try_state::<ZmodemState>() else {
        return;
    };
    let Some((_, entry)) = state.sessions.remove(session_id) else {
        return;
    };
    if let Some(t) = entry.transfer.lock().take() {
        t.cancel.cancel();
    }
    if let Some((_, cancel)) = entry.ymodem.lock().take() {
        cancel.cancel();
    }
    entry.clear_drag_drop();
}

/// Terminal input during a transfer is swallowed; Ctrl+C cancels it.
/// Returns `true` when the input must not reach the session.
pub fn intercept_input<R: Runtime>(app: &AppHandle<R>, session_id: &str, data: &[u8]) -> bool {
    let Some(state) = app.try_state::<ZmodemState>() else {
        return false;
    };
    let Some(entry) = state.get(session_id) else {
        return false;
    };
    let ymodem = entry.ymodem.lock().as_ref().map(|(_, c)| c.clone());
    if let Some(cancel) = ymodem {
        if data == b"\x03" {
            entry.write(ymodem::CANCEL_SEQUENCE.to_vec());
            cancel.cancel();
        }
        return true;
    }
    if entry.sentry.lock().is_active() {
        if data == b"\x03" {
            cancel_transfer(app, &entry, true);
        }
        return true;
    }
    false
}

/// Finish transfer `id` once: report `outcome` (None = silent).
fn finish_transfer<R: Runtime>(
    app: &AppHandle<R>,
    entry: &SessionZ,
    id: u64,
    outcome: Option<Result<(), String>>,
) {
    {
        let mut transfer = entry.transfer.lock();
        if transfer.as_ref().map(|t| t.id) != Some(id) {
            return;
        }
        if let Some(t) = transfer.take() {
            t.cancel.cancel();
        }
    }
    match outcome {
        Some(Ok(())) => events::emit(
            app,
            channels::COMPLETE,
            SessionOnlyEvent {
                session_id: &entry.session_id,
            },
        ),
        Some(Err(message)) => emit_error(app, &entry.session_id, &message),
        None => {}
    }
}

/// User cancel (`cancelZmodem`, Ctrl+C): abort, CAN, cooldown; for uploads
/// also ignore stray restarts briefly and follow up with Ctrl+C.
fn cancel_transfer<R: Runtime>(app: &AppHandle<R>, entry: &Arc<SessionZ>, interrupt: bool) {
    let role = entry.with_sentry(|s, now| {
        let role = s.cancel(now);
        if role == Some(Role::Send) {
            s.ignore_detection_for(Duration::from_millis(300), now);
        }
        role
    });
    if let Some(role) = role {
        if role == Role::Send {
            entry.schedule_ctrl_c(Duration::from_millis(120));
        }
        let id = entry.transfer.lock().as_ref().map(|t| t.id);
        match id {
            Some(id) => finish_transfer(app, entry, id, Some(Err(TRANSFER_CANCELLED.into()))),
            None => emit_error(app, &entry.session_id, TRANSFER_CANCELLED),
        }
    } else if interrupt && entry.drag_drop.lock().is_some() {
        interrupt_pending_drag_drop(entry);
    }
    entry.clear_drag_drop();
}

/// The drag-drop `rz` never started: stop it on the remote.
fn interrupt_pending_drag_drop(entry: &Arc<SessionZ>) {
    entry.with_sentry(|s, now| {
        s.ignore_detection_for(Duration::from_millis(1000), now);
        s.send_extra_abort();
    });
    entry.schedule_ctrl_c(Duration::from_millis(120));
}

// ---------------------------------------------------------------------------
// Transfers
// ---------------------------------------------------------------------------

struct TransferCtx<R: Runtime> {
    app: AppHandle<R>,
    entry: Arc<SessionZ>,
    events: mpsc::UnboundedReceiver<TransferEvent>,
    cancel: CancellationToken,
}

fn start_transfer<R: Runtime>(
    app: &AppHandle<R>,
    state: &ZmodemState,
    entry: &Arc<SessionZ>,
    role: Role,
) {
    let id = state.next_id.fetch_add(1, Ordering::SeqCst) + 1;
    let (tx, rx) = mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    // A previous transfer task still finishing (e.g. flushing files) is
    // superseded silently.
    if let Some(old) = entry.transfer.lock().replace(TransferCtl {
        id,
        events: tx,
        cancel: cancel.clone(),
    }) {
        old.cancel.cancel();
    }
    tracing::info!(session_id = %entry.session_id, transfer = role.transfer_type(), "zmodem transfer detected");
    events::emit(
        app,
        channels::DETECT,
        DetectEvent {
            session_id: &entry.session_id,
            transfer_type: role.transfer_type(),
        },
    );
    let ctx = TransferCtx {
        app: app.clone(),
        entry: entry.clone(),
        events: rx,
        cancel,
    };
    tauri::async_runtime::spawn(async move {
        let app = ctx.app.clone();
        let entry = ctx.entry.clone();
        let cancel = ctx.cancel.clone();
        let outcome = match role {
            Role::Receive => run_download(ctx).await,
            Role::Send => run_upload(ctx).await,
        };
        if cancel.is_cancelled() {
            // Cancelled by the user (already reported) or the session ended.
            finish_transfer(&app, &entry, id, None);
            return;
        }
        if outcome.is_err() {
            // Make sure the protocol session is gone (dialog cancel, timeouts).
            let role = entry.with_sentry(|s, now| s.cancel(now));
            if role.is_some() {
                entry.schedule_ctrl_c(Duration::from_millis(150));
            }
        }
        finish_transfer(&app, &entry, id, Some(outcome));
    });
}

async fn pick_folder<R: Runtime>(app: &AppHandle<R>, title: &str) -> Option<PathBuf> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = oneshot::channel();
    app.dialog()
        .file()
        .set_title(title)
        .set_can_create_directories(true)
        .pick_folder(move |path| {
            let _ = tx.send(path);
        });
    rx.await.ok().flatten().and_then(|p| p.into_path().ok())
}

async fn pick_files<R: Runtime>(app: &AppHandle<R>, title: &str) -> Vec<PathBuf> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = oneshot::channel();
    app.dialog().file().set_title(title).pick_files(move |paths| {
        let _ = tx.send(paths);
    });
    rx.await
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| p.into_path().ok())
        .collect()
}

/// File name of a remote offer, reduced to a safe basename.
fn safe_download_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("").trim();
    if base.is_empty() || base == "." || base == ".." {
        format!("untitled_{}", netcatty_core::ids::now_ms())
    } else {
        base.to_string()
    }
}

/// `name`, `name (1).ext`, … — never overwrite an existing download.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string());
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    (1..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .unwrap_or(first)
}

struct DownloadFile {
    file: Option<tokio::fs::File>,
    path: PathBuf,
    name: String,
    size: u64,
    received: u64,
    index: usize,
    completed: bool,
}

/// Remote `sz`: save every offered file into a directory the user picks.
async fn run_download<R: Runtime>(mut ctx: TransferCtx<R>) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    let session_id = ctx.entry.session_id.clone();
    // The session already answered ZRQINIT (so `sz` does not time out while
    // the dialog is open); offers wait in the queue until a folder is chosen.
    let dir = tokio::select! {
        dir = pick_folder(&ctx.app, "Select download directory (ZMODEM)") => dir,
        _ = ctx.cancel.cancelled() => return Err(TRANSFER_CANCELLED.into()),
    };
    let Some(dir) = dir else {
        return Err(TRANSFER_CANCELLED.into());
    };

    let mut files: Vec<DownloadFile> = Vec::new();
    let mut last_progress = Instant::now() - PROGRESS_THROTTLE;
    let outcome: Result<(), String> = loop {
        let event = tokio::select! {
            e = ctx.events.recv() => e,
            _ = ctx.cancel.cancelled() => break Err(TRANSFER_CANCELLED.into()),
        };
        let Some(event) = event else {
            break Err(TRANSFER_CANCELLED.into());
        };
        match event {
            TransferEvent::Rx(ReceiveEvent::Offer(info)) => {
                let name = safe_download_name(&info.name);
                let size = info.size.unwrap_or(0);
                let index = files.len();
                events::emit(
                    &ctx.app,
                    channels::PROGRESS,
                    ProgressEvent {
                        session_id: &session_id,
                        filename: &name,
                        transferred: 0,
                        total: size,
                        file_index: index,
                        file_count: -1,
                        transfer_type: "download",
                        finalizing: false,
                    },
                );
                let path = unique_path(&dir, &name);
                let file = match tokio::fs::File::create(&path).await {
                    Ok(f) => f,
                    Err(err) => break Err(err.to_string()),
                };
                files.push(DownloadFile {
                    file: Some(file),
                    path,
                    name,
                    size,
                    received: 0,
                    index,
                    completed: false,
                });
                if let Err(err) = ctx.entry.with_sentry(|s, now| s.rx_accept(0, now)) {
                    break Err(err.to_string());
                }
            }
            TransferEvent::Rx(ReceiveEvent::Data(bytes)) => {
                let Some(current) = files.last_mut() else {
                    continue;
                };
                let Some(file) = current.file.as_mut() else {
                    continue;
                };
                if let Err(err) = file.write_all(&bytes).await {
                    break Err(err.to_string());
                }
                current.received += bytes.len() as u64;
                if last_progress.elapsed() >= PROGRESS_THROTTLE {
                    last_progress = Instant::now();
                    events::emit(
                        &ctx.app,
                        channels::PROGRESS,
                        ProgressEvent {
                            session_id: &session_id,
                            filename: &current.name,
                            transferred: current.received,
                            total: current.size,
                            file_index: current.index,
                            file_count: -1,
                            transfer_type: "download",
                            finalizing: false,
                        },
                    );
                }
            }
            TransferEvent::Rx(ReceiveEvent::FileEnd) => {
                if let Some(current) = files.last_mut() {
                    if let Some(mut file) = current.file.take() {
                        if let Err(err) = file.flush().await {
                            break Err(err.to_string());
                        }
                    }
                    current.completed = true;
                }
            }
            TransferEvent::Rx(ReceiveEvent::SessionEnd) | TransferEvent::Ended => break Ok(()),
            TransferEvent::Failed(message) => break Err(message),
            TransferEvent::Tx(_) => {}
        }
    };
    // Partial downloads are removed.
    for f in &mut files {
        f.file.take();
        if !f.completed {
            let _ = tokio::fs::remove_file(&f.path).await;
        }
    }
    outcome
}

/// Wait for the next session event, bounded by `timeout`.
async fn next_event<R: Runtime>(
    ctx: &mut TransferCtx<R>,
    timeout: Duration,
    what: &str,
) -> Result<TransferEvent, String> {
    tokio::select! {
        e = ctx.events.recv() => e.ok_or_else(|| TRANSFER_CANCELLED.to_string()),
        _ = ctx.cancel.cancelled() => Err(TRANSFER_CANCELLED.into()),
        _ = tokio::time::sleep(timeout) => {
            // Stuck receiver: abort it so the terminal recovers.
            let entry = ctx.entry.clone();
            entry.with_sentry(|s, now| {
                s.cancel(now);
                s.ignore_detection_for(Duration::from_millis(1000), now);
            });
            entry.abort_remote_process();
            Err(what.to_string())
        }
    }
}

/// Keep `rz` alive (ZSINIT every 5 s) while `fut` runs.
async fn with_keepalive<R: Runtime, T>(
    ctx: &TransferCtx<R>,
    fut: impl std::future::Future<Output = T>,
) -> T {
    tokio::pin!(fut);
    let mut ticker = tokio::time::interval(KEEPALIVE_INTERVAL);
    ticker.tick().await;
    loop {
        tokio::select! {
            value = &mut fut => return value,
            _ = ticker.tick() => {
                let _ = ctx.entry.with_sentry(|s, now| s.tx_keepalive(now));
            }
        }
    }
}

struct UploadItem {
    path: PathBuf,
    name: String,
    size: u64,
    mtime: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct UploadPlan {
    offer: Vec<usize>,
    remove: Vec<usize>,
    aborted: bool,
}

/// `buildUploadPlan`: ask once per conflicting name (in order); "apply to
/// rest" reuses the answer; cancel aborts everything.
async fn build_upload_plan<F, Fut>(names: &[String], existing: &[String], mut decide: F) -> UploadPlan
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = OverwriteDecision>,
{
    let mut plan = UploadPlan::default();
    let mut bulk: Option<OverwriteAction> = None;
    for (i, name) in names.iter().enumerate() {
        if !existing.contains(name) {
            plan.offer.push(i);
            continue;
        }
        let action = match bulk {
            Some(a) => a,
            None => {
                let d = decide(name.clone()).await;
                if d.apply_to_rest && d.action != OverwriteAction::Cancel {
                    bulk = Some(d.action);
                }
                d.action
            }
        };
        match action {
            OverwriteAction::Cancel => {
                return UploadPlan {
                    aborted: true,
                    ..Default::default()
                }
            }
            OverwriteAction::Overwrite => {
                plan.remove.push(i);
                plan.offer.push(i);
            }
            OverwriteAction::Skip => {}
        }
    }
    plan
}

/// `buildModeRestores`: `{ path, mode }` for overwritten files whose mode
/// was captured, de-duplicated.
fn build_mode_restores(
    dir: &str,
    names: &[String],
    indices: &[usize],
    modes: &std::collections::HashMap<String, String>,
) -> Vec<(String, String)> {
    let base = dir.trim_end_matches('/');
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for &i in indices {
        let name = &names[i];
        let Some(mode) = modes.get(name) else {
            continue;
        };
        let target = format!("{base}/{name}");
        if seen.insert(target.clone()) {
            out.push((target, mode.clone()));
        }
    }
    out
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn valid_mode(mode: &str) -> bool {
    (3..=4).contains(&mode.len()) && mode.bytes().all(|b| (b'0'..=b'7').contains(&b))
}

struct ConflictProbe {
    dir: String,
    existing: Vec<String>,
    modes: std::collections::HashMap<String, String>,
}

const PROBE_SCRIPT: &str = r#"SELF=$$
find_login_shell() {
  ps -e -o pid= -o ppid= -o tty= -o comm= 2>/dev/null | awk -v pp="$1" -v self="$SELF" '
    $1 != self && $2 == pp && $4 ~ /^-?(ba|z|fi|k|da|a)?sh$/ {
      if ($3 != "?") { print $1; found=1; exit }
      if (any == "") any=$1
    }
    END { if (!found && any != "") print any }'
}
find_fg_leaf() {
  ps -e -o pid= -o ppid= -o stat= -o comm= 2>/dev/null | awk -v start="$1" '
    { pp[$1]=$2; st[$1]=$3; ord[NR]=$1 }
    function depth(p,  d){ d=0; while(p!="" && d<64){ if(p==start) return d; p=pp[p]; d++ } return -1 }
    END { best=-1; bp=""; for(i=1;i<=NR;i++){ p=ord[i];
      if(index(st[p],"+")==0) continue; d=depth(p); if(d<0) continue;
      if(d>best){best=d; bp=p} } print bp }'
}
login=$(find_login_shell "$PPID")
[ -n "$login" ] || exit 0
leaf=$(find_fg_leaf "$login")
[ -n "$leaf" ] || leaf="$login"
dir=$(readlink /proc/$leaf/cwd 2>/dev/null)
[ -n "$dir" ] || exit 0
printf 'DIR\t%s\n' "$dir"
cd "$dir" 2>/dev/null || exit 0
for n in "$@"; do
  [ -e "$n" ] || continue
  m=$(stat -c %a -- "$n" 2>/dev/null || stat -f %Lp -- "$n" 2>/dev/null)
  printf 'EXIST\t%s\t%s\n' "$n" "$m"
done"#;

fn parse_probe(output: &str) -> Option<ConflictProbe> {
    let mut dir = None;
    let mut existing = Vec::new();
    let mut modes = std::collections::HashMap::new();
    for line in output.split('\n') {
        let mut parts = line.split('\t');
        match (parts.next(), parts.next(), parts.next()) {
            (Some("DIR"), Some(d), _) => dir = Some(d.to_string()),
            (Some("EXIST"), Some(name), mode) if !name.is_empty() => {
                existing.push(name.to_string());
                if let Some(mode) = mode.filter(|m| valid_mode(m)) {
                    modes.insert(name.to_string(), mode.to_string());
                }
            }
            _ => {}
        }
    }
    dir.map(|dir| ConflictProbe {
        dir,
        existing,
        modes,
    })
}

/// Resolve the directory the running `rz` writes to (its cwd) and which of
/// `names` exist there (SSH sessions only, never single-channel ones).
async fn probe_conflicts(conn: &netcatty_ssh::SshConnection, names: &[String]) -> Option<ConflictProbe> {
    let argv: Vec<String> = names.iter().map(|n| shell_quote(n)).collect();
    let cmd = format!("exec sh -c {} sh {}", shell_quote(PROBE_SCRIPT), argv.join(" "));
    let out = conn.exec(&cmd, Some(REMOTE_EXEC_TIMEOUT)).await.ok()?;
    parse_probe(&out.stdout_lossy())
}

/// Run a parameterised script that only proceeds after reading the commit
/// token on stdin (so a half-opened channel never acts).
async fn exec_committed(conn: &netcatty_ssh::SshConnection, script: &str, args: &[String]) {
    let guarded = format!(
        "IFS= read -r token || exit 125; [ \"$token\" = {} ] || exit 125; {script}",
        shell_quote(COMMIT_TOKEN)
    );
    let cmd = format!("exec sh -c {} sh {}", shell_quote(&guarded), args.join(" "));
    let stdin = format!("{COMMIT_TOKEN}\n").into_bytes();
    let _ = conn.exec_with_stdin(&cmd, stdin, Some(REMOTE_EXEC_TIMEOUT)).await;
}

async fn remove_remote_files(conn: &netcatty_ssh::SshConnection, paths: &[String]) {
    if paths.is_empty() {
        return;
    }
    let args: Vec<String> = paths.iter().map(|p| shell_quote(p)).collect();
    exec_committed(conn, "rm -f -- \"$@\"", &args).await;
}

async fn restore_remote_modes(conn: &netcatty_ssh::SshConnection, entries: &[(String, String)]) {
    let mut args = Vec::new();
    for (path, mode) in entries {
        if valid_mode(mode) {
            args.push(shell_quote(mode));
            args.push(shell_quote(path));
        }
    }
    if args.is_empty() {
        return;
    }
    exec_committed(
        conn,
        "while [ \"$#\" -ge 2 ]; do chmod \"$1\" \"$2\" 2>/dev/null; shift 2; done",
        &args,
    )
    .await;
}

async fn request_overwrite<R: Runtime>(
    app: &AppHandle<R>,
    session_id: &str,
    filename: String,
    cancel: CancellationToken,
) -> OverwriteDecision {
    let Some(state) = app.try_state::<ZmodemState>() else {
        return OverwriteDecision {
            action: OverwriteAction::Skip,
            apply_to_rest: false,
        };
    };
    let request_id = netcatty_core::ids::new_id();
    let (tx, rx) = oneshot::channel();
    state.overwrite.insert(request_id.clone(), tx);
    events::emit(
        app,
        channels::OVERWRITE_REQUEST,
        OverwriteRequestEvent {
            session_id,
            request_id: &request_id,
            filename: &filename,
        },
    );
    let skip = OverwriteDecision {
        action: OverwriteAction::Skip,
        apply_to_rest: false,
    };
    let decision = tokio::select! {
        d = rx => d.unwrap_or(skip),
        _ = tokio::time::sleep(OVERWRITE_DECISION_TIMEOUT) => skip,
        _ = cancel.cancelled() => OverwriteDecision { action: OverwriteAction::Cancel, apply_to_rest: false },
    };
    state.overwrite.remove(&request_id);
    decision
}

/// Remote `rz`: offer the drag-dropped files or the ones the user picks.
async fn run_upload<R: Runtime>(mut ctx: TransferCtx<R>) -> Result<(), String> {
    let drag = ctx.entry.take_drag_drop();
    let temp_paths = drag.as_ref().map(|d| d.temp_paths.clone()).unwrap_or_default();
    let result = upload_inner(&mut ctx, drag).await;
    remove_temp_files(&temp_paths);
    result
}

async fn upload_inner<R: Runtime>(
    ctx: &mut TransferCtx<R>,
    drag: Option<DragDropUpload>,
) -> Result<(), String> {
    let is_drag_drop = drag.is_some();
    let (paths, names) = match drag {
        Some(d) => (d.paths, d.names),
        None => {
            let app = ctx.app.clone();
            let cancel = ctx.cancel.clone();
            let picked = with_keepalive(ctx, async {
                tokio::select! {
                    p = pick_files(&app, "Select files to upload (ZMODEM)") => p,
                    _ = cancel.cancelled() => Vec::new(),
                }
            })
            .await;
            if picked.is_empty() {
                return Err(TRANSFER_CANCELLED.into());
            }
            let names = picked
                .iter()
                .map(|p| {
                    p.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "file".into())
                })
                .collect();
            (picked, names)
        }
    };
    let mut items = Vec::with_capacity(paths.len());
    for (path, name) in paths.into_iter().zip(names) {
        let meta = tokio::fs::metadata(&path)
            .await
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        items.push(UploadItem {
            path,
            name,
            size: meta.len(),
            mtime,
        });
    }
    let names: Vec<String> = items.iter().map(|i| i.name.clone()).collect();

    // Conflict handling (SSH only). Drag-drop starts `rz -y`, which
    // replaces files in place, so it never pre-deletes.
    let mut plan = UploadPlan {
        offer: (0..items.len()).collect(),
        ..Default::default()
    };
    let mut probe_info: Option<ConflictProbe> = None;
    let conn = if is_drag_drop {
        None
    } else {
        ctx.app.try_state::<AppState<R>>().and_then(|s| {
            if s.system.is_single_channel(&ctx.entry.session_id) {
                None
            } else {
                s.sessions.connection_of(&ctx.entry.session_id)
            }
        })
    };
    if let Some(conn) = &conn {
        let probe = with_keepalive(ctx, probe_conflicts(conn, &names)).await;
        if let Some(probe) = probe.filter(|p| !p.existing.is_empty()) {
            let app = ctx.app.clone();
            let sid = ctx.entry.session_id.clone();
            let cancel = ctx.cancel.clone();
            let existing = probe.existing.clone();
            plan = with_keepalive(
                ctx,
                build_upload_plan(&names, &existing, |name| {
                    request_overwrite(&app, &sid, name, cancel.clone())
                }),
            )
            .await;
            if ctx.cancel.is_cancelled() || plan.aborted {
                return Err(TRANSFER_CANCELLED.into());
            }
            if !plan.remove.is_empty() {
                let base = probe.dir.trim_end_matches('/').to_string();
                let mut targets: Vec<String> =
                    plan.remove.iter().map(|&i| format!("{base}/{}", names[i])).collect();
                targets.dedup();
                with_keepalive(ctx, remove_remote_files(conn, &targets)).await;
            }
            probe_info = Some(probe);
        }
    }

    let offers: Vec<usize> = plan.offer.clone();
    let mut skipped: Vec<usize> = Vec::new();
    let mut saw_backpressure = false;
    let file_end_timeout = |bp: bool| {
        if bp {
            UPLOAD_BACKPRESSURE_FILE_END_TIMEOUT
        } else {
            UPLOAD_FILE_END_TIMEOUT
        }
    };
    for (pos, &idx) in offers.iter().enumerate() {
        if ctx.cancel.is_cancelled() {
            return Err(TRANSFER_CANCELLED.into());
        }
        let item = &items[idx];
        let bytes_remaining: u64 = offers[pos..].iter().map(|&i| items[i].size).sum();
        let app = ctx.app.clone();
        let sid = ctx.entry.session_id.clone();
        let emit = |transferred: u64, finalizing: bool| {
            events::emit(
                &app,
                channels::PROGRESS,
                ProgressEvent {
                    session_id: &sid,
                    filename: &item.name,
                    transferred,
                    total: item.size,
                    file_index: pos,
                    file_count: offers.len() as i64,
                    transfer_type: "upload",
                    finalizing,
                },
            )
        };
        emit(0, false);
        let info = FileInfo {
            name: item.name.clone(),
            size: Some(item.size),
            mtime: item.mtime,
            mode: None,
            files_remaining: Some((offers.len() - pos) as u64),
            bytes_remaining: Some(bytes_remaining),
        };
        ctx.entry
            .with_sentry(|s, now| s.tx_offer(&info, now))
            .map_err(|e| e.to_string())?;
        let offer_timeout_msg = format!(
            "Remote did not respond to the offer for {}. The upload was stopped so the terminal can recover.",
            item.name
        );
        let accepted_at = loop {
            match next_event(ctx, file_end_timeout(saw_backpressure), &offer_timeout_msg).await? {
                TransferEvent::Tx(SendEvent::OfferAccepted { offset }) => break Some(offset),
                TransferEvent::Tx(SendEvent::OfferSkipped) => break None,
                TransferEvent::Failed(message) => return Err(message),
                TransferEvent::Ended => return Err(TRANSFER_CANCELLED.into()),
                _ => {}
            }
        };
        let Some(offset) = accepted_at else {
            skipped.push(idx);
            continue;
        };
        send_file(ctx, item, offset, &emit, &mut saw_backpressure, file_end_timeout).await?;
    }

    let restore = |skipped: &[usize]| -> Vec<(String, String)> {
        let Some(probe) = &probe_info else {
            return Vec::new();
        };
        let indices: Vec<usize> = plan
            .remove
            .iter()
            .copied()
            .filter(|i| !skipped.contains(i))
            .collect();
        build_mode_restores(&probe.dir, &names, &indices, &probe.modes)
    };

    if !skipped.is_empty() {
        let restores = restore(&skipped);
        ctx.entry.with_sentry(|s, now| s.cancel(now));
        ctx.entry.abort_remote_process();
        if let Some(conn) = &conn {
            restore_remote_modes(conn, &restores).await;
        }
        let listed: Vec<&str> = skipped.iter().map(|&i| names[i].as_str()).collect();
        return Err(if skipped.len() == offers.len() {
            format!(
                "Remote protected existing files and skipped the upload (not overwritten): {}",
                listed.join(", ")
            )
        } else {
            format!("Remote skipped some files (not overwritten): {}", listed.join(", "))
        });
    }

    ctx.entry
        .with_sentry(|s, now| s.tx_close(now))
        .map_err(|e| e.to_string())?;
    loop {
        match next_event(
            ctx,
            UPLOAD_SESSION_CLOSE_TIMEOUT,
            "Remote did not finish the ZMODEM upload session in time. The upload was stopped so the terminal can recover.",
        )
        .await?
        {
            TransferEvent::Tx(SendEvent::Closed) | TransferEvent::Ended => break,
            TransferEvent::Failed(message) => return Err(message),
            _ => {}
        }
    }
    if let Some(conn) = &conn {
        restore_remote_modes(conn, &restore(&[])).await;
    }
    Ok(())
}

/// Stream one accepted file, honouring ZRPOS repositioning and transport
/// backpressure, then wait for the receiver's confirmation.
async fn send_file<R: Runtime>(
    ctx: &mut TransferCtx<R>,
    item: &UploadItem,
    start: u32,
    emit: &impl Fn(u64, bool),
    saw_backpressure: &mut bool,
    file_end_timeout: impl Fn(bool) -> Duration,
) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(&item.path)
        .await
        .map_err(|e| e.to_string())?;
    let mut reposition = Some(start);
    let mut first = true;
    let mut sent: u64 = 0;
    let mut displayed: u64 = 0;
    let mut last_progress = Instant::now();
    let mut buf = vec![0u8; UPLOAD_CHUNK_SIZE];
    let confirm_msg = format!(
        "Remote did not confirm receiving {}. The upload was stopped so the terminal can recover.",
        item.name
    );
    let base_outstanding = ctx.entry.outstanding.load(Ordering::SeqCst);
    let delivered = |sent: u64, displayed: &mut u64, entry: &SessionZ| -> u64 {
        let outstanding = entry
            .outstanding
            .load(Ordering::SeqCst)
            .saturating_sub(base_outstanding) as u64;
        *displayed = sent.saturating_sub(outstanding).max(*displayed).min(item.size);
        *displayed
    };
    loop {
        if let Some(offset) = reposition.take() {
            file.seek(std::io::SeekFrom::Start(u64::from(offset)))
                .await
                .map_err(|e| e.to_string())?;
            sent = u64::from(offset);
            // The first position came with ZRPOS; later ones restart ZDATA.
            if !std::mem::take(&mut first) {
                ctx.entry
                    .with_sentry(|s, now| s.tx_reposition(offset, now))
                    .map_err(|e| e.to_string())?;
            }
        }
        // Inbound control frames (ZRPOS, failures) between chunks.
        while let Ok(event) = ctx.events.try_recv() {
            match event {
                TransferEvent::Tx(SendEvent::Reposition { offset }) => reposition = Some(offset),
                TransferEvent::Failed(message) => return Err(message),
                TransferEvent::Ended => return Err(TRANSFER_CANCELLED.into()),
                _ => {}
            }
        }
        if reposition.is_some() {
            continue;
        }
        if ctx.cancel.is_cancelled() {
            return Err(TRANSFER_CANCELLED.into());
        }
        let n = file.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            ctx.entry
                .with_sentry(|s, now| s.tx_send_data(&[], true, now))
                .map_err(|e| e.to_string())?;
            emit(item.size, true);
            match wait_file_ack(ctx, file_end_timeout(*saw_backpressure), &confirm_msg).await? {
                Some(offset) => {
                    reposition = Some(offset);
                    continue;
                }
                None => return Ok(()),
            }
        }
        ctx.entry
            .with_sentry(|s, now| s.tx_send_data(&buf[..n], false, now))
            .map_err(|e| e.to_string())?;
        sent += n as u64;
        if last_progress.elapsed() >= PROGRESS_THROTTLE {
            last_progress = Instant::now();
            emit(delivered(sent, &mut displayed, &ctx.entry), false);
        }
        if ctx.entry.outstanding.load(Ordering::SeqCst) >= UPLOAD_HIGH_WATER {
            *saw_backpressure = true;
            // Parked on backpressure: keep progress moving with the bytes
            // the transport actually took.
            let entry = ctx.entry.clone();
            let cancel = ctx.cancel.clone();
            let drain = entry.wait_drain(UPLOAD_HIGH_WATER / 2, &cancel);
            tokio::pin!(drain);
            let mut ticker = tokio::time::interval(PROGRESS_THROTTLE);
            let result = loop {
                tokio::select! {
                    r = &mut drain => break r,
                    _ = ticker.tick() => emit(delivered(sent, &mut displayed, &entry), false),
                }
            };
            if let Err(message) = result {
                if message != TRANSFER_CANCELLED {
                    entry.with_sentry(|s, now| {
                        s.cancel(now);
                        s.ignore_detection_for(Duration::from_millis(1000), now);
                    });
                    entry.abort_remote_process();
                }
                return Err(message);
            }
        }
        tokio::task::yield_now().await;
    }
}

/// After ZEOF: `Ok(None)` when the receiver confirmed the file,
/// `Ok(Some(offset))` when it asked for a resend.
async fn wait_file_ack<R: Runtime>(
    ctx: &mut TransferCtx<R>,
    timeout: Duration,
    message: &str,
) -> Result<Option<u32>, String> {
    loop {
        match next_event(ctx, timeout, message).await? {
            TransferEvent::Tx(SendEvent::FileReceived) => return Ok(None),
            TransferEvent::Tx(SendEvent::Reposition { offset }) => return Ok(Some(offset)),
            TransferEvent::Failed(message) => return Err(message),
            TransferEvent::Ended => return Err(TRANSFER_CANCELLED.into()),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelOptions {
    #[serde(default)]
    pub interrupt: Option<bool>,
}

/// `cancelZmodem(sessionId, options)`.
#[tauri::command]
pub async fn zmodem_cancel<R: Runtime>(
    app: AppHandle<R>,
    session_id: String,
    options: Option<CancelOptions>,
) -> CmdResult<()> {
    let Some(state) = app.try_state::<ZmodemState>() else {
        return Ok(());
    };
    if let Some(entry) = state.get(&session_id) {
        let interrupt = options.and_then(|o| o.interrupt) != Some(false);
        cancel_transfer(&app, &entry, interrupt);
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverwriteResponse {
    pub request_id: String,
    pub action: OverwriteAction,
    #[serde(default)]
    pub apply_to_rest: bool,
}

/// `respondZmodemOverwrite({ requestId, action, applyToRest })`.
#[tauri::command]
pub fn zmodem_overwrite_response<R: Runtime>(app: AppHandle<R>, payload: OverwriteResponse) {
    if let Some(state) = app.try_state::<ZmodemState>() {
        if let Some((_, tx)) = state.overwrite.remove(&payload.request_id) {
            let _ = tx.send(OverwriteDecision {
                action: payload.action,
                apply_to_rest: payload.apply_to_rest,
            });
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DragDropFile {
    pub path: String,
    #[serde(default)]
    pub remote_name: Option<String>,
    /// A staged temp copy (deleted after the upload).
    #[serde(default)]
    pub temp: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DragDropPayload {
    pub session_id: String,
    #[serde(default)]
    pub files: Vec<DragDropFile>,
    #[serde(default)]
    pub upload_command: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SuccessResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SuccessResult {
    fn fail(error: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(error.into()),
        }
    }
}

/// `startZmodemDragDropUpload(sessionId, files, uploadCommand)`: queue the
/// files and type `rz -y` (or the given command); the upload starts when
/// `rz` answers.
#[tauri::command]
pub async fn zmodem_drag_drop_upload<R: Runtime>(
    state: Ctx<'_, R>,
    payload: DragDropPayload,
) -> CmdResult<SuccessResult> {
    let app = state.app.clone();
    let temp_paths: Vec<PathBuf> = payload
        .files
        .iter()
        .filter(|f| f.temp)
        .map(|f| PathBuf::from(&f.path))
        .collect();
    let fail = |message: &str| -> CmdResult<SuccessResult> {
        remove_temp_files(&temp_paths);
        Ok(SuccessResult::fail(message))
    };
    let Some(zstate) = app.try_state::<ZmodemState>() else {
        return fail("ZMODEM upload is not available for this session");
    };
    if !state.sessions.contains(&payload.session_id) {
        return fail("ZMODEM upload is not available for this session");
    }
    let entry = zstate.get_or_create(&app, &payload.session_id);
    if entry.transfer_active() {
        return fail("ZMODEM transfer already in progress");
    }
    let mut paths = Vec::new();
    let mut names = Vec::new();
    for file in &payload.files {
        if file.path.is_empty() {
            continue;
        }
        let path = PathBuf::from(&file.path);
        if tokio::fs::metadata(&path).await.is_err() {
            continue;
        }
        let name = file
            .remote_name
            .clone()
            .filter(|n| !n.is_empty())
            .or_else(|| path.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "file".into());
        paths.push(path);
        names.push(name);
    }
    if paths.is_empty() {
        return fail("No readable files to upload");
    }
    if entry.drag_drop.lock().is_some() {
        return fail("ZMODEM drag-drop upload already pending");
    }
    // -y: overwrite same-named remote files (lrzsz protect mode otherwise skips).
    let command = payload
        .upload_command
        .clone()
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| "rz -y\r".to_string());
    let timer = CancellationToken::new();
    *entry.drag_drop.lock() = Some(DragDropUpload {
        paths,
        names,
        temp_paths,
        timer: timer.clone(),
    });
    entry.with_sentry(|s, now| s.arm_command_echo(command.as_bytes(), now));
    entry.write(command.into_bytes());

    // The remote rz must start soon; otherwise stop it and report.
    let app2 = app.clone();
    let entry2 = entry.clone();
    tauri::async_runtime::spawn(async move {
        tokio::select! {
            _ = timer.cancelled() => {}
            _ = tokio::time::sleep(DRAG_DROP_START_TIMEOUT) => {
                if entry2.drag_drop.lock().is_none() || entry2.sentry.lock().is_active() {
                    return;
                }
                tracing::warn!(session_id = %entry2.session_id, "drag-drop upload did not start before timeout");
                interrupt_pending_drag_drop(&entry2);
                entry2.clear_drag_drop();
                emit_error(&app2, &entry2.session_id, "ZMODEM drag-drop upload did not start");
            }
        }
    });
    Ok(SuccessResult {
        success: true,
        error: None,
    })
}

// ---------------------------------------------------------------------------
// YMODEM (serial)
// ---------------------------------------------------------------------------

/// Transport of a YMODEM transfer: reads the raw serial output the pump
/// hands over, writes through the session.
struct SessionYmodemIo<R: Runtime> {
    registry: crate::sessions::SessionRegistry<R>,
    session_id: String,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    queue: VecDeque<u8>,
    cancel: CancellationToken,
}

impl<R: Runtime> YmodemIo for SessionYmodemIo<R> {
    async fn write(&mut self, data: &[u8]) -> YResult<()> {
        if self.cancel.is_cancelled() {
            return Err(YmodemError::cancelled());
        }
        self.registry
            .write_input(
                &self.session_id,
                SessionInput::Bytes(Bytes::copy_from_slice(data)),
                &InputMeta::automated(),
            )
            .await
            .map_err(|_| YmodemError::closed())
    }

    async fn read_byte(&mut self, timeout: Duration) -> YResult<u8> {
        loop {
            if self.cancel.is_cancelled() {
                return Err(YmodemError::cancelled());
            }
            if let Some(b) = self.queue.pop_front() {
                return Ok(b);
            }
            tokio::select! {
                chunk = self.rx.recv() => match chunk {
                    Some(chunk) => self.queue.extend(chunk),
                    None => return Err(YmodemError::closed()),
                },
                _ = self.cancel.cancelled() => return Err(YmodemError::cancelled()),
                _ = tokio::time::sleep(timeout) => return Err(YmodemError::timeout()),
            }
        }
    }

    fn unread_byte(&mut self, byte: u8) {
        self.queue.push_front(byte);
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YmodemSendPayload {
    pub session_id: String,
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YmodemReceivePayload {
    pub session_id: String,
    #[serde(default)]
    pub destination_dir: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct YmodemFile {
    pub file_name: String,
    pub file_path: String,
    pub total_bytes: u64,
    pub written_bytes: u64,
}

/// `{ success, fileName?, filePath?, totalBytes?, writtenBytes?, files?, fileCount?, error?, code? }`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct YmodemResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets_sent: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<YmodemFile>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl YmodemResult {
    fn fail(error: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(error.into()),
            ..Default::default()
        }
    }

    fn from_error(err: YmodemError) -> Self {
        Self {
            success: false,
            error: Some(err.message),
            code: Some(err.code.to_string()),
            ..Default::default()
        }
    }
}

/// Validate a serial session and claim it for a YMODEM transfer.
async fn begin_ymodem<R: Runtime>(
    state: &AppState<R>,
    session_id: &str,
    what: &str,
) -> Result<(Arc<SessionZ>, SessionYmodemIo<R>), YmodemResult> {
    let not_serial = || YmodemResult::fail(format!("YMODEM {what} requires an active serial session"));
    let Some(session) = state.sessions.get(session_id) else {
        return Err(not_serial());
    };
    if session.lock().await.protocol != "serial" {
        return Err(not_serial());
    }
    let Some(zstate) = state.app.try_state::<ZmodemState>() else {
        return Err(not_serial());
    };
    let entry = zstate.get_or_create(&state.app, session_id);
    if entry.ymodem.lock().is_some() {
        return Err(YmodemResult::fail("A YMODEM transfer is already in progress"));
    }
    if entry.sentry.lock().is_active() {
        return Err(YmodemResult::fail(
            "Another serial file transfer is already in progress",
        ));
    }
    let (tx, rx) = mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    *entry.ymodem.lock() = Some((tx, cancel.clone()));
    let io = SessionYmodemIo {
        registry: state.sessions.clone(),
        session_id: session_id.to_string(),
        rx,
        queue: VecDeque::new(),
        cancel,
    };
    Ok((entry, io))
}

fn timeout_of(ms: Option<u64>) -> Duration {
    ms.filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or(ymodem::DEFAULT_TIMEOUT)
}

/// `sendSerialYmodem(sessionId, filePath)`.
#[tauri::command]
pub async fn serial_ymodem_send<R: Runtime>(
    state: Ctx<'_, R>,
    payload: YmodemSendPayload,
) -> CmdResult<YmodemResult> {
    let Some(file_path) = payload.file_path.filter(|p| !p.is_empty()) else {
        if state.sessions.get(&payload.session_id).is_none() {
            return Ok(YmodemResult::fail("YMODEM send requires an active serial session"));
        }
        return Ok(YmodemResult::fail("No file selected"));
    };
    let (entry, mut io) = match begin_ymodem(&state, &payload.session_id, "send").await {
        Ok(v) => v,
        Err(result) => return Ok(result),
    };
    let result = ymodem::send_file(
        &mut io,
        Path::new(&file_path),
        timeout_of(payload.timeout_ms),
        ymodem::DEFAULT_RETRY_LIMIT,
    )
    .await;
    *entry.ymodem.lock() = None;
    Ok(match result {
        Ok(sent) => YmodemResult {
            success: true,
            file_name: Some(sent.file_name),
            total_bytes: Some(sent.total_bytes),
            written_bytes: Some(sent.written_bytes),
            packets_sent: Some(sent.packets_sent),
            ..Default::default()
        },
        Err(err) => YmodemResult::from_error(err),
    })
}

/// `receiveSerialYmodem(sessionId, destinationDir)`.
#[tauri::command]
pub async fn serial_ymodem_receive<R: Runtime>(
    state: Ctx<'_, R>,
    payload: YmodemReceivePayload,
) -> CmdResult<YmodemResult> {
    let Some(dir) = payload.destination_dir.filter(|p| !p.is_empty()) else {
        if state.sessions.get(&payload.session_id).is_none() {
            return Ok(YmodemResult::fail("YMODEM receive requires an active serial session"));
        }
        return Ok(YmodemResult::fail("No destination directory selected"));
    };
    let (entry, mut io) = match begin_ymodem(&state, &payload.session_id, "receive").await {
        Ok(v) => v,
        Err(result) => return Ok(result),
    };
    let dir = std::path::absolute(&dir).unwrap_or_else(|_| PathBuf::from(&dir));
    let result = ymodem::receive_files(
        &mut io,
        &dir,
        timeout_of(payload.timeout_ms),
        ymodem::DEFAULT_RETRY_LIMIT,
    )
    .await;
    if let Err(err) = &result {
        if err.code != "YMODEM_CANCELLED" && err.code != "YMODEM_REMOTE_CANCELLED" {
            let _ = io.write(&ymodem::CANCEL_SEQUENCE).await;
        }
    }
    *entry.ymodem.lock() = None;
    Ok(match result {
        Ok(received) => {
            let files: Vec<YmodemFile> = received
                .files
                .iter()
                .map(|f| YmodemFile {
                    file_name: f.file_name.clone(),
                    file_path: f.file_path.to_string_lossy().into_owned(),
                    total_bytes: f.total_bytes,
                    written_bytes: f.written_bytes,
                })
                .collect();
            YmodemResult {
                success: true,
                file_name: files.first().map(|f| f.file_name.clone()),
                file_path: files.first().map(|f| f.file_path.clone()),
                total_bytes: Some(received.total_bytes()),
                written_bytes: Some(received.written_bytes()),
                file_count: Some(files.len()),
                files: Some(files),
                ..Default::default()
            }
        }
        Err(err) => YmodemResult::from_error(err),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(action: OverwriteAction, apply_to_rest: bool) -> OverwriteDecision {
        OverwriteDecision {
            action,
            apply_to_rest,
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn upload_plan_follows_decisions() {
        // Mirrors zmodemHelper.test.cjs buildUploadPlan cases.
        let all = names(&["a", "b", "c", "d"]);
        let existing = names(&["b", "c", "d"]);
        let mut answers = vec![
            decision(OverwriteAction::Overwrite, false),
            decision(OverwriteAction::Skip, true),
        ]
        .into_iter();
        let mut asked = Vec::new();
        let plan = build_upload_plan(&all, &existing, |name| {
            asked.push(name);
            let d = answers.next().unwrap();
            async move { d }
        })
        .await;
        assert_eq!(asked, names(&["b", "c"]));
        assert_eq!(plan.offer, vec![0, 1]);
        assert_eq!(plan.remove, vec![1]);
        assert!(!plan.aborted);

        let plan = build_upload_plan(&all, &existing, |_| async {
            decision(OverwriteAction::Cancel, true)
        })
        .await;
        assert!(plan.aborted && plan.offer.is_empty());

        // No conflicts: nothing is asked.
        let plan = build_upload_plan(&all, &[], |_| async { unreachable!() }).await;
        assert_eq!(plan.offer, vec![0, 1, 2, 3]);
    }

    #[test]
    fn mode_restores_dedupe_and_skip_missing_modes() {
        let names = names(&["x", "y", "x"]);
        let mut modes = std::collections::HashMap::new();
        modes.insert("x".to_string(), "755".to_string());
        let restores = build_mode_restores("/srv/", &names, &[0, 1, 2], &modes);
        assert_eq!(restores, vec![("/srv/x".to_string(), "755".to_string())]);
    }

    #[test]
    fn probe_output_parsing() {
        let probe = parse_probe("DIR\t/home/u\nEXIST\ta b\t644\nEXIST\tc\tbad\n\n").unwrap();
        assert_eq!(probe.dir, "/home/u");
        assert_eq!(probe.existing, names(&["a b", "c"]));
        assert_eq!(probe.modes.get("a b").map(String::as_str), Some("644"));
        assert!(!probe.modes.contains_key("c"));
        assert!(parse_probe("EXIST\tx\t644\n").is_none());
    }

    #[test]
    fn download_names_and_unique_paths() {
        assert_eq!(safe_download_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_download_name("C:\\x\\y.txt"), "y.txt");
        assert!(safe_download_name("..").starts_with("untitled_"));
        let dir = std::env::temp_dir().join(format!("zmodem-unique-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"").unwrap();
        std::fs::write(dir.join("a (1).txt"), b"").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (2).txt"));
        assert_eq!(unique_path(&dir, "b"), dir.join("b"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quoting_and_mode_validation() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert!(valid_mode("644") && valid_mode("0755"));
        assert!(!valid_mode("8") && !valid_mode("64a") && !valid_mode("12345"));
        assert!(might_start_transfer(b"abc\x18"));
        assert!(might_start_transfer(b"echo *"));
        assert!(!might_start_transfer(b"plain"));
    }
}
