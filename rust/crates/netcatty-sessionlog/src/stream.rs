//! Live session log streams (port of `sessionLogStreamManager.cjs`).
//!
//! A stream receives decoded session output through [`StreamManager::append_data`]
//! (cheap: it only buffers) and is written to disk by a small per-stream
//! flush thread every [`FLUSH_INTERVAL`] (or as soon as
//! [`MAX_BUFFER_SIZE`] bytes are pending):
//!
//! * `raw` logs append the (sanitized) output to the file as is;
//! * `txt` / `html` logs keep a [`TerminalTextRenderer`] in memory and
//!   rewrite the whole rendered file on each flush (live snapshots include a
//!   pending cleared screen; the final write commits it).
//!
//! Every start returns a [`StreamToken`]. Stops can be guarded by it so a
//! late stop from a previous incarnation of a reused session id cannot end
//! the fresh stream (Electron issue #916); manual streams require it.
//!
//! The manager also keeps the last log *record* per session (active or
//! finalized) so "open log" ([`StreamManager::prepare_session_log`]) works
//! after recording stopped. Records are identity-scoped: a late finalization
//! never restores a target that was forgotten or replaced.
//!
//! `stop_stream` and `prepare_session_log` block on file I/O; call them from
//! a blocking context.

use crate::html::wrap_terminal_html_content;
use crate::naming::{format_log_timestamp, now_ms, safe_path_segment, to_local_iso_string};
use crate::rewrite::{ProgrammaticCommandLogRewriter, SudoAutofill};
use crate::sanitizer::{RenderOptions, TerminalTextRenderer};
use parking_lot::{Condvar, Mutex};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

/// Periodic flush interval.
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(500);
/// Pending output (bytes) that triggers an immediate flush.
pub const MAX_BUFFER_SIZE: usize = 64 * 1024;
const SNAPSHOT_RETRY_MIN_MS: u64 = 250;
const SNAPSHOT_RETRY_MAX_MS: u64 = 5000;

/// Opaque identity of one started stream.
pub type StreamToken = u64;

/// Clock used for line timestamps (ms since the epoch). Injectable for tests.
pub type TimestampProvider = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Log file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Txt,
    Raw,
    Html,
}

impl LogFormat {
    /// Strict parse of `"txt" | "raw" | "html"`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "txt" => Some(Self::Txt),
            "raw" => Some(Self::Raw),
            "html" => Some(Self::Html),
            _ => None,
        }
    }

    /// Lenient parse used by automatic logs: anything unknown is `txt`.
    pub fn from_setting(value: &str) -> Self {
        Self::parse(value).unwrap_or(Self::Txt)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Txt => "txt",
            Self::Raw => "raw",
            Self::Html => "html",
        }
    }

    /// File extension: raw logs are `.log`.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Txt => "txt",
            Self::Raw => "log",
            Self::Html => "html",
        }
    }
}

/// Options of an automatic log (`startStream`): written to
/// `directory/<safe host label>/<YYYY-MM-DDTHH-MM-SS>.<ext>`.
#[derive(Clone)]
pub struct StreamOptions {
    pub host_label: String,
    pub hostname: String,
    pub directory: PathBuf,
    pub format: LogFormat,
    pub start_time: Option<i64>,
    pub timestamps_enabled: bool,
    pub timestamp_provider: Option<TimestampProvider>,
}

/// Options of a log written to an explicit path (`startStreamToFile`).
#[derive(Clone)]
pub struct FileStreamOptions {
    pub file_path: PathBuf,
    pub format: LogFormat,
    pub host_label: String,
    pub start_time: Option<i64>,
    pub timestamps_enabled: bool,
    pub timestamp_provider: Option<TimestampProvider>,
    /// Text already on screen when recording starts (e.g. the prompt).
    pub initial_line: String,
    /// When the initial line is unterminated and the first output starts
    /// with a bare `\r` (devices that redraw the prompt), put it on its own
    /// line instead of letting the `\r` overwrite it.
    pub separate_initial_line_before_leading_carriage_return: bool,
    /// Ignore stops that do not present this stream's token.
    pub stop_requires_token: bool,
    /// The session is on the alternate screen when recording starts.
    pub alternate_screen_active: bool,
}

impl FileStreamOptions {
    pub fn new(file_path: impl Into<PathBuf>, format: LogFormat) -> Self {
        Self {
            file_path: file_path.into(),
            format,
            host_label: "session".into(),
            start_time: None,
            timestamps_enabled: false,
            timestamp_provider: None,
            initial_line: String::new(),
            separate_initial_line_before_leading_carriage_return: false,
            stop_requires_token: false,
            alternate_screen_active: false,
        }
    }
}

/// Output waiting for the next flush, plus the input-side sanitizers.
struct Pending {
    /// Sanitized chunks and their arrival time.
    chunks: Vec<(String, Option<i64>)>,
    len: usize,
    last_arrival: Option<i64>,
    rewriter: ProgrammaticCommandLogRewriter,
    sudo: SudoAutofill,
    separate_initial_line: bool,
    pending_initial_line_carriage_return: bool,
}

struct Writer {
    file: Option<File>,
    renderer: Option<TerminalTextRenderer>,
    snapshot_dirty: bool,
    snapshot_error: Option<String>,
    retry_delay_ms: u64,
    retry_at: Option<Instant>,
    error: Option<String>,
    /// `Some(result)` once finalized.
    finalized: Option<Option<PathBuf>>,
}

#[derive(Default)]
struct Signal {
    wake: bool,
    stop: bool,
}

struct Stream {
    token: StreamToken,
    file_path: PathBuf,
    format: LogFormat,
    host_label: String,
    start_time: i64,
    stop_requires_token: bool,
    timestamp_provider: Option<TimestampProvider>,
    disabled: AtomicBool,
    pending: Mutex<Pending>,
    writer: Mutex<Writer>,
    signal: Mutex<Signal>,
    signal_cv: Condvar,
}

struct Record {
    file_path: PathBuf,
    token: StreamToken,
    /// The stream while it is active or finalizing.
    stream: Mutex<Option<Arc<Stream>>>,
    error: Mutex<Option<String>>,
}

#[derive(Default)]
struct ManagerState {
    active: HashMap<String, Arc<Stream>>,
    records: HashMap<String, Arc<Record>>,
}

/// Registry of live log streams keyed by session id. Cheap to clone.
#[derive(Clone, Default)]
pub struct StreamManager {
    state: Arc<Mutex<ManagerState>>,
    next_token: Arc<AtomicU64>,
}

impl StreamManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start an automatic log (`startStream`). An active stream of the same
    /// session is stopped first and the previous record forgotten. Returns
    /// `None` when no stream could be started (no directory, I/O error).
    pub fn start_stream(&self, session_id: &str, opts: StreamOptions) -> Option<StreamToken> {
        let existing = self.state.lock().active.get(session_id).map(|s| s.token);
        if let Some(token) = existing {
            tracing::warn!(
                session_id,
                "session log stream already active; stopping the old one"
            );
            self.stop_stream(session_id, Some(token));
        }
        self.forget_session_log(session_id);

        if opts.directory.as_os_str().is_empty() {
            tracing::warn!("no session log directory specified; skipping");
            return None;
        }
        let label = if opts.host_label.is_empty() {
            &opts.hostname
        } else {
            &opts.host_label
        };
        let host_dir = opts.directory.join(safe_path_segment(label, "unknown"));
        if let Err(err) = std::fs::create_dir_all(&host_dir) {
            tracing::error!(session_id, %err, "failed to create session log directory");
            return None;
        }
        let start_time = opts.start_time.unwrap_or_else(now_ms);
        let file_path = host_dir.join(format!(
            "{}.{}",
            to_local_iso_string(start_time),
            opts.format.extension()
        ));
        let host_label = [&opts.host_label, &opts.hostname]
            .into_iter()
            .find(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| "unknown".into());
        match self.create_stream(
            session_id,
            &file_path,
            opts.format,
            host_label,
            start_time,
            opts.timestamps_enabled,
            opts.timestamp_provider,
            false,
            false,
        ) {
            Ok(token) => Some(token),
            Err(err) => {
                tracing::error!(session_id, %err, "failed to start session log stream");
                None
            }
        }
    }

    /// Start a log at an explicit path (`startStreamToFile`).
    pub fn start_stream_to_file(
        &self,
        session_id: &str,
        opts: FileStreamOptions,
    ) -> Result<StreamToken, String> {
        if self.has_stream(session_id) {
            return Err("Stream already active for this session".into());
        }
        if opts.file_path.as_os_str().is_empty() {
            return Err("Missing filePath".into());
        }
        if let Some(parent) = opts
            .file_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(|e| node_io_error(&e, "mkdir", parent))?;
        }
        let token = self.create_stream(
            session_id,
            &opts.file_path,
            opts.format,
            if opts.host_label.is_empty() {
                "session".into()
            } else {
                opts.host_label.clone()
            },
            opts.start_time.unwrap_or_else(now_ms),
            opts.timestamps_enabled,
            opts.timestamp_provider.clone(),
            opts.stop_requires_token,
            opts.alternate_screen_active,
        )?;
        if !opts.initial_line.is_empty() {
            self.append_data(session_id, &opts.initial_line);
            if opts.separate_initial_line_before_leading_carriage_return
                && !opts.initial_line.ends_with(['\r', '\n'])
            {
                if let Some(stream) = self.active(session_id) {
                    stream.pending.lock().separate_initial_line = true;
                }
            }
        }
        Ok(token)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_stream(
        &self,
        session_id: &str,
        file_path: &Path,
        format: LogFormat,
        host_label: String,
        start_time: i64,
        timestamps_enabled: bool,
        timestamp_provider: Option<TimestampProvider>,
        stop_requires_token: bool,
        alternate_screen_active: bool,
    ) -> Result<StreamToken, String> {
        let is_raw = format == LogFormat::Raw;
        let file = if is_raw {
            Some(File::create(file_path).map_err(|e| node_io_error(&e, "open", file_path))?)
        } else {
            None
        };
        let token = self.next_token.fetch_add(1, Ordering::Relaxed) + 1;
        let timestamp_provider = if !is_raw && timestamps_enabled {
            Some(timestamp_provider.unwrap_or_else(|| Arc::new(now_ms)))
        } else {
            None
        };
        let stream = Arc::new(Stream {
            token,
            file_path: file_path.to_path_buf(),
            format,
            host_label,
            start_time,
            stop_requires_token,
            timestamp_provider,
            disabled: AtomicBool::new(false),
            pending: Mutex::new(Pending {
                chunks: Vec::new(),
                len: 0,
                last_arrival: None,
                rewriter: ProgrammaticCommandLogRewriter::new(),
                sudo: SudoAutofill::default(),
                separate_initial_line: false,
                pending_initial_line_carriage_return: false,
            }),
            writer: Mutex::new(Writer {
                file,
                renderer: (!is_raw).then(|| TerminalTextRenderer::new(alternate_screen_active)),
                snapshot_dirty: false,
                snapshot_error: None,
                retry_delay_ms: 0,
                retry_at: None,
                error: None,
                finalized: None,
            }),
            signal: Mutex::new(Signal::default()),
            signal_cv: Condvar::new(),
        });
        spawn_flush_thread(&stream);
        let record = Arc::new(Record {
            file_path: file_path.to_path_buf(),
            token,
            stream: Mutex::new(Some(stream.clone())),
            error: Mutex::new(None),
        });
        let mut state = self.state.lock();
        state.active.insert(session_id.to_string(), stream);
        state.records.insert(session_id.to_string(), record);
        drop(state);
        tracing::info!(session_id, "session log stream started");
        Ok(token)
    }

    fn active(&self, session_id: &str) -> Option<Arc<Stream>> {
        self.state.lock().active.get(session_id).cloned()
    }

    /// Buffer decoded output for the session's active stream (no-op without
    /// one). Never blocks on I/O.
    pub fn append_data(&self, session_id: &str, data: &str) {
        let Some(stream) = self.active(session_id) else {
            return;
        };
        if stream.disabled.load(Ordering::SeqCst) {
            return;
        }
        if stream.append(data) {
            stream.wake();
        }
    }

    /// Remember a sudo-autofill command typed into the session.
    pub fn register_sudo_autofill_input(&self, session_id: &str, input: &str) {
        if let Some(stream) = self.active(session_id) {
            if !stream.disabled.load(Ordering::SeqCst) {
                stream.pending.lock().sudo.register_input(input);
            }
        }
    }

    /// Replace the echo of `sent_command` with `display_command` in the log.
    pub fn register_programmatic_command_log_rewrite(
        &self,
        session_id: &str,
        sent_command: &str,
        display_command: &str,
    ) {
        if let Some(stream) = self.active(session_id) {
            if !stream.disabled.load(Ordering::SeqCst) {
                stream
                    .pending
                    .lock()
                    .rewriter
                    .queue_rewrite(sent_command, display_command);
            }
        }
    }

    /// Stop and finalize the session's stream. With `expected_token`, only
    /// that stream is stopped; streams started with `stop_requires_token`
    /// ignore token-less stops. Returns the final path, or `None` when no
    /// matching stream was active or finalization failed. Blocking.
    pub fn stop_stream(
        &self,
        session_id: &str,
        expected_token: Option<StreamToken>,
    ) -> Option<PathBuf> {
        let (stream, record) = {
            let mut state = self.state.lock();
            let stream = state.active.get(session_id)?.clone();
            match expected_token {
                Some(token) if token != stream.token => return None,
                None if stream.stop_requires_token => return None,
                _ => {}
            }
            state.active.remove(session_id);
            let record = state
                .records
                .get(session_id)
                .filter(|r| r.token == stream.token)
                .cloned();
            (stream, record)
        };
        stream.signal_stop();
        let result = stream.finalize();
        if let Some(record) = record {
            *record.error.lock() = match &result {
                Some(_) => None,
                None => Some(
                    stream
                        .writer
                        .lock()
                        .error
                        .clone()
                        .unwrap_or_else(|| "Failed to finalize session log".into()),
                ),
            };
            *record.stream.lock() = None;
        }
        tracing::info!(
            session_id,
            ok = result.is_some(),
            "session log stream stopped"
        );
        result
    }

    /// Flush the session's current log without ending recording, or return
    /// its last finalized log (`prepareSessionLog`). `Ok(None)` when the
    /// session has no log. Blocking.
    pub fn prepare_session_log(&self, session_id: &str) -> Result<Option<PathBuf>, String> {
        let Some(record) = self.state.lock().records.get(session_id).cloned() else {
            return Ok(None);
        };
        let stream = record.stream.lock().clone();
        if let Some(stream) = stream {
            stream.prepare_flush()?;
        }
        let same_record = |manager: &Self| {
            manager
                .state
                .lock()
                .records
                .get(session_id)
                .is_some_and(|r| Arc::ptr_eq(r, &record))
        };
        if !same_record(self) {
            return Err("Session log changed; try again".into());
        }
        if let Some(error) = record.error.lock().clone() {
            return Err(error);
        }
        let metadata = std::fs::metadata(&record.file_path)
            .map_err(|e| node_io_error(&e, "stat", &record.file_path))?;
        if !metadata.is_file() {
            return Err("Session log is not a file".into());
        }
        if !same_record(self) {
            return Err("Session log changed; try again".into());
        }
        Ok(Some(record.file_path.clone()))
    }

    /// Forget the session's log record without touching its writer.
    pub fn forget_session_log(&self, session_id: &str) {
        self.state.lock().records.remove(session_id);
    }

    /// Token of the session's current record.
    pub fn session_log_token(&self, session_id: &str) -> Option<StreamToken> {
        self.state.lock().records.get(session_id).map(|r| r.token)
    }

    /// Drop the record only when it is still the inactive one observed as
    /// `expected_token` (`forgetInactiveSessionLog`).
    pub fn forget_inactive_session_log(
        &self,
        session_id: &str,
        expected_token: StreamToken,
    ) -> bool {
        let mut state = self.state.lock();
        if state.active.contains_key(session_id)
            || state.records.get(session_id).map(|r| r.token) != Some(expected_token)
        {
            return false;
        }
        state.records.remove(session_id).is_some()
    }

    pub fn has_session_log(&self, session_id: &str) -> bool {
        self.state.lock().records.contains_key(session_id)
    }

    pub fn has_stream(&self, session_id: &str) -> bool {
        self.state.lock().active.contains_key(session_id)
    }

    /// Token of the session's active stream.
    pub fn stream_token(&self, session_id: &str) -> Option<StreamToken> {
        self.state.lock().active.get(session_id).map(|s| s.token)
    }

    /// Absolute paths of files written by active streams (clear-all skips them).
    pub fn active_log_paths(&self) -> Vec<PathBuf> {
        self.state
            .lock()
            .active
            .values()
            .filter(|s| !s.disabled.load(Ordering::SeqCst))
            .map(|s| normalize_path(&s.file_path))
            .collect()
    }

    /// Stop every active stream and forget all records (app quit).
    pub fn cleanup_all(&self) {
        let streams: Vec<(String, StreamToken)> = self
            .state
            .lock()
            .active
            .iter()
            .map(|(id, s)| (id.clone(), s.token))
            .collect();
        for (id, token) in streams {
            self.stop_stream(&id, Some(token));
        }
        self.state.lock().records.clear();
    }
}

fn spawn_flush_thread(stream: &Arc<Stream>) {
    let weak: Weak<Stream> = Arc::downgrade(stream);
    let spawned = std::thread::Builder::new()
        .name("session-log-flush".into())
        .spawn(move || loop {
            let Some(stream) = weak.upgrade() else {
                return;
            };
            {
                let mut signal = stream.signal.lock();
                if !signal.stop && !signal.wake {
                    stream.signal_cv.wait_for(&mut signal, FLUSH_INTERVAL);
                }
                if signal.stop {
                    return;
                }
                signal.wake = false;
            }
            stream.flush_tick();
        });
    if let Err(err) = spawned {
        // Without the thread the log is still written on prepare / stop.
        tracing::error!(%err, "failed to spawn the session log flush thread");
    }
}

impl Stream {
    fn is_raw(&self) -> bool {
        self.format == LogFormat::Raw
    }

    fn wake(&self) {
        self.signal.lock().wake = true;
        self.signal_cv.notify_one();
    }

    fn signal_stop(&self) {
        self.signal.lock().stop = true;
        self.signal_cv.notify_one();
    }

    /// `appendData`: initial-line separation, then sanitize and buffer.
    /// Returns whether the buffer reached [`MAX_BUFFER_SIZE`].
    fn append(&self, data: &str) -> bool {
        let mut pending = self.pending.lock();
        let mut chunk = std::borrow::Cow::Borrowed(data);
        if pending.pending_initial_line_carriage_return && !chunk.is_empty() {
            pending.pending_initial_line_carriage_return = false;
            chunk = if chunk.starts_with('\n') {
                format!("\r{chunk}").into()
            } else {
                format!("\n\r{chunk}").into()
            };
        } else if pending.separate_initial_line && !chunk.is_empty() {
            pending.separate_initial_line = false;
            if chunk == "\r" {
                pending.pending_initial_line_carriage_return = true;
                return false;
            }
            if chunk.starts_with('\r') && !chunk.starts_with("\r\n") {
                chunk = format!("\n{chunk}").into();
            }
        }
        self.append_buffered(&mut pending, &chunk)
    }

    fn append_buffered(&self, pending: &mut Pending, chunk: &str) -> bool {
        if let Some(provider) = &self.timestamp_provider {
            if !chunk.is_empty() {
                pending.last_arrival = Some(provider());
            }
        }
        let readable = pending.rewriter.append(chunk);
        let sanitized = pending.sudo.sanitize(&readable, false);
        buffer_readable(pending, sanitized);
        pending.len + pending.sudo.pending_len() >= MAX_BUFFER_SIZE
    }

    /// Release everything held by the sanitizers (stream end).
    fn drain_final(&self, pending: &mut Pending) {
        if pending.pending_initial_line_carriage_return {
            pending.pending_initial_line_carriage_return = false;
            self.append_buffered(pending, "\n\r");
        }
        let readable = pending.rewriter.finish();
        if !readable.is_empty() {
            let sanitized = pending.sudo.sanitize(&readable, false);
            buffer_readable(pending, sanitized);
        }
        let rest = pending.sudo.sanitize("", true);
        buffer_readable(pending, rest);
    }

    fn take_pending(&self) -> Vec<(String, Option<i64>)> {
        let mut pending = self.pending.lock();
        pending.len = 0;
        std::mem::take(&mut pending.chunks)
    }

    /// Write buffered output: raw → file, txt/html → renderer (dirty).
    fn process(&self, writer: &mut Writer, chunks: Vec<(String, Option<i64>)>) -> bool {
        if chunks.is_empty() || self.disabled.load(Ordering::SeqCst) {
            return false;
        }
        if let Some(file) = writer.file.as_mut() {
            for (data, _) in &chunks {
                if let Err(err) = file.write_all(data.as_bytes()) {
                    tracing::error!(%err, "session log write failed");
                    self.disabled.store(true, Ordering::SeqCst);
                    writer.error = Some(node_io_error(&err, "write", &self.file_path));
                    return false;
                }
            }
        } else if let Some(renderer) = writer.renderer.as_mut() {
            let timestamps = self.timestamp_provider.is_some();
            for (data, timestamp) in &chunks {
                renderer.feed(data, if timestamps { *timestamp } else { None });
            }
            writer.snapshot_dirty = true;
        }
        true
    }

    fn render_snapshot(&self, writer: &mut Writer, finalize: bool) -> String {
        let Some(renderer) = writer.renderer.as_mut() else {
            return String::new();
        };
        if finalize {
            renderer.finish();
        }
        let formatter = |line: &str, timestamp: Option<i64>| {
            if line.is_empty() {
                String::new()
            } else {
                format!(
                    "[{}] {line}",
                    format_log_timestamp(timestamp.unwrap_or_else(now_ms))
                )
            }
        };
        let options = RenderOptions {
            include_pending_cleared_screen: !finalize,
            format_line: self
                .timestamp_provider
                .is_some()
                .then_some(&formatter as &dyn Fn(&str, Option<i64>) -> String),
        };
        if self.format == LogFormat::Html {
            let content = renderer.to_html_content(options);
            wrap_terminal_html_content(&content, &self.host_label, Some(self.start_time))
        } else {
            renderer.to_text(options)
        }
    }

    /// Write the current snapshot of a txt/html log.
    fn write_snapshot(&self, writer: &mut Writer) -> Result<(), String> {
        let content = self.render_snapshot(writer, false);
        writer.snapshot_dirty = false;
        match std::fs::write(&self.file_path, content) {
            Ok(()) => {
                writer.snapshot_error = None;
                writer.retry_delay_ms = 0;
                writer.retry_at = None;
                Ok(())
            }
            Err(err) => {
                tracing::error!(%err, "session log snapshot write failed");
                let message = node_io_error(&err, "open", &self.file_path);
                writer.snapshot_dirty = true;
                writer.snapshot_error = Some(message.clone());
                let delay = if writer.retry_delay_ms == 0 {
                    SNAPSHOT_RETRY_MIN_MS
                } else {
                    writer.retry_delay_ms
                };
                writer.retry_at = Some(Instant::now() + Duration::from_millis(delay));
                writer.retry_delay_ms = (delay * 2).min(SNAPSHOT_RETRY_MAX_MS);
                Err(message)
            }
        }
    }

    /// Periodic flush. A failed snapshot is retried with backoff, or sooner
    /// when new output arrives.
    fn flush_tick(&self) {
        let mut writer = self.writer.lock();
        if writer.finalized.is_some() {
            return;
        }
        let chunks = self.take_pending();
        let had_data = self.process(&mut writer, chunks);
        if self.is_raw() || !writer.snapshot_dirty || self.disabled.load(Ordering::SeqCst) {
            return;
        }
        let retry_due = writer.retry_at.is_none_or(|at| Instant::now() >= at);
        if had_data || retry_due {
            let _ = self.write_snapshot(&mut writer);
        }
    }

    /// Flush for "open log": the file on disk reflects all output so far
    /// (an empty txt/html log is materialized too).
    fn prepare_flush(&self) -> Result<(), String> {
        let mut writer = self.writer.lock();
        if let Some(result) = &writer.finalized {
            return match result {
                Some(_) => Ok(()),
                None => Err(writer
                    .error
                    .clone()
                    .unwrap_or_else(|| "Session log stream failed".into())),
            };
        }
        if self.disabled.load(Ordering::SeqCst) {
            return Err(writer
                .error
                .clone()
                .unwrap_or_else(|| "Session log stream failed".into()));
        }
        let chunks = self.take_pending();
        self.process(&mut writer, chunks);
        if self.disabled.load(Ordering::SeqCst) {
            return Err(writer
                .error
                .clone()
                .unwrap_or_else(|| "Failed to flush session log".into()));
        }
        if let Some(file) = writer.file.as_mut() {
            return file
                .flush()
                .map_err(|e| node_io_error(&e, "write", &self.file_path));
        }
        writer.snapshot_dirty = true;
        self.write_snapshot(&mut writer)
    }

    /// Final flush and close. Idempotent.
    fn finalize(&self) -> Option<PathBuf> {
        let mut writer = self.writer.lock();
        if let Some(result) = &writer.finalized {
            return result.clone();
        }
        {
            let mut pending = self.pending.lock();
            self.drain_final(&mut pending);
        }
        let chunks = self.take_pending();
        self.process(&mut writer, chunks);

        if let Some(mut file) = writer.file.take() {
            if let Err(err) = file.flush().and_then(|_| file.sync_data()) {
                self.disabled.store(true, Ordering::SeqCst);
                if writer.error.is_none() {
                    writer.error = Some(node_io_error(&err, "close", &self.file_path));
                }
            }
            if self.disabled.load(Ordering::SeqCst) && writer.error.is_none() {
                writer.error = Some("Session log stream failed".into());
            }
        } else if !self.disabled.load(Ordering::SeqCst) {
            let content = self.render_snapshot(&mut writer, true);
            match std::fs::write(&self.file_path, content) {
                Ok(()) => writer.snapshot_dirty = false,
                Err(err) => {
                    tracing::error!(%err, "final session log snapshot write failed");
                    self.disabled.store(true, Ordering::SeqCst);
                    writer.error = Some(node_io_error(&err, "open", &self.file_path));
                }
            }
        }
        // Parsed terminal state is no longer needed once the file is final.
        writer.renderer = None;
        let result = (!self.disabled.load(Ordering::SeqCst)).then(|| self.file_path.clone());
        writer.finalized = Some(result.clone());
        result
    }
}

fn buffer_readable(pending: &mut Pending, data: String) {
    if data.is_empty() {
        return;
    }
    pending.len += data.len();
    let timestamp = pending.last_arrival;
    pending.chunks.push((data, timestamp));
}

/// Node-style I/O error text (`ENOENT: no such file or directory, stat '…'`)
/// so renderer messages match the Electron backend.
pub fn node_io_error(err: &std::io::Error, syscall: &str, path: &Path) -> String {
    use std::io::ErrorKind;
    let code = match err.kind() {
        ErrorKind::NotFound => "ENOENT: no such file or directory",
        ErrorKind::PermissionDenied => "EACCES: permission denied",
        ErrorKind::AlreadyExists => "EEXIST: file already exists",
        ErrorKind::IsADirectory => "EISDIR: illegal operation on a directory",
        ErrorKind::NotADirectory => "ENOTDIR: not a directory",
        ErrorKind::StorageFull => "ENOSPC: no space left on device",
        _ => return err.to_string(),
    };
    format!("{code}, {syscall} '{}'", path.display())
}

/// `path.resolve` equivalent: absolute and lexically normalized.
pub fn normalize_path(path: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    //! Ported from `electron/bridges/sessionLogStreamManager.test.cjs`.
    use super::*;
    use chrono::{Local, TimeZone};
    use std::fs;

    fn local_ms(h: u32, m: u32, s: u32, ms: i64) -> i64 {
        Local
            .with_ymd_and_hms(2026, 1, 2, h, m, s)
            .single()
            .unwrap()
            .timestamp_millis()
            + ms
    }

    fn auto(dir: &Path, format: LogFormat) -> StreamOptions {
        StreamOptions {
            host_label: "host".into(),
            hostname: "host.example".into(),
            directory: dir.to_path_buf(),
            format,
            start_time: Some(local_ms(3, 4, 5, 0)),
            timestamps_enabled: false,
            timestamp_provider: None,
        }
    }

    fn sequence(times: Vec<i64>) -> TimestampProvider {
        let times = Mutex::new(times.into_iter());
        Arc::new(move || times.lock().next().unwrap_or(0))
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    fn wait_for_content(path: &Path, expected: &str) {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut last = String::new();
        while Instant::now() < deadline {
            if let Ok(content) = fs::read_to_string(path) {
                if content == expected {
                    return;
                }
                last = content;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out waiting for live snapshot; last content {last:?}");
    }

    const FRAMES: &str = "before tui\n\x1b[H\x1b[2Jframe one\n\x1b[H\x1b[2Jframe two\n";

    #[test]
    fn txt_live_snapshots_include_pending_cleared_screens() {
        let dir = tempfile::tempdir().unwrap();
        let m = StreamManager::new();
        m.start_stream("s", auto(dir.path(), LogFormat::Txt))
            .unwrap();
        m.append_data("s", FRAMES);
        let path = dir.path().join("host").join("2026-01-02T03-04-05.txt");
        wait_for_content(&path, "before tui\n\nframe one\n\nframe two");
        assert_eq!(m.stop_stream("s", None).unwrap(), path);
        assert_eq!(read(&path), "before tui\n\nframe one\n\nframe two");
    }

    #[test]
    fn stale_tokens_do_not_stop_a_fresh_stream() {
        let dir = tempfile::tempdir().unwrap();
        let m = StreamManager::new();
        let old = m
            .start_stream("s", auto(dir.path(), LogFormat::Raw))
            .unwrap();
        m.append_data("s", "first\n");
        let mut opts = auto(dir.path(), LogFormat::Raw);
        opts.start_time = Some(local_ms(3, 4, 6, 0));
        let fresh = m.start_stream("s", opts).unwrap();
        assert_ne!(old, fresh);
        assert!(m.stop_stream("s", Some(old)).is_none());
        assert!(m.has_stream("s"));
        m.append_data("s", "second\n");
        let path = m.stop_stream("s", Some(fresh)).unwrap();
        assert_eq!(read(&path), "second\n");
        // The replaced stream was finalized when the new one started.
        assert_eq!(
            read(&dir.path().join("host").join("2026-01-02T03-04-05.log")),
            "first\n"
        );
    }

    #[test]
    fn token_required_streams_ignore_tokenless_stops() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manual.log");
        let m = StreamManager::new();
        let mut opts = FileStreamOptions::new(&path, LogFormat::Raw);
        opts.stop_requires_token = true;
        let token = m.start_stream_to_file("s", opts).unwrap();
        assert!(m.stop_stream("s", None).is_none());
        assert!(m.has_stream("s"));
        assert_eq!(m.stop_stream("s", Some(token)).unwrap(), path);
    }

    fn manual_raw(initial: &str, separate: bool, chunks: &[&str]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("manual.log");
        let m = StreamManager::new();
        let mut opts = FileStreamOptions::new(&path, LogFormat::Raw);
        opts.initial_line = initial.into();
        opts.separate_initial_line_before_leading_carriage_return = separate;
        m.start_stream_to_file("s", opts).unwrap();
        for chunk in chunks {
            m.append_data("s", chunk);
        }
        assert_eq!(m.stop_stream("s", None).unwrap(), path);
        read(&path)
    }

    #[test]
    fn explicit_file_initial_line_handling() {
        assert_eq!(manual_raw("header\n", false, &["body\n"]), "header\nbody\n");
        assert_eq!(
            manual_raw("root@host:~# ", true, &["ls\r\nfile\r\n"]),
            "root@host:~# ls\r\nfile\r\n"
        );
        assert_eq!(
            manual_raw("H3C>", true, &["\rdisplay version\r\n"]),
            "H3C>\n\rdisplay version\r\n"
        );
        assert_eq!(
            manual_raw("root@host:~# command", true, &["\r\noutput\r\n"]),
            "root@host:~# command\r\noutput\r\n"
        );
        assert_eq!(
            manual_raw("root@host:~# command", true, &["\r", "\noutput\r\n"]),
            "root@host:~# command\r\noutput\r\n"
        );
        assert_eq!(manual_raw("H3C>", true, &["\r"]), "H3C>\n\r");
        assert_eq!(
            manual_raw(
                "H3C>",
                true,
                &["\rdisplay version\r\nComware Software\r\nH3C>"]
            ),
            "H3C>\n\rdisplay version\r\nComware Software\r\nH3C>"
        );
    }

    #[test]
    fn explicit_txt_logs_and_seeded_alternate_screen() {
        let dir = tempfile::tempdir().unwrap();
        let m = StreamManager::new();
        let path = dir.path().join("manual.txt");
        let mut opts = FileStreamOptions::new(&path, LogFormat::Txt);
        opts.alternate_screen_active = true;
        m.start_stream_to_file("s", opts).unwrap();
        m.append_data("s", "~\nstatus line\n\x1b[?1049l$ done\n");
        assert_eq!(m.stop_stream("s", None).unwrap(), path);
        assert_eq!(read(&path), "$ done");
    }

    fn sudo_case(marker: &str, prepared: &str, chunks: &[&str]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let m = StreamManager::new();
        m.start_stream("s", auto(dir.path(), LogFormat::Raw))
            .unwrap();
        m.register_sudo_autofill_input("s", &format!("\x15{prepared}\r"));
        for chunk in chunks {
            m.append_data("s", chunk);
        }
        let content = read(&m.stop_stream("s", None).unwrap());
        assert!(!content.contains(marker), "{content:?}");
        assert!(!content.contains("NETCATTY_SUDO"));
        content
    }

    #[test]
    fn raw_streams_hide_sudo_autofill_markers() {
        let marker = "__NETCATTY_SUDO_test__";
        let prepared = format!("sudo -p '[sudo] password for %p: {marker}' whoami");
        assert_eq!(
            sudo_case(
                marker,
                &prepared,
                &[
                    &format!("{prepared}\r\n"),
                    &format!("[sudo] password for alice: {marker}"),
                    "\r\nroot\n"
                ]
            ),
            "sudo whoami\r\n[sudo] password for alice: \r\nroot\n"
        );

        let marker = "__NETCATTY_SUDO_split__";
        let prepared = format!("sudo -p '[sudo] password for %p: {marker}' id");
        assert_eq!(
            sudo_case(
                marker,
                &prepared,
                &[
                    "sudo -p '[sudo] password for %p: __NET",
                    "CATTY_SUDO_split__' id\r\n[sudo] password for alice: __NET",
                    "CATTY_SUDO_split__\r\nuid=0\n"
                ]
            ),
            "sudo id\r\n[sudo] password for alice: \r\nuid=0\n"
        );

        let marker = "__NETCATTY_SUDO_long__";
        let long_arg = "a".repeat(6000);
        let prepared = format!("sudo -p '[sudo] password for %p: {marker}' printf '{long_arg}'");
        assert_eq!(
            sudo_case(
                marker,
                &prepared,
                &[
                    &prepared[..2500],
                    &prepared[2500..5200],
                    &format!("{}\r\n", &prepared[5200..]),
                    &format!("[sudo] password for alice: {marker}\r\n")
                ]
            ),
            format!("sudo printf '{long_arg}'\r\n[sudo] password for alice: \r\n")
        );

        let marker = "__NETCATTY_SUDO_warm__";
        let prepared = format!("sudo -p '[sudo] password for %p: {marker}' printf ok");
        assert_eq!(
            sudo_case(marker, &prepared, &[&format!("{prepared}\r\n"), "ok"]),
            "sudo printf ok\r\nok"
        );

        let marker = "__NETCATTY_SUDO_notice__";
        let prepared = format!("sudo -p '[sudo] password for %p: {marker}' whoami");
        assert_eq!(
            sudo_case(
                marker,
                &prepared,
                &[
                    "sudo: this is the first time notice",
                    &format!("[sudo] password for alice: {marker}\r\nroot\n")
                ]
            ),
            "sudo: this is the first time notice[sudo] password for alice: \r\nroot\n"
        );

        let marker = "__NETCATTY_SUDO_warm_prompt__";
        let prepared = format!(
            "sudo -p '[sudo] password for %p: {marker}' printf '[sudo] password for alice: '"
        );
        assert_eq!(
            sudo_case(marker, &prepared, &["[sudo] password for alice: "]),
            "[sudo] password for alice: "
        );

        let marker = "__NETCATTY_SUDO_history__";
        let prepared = format!("sudo -p '[sudo] password for %p: {marker}' whoami");
        assert_eq!(
            sudo_case(
                marker,
                &prepared,
                &[
                    &format!("[sudo] password for alice: {marker}\r\nroot\n"),
                    &format!("{prepared}\r\n")
                ]
            ),
            "[sudo] password for alice: \r\nroot\nsudo whoami\r\n"
        );
    }

    #[test]
    fn programmatic_rewrites_are_isolated_per_session() {
        let dir = tempfile::tempdir().unwrap();
        let sent = "sh -c 'private setup' && eval 'wrapped command'";
        let display = "sudo apt update && sudo apt upgrade -y";
        let m = StreamManager::new();
        let mut a = auto(dir.path(), LogFormat::Raw);
        a.host_label = "host-a".into();
        let mut b = auto(dir.path(), LogFormat::Raw);
        b.host_label = "host-b".into();
        m.start_stream("a", a).unwrap();
        m.start_stream("b", b).unwrap();
        m.register_programmatic_command_log_rewrite("a", sent, display);
        m.append_data("a", &sent[..12]);
        m.append_data("a", &format!("{}\r\nok-a\r\n", &sent[12..]));
        m.append_data("b", &format!("{sent}\r\nok-b\r\n"));
        assert_eq!(
            read(&m.stop_stream("a", None).unwrap()),
            format!("{display}\r\nok-a\r\n")
        );
        assert_eq!(
            read(&m.stop_stream("b", None).unwrap()),
            format!("{sent}\r\nok-b\r\n")
        );
    }

    #[test]
    fn host_directory_is_a_safe_unicode_segment() {
        let dir = tempfile::tempdir().unwrap();
        let m = StreamManager::new();
        let mut opts = auto(dir.path(), LogFormat::Raw);
        opts.host_label = "生产/服务器:东京*?<>|\0".into();
        let token = m.start_stream("s", opts).unwrap();
        m.append_data("s", "data\n");
        let path = m.stop_stream("s", Some(token)).unwrap();
        assert_eq!(
            path.parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy(),
            "生产_服务器_东京______"
        );
        assert_eq!(read(&path), "data\n");
    }

    fn timestamped(format: LogFormat, provider: TimestampProvider, chunks: &[&str]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let m = StreamManager::new();
        let mut opts = auto(dir.path(), format);
        opts.timestamps_enabled = true;
        opts.timestamp_provider = Some(provider);
        m.start_stream("s", opts).unwrap();
        for chunk in chunks {
            m.append_data("s", chunk);
        }
        read(&m.stop_stream("s", None).unwrap())
    }

    #[test]
    fn line_timestamps() {
        assert_eq!(
            timestamped(
                LogFormat::Txt,
                sequence(vec![
                    local_ms(3, 4, 5, 123),
                    local_ms(3, 4, 6, 456),
                    local_ms(3, 4, 7, 89)
                ]),
                &["first ", "line\nsecond line\npartial"]
            ),
            "[2026-01-02 03:04:06.456] first line\n[2026-01-02 03:04:06.456] second line\n[2026-01-02 03:04:06.456] partial"
        );
        let fixed: TimestampProvider = Arc::new(|| local_ms(3, 4, 5, 0));
        assert_eq!(
            timestamped(
                LogFormat::Txt,
                fixed.clone(),
                &["old prompt\rdocker denied\n"]
            ),
            "[2026-01-02 03:04:05.000] docker denied"
        );
        let html = timestamped(LogFormat::Html, fixed.clone(), &["line\n"]);
        assert!(html.contains("[2026-01-02 03:04:05.000] line"));
        let html = timestamped(
            LogFormat::Html,
            fixed.clone(),
            &["old prompt\rdocker denied\n"],
        );
        assert!(html.contains("[2026-01-02 03:04:05.000] docker denied"));
        assert!(!html.contains("old prompt"));
        assert_eq!(timestamped(LogFormat::Raw, fixed, &["line\n"]), "line\n");
    }

    #[test]
    fn timestamps_preserve_arrival_gaps_within_one_flush() {
        for format in [LogFormat::Txt, LogFormat::Html] {
            let now = Arc::new(AtomicU64::new(local_ms(3, 4, 5, 89) as u64));
            let clock = now.clone();
            let dir = tempfile::tempdir().unwrap();
            let m = StreamManager::new();
            let mut opts = auto(dir.path(), format);
            opts.timestamps_enabled = true;
            opts.timestamp_provider = Some(Arc::new(move || clock.load(Ordering::SeqCst) as i64));
            m.start_stream("s", opts).unwrap();
            m.append_data("s", "first\r\n");
            now.fetch_add(300, Ordering::SeqCst);
            m.append_data("s", "second\r\n");
            let content = read(&m.stop_stream("s", None).unwrap());
            assert!(
                content.contains("[2026-01-02 03:04:05.089] first"),
                "{content}"
            );
            assert!(
                content.contains("[2026-01-02 03:04:05.389] second"),
                "{content}"
            );
        }
    }

    #[test]
    fn line_timestamp_updates_when_a_later_snapshot_rewrites_the_line() {
        let dir = tempfile::tempdir().unwrap();
        let m = StreamManager::new();
        let mut opts = auto(dir.path(), LogFormat::Txt);
        opts.timestamps_enabled = true;
        opts.timestamp_provider = Some(sequence(vec![local_ms(3, 4, 5, 0), local_ms(3, 4, 6, 0)]));
        m.start_stream("s", opts).unwrap();
        m.append_data("s", "old prompt");
        let path = dir.path().join("host").join("2026-01-02T03-04-05.txt");
        wait_for_content(&path, "[2026-01-02 03:04:05.000] old prompt");
        m.append_data("s", "\rdocker denied");
        m.stop_stream("s", None).unwrap();
        assert_eq!(read(&path), "[2026-01-02 03:04:06.000] docker denied");
    }

    #[test]
    fn prepare_flushes_and_keeps_recording() {
        for format in [LogFormat::Txt, LogFormat::Html, LogFormat::Raw] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(format!("session.{}", format.as_str()));
            let m = StreamManager::new();
            m.start_stream_to_file("s", FileStreamOptions::new(&path, format))
                .unwrap();
            assert_eq!(
                m.prepare_session_log("s").unwrap().unwrap(),
                path,
                "empty logs exist"
            );
            assert!(path.is_file());
            m.append_data("s", "first\r\n");
            assert_eq!(m.prepare_session_log("s").unwrap().unwrap(), path);
            assert!(read(&path).contains("first"));
            assert!(m.has_stream("s"));
            m.append_data("s", "second\r\n");
            m.prepare_session_log("s").unwrap();
            let content = read(&path);
            assert!(content.find("first").unwrap() < content.find("second").unwrap());
            assert_eq!(m.stop_stream("s", None).unwrap(), path);
            assert!(!m.has_stream("s"));
            assert_eq!(
                m.prepare_session_log("s").unwrap().unwrap(),
                path,
                "stopped logs remain"
            );
            assert_eq!(m.prepare_session_log("s-wrong").unwrap(), None);
            fs::remove_file(&path).unwrap();
            let err = m.prepare_session_log("s").unwrap_err();
            assert!(err.starts_with("ENOENT"), "{err}");
        }
    }

    #[test]
    fn prepare_waits_for_a_concurrent_stop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.txt");
        let m = StreamManager::new();
        m.start_stream_to_file("s", FileStreamOptions::new(&path, LogFormat::Txt))
            .unwrap();
        m.append_data("s", &"x".repeat(200_000));
        let stopper = {
            let m = m.clone();
            std::thread::spawn(move || m.stop_stream("s", None))
        };
        let prepared = m.prepare_session_log("s").unwrap();
        assert_eq!(prepared.as_deref(), Some(path.as_path()));
        assert_eq!(stopper.join().unwrap().as_deref(), Some(path.as_path()));
        assert_eq!(read(&path).len(), 200_000);
    }

    #[test]
    fn rendered_logs_report_final_write_failures() {
        let dir = tempfile::tempdir().unwrap();
        // The target is a directory, so every write fails.
        let path = dir.path().join("occupied");
        let m = StreamManager::new();
        m.start_stream_to_file("s", FileStreamOptions::new(&path, LogFormat::Txt))
            .unwrap();
        fs::create_dir(&path).unwrap();
        m.append_data("s", "body\r\n");
        assert!(
            m.prepare_session_log("s").is_err(),
            "prepare reports snapshot failures"
        );
        assert!(
            m.has_stream("s"),
            "recording continues after a failed snapshot"
        );
        assert!(m.stop_stream("s", None).is_none());
        assert!(!m.has_stream("s"));
        assert!(m.prepare_session_log("s").is_err());
    }

    #[test]
    fn records_are_identity_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let m = StreamManager::new();
        let first = dir.path().join("first.txt");
        let token = m
            .start_stream_to_file("s", FileStreamOptions::new(&first, LogFormat::Txt))
            .unwrap();
        m.forget_session_log("s");
        assert!(!m.has_session_log("s"));
        assert_eq!(m.stop_stream("s", Some(token)).unwrap(), first);
        assert!(
            !m.has_session_log("s"),
            "late finalization does not restore a forgotten log"
        );

        let second = dir.path().join("second.txt");
        let token = m
            .start_stream_to_file("s", FileStreamOptions::new(&second, LogFormat::Txt))
            .unwrap();
        assert!(
            !m.forget_inactive_session_log("s", token),
            "active streams are kept"
        );
        m.stop_stream("s", Some(token));
        assert!(!m.forget_inactive_session_log("s", token + 100));
        assert!(m.forget_inactive_session_log("s", token));
        assert!(!m.has_session_log("s"));
    }

    #[test]
    fn active_paths_exclude_stopped_streams() {
        let dir = tempfile::tempdir().unwrap();
        let m = StreamManager::new();
        let path = dir.path().join("a").join("..").join("live.log");
        m.start_stream_to_file("s", FileStreamOptions::new(&path, LogFormat::Raw))
            .unwrap();
        assert_eq!(
            m.active_log_paths(),
            vec![normalize_path(&dir.path().join("live.log"))]
        );
        m.cleanup_all();
        assert!(m.active_log_paths().is_empty());
        assert!(!m.has_session_log("s"));
    }

    #[test]
    fn large_bursts_flush_without_waiting_for_stop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("burst.log");
        let m = StreamManager::new();
        m.start_stream_to_file("s", FileStreamOptions::new(&path, LogFormat::Raw))
            .unwrap();
        m.append_data("s", &"y".repeat(MAX_BUFFER_SIZE));
        let deadline = Instant::now() + Duration::from_secs(3);
        while fs::metadata(&path).map(|m| m.len()).unwrap_or(0) < MAX_BUFFER_SIZE as u64 {
            assert!(Instant::now() < deadline, "burst was not flushed");
            std::thread::sleep(Duration::from_millis(10));
        }
        m.stop_stream("s", None);
    }
}
