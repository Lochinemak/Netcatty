//! Streaming single-file transfers with progress, pause (checkpoint) and
//! cancellation. Directory recursion is driven by the renderer, which
//! enqueues one `TransferRequest` per file (same as the Electron design).
//!
//! Resume model (mirrors `transferBridge.cjs`): the target (or its `.part`
//! stage) is opened at `checkpoint_bytes`, any tail beyond the checkpoint is
//! truncated, and the source is skipped to the same offset. Pause and cancel
//! both flush outstanding writes and report the acknowledged byte count as
//! the new checkpoint; the staged `.part` is kept so a later request can
//! resume from it. Completion verifies the byte count against the known
//! total before promoting the stage to the final name.

use crate::client::{posix_basename, posix_parent, SftpClient};
use crate::error::{SftpError, SftpResult};
use crate::pipeline::{close_quietly, PipelinedReader, PipelinedWriter, PIPELINE_DEPTH};
use netcatty_core::ipc::EndpointType;
use russh_sftp::client::RawSftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use std::collections::VecDeque;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

/// Bytes read from the source per loop iteration.
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;
/// Minimum spacing between progress publications.
pub const DEFAULT_PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
/// Sliding window used for the speed estimate.
pub const DEFAULT_SPEED_WINDOW: Duration = Duration::from_secs(2);
/// Below this elapsed time the speed estimate is reported as 0.
const SPEED_MIN_ELAPSED: Duration = Duration::from_millis(50);

#[derive(Debug, Clone)]
pub struct TransferRequest {
    pub transfer_id: String,
    pub source_type: EndpointType,
    pub target_type: EndpointType,
    /// Remote path or local path depending on `source_type`.
    pub source_path: String,
    pub target_path: String,
    /// Known size, if the renderer already stat'ed the source.
    pub total_bytes: Option<u64>,
    /// Resume offset: bytes already present at the target.
    pub checkpoint_bytes: u64,
    /// Use a temporary `.part` target and rename on completion.
    pub stage_target: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct TransferProgress {
    pub transferred: u64,
    pub total: Option<u64>,
    /// Bytes per second over a sliding window.
    pub speed: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransferOutcome {
    Completed {
        total: u64,
    },
    Cancelled {
        checkpoint_bytes: u64,
    },
    Paused {
        checkpoint_bytes: u64,
    },
    Failed {
        error: String,
        checkpoint_bytes: u64,
    },
}

/// Control handle for a running transfer.
pub struct TransferHandle {
    pub transfer_id: String,
    pub progress: watch::Receiver<TransferProgress>,
    pub(crate) cancel: CancellationToken,
    pub(crate) pause: CancellationToken,
    pub done: tokio::sync::oneshot::Receiver<TransferOutcome>,
}

impl TransferHandle {
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
    /// Stop after the current chunk and report the checkpoint.
    pub fn pause(&self) {
        self.pause.cancel();
    }
}

/// Endpoints for one transfer. `None` means local filesystem.
pub struct TransferEndpoints {
    pub source: Option<Arc<SftpClient>>,
    pub target: Option<Arc<SftpClient>>,
}

/// Knobs for the copy loop; [`Default`] matches the Electron bridge.
#[derive(Debug, Clone, Copy)]
pub struct TransferTuning {
    pub chunk_size: usize,
    pub progress_interval: Duration,
    pub speed_window: Duration,
}

impl Default for TransferTuning {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            progress_interval: DEFAULT_PROGRESS_INTERVAL,
            speed_window: DEFAULT_SPEED_WINDOW,
        }
    }
}

/// Start a transfer. Progress is pushed to the watch channel at most every
/// ~100 ms; the outcome arrives on `done`.
pub fn start_transfer(
    request: TransferRequest,
    endpoints: TransferEndpoints,
    progress_tx: Option<mpsc::UnboundedSender<(String, TransferProgress)>>,
) -> SftpResult<TransferHandle> {
    start_transfer_with(request, endpoints, progress_tx, TransferTuning::default())
}

/// [`start_transfer`] with explicit tuning. Must be called from within a
/// Tokio runtime (the copy runs on a spawned task).
pub fn start_transfer_with(
    request: TransferRequest,
    endpoints: TransferEndpoints,
    progress_tx: Option<mpsc::UnboundedSender<(String, TransferProgress)>>,
    tuning: TransferTuning,
) -> SftpResult<TransferHandle> {
    if request.transfer_id.is_empty() {
        return Err(SftpError::InvalidArgument("transfer id is required".into()));
    }
    if request.source_type == EndpointType::Sftp && endpoints.source.is_none() {
        return Err(SftpError::InvalidArgument(
            "sftp source requires an sftp client".into(),
        ));
    }
    if request.target_type == EndpointType::Sftp && endpoints.target.is_none() {
        return Err(SftpError::InvalidArgument(
            "sftp target requires an sftp client".into(),
        ));
    }
    if request.source_path.is_empty() || request.target_path.is_empty() {
        return Err(SftpError::InvalidArgument(
            "source and target paths are required".into(),
        ));
    }

    let initial = TransferProgress {
        transferred: request.checkpoint_bytes,
        total: request.total_bytes,
        speed: 0.0,
    };
    let (watch_tx, watch_rx) = watch::channel(initial);
    let cancel = CancellationToken::new();
    let pause = CancellationToken::new();
    let (done_tx, done_rx) = oneshot::channel();
    let transfer_id = request.transfer_id.clone();

    let reporter = ProgressReporter {
        transfer_id: transfer_id.clone(),
        total: request.total_bytes,
        watch: watch_tx,
        sink: progress_tx,
        speed: SpeedCalculator::new(tuning.speed_window),
        interval: tuning.progress_interval,
        last_emit: None,
    };
    let worker = Worker {
        request,
        endpoints,
        cancel: cancel.clone(),
        pause: pause.clone(),
        reporter,
        tuning,
    };
    tokio::spawn(async move {
        let outcome = worker.run().await;
        let _ = done_tx.send(outcome);
    });

    Ok(TransferHandle {
        transfer_id,
        progress: watch_rx,
        cancel,
        pause,
        done: done_rx,
    })
}

/// Temporary staging path for a local target (`<dir>/.<name>.netcatty-part`).
pub fn staging_path(target: &str) -> PathBuf {
    let p = PathBuf::from(target);
    let name = p
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    p.with_file_name(format!(".{name}.netcatty-part"))
}

/// Staging path for a remote (POSIX) target.
pub fn remote_staging_path(target: &str) -> String {
    let name = posix_basename(target);
    let staged = format!(".{name}.netcatty-part");
    match posix_parent(target) {
        Some(parent) if parent == "/" => format!("/{staged}"),
        Some(parent) if parent == "." && !target.starts_with("./") => staged,
        Some(parent) => format!("{parent}/{staged}"),
        None => staged,
    }
}

// --- speed -----------------------------------------------------------------

/// Sliding-window throughput estimate (bytes/second).
#[derive(Debug, Clone)]
pub struct SpeedCalculator {
    window: Duration,
    samples: VecDeque<(Instant, u64)>,
}

impl SpeedCalculator {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            samples: VecDeque::new(),
        }
    }

    /// Record the cumulative byte count `bytes` observed at `at`.
    pub fn sample(&mut self, at: Instant, bytes: u64) {
        if let Some(&(last_at, last_bytes)) = self.samples.back() {
            if at < last_at || bytes < last_bytes {
                // Non-monotonic input (restart from a checkpoint): reset.
                self.samples.clear();
            }
        }
        self.samples.push_back((at, bytes));
        // Keep exactly one sample at or before the window boundary.
        if let Some(boundary) = at.checked_sub(self.window) {
            while self.samples.len() >= 2 && self.samples[1].0 <= boundary {
                self.samples.pop_front();
            }
        }
    }

    /// Bytes/second over the window ending at `now`.
    pub fn speed(&self, now: Instant) -> f64 {
        let (Some(&(first_at, first_bytes)), Some(&(last_at, last_bytes))) =
            (self.samples.front(), self.samples.back())
        else {
            return 0.0;
        };
        if self.samples.len() < 2 || now < first_at {
            return 0.0;
        }
        let mut boundary_at = first_at;
        let mut boundary_bytes = first_bytes as f64;
        if let Some(target) = now.checked_sub(self.window) {
            if target > first_at && self.samples.len() >= 2 {
                let (next_at, next_bytes) = self.samples[1];
                let range = next_at.saturating_duration_since(first_at).as_secs_f64();
                if range > 0.0 {
                    let ratio = target.saturating_duration_since(first_at).as_secs_f64() / range;
                    boundary_bytes =
                        first_bytes as f64 + (next_bytes as f64 - first_bytes as f64) * ratio;
                    boundary_at = target;
                }
            }
        }
        let elapsed = now.max(last_at).saturating_duration_since(boundary_at);
        if elapsed < SPEED_MIN_ELAPSED {
            return 0.0;
        }
        let delta = last_bytes as f64 - boundary_bytes;
        if delta <= 0.0 {
            return 0.0;
        }
        delta / elapsed.as_secs_f64()
    }
}

// --- progress ----------------------------------------------------------------

struct ProgressReporter {
    transfer_id: String,
    total: Option<u64>,
    watch: watch::Sender<TransferProgress>,
    sink: Option<mpsc::UnboundedSender<(String, TransferProgress)>>,
    speed: SpeedCalculator,
    interval: Duration,
    last_emit: Option<Instant>,
}

impl ProgressReporter {
    fn report(&mut self, transferred: u64, force: bool) {
        let now = Instant::now();
        self.speed.sample(now, transferred);
        if !force {
            if let Some(last) = self.last_emit {
                if now.duration_since(last) < self.interval {
                    return;
                }
            }
        }
        let progress = TransferProgress {
            transferred,
            total: self.total,
            speed: self.speed.speed(now),
        };
        self.watch.send_replace(progress);
        if let Some(sink) = &self.sink {
            let _ = sink.send((self.transfer_id.clone(), progress));
        }
        self.last_emit = Some(now);
    }
}

// --- worker ------------------------------------------------------------------

enum Stop {
    Cancelled(u64),
    Paused(u64),
    Failed(String, u64),
}

impl Stop {
    fn failed(err: impl std::fmt::Display, checkpoint: u64) -> Self {
        Stop::Failed(err.to_string(), checkpoint)
    }
}

enum Source {
    Local {
        file: tokio::fs::File,
        buf: Vec<u8>,
        chunk: usize,
    },
    Sftp {
        reader: PipelinedReader,
        session: Arc<RawSftpSession>,
        handle: String,
        current: Vec<u8>,
    },
}

impl Source {
    async fn open_local(
        path: &str,
        offset: u64,
        chunk: usize,
    ) -> std::io::Result<(Self, Option<u64>)> {
        let mut file = tokio::fs::File::open(path).await?;
        let size = file.metadata().await.ok().map(|m| m.len());
        if offset > 0 {
            file.seek(SeekFrom::Start(offset)).await?;
        }
        Ok((
            Source::Local {
                file,
                buf: Vec::new(),
                chunk,
            },
            size,
        ))
    }

    async fn open_sftp(
        client: &SftpClient,
        path: &str,
        offset: u64,
    ) -> SftpResult<(Self, Option<u64>)> {
        let session = client.session.clone();
        let wire = client.wire_path_default(path);
        let handle = session
            .open(wire, OpenFlags::READ, FileAttributes::empty())
            .await?
            .handle;
        let size = match session.fstat(handle.as_str()).await {
            Ok(attrs) => attrs.attrs.size,
            Err(_) => None,
        };
        let reader = PipelinedReader::new(
            session.clone(),
            handle.clone(),
            offset,
            size,
            client.limits.read_len,
            PIPELINE_DEPTH,
        );
        Ok((
            Source::Sftp {
                reader,
                session,
                handle,
                current: Vec::new(),
            },
            size,
        ))
    }

    async fn next_chunk(&mut self) -> SftpResult<Option<&[u8]>> {
        match self {
            Source::Local { file, buf, chunk } => {
                buf.resize(*chunk, 0);
                let n = file.read(buf).await?;
                if n == 0 {
                    return Ok(None);
                }
                Ok(Some(&buf[..n]))
            }
            Source::Sftp {
                reader, current, ..
            } => match reader.next_chunk().await? {
                Some(data) => {
                    *current = data;
                    Ok(Some(&current[..]))
                }
                None => Ok(None),
            },
        }
    }

    async fn close(self) {
        if let Source::Sftp {
            reader,
            session,
            handle,
            ..
        } = self
        {
            drop(reader);
            close_quietly(&session, &handle).await;
        }
    }
}

enum Sink {
    Local {
        file: tokio::fs::File,
        position: u64,
    },
    Sftp {
        writer: PipelinedWriter,
        session: Arc<RawSftpSession>,
        handle: String,
    },
}

impl Sink {
    /// Size of the existing target/stage, if any.
    async fn existing_len_local(path: &str) -> Option<u64> {
        tokio::fs::metadata(path)
            .await
            .ok()
            .filter(|m| m.is_file())
            .map(|m| m.len())
    }

    async fn existing_len_sftp(client: &SftpClient, path: &str) -> Option<u64> {
        client
            .session
            .stat(client.wire_path_default(path))
            .await
            .ok()
            .and_then(|a| a.attrs.size)
    }

    async fn open_local(path: &str, offset: u64) -> std::io::Result<Self> {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(offset == 0)
            .open(path)
            .await?;
        if offset > 0 {
            // Drop any in-flight tail beyond the checkpoint, then append.
            file.set_len(offset).await?;
            file.seek(SeekFrom::Start(offset)).await?;
        }
        Ok(Sink::Local {
            file,
            position: offset,
        })
    }

    async fn open_sftp(client: &SftpClient, path: &str, offset: u64) -> SftpResult<Self> {
        let session = client.session.clone();
        let wire = client.wire_path_default(path);
        let mut flags = OpenFlags::WRITE | OpenFlags::CREATE;
        if offset == 0 {
            flags |= OpenFlags::TRUNCATE;
        }
        let handle = session
            .open(wire, flags, FileAttributes::empty())
            .await?
            .handle;
        if offset > 0 {
            let attrs = FileAttributes {
                size: Some(offset),
                ..FileAttributes::empty()
            };
            if let Err(err) = session.fsetstat(handle.as_str(), attrs).await {
                tracing::debug!(error = %err, "could not truncate staged remote file to checkpoint");
            }
        }
        let writer = PipelinedWriter::new(
            session.clone(),
            handle.clone(),
            offset,
            client.limits.write_len,
            PIPELINE_DEPTH,
        );
        Ok(Sink::Sftp {
            writer,
            session,
            handle,
        })
    }

    async fn write(&mut self, data: &[u8]) -> SftpResult<()> {
        match self {
            Sink::Local { file, position } => {
                tokio::io::AsyncWriteExt::write_all(file, data).await?;
                *position += data.len() as u64;
                Ok(())
            }
            Sink::Sftp { writer, .. } => writer.write(data).await,
        }
    }

    async fn flush(&mut self) -> SftpResult<()> {
        match self {
            Sink::Local { file, .. } => Ok(tokio::io::AsyncWriteExt::flush(file).await?),
            Sink::Sftp { writer, .. } => writer.flush().await,
        }
    }

    /// Bytes durably accepted by the target, contiguous from offset 0.
    fn acknowledged(&self) -> u64 {
        match self {
            Sink::Local { position, .. } => *position,
            Sink::Sftp { writer, .. } => writer.acknowledged(),
        }
    }

    async fn close(self) -> SftpResult<()> {
        match self {
            Sink::Local { file, .. } => {
                file.sync_all().await?;
                Ok(())
            }
            Sink::Sftp {
                writer,
                session,
                handle,
            } => {
                drop(writer);
                session.close(handle).await?;
                Ok(())
            }
        }
    }

    async fn close_quietly(self) {
        match self {
            Sink::Local { .. } => {}
            Sink::Sftp {
                writer,
                session,
                handle,
            } => {
                drop(writer);
                close_quietly(&session, &handle).await;
            }
        }
    }
}

struct Worker {
    request: TransferRequest,
    endpoints: TransferEndpoints,
    cancel: CancellationToken,
    pause: CancellationToken,
    reporter: ProgressReporter,
    tuning: TransferTuning,
}

impl Worker {
    async fn run(mut self) -> TransferOutcome {
        match self.copy().await {
            Ok(total) => TransferOutcome::Completed { total },
            Err(Stop::Cancelled(checkpoint_bytes)) => {
                TransferOutcome::Cancelled { checkpoint_bytes }
            }
            Err(Stop::Paused(checkpoint_bytes)) => TransferOutcome::Paused { checkpoint_bytes },
            Err(Stop::Failed(error, checkpoint_bytes)) => TransferOutcome::Failed {
                error,
                checkpoint_bytes,
            },
        }
    }

    fn write_path(&self) -> String {
        if !self.request.stage_target {
            return self.request.target_path.clone();
        }
        match self.request.target_type {
            EndpointType::Local => staging_path(&self.request.target_path)
                .to_string_lossy()
                .into_owned(),
            EndpointType::Sftp => remote_staging_path(&self.request.target_path),
        }
    }

    async fn copy(&mut self) -> Result<u64, Stop> {
        let req = self.request.clone();
        let requested_checkpoint = req.checkpoint_bytes;

        if req.source_type == EndpointType::Local
            && req.target_type == EndpointType::Local
            && req.source_path == req.target_path
        {
            return Err(Stop::failed(
                "source and target are the same file",
                requested_checkpoint,
            ));
        }
        if self.cancel.is_cancelled() {
            return Err(Stop::Cancelled(requested_checkpoint));
        }

        let write_path = self.write_path();

        // Reconcile the claimed checkpoint with what is actually on disk.
        let mut checkpoint = requested_checkpoint;
        if checkpoint > 0 {
            let existing = match (req.target_type, &self.endpoints.target) {
                (EndpointType::Local, _) => Sink::existing_len_local(&write_path).await,
                (EndpointType::Sftp, Some(client)) => {
                    Sink::existing_len_sftp(client, &write_path).await
                }
                (EndpointType::Sftp, None) => None,
            };
            match existing {
                Some(len) if len >= checkpoint => {}
                _ => {
                    tracing::warn!(
                        transfer_id = %req.transfer_id,
                        claimed = checkpoint,
                        "staged target shorter than checkpoint; restarting from 0"
                    );
                    checkpoint = 0;
                }
            }
        }

        // Open the source at the checkpoint.
        let (mut source, source_size) = match (req.source_type, &self.endpoints.source) {
            (EndpointType::Local, _) => {
                Source::open_local(&req.source_path, checkpoint, self.tuning.chunk_size)
                    .await
                    .map_err(|e| Stop::failed(format!("cannot open source: {e}"), checkpoint))?
            }
            (EndpointType::Sftp, Some(client)) => {
                Source::open_sftp(client, &req.source_path, checkpoint)
                    .await
                    .map_err(|e| Stop::failed(format!("cannot open source: {e}"), checkpoint))?
            }
            (EndpointType::Sftp, None) => {
                return Err(Stop::failed("missing sftp source", checkpoint))
            }
        };
        let total = req.total_bytes.or(source_size);
        self.reporter.total = total;
        if let Some(total) = total {
            if checkpoint > total {
                source.close().await;
                return Err(Stop::failed(
                    format!("checkpoint {checkpoint} exceeds source size {total}"),
                    0,
                ));
            }
        }

        // Open the sink.
        let sink = match (req.target_type, &self.endpoints.target) {
            (EndpointType::Local, _) => Sink::open_local(&write_path, checkpoint)
                .await
                .map_err(|e| Stop::failed(format!("cannot open target: {e}"), checkpoint)),
            (EndpointType::Sftp, Some(client)) => Sink::open_sftp(client, &write_path, checkpoint)
                .await
                .map_err(|e| Stop::failed(format!("cannot open target: {e}"), checkpoint)),
            (EndpointType::Sftp, None) => Err(Stop::failed("missing sftp target", checkpoint)),
        };
        let mut sink = match sink {
            Ok(sink) => sink,
            Err(stop) => {
                source.close().await;
                return Err(stop);
            }
        };

        let mut transferred = checkpoint;
        self.reporter.report(transferred, true);

        let result = loop {
            if self.cancel.is_cancelled() {
                break Err(StopKind::Cancel);
            }
            if self.pause.is_cancelled() {
                break Err(StopKind::Pause);
            }
            let chunk = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break Err(StopKind::Cancel),
                _ = self.pause.cancelled() => break Err(StopKind::Pause),
                read = source.next_chunk() => read,
            };
            let chunk = match chunk {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break Ok(()),
                Err(err) => break Err(StopKind::Error(format!("read failed: {err}"))),
            };
            if let Err(err) = sink.write(chunk).await {
                break Err(StopKind::Error(format!("write failed: {err}")));
            }
            transferred += chunk.len() as u64;
            self.reporter.report(transferred, false);
        };

        source.close().await;

        match result {
            Ok(()) => {}
            Err(kind) => {
                // Settle outstanding writes so the checkpoint is exact.
                let flushed = sink.flush().await.is_ok();
                let checkpoint = if flushed {
                    transferred
                } else {
                    sink.acknowledged()
                };
                sink.close_quietly().await;
                self.reporter.report(checkpoint, true);
                return Err(match kind {
                    StopKind::Cancel => Stop::Cancelled(checkpoint),
                    StopKind::Pause => Stop::Paused(checkpoint),
                    StopKind::Error(message) => Stop::Failed(message, checkpoint),
                });
            }
        }

        if let Err(err) = sink.flush().await {
            let checkpoint = sink.acknowledged();
            sink.close_quietly().await;
            return Err(Stop::failed(format!("write failed: {err}"), checkpoint));
        }
        if let Some(total) = total {
            if transferred != total {
                sink.close_quietly().await;
                return Err(Stop::failed(
                    format!("size mismatch: expected {total} bytes, transferred {transferred}"),
                    transferred,
                ));
            }
        }
        if let Err(err) = sink.close().await {
            return Err(Stop::failed(format!("close failed: {err}"), transferred));
        }

        if req.stage_target {
            self.promote(&write_path, &req.target_path)
                .await
                .map_err(|e| Stop::failed(format!("rename failed: {e}"), transferred))?;
        }

        self.reporter.report(transferred, true);
        Ok(transferred)
    }

    /// Move the finished stage onto the final target name.
    async fn promote(&self, staged: &str, target: &str) -> SftpResult<()> {
        match (self.request.target_type, &self.endpoints.target) {
            (EndpointType::Local, _) => {
                if let Err(first) = tokio::fs::rename(staged, target).await {
                    if tokio::fs::metadata(target).await.is_ok() {
                        tokio::fs::remove_file(target).await?;
                        tokio::fs::rename(staged, target).await?;
                    } else {
                        return Err(first.into());
                    }
                }
                Ok(())
            }
            (EndpointType::Sftp, Some(client)) => {
                let from = client.wire_path_default(staged);
                let to = client.wire_path_default(target);
                if client
                    .session
                    .rename(from.clone(), to.clone())
                    .await
                    .is_err()
                {
                    // SFTP v3 rename refuses to overwrite: remove then retry.
                    let _ = client.session.remove(to.clone()).await;
                    client.session.rename(from, to).await?;
                }
                Ok(())
            }
            (EndpointType::Sftp, None) => {
                Err(SftpError::InvalidArgument("missing sftp target".into()))
            }
        }
    }
}

enum StopKind {
    Cancel,
    Pause,
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netcatty-sftp-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 7 + i / 251) % 256) as u8).collect()
    }

    fn local_request(
        id: &str,
        source: &std::path::Path,
        target: &std::path::Path,
        checkpoint: u64,
    ) -> TransferRequest {
        TransferRequest {
            transfer_id: id.to_string(),
            source_type: EndpointType::Local,
            target_type: EndpointType::Local,
            source_path: source.to_string_lossy().into_owned(),
            target_path: target.to_string_lossy().into_owned(),
            total_bytes: None,
            checkpoint_bytes: checkpoint,
            stage_target: true,
        }
    }

    fn no_endpoints() -> TransferEndpoints {
        TransferEndpoints {
            source: None,
            target: None,
        }
    }

    #[test]
    fn staging_path_shape() {
        assert_eq!(
            staging_path("/tmp/a.txt"),
            PathBuf::from("/tmp/.a.txt.netcatty-part")
        );
        assert_eq!(
            remote_staging_path("/srv/data/a.txt"),
            "/srv/data/.a.txt.netcatty-part"
        );
        assert_eq!(remote_staging_path("/a.txt"), "/.a.txt.netcatty-part");
        assert_eq!(remote_staging_path("a.txt"), ".a.txt.netcatty-part");
        assert_eq!(remote_staging_path("./a.txt"), "./.a.txt.netcatty-part");
    }

    #[test]
    fn speed_calculator_sliding_window() {
        let mut calc = SpeedCalculator::new(Duration::from_secs(2));
        let start = Instant::now();
        assert_eq!(calc.speed(start), 0.0);
        let step = Duration::from_millis(100);
        let per_step = 1024 * 1024u64;
        let mut at = start;
        let mut bytes = 0u64;
        for _ in 0..30 {
            calc.sample(at, bytes);
            at += step;
            bytes += per_step;
        }
        let now = at - step;
        let speed = calc.speed(now);
        let expected = per_step as f64 * 10.0;
        assert!(
            (speed - expected).abs() / expected < 0.1,
            "speed {speed} vs {expected}"
        );
        // Window pruning keeps the sample set bounded.
        assert!(calc.samples.len() <= 22, "samples {}", calc.samples.len());
        // A stall drives the estimate down.
        calc.sample(now + Duration::from_secs(2), bytes - per_step);
        let stalled = calc.speed(now + Duration::from_secs(4));
        assert!(stalled < expected / 2.0, "stalled {stalled}");
    }

    #[tokio::test]
    async fn local_copy_completes_through_stage() {
        let dir = temp_dir();
        let source = dir.join("src.bin");
        let target = dir.join("out.bin");
        let data = pattern(3 * 1024 * 1024 + 123);
        std::fs::write(&source, &data).unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        let handle = start_transfer(
            local_request("t1", &source, &target, 0),
            no_endpoints(),
            Some(tx),
        )
        .unwrap();
        let outcome = handle.done.await.unwrap();
        assert_eq!(
            outcome,
            TransferOutcome::Completed {
                total: data.len() as u64
            }
        );
        assert_eq!(std::fs::read(&target).unwrap(), data);
        assert!(!staging_path(target.to_str().unwrap()).exists());
        let last = *handle.progress.borrow();
        assert_eq!(last.transferred, data.len() as u64);
        assert_eq!(last.total, Some(data.len() as u64));
        let mut seen = Vec::new();
        while let Ok((id, p)) = rx.try_recv() {
            assert_eq!(id, "t1");
            seen.push(p.transferred);
        }
        assert_eq!(seen.first(), Some(&0));
        assert_eq!(seen.last(), Some(&(data.len() as u64)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cancel_before_first_chunk_reports_checkpoint() {
        let dir = temp_dir();
        let source = dir.join("src.bin");
        let target = dir.join("out.bin");
        std::fs::write(&source, pattern(512 * 1024)).unwrap();
        let handle = start_transfer(
            local_request("t2", &source, &target, 0),
            no_endpoints(),
            None,
        )
        .unwrap();
        handle.cancel();
        let outcome = handle.done.await.unwrap();
        assert_eq!(
            outcome,
            TransferOutcome::Cancelled {
                checkpoint_bytes: 0
            }
        );
        assert!(!target.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn pause_then_resume_from_checkpoint() {
        let dir = temp_dir();
        let source = dir.join("src.bin");
        let target = dir.join("out.bin");
        let data = pattern(2 * 1024 * 1024);
        std::fs::write(&source, &data).unwrap();
        let tuning = TransferTuning {
            chunk_size: 64 * 1024,
            progress_interval: Duration::ZERO,
            speed_window: Duration::from_secs(2),
        };

        let mut handle = start_transfer_with(
            local_request("t3", &source, &target, 0),
            no_endpoints(),
            None,
            tuning,
        )
        .unwrap();
        loop {
            let transferred = handle.progress.borrow_and_update().transferred;
            if transferred > 0 {
                break;
            }
            handle.progress.changed().await.unwrap();
        }
        handle.pause();
        let outcome = handle.done.await.unwrap();
        let checkpoint = match outcome {
            TransferOutcome::Paused { checkpoint_bytes } => checkpoint_bytes,
            other => panic!("expected pause, got {other:?}"),
        };
        assert!(
            checkpoint > 0 && checkpoint < data.len() as u64,
            "checkpoint {checkpoint}"
        );
        let staged = staging_path(target.to_str().unwrap());
        assert_eq!(std::fs::metadata(&staged).unwrap().len(), checkpoint);
        assert!(!target.exists());

        // Resume: the stage must be appended, not rewritten.
        let resumed = start_transfer(
            local_request("t3", &source, &target, checkpoint),
            no_endpoints(),
            None,
        )
        .unwrap();
        let outcome = resumed.done.await.unwrap();
        assert_eq!(
            outcome,
            TransferOutcome::Completed {
                total: data.len() as u64
            }
        );
        assert_eq!(std::fs::read(&target).unwrap(), data);
        assert!(!staged.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn bogus_checkpoint_restarts_from_zero() {
        let dir = temp_dir();
        let source = dir.join("src.bin");
        let target = dir.join("out.bin");
        let data = pattern(300 * 1024);
        std::fs::write(&source, &data).unwrap();
        // Claimed checkpoint with no stage on disk → start over.
        let handle = start_transfer(
            local_request("t4", &source, &target, 100_000),
            no_endpoints(),
            None,
        )
        .unwrap();
        assert_eq!(
            handle.done.await.unwrap(),
            TransferOutcome::Completed {
                total: data.len() as u64
            }
        );
        assert_eq!(std::fs::read(&target).unwrap(), data);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn missing_source_fails() {
        let dir = temp_dir();
        let source = dir.join("missing.bin");
        let target = dir.join("out.bin");
        let handle = start_transfer(
            local_request("t5", &source, &target, 0),
            no_endpoints(),
            None,
        )
        .unwrap();
        match handle.done.await.unwrap() {
            TransferOutcome::Failed {
                error,
                checkpoint_bytes,
            } => {
                assert!(error.contains("cannot open source"), "{error}");
                assert_eq!(checkpoint_bytes, 0);
            }
            other => panic!("expected failure, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn size_mismatch_is_reported() {
        let dir = temp_dir();
        let source = dir.join("src.bin");
        let target = dir.join("out.bin");
        std::fs::write(&source, pattern(1000)).unwrap();
        let mut req = local_request("t6", &source, &target, 0);
        req.total_bytes = Some(2000);
        let handle = start_transfer(req, no_endpoints(), None).unwrap();
        match handle.done.await.unwrap() {
            TransferOutcome::Failed { error, .. } => {
                assert!(error.contains("size mismatch"), "{error}")
            }
            other => panic!("expected failure, got {other:?}"),
        }
        assert!(!target.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_transfer_validates_endpoints() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let _guard = rt.enter();
        let req = TransferRequest {
            transfer_id: "x".into(),
            source_type: EndpointType::Sftp,
            target_type: EndpointType::Local,
            source_path: "/a".into(),
            target_path: "/b".into(),
            total_bytes: None,
            checkpoint_bytes: 0,
            stage_target: false,
        };
        assert!(matches!(
            start_transfer(req, no_endpoints(), None),
            Err(SftpError::InvalidArgument(_))
        ));
    }
}
