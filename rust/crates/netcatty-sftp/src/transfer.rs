//! Streaming single-file transfers with progress, pause (checkpoint) and
//! cancellation. Directory recursion is driven by the renderer, which
//! enqueues one `TransferRequest` per file (same as the Electron design).

use crate::client::SftpClient;
use crate::error::SftpResult;
use netcatty_core::ipc::EndpointType;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

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
    Completed { total: u64 },
    Cancelled { checkpoint_bytes: u64 },
    Paused { checkpoint_bytes: u64 },
    Failed { error: String, checkpoint_bytes: u64 },
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

/// Start a transfer. Progress is pushed to the watch channel at most every
/// ~100 ms; the outcome arrives on `done`.
pub fn start_transfer(
    request: TransferRequest,
    endpoints: TransferEndpoints,
    progress_tx: Option<mpsc::UnboundedSender<(String, TransferProgress)>>,
) -> SftpResult<TransferHandle> {
    let _ = (request, endpoints, progress_tx);
    todo!("spawn copy task: local→sftp, sftp→local, sftp→sftp (through memory), local→local (sftp agent task)")
}

/// Temporary staging path for a target (`<dir>/.<name>.netcatty-part`).
pub fn staging_path(target: &str) -> PathBuf {
    let p = PathBuf::from(target);
    let name = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    p.with_file_name(format!(".{name}.netcatty-part"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_path_shape() {
        assert_eq!(staging_path("/tmp/a.txt"), PathBuf::from("/tmp/.a.txt.netcatty-part"));
    }
}
