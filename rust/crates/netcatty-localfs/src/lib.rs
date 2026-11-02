//! `netcatty-localfs` — local filesystem operations for the file browser and
//! transfers (mirrors `electron/bridges/localFsBridge.cjs`).
//!
//! All functions are async and run blocking filesystem work on the tokio
//! blocking pool. Paths are passed as received from the renderer.

use netcatty_core::ipc::{LocalTreeEntry, LocalTreeProgressEvent, PathValidation, SystemInfo};
use netcatty_core::models::{FileEntryType, RemoteFile, StatResult};
use netcatty_core::{CoreError, CoreResult};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// List a directory. Mirrors `listLocalDir`: stat follows symlinks for
/// size/mtime/type, `linkTarget` records the target kind (`None` inside
/// `Some` for broken links), owner is the directory entry's uid as a string
/// (name when resolvable), and `hidden` reflects the Windows hidden
/// attribute (always `false` elsewhere). Entries that cannot be stat'ed are
/// skipped.
pub async fn list_dir(path: &str) -> CoreResult<Vec<RemoteFile>> {
    let _ = path;
    todo!("list_dir (localfs agent task)")
}

/// Read a file. With `max_bytes`, return the **last** `max_bytes` bytes
/// (log tailing semantics of the Electron bridge).
pub async fn read_file(path: &str, max_bytes: Option<u64>) -> CoreResult<Vec<u8>> {
    let _ = (path, max_bytes);
    todo!()
}

pub async fn write_file(path: &str, content: &[u8]) -> CoreResult<()> {
    let _ = (path, content);
    todo!()
}

/// Delete a file / symlink / directory tree. When `expected_type` is given
/// and differs from the current type, fail with `InvalidArgument` and the
/// message `Local target changed before replace: expected X, found Y`.
pub async fn delete(path: &str, expected_type: Option<FileEntryType>) -> CoreResult<()> {
    let _ = (path, expected_type);
    todo!()
}

pub async fn rename(old_path: &str, new_path: &str) -> CoreResult<()> {
    let _ = (old_path, new_path);
    todo!()
}

/// `mkdir -p`; an existing directory is not an error (Windows drive roots).
pub async fn mkdir(path: &str) -> CoreResult<()> {
    let _ = path;
    todo!()
}

/// Stat following symlinks; includes `dev`/`ino` except on Windows.
pub async fn stat(path: &str) -> CoreResult<StatResult> {
    let _ = path;
    todo!()
}

/// Stat without following symlinks.
pub async fn lstat(path: &str) -> CoreResult<StatResult> {
    let _ = path;
    todo!()
}

pub async fn realpath(path: &str) -> CoreResult<String> {
    let _ = path;
    todo!()
}

/// Extract `.zip`, `.tar`, `.tar.gz`/`.tgz`, `.tar.bz2`, `.tar.xz` next to
/// the archive using the system `tar` / `unzip` binaries.
pub async fn extract_archive(path: &str) -> CoreResult<()> {
    let _ = path;
    todo!()
}

/// Limits for [`list_tree`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TreeLimits {
    pub max_directories: Option<u64>,
    pub max_entries: Option<u64>,
}

/// Recursively walk `path` (not following symlinks). Progress events with
/// batched entries are pushed to `progress` roughly every 200 entries or
/// 100 ms; the full list is returned at the end. Cancel with `cancel`.
pub async fn list_tree(
    scan_id: &str,
    path: &str,
    limits: TreeLimits,
    progress: Option<mpsc::UnboundedSender<LocalTreeProgressEvent>>,
    cancel: CancellationToken,
) -> CoreResult<Vec<LocalTreeEntry>> {
    let _ = (scan_id, path, limits, progress, cancel);
    todo!()
}

pub fn home_dir() -> CoreResult<String> {
    dirs::home_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .ok_or_else(|| CoreError::not_found("home directory not found"))
}

/// Windows: drive letters (`C:\`, `D:\`); elsewhere: `["/"]`.
pub async fn list_drives() -> CoreResult<Vec<String>> {
    todo!()
}

pub fn system_info() -> SystemInfo {
    todo!("username + hostname (localfs agent task)")
}

/// `validatePath` IPC: existence and kind of a path.
pub async fn validate_path(path: &str) -> PathValidation {
    let _ = path;
    todo!()
}
