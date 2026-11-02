//! Local filesystem commands.

use super::{raw_body, require_header, CmdResult};
use crate::events;
use crate::state::Ctx;
use netcatty_core::ipc::{events as ev, LocalTreeEntry, LocalTreeProgressEvent};
use netcatty_core::models::{FileEntryType, RemoteFile, StatResult};
use netcatty_core::CoreError;
use netcatty_localfs::TreeLimits;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tauri::command]
pub async fn local_list_dir(path: String) -> CmdResult<Vec<RemoteFile>> {
    netcatty_localfs::list_dir(&path).await
}

#[tauri::command]
pub async fn local_read_file(
    path: String,
    max_bytes: Option<u64>,
) -> CmdResult<tauri::ipc::Response> {
    let bytes = netcatty_localfs::read_file(&path, max_bytes).await?;
    Ok(tauri::ipc::Response::new(bytes))
}

/// Raw body = file content; header `path` = destination.
#[tauri::command]
pub async fn local_write_file(request: tauri::ipc::Request<'_>) -> CmdResult<()> {
    let body = raw_body(&request)?;
    let path = require_header(request.headers(), "path")?;
    netcatty_localfs::write_file(&path, body).await
}

#[tauri::command]
pub async fn local_delete(path: String, expected_type: Option<FileEntryType>) -> CmdResult<()> {
    netcatty_localfs::delete(&path, expected_type).await
}

#[tauri::command]
pub async fn local_rename(old_path: String, new_path: String) -> CmdResult<()> {
    netcatty_localfs::rename(&old_path, &new_path).await
}

#[tauri::command]
pub async fn local_mkdir(path: String) -> CmdResult<()> {
    netcatty_localfs::mkdir(&path).await
}

#[tauri::command]
pub async fn local_stat(path: String) -> CmdResult<StatResult> {
    netcatty_localfs::stat(&path).await
}

#[tauri::command]
pub async fn local_lstat(path: String) -> CmdResult<StatResult> {
    netcatty_localfs::lstat(&path).await
}

#[tauri::command]
pub async fn local_realpath(path: String) -> CmdResult<String> {
    netcatty_localfs::realpath(&path).await
}

#[tauri::command]
pub async fn local_extract(path: String) -> CmdResult<()> {
    netcatty_localfs::extract_archive(&path).await
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeLimitsPayload {
    #[serde(default)]
    pub max_directories: Option<u64>,
    #[serde(default)]
    pub max_entries: Option<u64>,
}

impl From<TreeLimitsPayload> for TreeLimits {
    fn from(p: TreeLimitsPayload) -> Self {
        TreeLimits {
            max_directories: p.max_directories,
            max_entries: p.max_entries,
        }
    }
}

/// Walk a directory tree; progress + streamed entries arrive on
/// `netcatty:local:tree-progress` keyed by `scanId`. Cancel with
/// `local_cancel_tree_scan`.
#[tauri::command]
pub async fn local_list_tree<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    scan_id: String,
    path: String,
    limits: Option<TreeLimitsPayload>,
) -> CmdResult<Vec<LocalTreeEntry>> {
    if scan_id.trim().is_empty() {
        return Err(CoreError::invalid("scanId is required"));
    }
    if state.tree_scans.contains_key(&scan_id) {
        return Err(CoreError::invalid(format!(
            "scan {scan_id} is already running"
        )));
    }
    let cancel = CancellationToken::new();
    state.tree_scans.insert(scan_id.clone(), cancel.clone());

    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<LocalTreeProgressEvent>();
    let app = state.app.clone();
    let forwarder = tokio::spawn(async move {
        while let Some(event) = progress_rx.recv().await {
            events::emit(&app, ev::LOCAL_TREE_PROGRESS, event);
        }
    });

    let result = netcatty_localfs::list_tree(
        &scan_id,
        &path,
        limits.unwrap_or_default().into(),
        Some(progress_tx),
        cancel,
    )
    .await;
    // The sender moved into `list_tree` is dropped by now; let the forwarder
    // drain whatever is left before returning (bounded, in case a clone of
    // the sender outlives the walk).
    if tokio::time::timeout(std::time::Duration::from_secs(2), forwarder)
        .await
        .is_err()
    {
        tracing::debug!(scan_id, "tree progress forwarder did not finish promptly");
    }
    state.tree_scans.remove(&scan_id);
    result
}

#[tauri::command]
pub async fn local_cancel_tree_scan<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    scan_id: String,
) -> CmdResult<()> {
    if let Some(token) = state.tree_scans.get(&scan_id) {
        token.cancel();
    }
    Ok(())
}

#[tauri::command]
pub fn local_home_dir() -> CmdResult<String> {
    netcatty_localfs::home_dir()
}

#[tauri::command]
pub async fn local_list_drives() -> CmdResult<Vec<String>> {
    netcatty_localfs::list_drives().await
}
