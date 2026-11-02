//! Local filesystem commands.

use super::CmdResult;
use crate::state::AppState;
use netcatty_core::ipc::LocalTreeEntry;
use netcatty_core::models::{FileEntryType, RemoteFile, StatResult};
use serde::Deserialize;
use tauri::State;

#[tauri::command]
pub async fn local_list_dir(path: String) -> CmdResult<Vec<RemoteFile>> {
    netcatty_localfs::list_dir(&path).await
}

#[tauri::command]
pub async fn local_read_file(path: String, max_bytes: Option<u64>) -> CmdResult<tauri::ipc::Response> {
    let bytes = netcatty_localfs::read_file(&path, max_bytes).await?;
    Ok(tauri::ipc::Response::new(bytes))
}

/// Raw body = file content; header `path` = destination.
#[tauri::command]
pub async fn local_write_file(request: tauri::ipc::Request<'_>) -> CmdResult<()> {
    let _ = request;
    todo!("extract path header + raw body (tauri agent task)")
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

/// Walk a directory tree; progress + streamed entries arrive on
/// `netcatty:local:tree-progress` keyed by `scanId`.
#[tauri::command]
pub async fn local_list_tree(state: State<'_, AppState>, scan_id: String, path: String, limits: Option<TreeLimitsPayload>) -> CmdResult<Vec<LocalTreeEntry>> {
    let _ = (state, scan_id, path, limits);
    todo!("register CancellationToken by scan_id, forward progress events (tauri agent task)")
}

#[tauri::command]
pub async fn local_cancel_tree_scan(state: State<'_, AppState>, scan_id: String) -> CmdResult<()> {
    let _ = (state, scan_id);
    todo!()
}

#[tauri::command]
pub fn local_home_dir() -> CmdResult<String> {
    netcatty_localfs::home_dir()
}

#[tauri::command]
pub async fn local_list_drives() -> CmdResult<Vec<String>> {
    netcatty_localfs::list_drives().await
}
