//! SFTP browse + transfer commands.

use super::session::SuccessResult;
use super::CmdResult;
use crate::state::AppState;
use netcatty_core::ipc::{OpenSftpResult, SshSessionOptions, StreamTransferOptions, StreamTransferResult};
use netcatty_core::models::{FileEntryType, RemoteFile, SftpFilenameEncoding, StatResult};
use serde::Serialize;
use tauri::State;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HomeDirResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Open an SFTP browser on a fresh connection, or on the live connection of
/// `payload.sourceSessionId` when `reuseTransport != false` and it matches.
#[tauri::command]
pub async fn sftp_open(state: State<'_, AppState>, payload: SshSessionOptions) -> CmdResult<OpenSftpResult> {
    let _ = (state, payload);
    todo!()
}

#[tauri::command]
pub async fn sftp_open_for_session(state: State<'_, AppState>, session_id: String, payload: Option<SshSessionOptions>) -> CmdResult<OpenSftpResult> {
    let _ = (state, session_id, payload);
    todo!()
}

#[tauri::command]
pub async fn sftp_list(state: State<'_, AppState>, sftp_id: String, path: String, encoding: Option<SftpFilenameEncoding>) -> CmdResult<Vec<RemoteFile>> {
    let _ = (state, sftp_id, path, encoding);
    todo!()
}

#[tauri::command]
pub async fn sftp_realpath(state: State<'_, AppState>, sftp_id: String, path: String, encoding: Option<SftpFilenameEncoding>) -> CmdResult<String> {
    let _ = (state, sftp_id, path, encoding);
    todo!()
}

/// Read as UTF-8 text (lossy).
#[tauri::command]
pub async fn sftp_read(state: State<'_, AppState>, sftp_id: String, path: String, encoding: Option<SftpFilenameEncoding>) -> CmdResult<String> {
    let _ = (state, sftp_id, path, encoding);
    todo!()
}

/// Read raw bytes; returned as an `ArrayBuffer` to the renderer.
#[tauri::command]
pub async fn sftp_read_binary(state: State<'_, AppState>, sftp_id: String, path: String, encoding: Option<SftpFilenameEncoding>) -> CmdResult<tauri::ipc::Response> {
    let _ = (state, sftp_id, path, encoding);
    todo!()
}

#[tauri::command]
pub async fn sftp_write(state: State<'_, AppState>, sftp_id: String, path: String, content: String, encoding: Option<SftpFilenameEncoding>) -> CmdResult<()> {
    let _ = (state, sftp_id, path, content, encoding);
    todo!()
}

/// Binary write: the renderer invokes with a raw `ArrayBuffer` body and
/// passes `sftpId`, `path`, `encoding` as request headers.
#[tauri::command]
pub async fn sftp_write_binary(state: State<'_, AppState>, request: tauri::ipc::Request<'_>) -> CmdResult<()> {
    let _ = (state, request);
    todo!()
}

#[tauri::command]
pub async fn sftp_mkdir(state: State<'_, AppState>, sftp_id: String, path: String, encoding: Option<SftpFilenameEncoding>) -> CmdResult<()> {
    let _ = (state, sftp_id, path, encoding);
    todo!()
}

#[tauri::command]
pub async fn sftp_delete(state: State<'_, AppState>, sftp_id: String, path: String, encoding: Option<SftpFilenameEncoding>, expected_type: Option<FileEntryType>) -> CmdResult<()> {
    let _ = (state, sftp_id, path, encoding, expected_type);
    todo!()
}

#[tauri::command]
pub async fn sftp_rename(state: State<'_, AppState>, sftp_id: String, old_path: String, new_path: String, encoding: Option<SftpFilenameEncoding>) -> CmdResult<()> {
    let _ = (state, sftp_id, old_path, new_path, encoding);
    todo!()
}

#[tauri::command]
pub async fn sftp_stat(state: State<'_, AppState>, sftp_id: String, path: String, encoding: Option<SftpFilenameEncoding>) -> CmdResult<StatResult> {
    let _ = (state, sftp_id, path, encoding);
    todo!()
}

#[tauri::command]
pub async fn sftp_lstat(state: State<'_, AppState>, sftp_id: String, path: String, encoding: Option<SftpFilenameEncoding>) -> CmdResult<Option<StatResult>> {
    let _ = (state, sftp_id, path, encoding);
    todo!()
}

#[tauri::command]
pub async fn sftp_chmod(state: State<'_, AppState>, sftp_id: String, path: String, mode: String, encoding: Option<SftpFilenameEncoding>) -> CmdResult<()> {
    let _ = (state, sftp_id, path, mode, encoding);
    todo!()
}

#[tauri::command]
pub async fn sftp_extract(state: State<'_, AppState>, sftp_id: String, path: String, encoding: Option<SftpFilenameEncoding>) -> CmdResult<SuccessResult> {
    let _ = (state, sftp_id, path, encoding);
    todo!()
}

#[tauri::command]
pub async fn sftp_home_dir(state: State<'_, AppState>, sftp_id: String, encoding: Option<SftpFilenameEncoding>) -> CmdResult<HomeDirResult> {
    let _ = (state, sftp_id, encoding);
    todo!()
}

#[tauri::command]
pub async fn sftp_close(state: State<'_, AppState>, sftp_id: String) -> CmdResult<SuccessResult> {
    let _ = (state, sftp_id);
    todo!()
}

/// Start a streaming transfer; resolves when it completes, fails, pauses or
/// is cancelled. Progress is pushed on `netcatty:sftp:global-transfer`.
#[tauri::command]
pub async fn transfer_start(state: State<'_, AppState>, payload: StreamTransferOptions) -> CmdResult<StreamTransferResult> {
    let _ = (state, payload);
    todo!()
}

#[tauri::command]
pub async fn transfer_cancel(state: State<'_, AppState>, transfer_id: String) -> CmdResult<()> {
    let _ = (state, transfer_id);
    todo!()
}

#[tauri::command]
pub async fn transfer_pause(state: State<'_, AppState>, transfer_id: String) -> CmdResult<SuccessResult> {
    let _ = (state, transfer_id);
    todo!()
}
