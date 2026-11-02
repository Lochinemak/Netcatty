//! Terminal session commands (SSH shell, local PTY) and SSH exec.

use super::CmdResult;
use crate::state::AppState;
use netcatty_core::ipc::{
    DiscoveredShell, ExecCommandOptions, ExecResult, LocalSessionOptions, PathValidation, ResizePayload,
    SshSessionOptions, StartSessionResult, WriteToSessionPayload,
};
use serde::Serialize;
use tauri::State;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SuccessResult {
    pub fn ok() -> Self {
        Self { success: true, error: None }
    }
    pub fn fail(error: impl Into<String>) -> Self {
        Self { success: false, error: Some(error.into()) }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PwdResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteInfoResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Start an interactive SSH shell. Resolves with the session id once the
/// shell channel is open; connection progress / prompts arrive as events.
#[tauri::command]
pub async fn session_start_ssh(state: State<'_, AppState>, payload: SshSessionOptions) -> CmdResult<StartSessionResult> {
    let _ = (state, payload);
    todo!("connect (or reuse via sourceSessionId), open_shell, register session (tauri agent task)")
}

/// Connect + authenticate + disconnect, reporting errors like a real start.
#[tauri::command]
pub async fn session_test_connection(state: State<'_, AppState>, payload: SshSessionOptions) -> CmdResult<StartSessionResult> {
    let _ = (state, payload);
    todo!()
}

#[tauri::command]
pub async fn session_cancel_test_connection(state: State<'_, AppState>, session_id: String) -> CmdResult<SuccessResult> {
    let _ = (state, session_id);
    todo!()
}

#[tauri::command]
pub async fn session_start_local(state: State<'_, AppState>, payload: LocalSessionOptions) -> CmdResult<StartSessionResult> {
    let _ = (state, payload);
    todo!("PtySession::spawn + register (tauri agent task)")
}

#[tauri::command]
pub async fn session_write(state: State<'_, AppState>, payload: WriteToSessionPayload) -> CmdResult<()> {
    let _ = (state, payload);
    todo!("decode base64 when binary, honor lineDelayMs for multi-line automated writes (tauri agent task)")
}

#[tauri::command]
pub async fn session_resize(state: State<'_, AppState>, payload: ResizePayload) -> CmdResult<()> {
    state.sessions.resize(&payload.session_id, payload.cols, payload.rows).await
}

/// Send an interrupt (Ctrl-C) to the session's foreground process.
#[tauri::command]
pub async fn session_interrupt(state: State<'_, AppState>, session_id: String) -> CmdResult<()> {
    state.sessions.write(&session_id, bytes::Bytes::from_static(b"\x03")).await
}

/// Renderer back-pressure hint. The Rust pump applies bounded channels, so
/// this only toggles a per-session pause flag.
#[tauri::command]
pub async fn session_set_flow_paused(state: State<'_, AppState>, session_id: String, paused: bool) -> CmdResult<()> {
    let _ = (state, session_id, paused);
    todo!()
}

#[tauri::command]
pub async fn session_ack_flow(state: State<'_, AppState>, session_id: String, bytes: u64) -> CmdResult<()> {
    let _ = (state, session_id, bytes);
    Ok(())
}

#[tauri::command]
pub async fn session_close(state: State<'_, AppState>, session_id: String) -> CmdResult<()> {
    state.sessions.close(&session_id).await
}

/// One-shot remote command on a fresh connection (or on the connection of
/// `sessionId` when given and alive).
#[tauri::command]
pub async fn session_exec(state: State<'_, AppState>, payload: ExecCommandOptions) -> CmdResult<ExecResult> {
    let _ = (state, payload);
    todo!()
}

/// Working directory of the session's foreground process: local sessions
/// use the PTY cwd discovery; SSH sessions run `readlink /proc/<pid>/cwd`
/// style probes on an exec channel of the same connection.
#[tauri::command]
pub async fn session_pwd(state: State<'_, AppState>, session_id: String) -> CmdResult<PwdResult> {
    let _ = (state, session_id);
    todo!()
}

#[tauri::command]
pub async fn session_remote_info(state: State<'_, AppState>, session_id: String) -> CmdResult<RemoteInfoResult> {
    let _ = (state, session_id);
    todo!()
}

#[tauri::command]
pub fn local_get_default_shell() -> String {
    netcatty_pty::default_shell()
}

#[tauri::command]
pub fn local_discover_shells() -> Vec<DiscoveredShell> {
    netcatty_pty::discover_shells()
}

#[tauri::command]
pub async fn local_validate_path(path: String, kind: Option<String>) -> PathValidation {
    let _ = kind;
    netcatty_localfs::validate_path(&path).await
}
