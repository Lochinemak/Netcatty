//! Port forwarding commands.

use super::session::SuccessResult;
use super::CmdResult;
use crate::state::AppState;
use netcatty_core::ipc::{PortForwardOptions, PortForwardSnapshot, PortForwardStartResult, PortForwardTunnelInfo};
use netcatty_core::models::PortForwardingStatus;
use serde::Serialize;
use tauri::State;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatusResult {
    pub status: PortForwardingStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Register the tunnel as connecting, dial SSH (reusing a live session
/// connection for the same endpoint when `reuseTransport != false`), then
/// activate. Status transitions are published as events; this resolves once
/// the tunnel is active or failed.
#[tauri::command]
pub async fn portforward_start(state: State<'_, AppState>, payload: PortForwardOptions) -> CmdResult<PortForwardStartResult> {
    let _ = (state, payload);
    todo!()
}

#[tauri::command]
pub async fn portforward_stop(state: State<'_, AppState>, tunnel_id: String) -> CmdResult<SuccessResult> {
    let _ = (state, tunnel_id);
    todo!()
}

#[tauri::command]
pub async fn portforward_stop_by_rule(state: State<'_, AppState>, rule_id: String) -> CmdResult<SuccessResult> {
    let _ = (state, rule_id);
    todo!()
}

#[tauri::command]
pub async fn portforward_stop_all(state: State<'_, AppState>) -> CmdResult<SuccessResult> {
    let _ = state;
    todo!()
}

#[tauri::command]
pub fn portforward_status(state: State<'_, AppState>, tunnel_id: String) -> CmdResult<TunnelStatusResult> {
    let _ = (state, tunnel_id);
    todo!()
}

#[tauri::command]
pub fn portforward_list(state: State<'_, AppState>) -> Vec<PortForwardTunnelInfo> {
    state.tunnels.list()
}

#[tauri::command]
pub fn portforward_snapshot(state: State<'_, AppState>) -> PortForwardSnapshot {
    state.tunnels.snapshot()
}
