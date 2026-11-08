//! Catty Agent terminal exec (`aiExec` / `aiCattyCancelExec`).
//!
//! Runs a command in a live terminal session through the marker-wrapped PTY
//! engine (`netcatty_ptyexec`) owned by the MCP host, so blocklist, observer
//! mode, scope checks and per-chat cancellation are shared with MCP tools.

use super::mcp::mcp;
use super::CmdResult;
use crate::state::Ctx;
use serde_json::Value;
use tauri::Runtime;

/// `aiExec(sessionId, command, chatSessionId?)` →
/// `{ ok, stdout?, stderr?, exitCode?, error? }`.
#[tauri::command]
pub async fn ai_exec<R: Runtime>(state: Ctx<'_, R>, session_id: String, command: String, chat_session_id: Option<String>) -> CmdResult<Value> {
    let host = mcp(&state)?.host.clone();
    Ok(host.catty_exec(&session_id, &command, chat_session_id.as_deref()).await)
}

/// `aiCattyCancelExec(chatSessionId)` → `{ ok }`.
#[tauri::command]
pub async fn ai_catty_cancel_exec<R: Runtime>(state: Ctx<'_, R>, chat_session_id: String) -> CmdResult<Value> {
    let host = mcp(&state)?.host.clone();
    Ok(host.catty_cancel(&chat_session_id).await)
}
