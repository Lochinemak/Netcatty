//! SSH utility commands and prompt responses.

use super::session::SuccessResult;
use super::CmdResult;
use crate::state::AppState;
use netcatty_core::ipc::{
    GenerateKeyPairOptions, GenerateKeyPairResult, HostKeyVerifyResponse, KeyboardInteractiveResponse,
    PassphraseResponse,
};
use netcatty_core::models::KnownHost;
use serde::{Deserialize, Serialize};
use tauri::State;

#[tauri::command]
pub fn ssh_generate_key_pair(payload: GenerateKeyPairOptions) -> CmdResult<GenerateKeyPairResult> {
    Ok(netcatty_ssh::generate_key_pair(&payload)?)
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckAgentOptions {
    #[serde(default)]
    pub identity_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckAgentResult {
    pub running: bool,
    pub startup_type: Option<String>,
    pub error: Option<String>,
}

/// Probe the SSH agent (`$SSH_AUTH_SOCK` or `identityAgent`).
#[tauri::command]
pub async fn ssh_check_agent(payload: Option<CheckAgentOptions>) -> CmdResult<CheckAgentResult> {
    let _ = payload;
    todo!("AgentClient::connect_env / connect_uds + request_identities (tauri agent task)")
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultKeyFile {
    pub name: String,
    pub path: String,
}

#[tauri::command]
pub fn ssh_get_default_keys() -> Vec<DefaultKeyFile> {
    netcatty_ssh::keygen::default_key_files()
        .into_iter()
        .map(|(name, path)| DefaultKeyFile { name, path })
        .collect()
}

/// Parse `~/.ssh/known_hosts` into vault records.
#[tauri::command]
pub async fn ssh_read_known_hosts() -> CmdResult<Vec<KnownHost>> {
    todo!("read ~/.ssh/known_hosts and parse (tauri agent task)")
}

#[tauri::command]
pub fn ssh_respond_host_key(state: State<'_, AppState>, payload: HostKeyVerifyResponse) -> SuccessResult {
    if state.prompts.resolve_host_key(payload) {
        SuccessResult::ok()
    } else {
        SuccessResult::fail("request not found or expired")
    }
}

#[tauri::command]
pub fn ssh_respond_keyboard_interactive(state: State<'_, AppState>, payload: KeyboardInteractiveResponse) -> SuccessResult {
    if state.prompts.resolve_keyboard_interactive(payload) {
        SuccessResult::ok()
    } else {
        SuccessResult::fail("request not found or expired")
    }
}

#[tauri::command]
pub fn ssh_respond_passphrase(state: State<'_, AppState>, payload: PassphraseResponse) -> SuccessResult {
    if state.prompts.resolve_passphrase(payload) {
        SuccessResult::ok()
    } else {
        SuccessResult::fail("request not found or expired")
    }
}
