//! SSH utility commands and prompt responses.

use super::session::SuccessResult;
use super::CmdResult;
use crate::state::Ctx;
use netcatty_core::ipc::{
    GenerateKeyPairOptions, GenerateKeyPairResult, HostKeyVerifyResponse,
    KeyboardInteractiveResponse, PassphraseResponse,
};
use netcatty_core::models::KnownHost;
use netcatty_core::CoreError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

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
    /// `"running"` | `"stopped"` (mirrors the Electron bridge).
    pub startup_type: Option<String>,
    pub error: Option<String>,
}

impl CheckAgentResult {
    fn running() -> Self {
        Self {
            running: true,
            startup_type: Some("running".into()),
            error: None,
        }
    }
    fn stopped(error: impl Into<String>) -> Self {
        Self {
            running: false,
            startup_type: Some("stopped".into()),
            error: Some(error.into()),
        }
    }
}

const AGENT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Expand a leading `~` / `~/` in a user supplied path.
pub fn expand_tilde(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed == "~" || trimmed.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{}", home.to_string_lossy(), &trimmed[1..]);
        }
    }
    trimmed.to_string()
}

/// Probe the SSH agent (`$SSH_AUTH_SOCK` or `identityAgent`) by connecting
/// and requesting its identities.
#[tauri::command]
pub async fn ssh_check_agent(payload: Option<CheckAgentOptions>) -> CmdResult<CheckAgentResult> {
    let identity_agent = payload
        .and_then(|p| p.identity_agent)
        .map(|s| expand_tilde(&s))
        .filter(|s| !s.is_empty());
    match tokio::time::timeout(AGENT_PROBE_TIMEOUT, probe_agent(identity_agent)).await {
        Ok(Ok(_identities)) => Ok(CheckAgentResult::running()),
        Ok(Err(error)) => Ok(CheckAgentResult::stopped(error)),
        Err(_) => Ok(CheckAgentResult::stopped("SSH agent connect timeout")),
    }
}

#[cfg(unix)]
async fn probe_agent(identity_agent: Option<String>) -> Result<usize, String> {
    use russh::keys::agent::client::AgentClient;
    let mut client = match identity_agent {
        Some(path) => AgentClient::connect_uds(path).await,
        None => AgentClient::connect_env().await,
    }
    .map_err(|err| format!("SSH agent socket not connectable: {err}"))?;
    let identities = client
        .request_identities()
        .await
        .map_err(|err| format!("SSH agent did not answer: {err}"))?;
    Ok(identities.len())
}

#[cfg(windows)]
async fn probe_agent(identity_agent: Option<String>) -> Result<usize, String> {
    use russh::keys::agent::client::AgentClient;
    let pipe = identity_agent.unwrap_or_else(|| r"\\.\pipe\openssh-ssh-agent".to_string());
    let mut client = AgentClient::connect_named_pipe(pipe)
        .await
        .map_err(|err| format!("SSH agent pipe not connectable: {err}"))?;
    let identities = client
        .request_identities()
        .await
        .map_err(|err| format!("SSH agent did not answer: {err}"))?;
    Ok(identities.len())
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

/// Parse `~/.ssh/known_hosts` into vault records. A missing file yields an
/// empty list.
#[tauri::command]
pub async fn ssh_read_known_hosts() -> CmdResult<Vec<KnownHost>> {
    let Some(home) = dirs::home_dir() else {
        return Ok(Vec::new());
    };
    let path = home.join(".ssh").join("known_hosts");
    match tokio::fs::read_to_string(&path).await {
        Ok(text) => Ok(netcatty_ssh::known_hosts::parse_openssh_known_hosts(&text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(CoreError::io(format!(
            "failed to read {}: {err}",
            path.display()
        ))),
    }
}

#[tauri::command]
pub fn ssh_respond_host_key<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: HostKeyVerifyResponse,
) -> SuccessResult {
    if state.prompts.resolve_host_key(payload) {
        SuccessResult::ok()
    } else {
        SuccessResult::fail("request not found or expired")
    }
}

#[tauri::command]
pub fn ssh_respond_keyboard_interactive<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: KeyboardInteractiveResponse,
) -> SuccessResult {
    if state.prompts.resolve_keyboard_interactive(payload) {
        SuccessResult::ok()
    } else {
        SuccessResult::fail("request not found or expired")
    }
}

#[tauri::command]
pub fn ssh_respond_passphrase<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: PassphraseResponse,
) -> SuccessResult {
    if state.prompts.resolve_passphrase(payload) {
        SuccessResult::ok()
    } else {
        SuccessResult::fail("request not found or expired")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expansion() {
        let home = dirs::home_dir().unwrap().to_string_lossy().into_owned();
        assert_eq!(
            expand_tilde("~/.ssh/agent.sock"),
            format!("{home}/.ssh/agent.sock")
        );
        assert_eq!(expand_tilde("~"), home);
        assert_eq!(expand_tilde("/tmp/sock"), "/tmp/sock");
        assert_eq!(expand_tilde("~user/x"), "~user/x");
    }
}
