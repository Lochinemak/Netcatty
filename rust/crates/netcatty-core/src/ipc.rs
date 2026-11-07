//! IPC payload types shared between the Tauri command layer and the renderer.
//!
//! These mirror the `NetcattyBridge` contract in `types/global/netcatty-bridge-*.d.ts`
//! and `global.d.ts`. Field names are camelCase on the wire.
//!
//! Event names (`events::*`) intentionally keep the Electron channel names so
//! the renderer-side adapter is a thin mapping.

use crate::models::{
    HostAlgorithmOverrides, HostAuthMethod, HostTotpConfig, KeyType, KnownHost, PortForwardingType,
    ProxyConfig,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Event channel names emitted from Rust to the renderer.
pub mod events {
    /// `{ sessionId, data }` — terminal output.
    pub const SESSION_DATA: &str = "netcatty:data";
    /// `SessionExitEvent`.
    pub const SESSION_EXIT: &str = "netcatty:exit";
    /// `AuthFailedEvent`.
    pub const AUTH_FAILED: &str = "netcatty:auth:failed";
    /// `KeyboardInteractiveRequest`.
    pub const KEYBOARD_INTERACTIVE: &str = "netcatty:keyboard-interactive";
    /// `{ requestId, sessionId?, reason? }`.
    pub const KEYBOARD_INTERACTIVE_CANCELLED: &str = "netcatty:keyboard-interactive-cancelled";
    /// `HostKeyVerifyRequest`.
    pub const HOST_KEY_VERIFY: &str = "netcatty:host-key:verify";
    /// `PassphraseRequest`.
    pub const PASSPHRASE_REQUEST: &str = "netcatty:passphrase-request";
    pub const PASSPHRASE_TIMEOUT: &str = "netcatty:passphrase-timeout";
    pub const PASSPHRASE_CANCELLED: &str = "netcatty:passphrase-cancelled";
    pub const PASSPHRASE_AUTH_FAILED: &str = "netcatty:passphrase-auth-failed";
    /// `ChainProgressEvent` — jump host chain progress.
    pub const CHAIN_PROGRESS: &str = "netcatty:chain:progress";
    /// `PortForwardStatusEvent`.
    pub const PORT_FORWARD_STATUS: &str = "netcatty:portforward:status";
    /// `PortForwardRuntimeEvent`.
    pub const PORT_FORWARD_RUNTIME: &str = "netcatty:portforward:runtime";
    /// `SftpConnectionProgress`.
    pub const SFTP_CONNECTION_PROGRESS: &str = "netcatty:sftp:connection-progress";
    /// `TransferEvent`.
    pub const SFTP_GLOBAL_TRANSFER: &str = "netcatty:sftp:global-transfer";
    /// `TelnetEchoModeEvent`.
    pub const TELNET_ECHO_MODE: &str = "netcatty:telnet:echo-mode";
    /// `{ sessionId }`.
    pub const TELNET_AUTO_LOGIN_COMPLETE: &str = "netcatty:telnet:auto-login-complete";
    /// `LocalTreeProgressEvent`.
    pub const LOCAL_TREE_PROGRESS: &str = "netcatty:local:tree-progress";
    /// No payload — the cloud sync master password became available
    /// (another window unlocked sync).
    pub const CLOUD_SYNC_PASSWORD_AVAILABLE: &str = "netcatty:cloudsync:password-available";
    /// `{ source, payload: { key, value } }` — a setting changed in the
    /// window labelled `source`; other windows apply it.
    pub const SETTINGS_CHANGED: &str = "netcatty:settings:changed";
    /// UI language string (`"en"`, `"zh-CN"`, …).
    pub const LANGUAGE_CHANGED: &str = "netcatty:language-changed";
    /// `{ label, fullscreen }` — the window entered / left fullscreen.
    pub const WINDOW_FULLSCREEN_CHANGED: &str = "netcatty:window:fullscreen-changed";
}

// ---------------------------------------------------------------------------
// Session start options
// ---------------------------------------------------------------------------

/// A jump host (bastion) hop. Mirrors `NetcattyJumpHost`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JumpHost {
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<HostAuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_mfa: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<HostTotpConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file_paths: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_ssh_agent: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_public_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identities_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_interval: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_count_max: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_tcp_connect_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_auth_ready_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_host_keys: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_algorithms: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_ecdsa_host_key: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm_overrides: Option<HostAlgorithmOverrides>,
}

fn default_ssh_port() -> u16 {
    22
}

/// Session log configuration (`sessionLog` on start options).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionLogConfig {
    pub enabled: bool,
    #[serde(default)]
    pub directory: String,
    #[serde(default)]
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamps_enabled: Option<bool>,
}

/// Mirrors `NetcattySSHOptions`. Used by `startSSHSession`, `testConnection`,
/// `openSftp` and (as a base) `execCommand` / port forwarding.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshSessionOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_label: Option<String>,
    pub hostname: String,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<HostAuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_mfa: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<HostTotpConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_forwarding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x11_forwarding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x11_display: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cols: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_hosts: Option<Vec<KnownHost>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_host_keys: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_unattended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_hosts: Option<Vec<JumpHost>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_interval: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_count_max: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_tcp_connect_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_auth_ready_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_algorithms: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_ecdsa_host_key: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm_overrides: Option<HostAlgorithmOverrides>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sudo: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_log: Option<SessionLogConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file_paths: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_ssh_agent: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_public_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identities_only: Option<bool>,
    /// Reuse the authenticated transport of this existing session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_exact_source_session: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse_transport: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_channel_ssh: Option<bool>,
    /// Anything else the renderer sends (plugin / future fields).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl SshSessionOptions {
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(22)
    }
    pub fn cols(&self) -> u16 {
        self.cols.unwrap_or(80)
    }
    pub fn rows(&self) -> u16 {
        self.rows.unwrap_or(24)
    }
    pub fn verify_host_keys(&self) -> bool {
        self.verify_host_keys.unwrap_or(true)
    }
}

/// `startLocalSession` options.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalSessionOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cols: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_log: Option<SessionLogConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_epoch: Option<u64>,
}

/// `startTelnetSession` options.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelnetSessionOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cols: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_log: Option<SessionLogConfig>,
}

/// `execCommand` options: SSH options plus the command.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecCommandOptions {
    #[serde(flatten)]
    pub ssh: SshSessionOptions,
    pub command: String,
    /// Overall timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_keyboard_interactive: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub code: Option<i32>,
}

/// `generateKeyPair` options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateKeyPairOptions {
    #[serde(rename = "type")]
    pub key_type: KeyType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateKeyPairResult {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<KeyType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `writeToSession` payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteToSessionPayload {
    pub session_id: String,
    /// UTF-8 text, or base64 when `binary` is true.
    pub data: String,
    #[serde(default)]
    pub binary: bool,
    #[serde(default)]
    pub automated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paste_request_id: Option<String>,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResizePayload {
    pub session_id: String,
    pub cols: u16,
    pub rows: u16,
}

/// Result of `startSSHSession` and friends (renderer unwraps `.sessionId`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartSessionResult {
    pub session_id: String,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDataEvent {
    pub session_id: String,
    pub data: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExitReason {
    Exited,
    Error,
    Timeout,
    Closed,
    Signaled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionExitEvent {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_signal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub reason: ExitReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_closed_without_exit_status: Option<bool>,
}

impl SessionExitEvent {
    pub fn closed(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            exit_code: Some(0),
            signal: None,
            exit_signal: None,
            error: None,
            reason: ExitReason::Closed,
            remote_closed_without_exit_status: None,
        }
    }
    pub fn exited(session_id: impl Into<String>, code: Option<i32>) -> Self {
        Self {
            session_id: session_id.into(),
            exit_code: code,
            signal: None,
            exit_signal: None,
            error: None,
            reason: ExitReason::Exited,
            remote_closed_without_exit_status: Some(code.is_none()),
        }
    }
    pub fn error(session_id: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            exit_code: None,
            signal: None,
            exit_signal: None,
            error: Some(error.into()),
            reason: ExitReason::Error,
            remote_closed_without_exit_status: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthFailedEvent {
    pub session_id: String,
    pub error: String,
    pub hostname: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyboardInteractivePrompt {
    pub prompt: String,
    pub echo: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyboardInteractiveRequest {
    pub request_id: String,
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<KeyboardInteractivePrompt>,
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_save_password: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyboardInteractiveResponse {
    pub request_id: String,
    #[serde(default)]
    pub responses: Vec<String>,
    #[serde(default)]
    pub cancelled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostKeyStatus {
    Unknown,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyVerifyRequest {
    pub request_id: String,
    pub session_id: String,
    pub hostname: String,
    pub port: u16,
    pub status: HostKeyStatus,
    pub key_type: String,
    /// SHA256 fingerprint without prefix.
    pub fingerprint: String,
    /// Base64 public key blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyVerifyResponse {
    pub request_id: String,
    pub accept: bool,
    #[serde(default)]
    pub add_to_known_hosts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassphraseRequest {
    pub request_id: String,
    pub key_path: String,
    pub key_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase_invalid: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassphraseResponse {
    pub request_id: String,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub cancelled: bool,
    #[serde(default)]
    pub skip: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainProgressEvent {
    pub session_id: String,
    /// 0-based index of the hop being connected.
    pub hop_index: usize,
    pub hop_count: usize,
    pub hostname: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Port forwarding
// ---------------------------------------------------------------------------

/// `PortForwardOptions` in `global.d.ts`: SSH options plus tunnel parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortForwardOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub tunnel_id: String,
    #[serde(rename = "type")]
    pub forward_type: PortForwardingType,
    pub local_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    #[serde(flatten)]
    pub ssh: SshSessionOptions,
}

impl PortForwardOptions {
    pub fn bind_address(&self) -> &str {
        self.bind_address.as_deref().unwrap_or("127.0.0.1")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortForwardStartResult {
    pub tunnel_id: String,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reused: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<crate::models::PortForwardingStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortForwardStatusEvent {
    pub tunnel_id: String,
    pub status: crate::models::PortForwardingStatus,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub epoch: u64,
    pub revision: u64,
    #[serde(default)]
    pub cleanup_required: bool,
}

/// One entry in the authoritative tunnel snapshot (`portforward:snapshot`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortForwardTunnelInfo {
    pub tunnel_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(rename = "type")]
    pub forward_type: PortForwardingType,
    pub status: crate::models::PortForwardingStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub local_port: u16,
    pub bind_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    pub hostname: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortForwardSnapshot {
    pub epoch: u64,
    pub revision: u64,
    pub tunnels: Vec<PortForwardTunnelInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum PortForwardRuntimeEvent {
    Upsert {
        epoch: u64,
        revision: u64,
        tunnel: PortForwardTunnelInfo,
    },
    Remove {
        epoch: u64,
        revision: u64,
        tunnel_id: String,
    },
    Reset {
        epoch: u64,
        revision: u64,
    },
}

// ---------------------------------------------------------------------------
// SFTP / transfers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpConnectionProgress {
    pub session_id: String,
    pub label: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenSftpResult {
    pub sftp_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reused_connection: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferEventType {
    Queued,
    Started,
    Progress,
    Pausing,
    Paused,
    Resumed,
    Cancelled,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointType {
    Local,
    Sftp,
}

/// `startStreamTransfer` options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamTransferOptions {
    pub transfer_id: String,
    pub source_path: String,
    pub target_path: String,
    pub source_type: EndpointType,
    pub target_type: EndpointType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sftp_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_sftp_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_encoding: Option<crate::models::SftpFilenameEncoding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_encoding: Option<crate::models::SftpFilenameEncoding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_bytes: Option<u64>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamTransferResult {
    pub transfer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// `onGlobalSftpTransferEvent` payload (subset the first version emits).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferEvent {
    #[serde(rename = "type")]
    pub event_type: TransferEventType,
    pub transfer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<crate::models::TransferDirection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transferred: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    /// Bytes per second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<crate::models::TransferPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumable: Option<bool>,
}

// ---------------------------------------------------------------------------
// Local filesystem
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalTreeEntry {
    pub local_path: String,
    pub relative_path: String,
    #[serde(rename = "type")]
    pub entry_type: crate::models::FileEntryType,
    pub size: u64,
    pub last_modified: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalTreeProgressEvent {
    pub scan_id: String,
    pub file_count: u64,
    pub directory_count: u64,
    pub entry_count: u64,
    /// Newly discovered rows since the previous event.
    #[serde(default)]
    pub entries: Vec<LocalTreeEntry>,
    #[serde(default)]
    pub done: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathValidation {
    pub exists: bool,
    pub is_file: bool,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    pub username: String,
    pub hostname: String,
}

/// A discovered local shell (`DiscoveredShell`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredShell {
    pub id: String,
    pub name: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    pub icon: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelnetEchoModeEvent {
    pub session_id: String,
    pub remote_echo: bool,
    pub local_echo: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_options_accept_renderer_payload() {
        let json = r#"{"hostname":"h","username":"u","port":2222,"cols":120,"rows":40,
            "knownHosts":[],"verifyHostKeys":true,"jumpHosts":[{"hostname":"j","username":"ju"}],
            "proxy":{"type":"socks5","host":"127.0.0.1","port":1080},"sshDebugLogEnabled":true}"#;
        let opts: SshSessionOptions = serde_json::from_str(json).unwrap();
        assert_eq!(opts.port(), 2222);
        assert_eq!(opts.jump_hosts.as_ref().unwrap()[0].port, 22);
        assert_eq!(
            opts.extra.get("sshDebugLogEnabled"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn exec_options_flatten_ssh() {
        let json = r#"{"hostname":"h","username":"u","command":"uname -a","timeout":5000}"#;
        let opts: ExecCommandOptions = serde_json::from_str(json).unwrap();
        assert_eq!(opts.ssh.hostname, "h");
        assert_eq!(opts.command, "uname -a");
    }

    #[test]
    fn port_forward_options_flatten_ssh() {
        let json = r#"{"tunnelId":"t1","type":"local","localPort":8080,"remoteHost":"db","remotePort":5432,"hostname":"bastion","username":"ops"}"#;
        let opts: PortForwardOptions = serde_json::from_str(json).unwrap();
        assert_eq!(opts.forward_type, PortForwardingType::Local);
        assert_eq!(opts.bind_address(), "127.0.0.1");
        assert_eq!(opts.ssh.hostname, "bastion");
    }

    #[test]
    fn exit_event_shape() {
        let v = serde_json::to_value(SessionExitEvent::closed("s")).unwrap();
        assert_eq!(v["reason"], "closed");
        assert_eq!(v["exitCode"], 0);
        assert!(v.get("error").is_none());
    }
}

// ---------------------------------------------------------------------------
// Remote desktop (VNC / RDP)
// ---------------------------------------------------------------------------

/// `startRemoteDesktopSession` options.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteDesktopOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// `"vnc"` or `"rdp"`.
    pub protocol: String,
    pub hostname: String,
    /// Defaults to the protocol's well-known port (5900 / 3389).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// RDP logon domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Desktop size to request (RDP). Defaults to 1280×800.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u16>,
}

impl std::fmt::Debug for RemoteDesktopOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The password must never reach a log line.
        f.debug_struct("RemoteDesktopOptions")
            .field("session_id", &self.session_id)
            .field("protocol", &self.protocol)
            .field("hostname", &self.hostname)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("domain", &self.domain)
            .field("width", &self.width)
            .field("height", &self.height)
            .finish()
    }
}

/// One input event of `sendRemoteDesktopInput`. Coordinates are remote
/// desktop pixels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RemoteDesktopInputEvent {
    /// `buttons`: bit 0 left, bit 1 middle, bit 2 right.
    Pointer {
        x: u16,
        y: u16,
        buttons: u8,
    },
    /// Wheel notches; positive `deltaY` scrolls up, positive `deltaX` right.
    #[serde(rename_all = "camelCase")]
    Wheel {
        x: u16,
        y: u16,
        #[serde(default)]
        delta_x: i16,
        #[serde(default)]
        delta_y: i16,
    },
    /// `keysym`: X11 keysym (VNC). `scancode`: PC set-1 scancode, `0xE000`
    /// or-ed in for extended keys (RDP). 0 means "no mapping".
    Key {
        down: bool,
        #[serde(default)]
        keysym: u32,
        #[serde(default)]
        scancode: u16,
    },
    Clipboard {
        text: String,
    },
    /// Ask for a full repaint.
    Refresh,
}

/// `sendRemoteDesktopInput` payload: a batch, applied in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteDesktopInputPayload {
    pub session_id: String,
    pub events: Vec<RemoteDesktopInputEvent>,
}

/// Control message of a remote desktop session, delivered as JSON on the
/// session's channel. Pixel data travels as binary messages on the same
/// channel (see `rust/docs/ipc-contract.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RemoteDesktopControlEvent {
    Connected {
        width: u16,
        height: u16,
    },
    Resize {
        width: u16,
        height: u16,
    },
    Clipboard {
        text: String,
    },
    Bell,
    /// Always the last message. `error` is absent for a deliberate close.
    Closed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

#[cfg(test)]
mod remote_desktop_tests {
    use super::*;

    #[test]
    fn input_events_use_the_renderer_wire_shape() {
        let payload: RemoteDesktopInputPayload = serde_json::from_str(
            r#"{"sessionId":"s1","events":[
                {"type":"pointer","x":3,"y":4,"buttons":1},
                {"type":"wheel","x":3,"y":4,"deltaY":-2},
                {"type":"key","down":true,"keysym":97,"scancode":30},
                {"type":"clipboard","text":"hi"},
                {"type":"refresh"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(payload.session_id, "s1");
        assert_eq!(
            payload.events,
            vec![
                RemoteDesktopInputEvent::Pointer {
                    x: 3,
                    y: 4,
                    buttons: 1
                },
                RemoteDesktopInputEvent::Wheel {
                    x: 3,
                    y: 4,
                    delta_x: 0,
                    delta_y: -2
                },
                RemoteDesktopInputEvent::Key {
                    down: true,
                    keysym: 97,
                    scancode: 30
                },
                RemoteDesktopInputEvent::Clipboard { text: "hi".into() },
                RemoteDesktopInputEvent::Refresh,
            ]
        );
    }

    #[test]
    fn control_events_serialize_with_a_type_tag() {
        assert_eq!(
            serde_json::to_string(&RemoteDesktopControlEvent::Connected {
                width: 800,
                height: 600
            })
            .unwrap(),
            r#"{"type":"connected","width":800,"height":600}"#
        );
        assert_eq!(
            serde_json::to_string(&RemoteDesktopControlEvent::Closed { error: None }).unwrap(),
            r#"{"type":"closed"}"#
        );
        assert_eq!(
            serde_json::to_string(&RemoteDesktopControlEvent::Closed {
                error: Some("boom".into())
            })
            .unwrap(),
            r#"{"type":"closed","error":"boom"}"#
        );
    }

    #[test]
    fn options_debug_redacts_the_password() {
        let options = RemoteDesktopOptions {
            protocol: "rdp".into(),
            hostname: "h".into(),
            password: Some("hunter2".into()),
            ..Default::default()
        };
        assert!(!format!("{options:?}").contains("hunter2"));
    }
}
