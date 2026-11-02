//! Connection-related models (`domain/models/connection.ts`).
//!
//! `Host` has well over a hundred optional fields in the TypeScript model.
//! The fields the Rust backend actually consumes are typed; everything else
//! is preserved verbatim through `#[serde(flatten)] extra` so a vault written
//! by the Electron build round-trips through the Rust build without loss.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    Http,
    Socks5,
    Command,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyConfig {
    #[serde(rename = "type")]
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyProfile {
    pub id: String,
    pub label: String,
    pub config: ProxyConfig,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
}

/// Jump host / bastion chain: ordered host ids, first = closest to client.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostChainConfig {
    pub host_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MultiLineRunMode {
    LineDelay,
    Paste,
}

/// Per-host SSH algorithm override lists. Non-empty lists fully replace the
/// offered list for that category (same semantics as ssh2's `algorithms`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostAlgorithmOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kex: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_host_key: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compress: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

/// Built-in protocols. Plugin protocols (`plugin:<id>`) are carried as the
/// `Other` variant so unknown values never fail deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HostProtocol {
    #[default]
    Ssh,
    Telnet,
    Mosh,
    Et,
    Local,
    Serial,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SerialParity {
    None,
    Even,
    Odd,
    Mark,
    Space,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerialFlowControl {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "xon/xoff")]
    XonXoff,
    #[serde(rename = "rts/cts")]
    RtsCts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SerialConfig {
    pub path: String,
    pub baud_rate: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_bits: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_bits: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parity: Option<SerialParity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_control: Option<SerialFlowControl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_echo: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_mode: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backspace_behavior: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_oriented_backspace: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HostAuthMethod {
    #[default]
    Auto,
    Password,
    Key,
    Certificate,
}

/// Per-host TOTP authenticator. `uri` is an `otpauth://totp/...` URI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostTotpConfig {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_submit: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_pattern: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpBookmark {
    pub id: String,
    pub path: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostOutputTrigger {
    pub id: String,
    pub pattern: String,
    pub script_id: String,
}

/// A saved host. See module docs for the `extra` round-trip strategy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Legacy os marker (`linux` | `windows` | `macos`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<HostProtocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub save_password: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<HostAuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_mfa: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<HostTotpConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_ssh_agent: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identities_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_forwarding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x11_forwarding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_command_run_mode: Option<MultiLineRunMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_config: Option<ProxyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_proxy: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_chain: Option<HostChainConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_variables: Option<Vec<EnvVar>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telnet_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telnet_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telnet_username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telnet_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_config: Option<SerialConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sftp_sudo: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sftp_file_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sftp_encoding: Option<super::sftp::SftpFilenameEncoding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sftp_bookmarks: Option<Vec<SftpBookmark>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_algorithms: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_ecdsa_host_key: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<HostAlgorithmOverrides>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_interval: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_count_max: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_override: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_tcp_connect_timeout_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_auth_ready_timeout_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file_paths: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_connected_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_shell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_shell_args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_start_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
    /// Every field not modelled above, preserved verbatim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Host {
    /// Effective SSH port (defaults to 22).
    pub fn ssh_port(&self) -> u16 {
        self.port.unwrap_or(22)
    }

    /// Effective protocol (defaults to SSH).
    pub fn effective_protocol(&self) -> HostProtocol {
        self.protocol.clone().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    #[serde(rename = "RSA")]
    Rsa,
    #[serde(rename = "ECDSA")]
    Ecdsa,
    #[serde(rename = "ED25519")]
    Ed25519,
    #[serde(rename = "ED25519-SK")]
    Ed25519Sk,
    #[serde(rename = "ECDSA-SK")]
    EcdsaSk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeySource {
    Generated,
    Imported,
    Reference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyCategory {
    Key,
    Certificate,
    Identity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKey {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub key_type: KeyType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_size: Option<u32>,
    pub private_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub save_passphrase: Option<bool>,
    pub source: KeySource,
    pub category: KeyCategory,
    pub created: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityAuthMethod {
    Password,
    Key,
    Certificate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub id: String,
    pub label: String,
    pub username: String,
    pub auth_method: IdentityAuthMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub created: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snippet {
    pub id: String,
    pub label: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shortkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_auto_run: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_round_trips_unknown_fields() {
        let json = r#"{"id":"h1","label":"Box","hostname":"example.com","username":"root","tags":[],"os":"linux","fontSize":14,"iconId":"server","sftpEncoding":"gb18030"}"#;
        let host: Host = serde_json::from_str(json).unwrap();
        assert_eq!(host.ssh_port(), 22);
        assert_eq!(
            host.sftp_encoding,
            Some(super::super::sftp::SftpFilenameEncoding::Gb18030)
        );
        assert_eq!(host.extra.get("fontSize"), Some(&Value::from(14)));
        let back = serde_json::to_value(&host).unwrap();
        assert_eq!(back["iconId"], "server");
        assert_eq!(back["fontSize"], 14);
        assert!(
            back.get("password").is_none(),
            "None fields must be omitted"
        );
    }

    #[test]
    fn plugin_protocol_is_preserved() {
        let host: Host = serde_json::from_str(r#"{"id":"x","protocol":"plugin:acme.db"}"#).unwrap();
        assert_eq!(
            host.protocol,
            Some(HostProtocol::Other("plugin:acme.db".into()))
        );
        let back = serde_json::to_string(&host).unwrap();
        assert!(back.contains("\"protocol\":\"plugin:acme.db\""));
    }

    #[test]
    fn key_type_names_match_ts() {
        assert_eq!(
            serde_json::to_string(&KeyType::Ed25519Sk).unwrap(),
            "\"ED25519-SK\""
        );
        assert_eq!(
            serde_json::to_string(&SerialFlowControl::RtsCts).unwrap(),
            "\"rts/cts\""
        );
    }
}
