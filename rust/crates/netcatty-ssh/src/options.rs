//! Connection options, normalized from the renderer payload.

use netcatty_core::ipc::{JumpHost, SshSessionOptions};
use netcatty_core::models::{
    HostAlgorithmOverrides, HostAuthMethod, HostTotpConfig, KnownHost, ProxyConfig,
};
use std::time::Duration;

/// Default TCP connect timeout (matches the Electron bridge).
pub const DEFAULT_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Default time allowed for handshake + authentication.
pub const DEFAULT_AUTH_READY_TIMEOUT: Duration = Duration::from_secs(60);

/// Authentication material and policy for one SSH hop.
#[derive(Debug, Clone, Default)]
pub struct HopOptions {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub label: Option<String>,
    pub host_id: Option<String>,
    pub auth_method: HostAuthMethod,
    pub requires_mfa: bool,
    pub password: Option<String>,
    pub totp: Option<HostTotpConfig>,
    /// PEM / OpenSSH private key text.
    pub private_key: Option<String>,
    pub certificate: Option<String>,
    pub passphrase: Option<String>,
    /// Human label for passphrase prompts (vault key label).
    pub key_label: Option<String>,
    /// Local key files to try (`IdentityFile`).
    pub identity_file_paths: Vec<String>,
    pub use_ssh_agent: bool,
    pub identity_agent: Option<String>,
    pub identities_only: bool,
    pub proxy: Option<ProxyConfig>,
    pub known_hosts: Vec<KnownHost>,
    pub verify_host_keys: bool,
    /// Fail instead of prompting for unknown host keys.
    pub host_key_unattended: bool,
    pub legacy_algorithms: bool,
    pub skip_ecdsa_host_key: bool,
    pub algorithm_overrides: Option<HostAlgorithmOverrides>,
    pub keepalive_interval: Option<Duration>,
    pub keepalive_count_max: u32,
    pub tcp_connect_timeout: Duration,
    pub auth_ready_timeout: Duration,
}

impl HopOptions {
    pub fn address(&self) -> String {
        format!("{}:{}", self.hostname, self.port)
    }
}

/// Full connection description: the target hop plus the ordered jump chain
/// (first element = closest to the client).
#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    pub target: HopOptions,
    pub jump_hosts: Vec<HopOptions>,
    pub agent_forwarding: bool,
    pub x11_forwarding: bool,
    pub x11_display: Option<String>,
    pub session_id: Option<String>,
}

fn secs(v: Option<u32>) -> Option<Duration> {
    match v {
        Some(0) | None => None,
        Some(n) => Some(Duration::from_secs(n as u64)),
    }
}

fn millis_or(v: Option<u64>, default: Duration) -> Duration {
    match v {
        Some(ms) if ms > 0 => Duration::from_millis(ms),
        _ => default,
    }
}

impl From<&SshSessionOptions> for HopOptions {
    fn from(o: &SshSessionOptions) -> Self {
        HopOptions {
            hostname: o.hostname.clone(),
            port: o.port(),
            username: o.username.clone(),
            label: o.host_label.clone(),
            host_id: o.host_id.clone(),
            auth_method: o.auth_method.unwrap_or_default(),
            requires_mfa: o.requires_mfa.unwrap_or(false),
            password: o.password.clone(),
            totp: o.totp.clone(),
            private_key: o.private_key.clone(),
            certificate: o.certificate.clone(),
            passphrase: o.passphrase.clone(),
            key_label: o.key_label.clone(),
            identity_file_paths: o.identity_file_paths.clone().unwrap_or_default(),
            use_ssh_agent: o.use_ssh_agent.unwrap_or(false),
            identity_agent: o.identity_agent.clone(),
            identities_only: o.identities_only.unwrap_or(false),
            proxy: o.proxy.clone(),
            known_hosts: o.known_hosts.clone().unwrap_or_default(),
            verify_host_keys: o.verify_host_keys(),
            host_key_unattended: o.host_key_unattended.unwrap_or(false),
            legacy_algorithms: o.legacy_algorithms.unwrap_or(false),
            skip_ecdsa_host_key: o.skip_ecdsa_host_key.unwrap_or(false),
            algorithm_overrides: o.algorithm_overrides.clone(),
            keepalive_interval: secs(o.keepalive_interval),
            keepalive_count_max: o.keepalive_count_max.unwrap_or(3),
            tcp_connect_timeout: millis_or(
                o.ssh_tcp_connect_timeout_ms,
                DEFAULT_TCP_CONNECT_TIMEOUT,
            ),
            auth_ready_timeout: millis_or(o.ssh_auth_ready_timeout_ms, DEFAULT_AUTH_READY_TIMEOUT),
        }
    }
}

impl HopOptions {
    /// Build a hop from a renderer `JumpHost`, inheriting algorithm settings,
    /// known hosts and timeouts from the target when the hop omits them
    /// (matches the Electron bridge's fallback behavior).
    pub fn from_jump(j: &JumpHost, target: &HopOptions) -> Self {
        HopOptions {
            hostname: j.hostname.clone(),
            port: j.port,
            username: j.username.clone(),
            label: j.label.clone(),
            host_id: j.host_id.clone(),
            auth_method: j.auth_method.unwrap_or_default(),
            requires_mfa: j.requires_mfa.unwrap_or(false),
            password: j.password.clone(),
            totp: j.totp.clone(),
            private_key: j.private_key.clone(),
            certificate: j.certificate.clone(),
            passphrase: j.passphrase.clone(),
            key_label: j.label.clone(),
            identity_file_paths: j.identity_file_paths.clone().unwrap_or_default(),
            use_ssh_agent: j.use_ssh_agent.unwrap_or(false),
            identity_agent: j.identity_agent.clone(),
            identities_only: j.identities_only.unwrap_or(false),
            proxy: j.proxy.clone(),
            known_hosts: target.known_hosts.clone(),
            verify_host_keys: j.verify_host_keys.unwrap_or(target.verify_host_keys),
            host_key_unattended: target.host_key_unattended,
            legacy_algorithms: j.legacy_algorithms.unwrap_or(target.legacy_algorithms),
            skip_ecdsa_host_key: j.skip_ecdsa_host_key.unwrap_or(target.skip_ecdsa_host_key),
            algorithm_overrides: j
                .algorithm_overrides
                .clone()
                .or_else(|| target.algorithm_overrides.clone()),
            keepalive_interval: secs(j.keepalive_interval).or(target.keepalive_interval),
            keepalive_count_max: j.keepalive_count_max.unwrap_or(target.keepalive_count_max),
            tcp_connect_timeout: millis_or(
                j.ssh_tcp_connect_timeout_ms,
                target.tcp_connect_timeout,
            ),
            auth_ready_timeout: millis_or(j.ssh_auth_ready_timeout_ms, target.auth_ready_timeout),
        }
    }
}

impl From<&SshSessionOptions> for ConnectOptions {
    fn from(o: &SshSessionOptions) -> Self {
        let target = HopOptions::from(o);
        let jump_hosts = o
            .jump_hosts
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|j| HopOptions::from_jump(j, &target))
            .collect();
        ConnectOptions {
            target,
            jump_hosts,
            agent_forwarding: o.agent_forwarding.unwrap_or(false),
            x11_forwarding: o.x11_forwarding.unwrap_or(false),
            x11_display: o.x11_display.clone(),
            session_id: o.session_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jump_hop_inherits_target_settings() {
        let opts: SshSessionOptions = serde_json::from_str(
            r#"{"hostname":"t","username":"u","legacyAlgorithms":true,"keepaliveInterval":15,
                "jumpHosts":[{"hostname":"j","username":"ju","port":2200}]}"#,
        )
        .unwrap();
        let c = ConnectOptions::from(&opts);
        assert_eq!(c.jump_hosts.len(), 1);
        assert_eq!(c.jump_hosts[0].port, 2200);
        assert!(c.jump_hosts[0].legacy_algorithms);
        assert_eq!(
            c.jump_hosts[0].keepalive_interval,
            Some(Duration::from_secs(15))
        );
        assert_eq!(c.target.tcp_connect_timeout, DEFAULT_TCP_CONNECT_TIMEOUT);
    }
}
