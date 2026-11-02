//! Known hosts and shell history (`domain/models/history.ts`).

use serde::{Deserialize, Serialize};

/// A trusted host key as stored in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownHost {
    pub id: String,
    /// Host pattern (hostname or `[host]:port` style pattern).
    pub hostname: String,
    pub port: u16,
    /// `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, ...
    pub key_type: String,
    /// Base64 public key blob (OpenSSH `known_hosts` column 3) — may be a
    /// fingerprint on very old records.
    pub public_key: String,
    /// SHA256 fingerprint without the `SHA256:` prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub discovered_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub converted_to_host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
}

impl KnownHost {
    /// Whether this record applies to `hostname:port`.
    pub fn matches(&self, hostname: &str, port: u16) -> bool {
        if self.port != port {
            return false;
        }
        let pattern = self.hostname.trim();
        let bracket = format!("[{hostname}]:{port}");
        pattern.eq_ignore_ascii_case(hostname) || pattern.eq_ignore_ascii_case(&bracket)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellHistoryEntry {
    pub id: String,
    pub command: String,
    pub host_id: String,
    pub session_id: String,
    pub timestamp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_host_matching() {
        let kh = KnownHost {
            id: "1".into(),
            hostname: "Example.com".into(),
            port: 2222,
            key_type: "ssh-ed25519".into(),
            public_key: "AAAA".into(),
            fingerprint: None,
            discovered_at: 0,
            last_seen: None,
            converted_to_host_id: None,
            order: None,
        };
        assert!(kh.matches("example.com", 2222));
        assert!(!kh.matches("example.com", 22));
        let bracket = KnownHost {
            hostname: "[example.com]:2222".into(),
            ..kh.clone()
        };
        assert!(bracket.matches("example.com", 2222));
    }
}
