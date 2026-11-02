//! Host key verification against the vault's `KnownHost` records and the
//! user's OpenSSH `~/.ssh/known_hosts` file.

use netcatty_core::models::KnownHost;
use russh::keys::PublicKey;

/// Information about the server key presented during the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyInfo {
    pub hostname: String,
    pub port: u16,
    /// `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, ...
    pub key_type: String,
    /// SHA256 fingerprint without `SHA256:` prefix.
    pub fingerprint: String,
    /// Base64 key blob.
    pub public_key: String,
    /// `Some(..)` when a different key for this host is already trusted.
    pub known_host_id: Option<String>,
    pub known_fingerprint: Option<String>,
}

impl HostKeyInfo {
    pub fn is_changed(&self) -> bool {
        self.known_host_id.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyDecision {
    /// Trust the key for this connection; `remember` asks the caller to
    /// persist it to the vault known-hosts list.
    Accept { remember: bool },
    Reject,
}

/// Outcome of matching a presented key against the trusted list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnownHostMatch {
    /// Key matches a trusted record.
    Trusted { known_host_id: String },
    /// Host is known but the key differs.
    Changed { known_host_id: String, known_fingerprint: Option<String> },
    /// No record for this host.
    Unknown,
}

/// SHA256 fingerprint (base64, no padding, no `SHA256:` prefix) of a key.
pub fn fingerprint_sha256(key: &PublicKey) -> String {
    let fp = key.fingerprint(russh::keys::HashAlg::Sha256).to_string();
    fp.strip_prefix("SHA256:").unwrap_or(&fp).to_string()
}

/// Base64 blob of the key (OpenSSH `known_hosts` third column).
pub fn public_key_base64(key: &PublicKey) -> String {
    key.to_openssh()
        .ok()
        .and_then(|line| line.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_default()
}

/// Compare a presented key with the vault records for `hostname:port`.
pub fn match_known_hosts(
    known_hosts: &[KnownHost],
    hostname: &str,
    port: u16,
    key_type: &str,
    key_base64: &str,
    fingerprint: &str,
) -> KnownHostMatch {
    let mut changed: Option<&KnownHost> = None;
    for kh in known_hosts.iter().filter(|kh| kh.matches(hostname, port)) {
        let same_blob = kh.public_key == key_base64;
        let same_fp = kh
            .fingerprint
            .as_deref()
            .map(|f| f.trim_start_matches("SHA256:") == fingerprint)
            .unwrap_or(false)
            || kh.public_key.trim_start_matches("SHA256:") == fingerprint;
        if same_blob || same_fp {
            return KnownHostMatch::Trusted { known_host_id: kh.id.clone() };
        }
        // Only treat it as "changed" when the record is for the same key type
        // (OpenSSH semantics); other types are simply additional keys.
        if kh.key_type == key_type && changed.is_none() {
            changed = Some(kh);
        }
    }
    match changed {
        Some(kh) => KnownHostMatch::Changed {
            known_host_id: kh.id.clone(),
            known_fingerprint: kh.fingerprint.clone(),
        },
        None => KnownHostMatch::Unknown,
    }
}

/// Parse an OpenSSH `known_hosts` file into vault records. Hashed entries
/// (`|1|...`) are skipped because the renderer cannot display them.
pub fn parse_openssh_known_hosts(text: &str) -> Vec<KnownHost> {
    todo!("parse known_hosts lines into KnownHost records (implemented by the ssh agent task)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kh(id: &str, host: &str, port: u16, kt: &str, blob: &str, fp: Option<&str>) -> KnownHost {
        KnownHost {
            id: id.into(),
            hostname: host.into(),
            port,
            key_type: kt.into(),
            public_key: blob.into(),
            fingerprint: fp.map(Into::into),
            discovered_at: 0,
            last_seen: None,
            converted_to_host_id: None,
            order: None,
        }
    }

    #[test]
    fn matching_semantics() {
        let list = vec![kh("a", "h", 22, "ssh-ed25519", "BLOB", Some("FP"))];
        assert_eq!(
            match_known_hosts(&list, "h", 22, "ssh-ed25519", "BLOB", "x"),
            KnownHostMatch::Trusted { known_host_id: "a".into() }
        );
        assert_eq!(
            match_known_hosts(&list, "h", 22, "ssh-ed25519", "OTHER", "FP"),
            KnownHostMatch::Trusted { known_host_id: "a".into() }
        );
        assert_eq!(
            match_known_hosts(&list, "h", 22, "ssh-ed25519", "OTHER", "ZZ"),
            KnownHostMatch::Changed { known_host_id: "a".into(), known_fingerprint: Some("FP".into()) }
        );
        assert_eq!(match_known_hosts(&list, "h", 22, "ssh-rsa", "OTHER", "ZZ"), KnownHostMatch::Unknown);
        assert_eq!(match_known_hosts(&list, "h", 2222, "ssh-ed25519", "BLOB", "FP"), KnownHostMatch::Unknown);
    }
}
