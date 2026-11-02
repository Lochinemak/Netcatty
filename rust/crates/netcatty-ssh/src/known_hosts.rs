//! Host key verification against the vault's `KnownHost` records and the
//! user's OpenSSH `~/.ssh/known_hosts` file.

use netcatty_core::models::KnownHost;
use russh::keys::{parse_public_key_base64, PublicKey};

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
    Accept {
        remember: bool,
    },
    Reject,
}

/// Outcome of matching a presented key against the trusted list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnownHostMatch {
    /// Key matches a trusted record.
    Trusted { known_host_id: String },
    /// Host is known but the key differs.
    Changed {
        known_host_id: String,
        known_fingerprint: Option<String>,
    },
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
            return KnownHostMatch::Trusted {
                known_host_id: kh.id.clone(),
            };
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

/// Split a `known_hosts` host pattern (`host`, `[host]:port`) into a
/// hostname and a port (22 when none is given).
pub fn split_host_pattern(pattern: &str) -> (String, u16) {
    let p = pattern.trim();
    if let Some(rest) = p.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once("]:") {
            if let Ok(port) = port.trim().parse::<u16>() {
                return (host.to_string(), port);
            }
        }
        if let Some(host) = rest.strip_suffix(']') {
            return (host.to_string(), 22);
        }
    }
    (p.to_string(), 22)
}

/// Parse an OpenSSH `known_hosts` file into vault records. Hashed entries
/// (`|1|...`) are skipped because the renderer cannot display them; `@marker`
/// prefixes (`@cert-authority`, `@revoked`) are skipped as well because the
/// vault has no notion of them. Comma-separated host lists produce one
/// record per host. The fingerprint is filled in when the blob parses.
pub fn parse_openssh_known_hosts(text: &str) -> Vec<KnownHost> {
    let now = netcatty_core::ids::now_ms();
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('@')
            || line.starts_with('|')
        {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(hosts), Some(key_type), Some(blob)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if !looks_like_key_type(key_type) {
            continue;
        }
        let fingerprint = parse_public_key_base64(blob)
            .ok()
            .map(|k| fingerprint_sha256(&k));
        for host in hosts.split(',').map(str::trim).filter(|h| !h.is_empty()) {
            if host.starts_with('|') || host.starts_with('!') {
                continue;
            }
            let (hostname, port) = split_host_pattern(host);
            if hostname.is_empty() {
                continue;
            }
            out.push(KnownHost {
                id: netcatty_core::ids::new_id(),
                hostname,
                port,
                key_type: key_type.to_string(),
                public_key: blob.to_string(),
                fingerprint: fingerprint.clone(),
                discovered_at: now,
                last_seen: None,
                converted_to_host_id: None,
                order: None,
            });
        }
    }
    out
}

fn looks_like_key_type(s: &str) -> bool {
    s.starts_with("ssh-") || s.starts_with("ecdsa-sha2-") || s.starts_with("sk-")
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
            KnownHostMatch::Trusted {
                known_host_id: "a".into()
            }
        );
        assert_eq!(
            match_known_hosts(&list, "h", 22, "ssh-ed25519", "OTHER", "FP"),
            KnownHostMatch::Trusted {
                known_host_id: "a".into()
            }
        );
        assert_eq!(
            match_known_hosts(&list, "h", 22, "ssh-ed25519", "OTHER", "ZZ"),
            KnownHostMatch::Changed {
                known_host_id: "a".into(),
                known_fingerprint: Some("FP".into())
            }
        );
        assert_eq!(
            match_known_hosts(&list, "h", 22, "ssh-rsa", "OTHER", "ZZ"),
            KnownHostMatch::Unknown
        );
        assert_eq!(
            match_known_hosts(&list, "h", 2222, "ssh-ed25519", "BLOB", "FP"),
            KnownHostMatch::Unknown
        );
    }

    const ED25519_BLOB: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIBIXa9JKkIZGyHdHHISz530BcYv8X4rtlYTFdmiyqBn9";

    #[test]
    fn host_pattern_split() {
        assert_eq!(
            split_host_pattern("example.com"),
            ("example.com".into(), 22)
        );
        assert_eq!(
            split_host_pattern("[example.com]:2222"),
            ("example.com".into(), 2222)
        );
        assert_eq!(split_host_pattern("[::1]:2200"), ("::1".into(), 2200));
        assert_eq!(split_host_pattern("[bare]"), ("bare".into(), 22));
    }

    #[test]
    fn parses_known_hosts_file() {
        let text = format!(
            "# comment\n\
             example.com,10.0.0.1 ssh-ed25519 {ED25519_BLOB} user@laptop\n\
             [bastion]:2222 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+notreallyakey\n\
             |1|hashedsalt|hashedhost ssh-ed25519 {ED25519_BLOB}\n\
             @cert-authority *.corp ssh-ed25519 {ED25519_BLOB}\n\
             broken-line\n\
             \n"
        );
        let hosts = parse_openssh_known_hosts(&text);
        assert_eq!(hosts.len(), 3);
        assert_eq!(hosts[0].hostname, "example.com");
        assert_eq!(hosts[0].port, 22);
        assert_eq!(hosts[0].key_type, "ssh-ed25519");
        assert_eq!(hosts[0].public_key, ED25519_BLOB);
        assert!(hosts[0].fingerprint.is_some());
        assert!(!hosts[0]
            .fingerprint
            .as_deref()
            .unwrap()
            .starts_with("SHA256:"));
        assert_eq!(hosts[1].hostname, "10.0.0.1");
        assert_eq!(hosts[1].fingerprint, hosts[0].fingerprint);
        assert_ne!(hosts[1].id, hosts[0].id);
        assert_eq!(hosts[2].hostname, "bastion");
        assert_eq!(hosts[2].port, 2222);
        assert_eq!(hosts[2].key_type, "ssh-rsa");
        // Garbage blob: record kept, fingerprint absent.
        assert!(hosts[2].fingerprint.is_none());
    }

    #[test]
    fn parsed_records_match_presented_keys() {
        let text = format!("[example.com]:2222 ssh-ed25519 {ED25519_BLOB}\n");
        let hosts = parse_openssh_known_hosts(&text);
        let key = parse_public_key_base64(ED25519_BLOB).unwrap();
        let fp = fingerprint_sha256(&key);
        assert!(matches!(
            match_known_hosts(
                &hosts,
                "example.com",
                2222,
                "ssh-ed25519",
                &public_key_base64(&key),
                &fp
            ),
            KnownHostMatch::Trusted { .. }
        ));
        assert_eq!(public_key_base64(&key), ED25519_BLOB);
    }
}
