//! Algorithm preference lists (mirrors `electron/bridges/sshAlgorithms.cjs`).
//!
//! Starting point is russh's safe default. Legacy mode appends SHA-1 key
//! exchanges, CBC ciphers and SHA-1 MACs *after* the modern entries so a
//! modern server still negotiates the strong algorithms. User overrides
//! replace a whole category when at least one name is recognised; the ECDSA
//! host-key kill switch is applied last so it is unconditional.

use crate::options::HopOptions;
use netcatty_core::models::HostAlgorithmOverrides;
use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
use russh::{cipher, compression, kex, mac, Preferred};
use std::borrow::Cow;
use std::str::FromStr;

/// KEX "pseudo-algorithms" that must always be advertised (extension
/// negotiation, strict kex). They are re-appended after any user override.
const KEX_EXTENSIONS: &[kex::Name] = &[
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

/// Modern additions on top of russh's default (OpenSSH offers these too).
const EXTRA_MODERN_KEX: &[kex::Name] = &[
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP521,
];
const EXTRA_MODERN_CIPHERS: &[cipher::Name] = &[cipher::AES_128_GCM];

const LEGACY_KEX: &[kex::Name] = &[kex::DH_G14_SHA1, kex::DH_G1_SHA1, kex::DH_GEX_SHA1];
const LEGACY_CIPHER_NAMES: &[&str] = &["aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"];
const LEGACY_MACS: &[mac::Name] = &[mac::HMAC_SHA1_ETM, mac::HMAC_SHA1];

/// Plain-text view of a built preference set, handy for logging and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmLists {
    pub kex: Vec<String>,
    pub cipher: Vec<String>,
    pub mac: Vec<String>,
    pub server_host_key: Vec<String>,
    pub compression: Vec<String>,
}

fn push_unique<T: PartialEq>(list: &mut Vec<T>, item: T) {
    if !list.contains(&item) {
        list.push(item);
    }
}

fn is_kex_extension(name: &kex::Name) -> bool {
    KEX_EXTENSIONS.contains(name)
}

fn parse_list<T, F>(category: &str, names: &[String], parse: F) -> Vec<T>
where
    F: Fn(&str) -> Option<T>,
{
    let mut out = Vec::new();
    for raw in names {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        match parse(name) {
            Some(v) => out.push(v),
            None => tracing::warn!("ignoring unsupported {category} algorithm override: {name}"),
        }
    }
    out
}

/// Build the russh [`Preferred`] set for a hop.
pub fn build_preferred(hop: &HopOptions) -> Preferred {
    build_preferred_from(
        hop.legacy_algorithms,
        hop.skip_ecdsa_host_key,
        hop.algorithm_overrides.as_ref(),
    )
}

/// Build a [`Preferred`] set from the raw knobs.
pub fn build_preferred_from(
    legacy: bool,
    skip_ecdsa_host_key: bool,
    overrides: Option<&HostAlgorithmOverrides>,
) -> Preferred {
    let defaults = Preferred::DEFAULT;

    // --- KEX ---------------------------------------------------------------
    let mut kex_list: Vec<kex::Name> = defaults
        .kex
        .iter()
        .copied()
        .filter(|n| !is_kex_extension(n))
        .collect();
    for n in EXTRA_MODERN_KEX {
        push_unique(&mut kex_list, *n);
    }
    if legacy {
        for n in LEGACY_KEX {
            push_unique(&mut kex_list, *n);
        }
    }

    // --- Ciphers -----------------------------------------------------------
    let mut cipher_list: Vec<cipher::Name> = defaults.cipher.to_vec();
    for n in EXTRA_MODERN_CIPHERS {
        push_unique(&mut cipher_list, *n);
    }
    if legacy {
        for name in LEGACY_CIPHER_NAMES {
            match cipher::Name::try_from(*name) {
                Ok(n) => push_unique(&mut cipher_list, n),
                Err(()) => {
                    tracing::debug!("legacy cipher {name} not supported by this build; skipped")
                }
            }
        }
    }

    // --- MACs --------------------------------------------------------------
    let mut mac_list: Vec<mac::Name> = defaults.mac.to_vec();
    if legacy {
        for n in LEGACY_MACS {
            push_unique(&mut mac_list, *n);
        }
    }

    // --- Host keys ---------------------------------------------------------
    let mut key_list: Vec<Algorithm> = defaults.key.to_vec();
    if legacy {
        // `ssh-rsa` (SHA-1) is already last in russh's default list; DSA is
        // not supported by this build so it is intentionally not advertised.
        push_unique(&mut key_list, Algorithm::Rsa { hash: None });
    }
    let mut host_key_certificates: Vec<Algorithm> = defaults.host_key_certificates.to_vec();

    // --- Compression -------------------------------------------------------
    let mut compression_list: Vec<compression::Name> = vec![compression::NONE];

    // --- Overrides ---------------------------------------------------------
    if let Some(o) = overrides {
        if let Some(names) = o.kex.as_deref().filter(|l| !l.is_empty()) {
            let parsed = parse_list("kex", names, |n| kex::Name::try_from(n).ok());
            let parsed: Vec<kex::Name> = parsed
                .into_iter()
                .filter(|n| !is_kex_extension(n))
                .collect();
            if !parsed.is_empty() {
                kex_list = parsed;
            }
        }
        if let Some(names) = o.cipher.as_deref().filter(|l| !l.is_empty()) {
            let parsed = parse_list("cipher", names, |n| cipher::Name::try_from(n).ok());
            if !parsed.is_empty() {
                cipher_list = parsed;
            }
        }
        if let Some(names) = o.hmac.as_deref().filter(|l| !l.is_empty()) {
            let parsed = parse_list("hmac", names, |n| mac::Name::try_from(n).ok());
            if !parsed.is_empty() {
                mac_list = parsed;
            }
        }
        if let Some(names) = o.server_host_key.as_deref().filter(|l| !l.is_empty()) {
            let mut keys = Vec::new();
            let mut certs = Vec::new();
            for raw in names {
                let name = raw.trim();
                if name.is_empty() {
                    continue;
                }
                if name.ends_with("-cert-v01@openssh.com") {
                    match Algorithm::new_certificate(name) {
                        Ok(a) if is_supported_host_key(&a) => push_unique(&mut certs, a),
                        _ => tracing::warn!("ignoring unsupported serverHostKey override: {name}"),
                    }
                } else {
                    match Algorithm::from_str(name) {
                        Ok(a) if is_supported_host_key(&a) => push_unique(&mut keys, a),
                        _ => tracing::warn!("ignoring unsupported serverHostKey override: {name}"),
                    }
                }
            }
            if !keys.is_empty() || !certs.is_empty() {
                key_list = keys;
                host_key_certificates = certs;
            }
        }
        if let Some(names) = o.compress.as_deref().filter(|l| !l.is_empty()) {
            let parsed = parse_list("compress", names, |n| compression::Name::try_from(n).ok());
            if !parsed.is_empty() {
                compression_list = parsed;
            }
        }
    }

    // --- ECDSA kill switch -------------------------------------------------
    if skip_ecdsa_host_key {
        key_list.retain(|a| !matches!(a, Algorithm::Ecdsa { .. }));
        host_key_certificates.retain(|a| !matches!(a, Algorithm::Ecdsa { .. }));
    }

    // Always re-append the extension markers.
    for n in KEX_EXTENSIONS {
        push_unique(&mut kex_list, *n);
    }

    Preferred {
        kex: Cow::Owned(kex_list),
        key: Cow::Owned(key_list),
        host_key_certificates: Cow::Owned(host_key_certificates),
        cipher: Cow::Owned(cipher_list),
        mac: Cow::Owned(mac_list),
        compression: Cow::Owned(compression_list),
    }
}

/// Host-key algorithms this build can verify signatures for.
fn is_supported_host_key(a: &Algorithm) -> bool {
    matches!(
        a,
        Algorithm::Ed25519
            | Algorithm::Rsa { .. }
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            }
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384
            }
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521
            }
    )
}

/// Human-readable algorithm name, including RSA hash variants.
pub fn algorithm_name(a: &Algorithm) -> String {
    match a {
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        } => "rsa-sha2-256".to_string(),
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        } => "rsa-sha2-512".to_string(),
        other => other.to_string(),
    }
}

/// Textual view of a [`Preferred`] set.
pub fn describe(p: &Preferred) -> AlgorithmLists {
    AlgorithmLists {
        kex: p.kex.iter().map(|n| n.as_ref().to_string()).collect(),
        cipher: p.cipher.iter().map(|n| n.as_ref().to_string()).collect(),
        mac: p.mac.iter().map(|n| n.as_ref().to_string()).collect(),
        server_host_key: p.key.iter().map(algorithm_name).collect(),
        compression: p
            .compression
            .iter()
            .map(|n| n.as_ref().to_string())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists(legacy: bool, skip: bool, o: Option<HostAlgorithmOverrides>) -> AlgorithmLists {
        describe(&build_preferred_from(legacy, skip, o.as_ref()))
    }

    #[test]
    fn default_lists_are_modern_and_keep_extensions() {
        let l = lists(false, false, None);
        assert!(l.kex.contains(&"curve25519-sha256".to_string()));
        assert!(l.kex.contains(&"ecdh-sha2-nistp256".to_string()));
        assert!(!l.kex.contains(&"diffie-hellman-group1-sha1".to_string()));
        assert_eq!(l.kex.last().unwrap(), "kex-strict-s-v00@openssh.com");
        assert!(l.kex.contains(&"ext-info-c".to_string()));
        assert!(l.cipher.contains(&"aes128-gcm@openssh.com".to_string()));
        assert!(!l.cipher.contains(&"aes256-cbc".to_string()));
        assert!(!l.mac.contains(&"hmac-sha1".to_string()));
        assert!(l
            .server_host_key
            .contains(&"ecdsa-sha2-nistp256".to_string()));
        assert!(l.server_host_key.contains(&"rsa-sha2-512".to_string()));
        assert_eq!(l.compression, vec!["none".to_string()]);
    }

    #[test]
    fn legacy_appends_after_modern() {
        let l = lists(true, false, None);
        let pos = |n: &str| l.kex.iter().position(|x| x == n).unwrap();
        assert!(pos("curve25519-sha256") < pos("diffie-hellman-group14-sha1"));
        assert!(l.kex.contains(&"diffie-hellman-group1-sha1".to_string()));
        assert!(l
            .kex
            .contains(&"diffie-hellman-group-exchange-sha1".to_string()));
        assert!(l.cipher.contains(&"aes256-cbc".to_string()));
        assert!(l.cipher.contains(&"aes128-cbc".to_string()));
        assert_eq!(l.cipher[0], "chacha20-poly1305@openssh.com");
        assert!(l.mac.contains(&"hmac-sha1".to_string()));
        assert!(l.mac.contains(&"hmac-sha1-etm@openssh.com".to_string()));
        assert!(l.server_host_key.contains(&"ssh-rsa".to_string()));
        // Extensions still terminate the list exactly once.
        assert_eq!(l.kex.iter().filter(|n| *n == "ext-info-c").count(), 1);
    }

    #[test]
    fn skip_ecdsa_removes_all_ecdsa_host_keys() {
        let l = lists(true, true, None);
        assert!(!l
            .server_host_key
            .iter()
            .any(|n| n.starts_with("ecdsa-sha2-")));
        assert!(l.server_host_key.contains(&"ssh-ed25519".to_string()));
    }

    #[test]
    fn overrides_replace_categories_and_skip_unknown_names() {
        let o = HostAlgorithmOverrides {
            kex: Some(vec![
                "diffie-hellman-group14-sha256".into(),
                "bogus-kex".into(),
            ]),
            cipher: Some(vec!["aes256-ctr".into(), "nope".into()]),
            hmac: Some(vec!["hmac-sha2-256".into()]),
            server_host_key: Some(vec![
                "ssh-ed25519".into(),
                "ecdsa-sha2-nistp256".into(),
                "ssh-xyz".into(),
            ]),
            compress: Some(vec!["none".into()]),
        };
        let l = lists(false, true, Some(o));
        assert_eq!(
            l.kex,
            vec![
                "diffie-hellman-group14-sha256",
                "ext-info-c",
                "ext-info-s",
                "kex-strict-c-v00@openssh.com",
                "kex-strict-s-v00@openssh.com"
            ]
        );
        assert_eq!(l.cipher, vec!["aes256-ctr"]);
        assert_eq!(l.mac, vec!["hmac-sha2-256"]);
        // skip_ecdsa_host_key is applied after overrides.
        assert_eq!(l.server_host_key, vec!["ssh-ed25519"]);
    }

    #[test]
    fn override_with_only_unknown_names_keeps_defaults() {
        let o = HostAlgorithmOverrides {
            kex: Some(vec!["bogus".into()]),
            cipher: None,
            hmac: None,
            server_host_key: None,
            compress: None,
        };
        let l = lists(false, false, Some(o));
        assert!(l.kex.contains(&"curve25519-sha256".to_string()));
    }

    #[test]
    fn build_preferred_reads_hop_options() {
        let hop = HopOptions {
            legacy_algorithms: true,
            ..Default::default()
        };
        let l = describe(&build_preferred(&hop));
        assert!(l.kex.contains(&"diffie-hellman-group14-sha1".to_string()));
    }
}
