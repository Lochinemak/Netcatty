//! Key pair generation (`generateKeyPair` IPC).

use crate::error::{SshError, SshResult};
use netcatty_core::ipc::{GenerateKeyPairOptions, GenerateKeyPairResult};
use netcatty_core::models::KeyType;
use russh::keys::ssh_key::private::{KeypairData, RsaKeypair};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, EcdsaCurve, PrivateKey};

const DEFAULT_RSA_BITS: u32 = 4096;
const MIN_RSA_BITS: u32 = 1024;
const MAX_RSA_BITS: u32 = 16384;

/// Generate an OpenSSH key pair. RSA honors `bits` (default 4096), ECDSA
/// honors `bits` as the curve size (256/384/521, default 256). Security-key
/// types (`*-SK`) return `success: false` with an explanatory error because
/// they require hardware enrolment through the FIDO flow, which the first
/// Rust version does not implement.
pub fn generate_key_pair(options: &GenerateKeyPairOptions) -> SshResult<GenerateKeyPairResult> {
    let comment = options.comment.clone().unwrap_or_default();
    let mut rng = russh::keys::key::safe_rng();

    let key = match options.key_type {
        KeyType::Ed25519 => PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(key_err)?,
        KeyType::Ecdsa => {
            let curve = match options.bits.unwrap_or(256) {
                256 => EcdsaCurve::NistP256,
                384 => EcdsaCurve::NistP384,
                521 => EcdsaCurve::NistP521,
                other => {
                    return Ok(failure(
                        options.key_type,
                        format!("Unsupported ECDSA curve size {other}; use 256, 384 or 521"),
                    ))
                }
            };
            PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve }).map_err(key_err)?
        }
        KeyType::Rsa => {
            let bits = options.bits.unwrap_or(DEFAULT_RSA_BITS);
            if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
                return Ok(failure(
                    options.key_type,
                    format!("RSA key size must be between {MIN_RSA_BITS} and {MAX_RSA_BITS} bits"),
                ));
            }
            let pair = RsaKeypair::random(&mut rng, bits as usize).map_err(key_err)?;
            PrivateKey::new(KeypairData::from(pair), "").map_err(key_err)?
        }
        KeyType::Ed25519Sk | KeyType::EcdsaSk => {
            return Ok(failure(
                options.key_type,
                "Security-key types require hardware enrolment (not supported in this build)"
                    .to_string(),
            ))
        }
    };

    let mut key = key;
    key.set_comment(comment.as_str());

    let public_key = key.public_key().to_openssh().map_err(key_err)?;
    let to_write = match options.passphrase.as_deref().filter(|p| !p.is_empty()) {
        Some(passphrase) => key.encrypt(&mut rng, passphrase).map_err(key_err)?,
        None => key,
    };
    let private_key = to_write.to_openssh(LineEnding::LF).map_err(key_err)?;

    Ok(GenerateKeyPairResult {
        success: true,
        private_key: Some(private_key.to_string()),
        public_key: Some(public_key),
        key_type: Some(options.key_type),
        error: None,
    })
}

fn failure(key_type: KeyType, error: String) -> GenerateKeyPairResult {
    GenerateKeyPairResult {
        success: false,
        key_type: Some(key_type),
        error: Some(error),
        ..Default::default()
    }
}

fn key_err(e: russh::keys::ssh_key::Error) -> SshError {
    SshError::Key(e.to_string())
}

/// Default key files OpenSSH would try (`~/.ssh/id_*`) that exist on disk.
/// Returns `(file name, absolute path)` pairs in OpenSSH's preference order.
pub fn default_key_files() -> Vec<(String, String)> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    default_key_files_in(&home.join(".ssh"))
}

/// [`default_key_files`] rooted at an explicit `.ssh` directory.
pub fn default_key_files_in(ssh_dir: &std::path::Path) -> Vec<(String, String)> {
    ["id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"]
        .iter()
        .filter_map(|name| {
            let path = ssh_dir.join(name);
            path.is_file()
                .then(|| (name.to_string(), path.to_string_lossy().into_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(kt: KeyType, bits: Option<u32>, passphrase: Option<&str>) -> GenerateKeyPairOptions {
        GenerateKeyPairOptions {
            key_type: kt,
            bits,
            comment: Some("netcatty-test".into()),
            passphrase: passphrase.map(Into::into),
        }
    }

    fn roundtrip(kt: KeyType, bits: Option<u32>, passphrase: Option<&str>) -> PrivateKey {
        let r = generate_key_pair(&opts(kt, bits, passphrase)).unwrap();
        assert!(r.success, "{:?}", r.error);
        assert_eq!(r.key_type, Some(kt));
        let private = r.private_key.unwrap();
        let public = r.public_key.unwrap();
        assert!(private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(private.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
        assert!(public.ends_with(" netcatty-test"));
        let parsed =
            russh::keys::decode_secret_key(&private, passphrase).expect("private key parses back");
        let pub_parsed = russh::keys::PublicKey::from_openssh(&public).unwrap();
        assert_eq!(parsed.public_key().key_data(), pub_parsed.key_data());
        parsed
    }

    #[test]
    fn ed25519_roundtrip() {
        let k = roundtrip(KeyType::Ed25519, None, None);
        assert_eq!(k.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn ecdsa_roundtrip_all_curves() {
        let k = roundtrip(KeyType::Ecdsa, None, None);
        assert_eq!(
            k.algorithm(),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            }
        );
        let k = roundtrip(KeyType::Ecdsa, Some(384), None);
        assert_eq!(
            k.algorithm(),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384
            }
        );
        let k = roundtrip(KeyType::Ecdsa, Some(521), None);
        assert_eq!(
            k.algorithm(),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521
            }
        );
        let bad = generate_key_pair(&opts(KeyType::Ecdsa, Some(123), None)).unwrap();
        assert!(!bad.success);
    }

    #[test]
    fn rsa_roundtrip_with_passphrase() {
        // 2048 bits keeps the test fast; 4096 is the production default.
        let k = roundtrip(KeyType::Rsa, Some(2048), Some("hunter2"));
        assert!(k.algorithm().is_rsa());
        let r = generate_key_pair(&opts(KeyType::Rsa, Some(2048), Some("hunter2"))).unwrap();
        let private = r.private_key.unwrap();
        assert!(matches!(
            russh::keys::decode_secret_key(&private, None),
            Err(russh::keys::Error::KeyIsEncrypted)
        ));
        assert!(russh::keys::decode_secret_key(&private, Some("wrong")).is_err());
        let bad = generate_key_pair(&opts(KeyType::Rsa, Some(512), None)).unwrap();
        assert!(!bad.success);
    }

    #[test]
    fn security_keys_are_rejected_gracefully() {
        for kt in [KeyType::Ed25519Sk, KeyType::EcdsaSk] {
            let r = generate_key_pair(&opts(kt, None, None)).unwrap();
            assert!(!r.success);
            assert!(r.error.as_deref().unwrap().contains("hardware enrolment"));
            assert!(r.private_key.is_none());
        }
    }

    #[test]
    fn default_key_files_only_lists_existing_files() {
        let dir =
            std::env::temp_dir().join(format!("netcatty-ssh-keygen-{}", netcatty_core::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("id_rsa"), "x").unwrap();
        std::fs::write(dir.join("id_ed25519"), "x").unwrap();
        std::fs::create_dir_all(dir.join("id_ecdsa")).unwrap(); // a directory, not a file
        let found = default_key_files_in(&dir);
        let names: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["id_ed25519", "id_rsa"]);
        assert!(found[0].1.ends_with("id_ed25519"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
