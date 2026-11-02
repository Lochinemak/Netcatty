//! Field-level credential encryption.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use base64::Engine as _;
use netcatty_core::{CoreError, CoreResult};
use zeroize::{Zeroize, Zeroizing};

pub const ENC_PREFIX_V1: &str = "enc:v1:";
pub const ENC_PREFIX_V2: &str = "enc:v2:";

/// Keychain coordinates of the master key.
pub const KEYRING_SERVICE: &str = "netcatty";
pub const KEYRING_USER: &str = "credential-master-key";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// AES-256-GCM cipher whose key lives in the OS keychain under
/// (`service = "netcatty"`, `user = "credential-master-key"`). When the
/// keychain is unavailable the cipher is `available() == false` and
/// `encrypt`/`decrypt` pass values through unchanged — the same degradation
/// the Electron bridge has on Linux without libsecret.
pub struct CredentialCipher {
    pub(crate) key: Option<[u8; KEY_LEN]>,
}

impl Drop for CredentialCipher {
    fn drop(&mut self) {
        if let Some(key) = self.key.as_mut() {
            key.zeroize();
        }
    }
}

impl CredentialCipher {
    /// Load or create the master key.
    ///
    /// A keychain miss generates a fresh random key and stores it. Any
    /// keychain error — including a stored value that is not a valid
    /// 32-byte key — leaves the cipher unavailable rather than silently
    /// replacing the user's key.
    pub fn load_or_create() -> Self {
        match load_or_create_key() {
            Ok(key) => Self { key: Some(key) },
            Err(reason) => {
                tracing::warn!(%reason, "credential master key unavailable; credential encryption disabled");
                Self { key: None }
            }
        }
    }

    /// Construct with an explicit key (tests).
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key: Some(key) }
    }

    /// A cipher that always passes values through (tests / degraded mode).
    pub fn unavailable() -> Self {
        Self { key: None }
    }

    pub fn available(&self) -> bool {
        self.key.is_some()
    }

    /// Encrypt plaintext → `enc:v2:<base64(nonce || ciphertext || tag)>`.
    /// Already-encrypted values (either prefix) are returned unchanged.
    pub fn encrypt(&self, plaintext: &str) -> CoreResult<String> {
        if Self::is_encrypted(plaintext) {
            return Ok(plaintext.to_string());
        }
        let Some(key) = self.key.as_ref() else {
            return Ok(plaintext.to_string());
        };

        let mut nonce_bytes = [0u8; NONCE_LEN];
        fill_random(&mut nonce_bytes).map_err(CoreError::internal)?;
        let nonce = Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::from(nonce_bytes);

        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| CoreError::internal("credential encryption failed"))?;

        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        Ok(format!("{ENC_PREFIX_V2}{}", B64.encode(blob)))
    }

    /// Decrypt `enc:v2:` values; `enc:v1:` and plaintext are returned as is.
    pub fn decrypt(&self, value: &str) -> CoreResult<String> {
        let Some(payload) = value.strip_prefix(ENC_PREFIX_V2) else {
            return Ok(value.to_string());
        };
        let Some(key) = self.key.as_ref() else {
            return Ok(value.to_string());
        };

        let blob = B64
            .decode(payload)
            .map_err(|_| CoreError::invalid("encrypted credential is not valid base64"))?;
        if blob.len() < NONCE_LEN + TAG_LEN {
            return Err(CoreError::invalid("encrypted credential is truncated"));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::try_from(nonce_bytes)
            .map_err(|_| CoreError::invalid("encrypted credential has an invalid nonce"))?;

        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(&nonce, ciphertext)
                .map_err(|_| CoreError::invalid("encrypted credential failed authentication"))?,
        );
        String::from_utf8(plaintext.to_vec())
            .map_err(|_| CoreError::invalid("decrypted credential is not valid UTF-8"))
    }

    pub fn is_encrypted(value: &str) -> bool {
        value.starts_with(ENC_PREFIX_V1) || value.starts_with(ENC_PREFIX_V2)
    }
}

fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    use rand::TryRng;
    rand::rngs::SysRng
        .try_fill_bytes(buf)
        .map_err(|err| format!("system RNG unavailable: {err}"))
}

fn load_or_create_key() -> Result<[u8; KEY_LEN], String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|err| format!("keychain entry unavailable: {err}"))?;

    match entry.get_password() {
        Ok(stored) => {
            let stored = Zeroizing::new(stored);
            let decoded = Zeroizing::new(
                B64.decode(stored.as_bytes())
                    .map_err(|_| "stored master key is not valid base64".to_string())?,
            );
            if decoded.len() != KEY_LEN {
                return Err(format!(
                    "stored master key has {} bytes, expected {KEY_LEN}",
                    decoded.len()
                ));
            }
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(&decoded);
            Ok(key)
        }
        Err(keyring::Error::NoEntry) => {
            let mut key = [0u8; KEY_LEN];
            fill_random(&mut key)?;
            let encoded = Zeroizing::new(B64.encode(key));
            if let Err(err) = entry.set_password(&encoded) {
                key.zeroize();
                return Err(format!("failed to store master key in keychain: {err}"));
            }
            tracing::info!("generated a new credential master key in the OS keychain");
            Ok(key)
        }
        Err(err) => Err(format!("keychain read failed: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> CredentialCipher {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8 ^ 0x5a;
        }
        CredentialCipher::with_key(key)
    }

    #[test]
    fn round_trip() {
        let c = cipher();
        for plain in ["", "hunter2", "pässwörd 日本語", &"x".repeat(5000)] {
            let enc = c.encrypt(plain).unwrap();
            assert!(enc.starts_with(ENC_PREFIX_V2), "{enc}");
            assert!(CredentialCipher::is_encrypted(&enc));
            assert_ne!(&enc[ENC_PREFIX_V2.len()..], plain);
            assert_eq!(c.decrypt(&enc).unwrap(), plain);
        }
    }

    #[test]
    fn encryption_is_randomized() {
        let c = cipher();
        let a = c.encrypt("same").unwrap();
        let b = c.encrypt("same").unwrap();
        assert_ne!(a, b);
        assert_eq!(c.decrypt(&a).unwrap(), "same");
        assert_eq!(c.decrypt(&b).unwrap(), "same");
    }

    #[test]
    fn passthrough_rules() {
        let c = cipher();
        let v1 = "enc:v1:AAAA";
        assert_eq!(c.encrypt(v1).unwrap(), v1);
        assert_eq!(c.decrypt(v1).unwrap(), v1);
        let v2 = c.encrypt("secret").unwrap();
        assert_eq!(c.encrypt(&v2).unwrap(), v2, "no double encryption");
        assert_eq!(c.decrypt("plain text").unwrap(), "plain text");

        let off = CredentialCipher::unavailable();
        assert!(!off.available());
        assert_eq!(off.encrypt("secret").unwrap(), "secret");
        assert_eq!(off.decrypt(&v2).unwrap(), v2);
        assert_eq!(off.decrypt("plain").unwrap(), "plain");
    }

    #[test]
    fn tamper_detection() {
        let c = cipher();
        let enc = c.encrypt("secret").unwrap();
        let mut blob = B64.decode(&enc[ENC_PREFIX_V2.len()..]).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let tampered = format!("{ENC_PREFIX_V2}{}", B64.encode(&blob));
        let err = c.decrypt(&tampered).unwrap_err();
        assert_eq!(err.code, netcatty_core::ErrorCode::InvalidArgument);

        let other = CredentialCipher::with_key([7u8; 32]);
        assert_eq!(
            other.decrypt(&enc).unwrap_err().code,
            netcatty_core::ErrorCode::InvalidArgument
        );

        assert_eq!(
            c.decrypt("enc:v2:!!notbase64").unwrap_err().code,
            netcatty_core::ErrorCode::InvalidArgument
        );
        assert_eq!(
            c.decrypt("enc:v2:AAAA").unwrap_err().code,
            netcatty_core::ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn wire_layout_is_nonce_then_ciphertext_and_tag() {
        let c = cipher();
        let enc = c.encrypt("abc").unwrap();
        let blob = B64.decode(&enc[ENC_PREFIX_V2.len()..]).unwrap();
        assert_eq!(blob.len(), NONCE_LEN + 3 + TAG_LEN);
    }
}
