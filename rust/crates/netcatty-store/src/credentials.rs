//! Field-level credential encryption.

use netcatty_core::CoreResult;

pub const ENC_PREFIX_V1: &str = "enc:v1:";
pub const ENC_PREFIX_V2: &str = "enc:v2:";

/// AES-256-GCM cipher whose key lives in the OS keychain under
/// (`service = "netcatty"`, `user = "credential-master-key"`). When the
/// keychain is unavailable the cipher is `available() == false` and
/// `encrypt`/`decrypt` pass values through unchanged — the same degradation
/// the Electron bridge has on Linux without libsecret.
pub struct CredentialCipher {
    pub(crate) key: Option<[u8; 32]>,
}

impl CredentialCipher {
    /// Load or create the master key.
    pub fn load_or_create() -> Self {
        todo!("keyring lookup, generate+store on miss, None on error (store agent task)")
    }

    /// Construct with an explicit key (tests).
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key: Some(key) }
    }

    pub fn available(&self) -> bool {
        self.key.is_some()
    }

    /// Encrypt plaintext → `enc:v2:<base64(nonce || ciphertext || tag)>`.
    /// Already-encrypted values (either prefix) are returned unchanged.
    pub fn encrypt(&self, plaintext: &str) -> CoreResult<String> {
        let _ = plaintext;
        todo!()
    }

    /// Decrypt `enc:v2:` values; `enc:v1:` and plaintext are returned as is.
    pub fn decrypt(&self, value: &str) -> CoreResult<String> {
        let _ = value;
        todo!()
    }

    pub fn is_encrypted(value: &str) -> bool {
        value.starts_with(ENC_PREFIX_V1) || value.starts_with(ENC_PREFIX_V2)
    }
}
