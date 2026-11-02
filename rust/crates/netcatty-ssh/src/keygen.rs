//! Key pair generation (`generateKeyPair` IPC).

use crate::error::SshResult;
use netcatty_core::ipc::{GenerateKeyPairOptions, GenerateKeyPairResult};

/// Generate an OpenSSH key pair. RSA honors `bits` (default 4096), ECDSA
/// honors `bits` as the curve size (256/384/521, default 256). Security-key
/// types (`*-SK`) return `success: false` with an explanatory error because
/// they require hardware enrolment through the FIDO flow, which the first
/// Rust version does not implement.
pub fn generate_key_pair(options: &GenerateKeyPairOptions) -> SshResult<GenerateKeyPairResult> {
    let _ = options;
    todo!("ssh-key based generation with optional passphrase (ssh agent task)")
}

/// Default key files OpenSSH would try (`~/.ssh/id_*`) that exist on disk.
pub fn default_key_files() -> Vec<(String, String)> {
    todo!("enumerate ~/.ssh/id_ed25519 / id_ecdsa / id_rsa / id_dsa (ssh agent task)")
}
