//! Authentication strategy (mirrors `sshAuthHelper.cjs`).
//!
//! Order for `HostAuthMethod::Auto`:
//! 1. `none` (to learn the server's allowed methods),
//! 2. publickey: explicit `private_key` (+certificate), then
//!    `identity_file_paths`, then agent identities (unless `identities_only`),
//! 3. keyboard-interactive (TOTP prompts auto-answered from `totp.uri`),
//! 4. password.
//!
//! `Password` tries KI first when `requires_mfa`, otherwise password then KI.
//! `Key`/`Certificate` skip password entirely.

use crate::error::SshResult;
use crate::handler::ClientHandler;
use crate::options::HopOptions;
use crate::SshCallbacks;
use russh::client::Handle;
use std::sync::Arc;

/// Authenticate `handle` for `hop`. Returns the method that succeeded.
pub async fn authenticate(
    handle: &Handle<ClientHandler>,
    hop: &HopOptions,
    callbacks: &Arc<dyn SshCallbacks>,
) -> SshResult<AuthOutcome> {
    let _ = (handle, hop, callbacks);
    todo!("authentication pipeline (ssh agent task)")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    None,
    PublicKey { source: KeySourceKind },
    KeyboardInteractive,
    Password,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySourceKind {
    Inline,
    File(String),
    Agent,
}

/// Compute the current TOTP code from an `otpauth://` URI.
pub fn totp_code(uri: &str) -> SshResult<String> {
    let _ = uri;
    todo!("totp-rs based code generation (ssh agent task)")
}

/// Heuristic: does a keyboard-interactive prompt ask for an OTP code?
pub fn is_otp_prompt(prompt: &str, extra_pattern: Option<&str>) -> bool {
    let _ = (prompt, extra_pattern);
    todo!("otp prompt detection (ssh agent task)")
}
