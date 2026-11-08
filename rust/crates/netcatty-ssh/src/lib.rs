//! `netcatty-ssh` — SSH transport layer built on [`russh`].
//!
//! Responsibilities (mirrors `electron/bridges/sshBridge*.cjs`,
//! `sshAuthHelper.cjs`, `hostKeyVerifier.cjs`, `sshConnectionPool.cjs`,
//! `proxyUtils.cjs`, `socks5Request.cjs`):
//!
//! * TCP connect with timeout, optionally through an HTTP CONNECT / SOCKS5
//!   proxy or a `command` proxy (ProxyCommand-style stdio).
//! * Jump host chains: each hop is a full SSH connection; the next hop's TCP
//!   stream is a `direct-tcpip` channel on the previous hop.
//! * Authentication in the OpenSSH order: none → publickey (explicit key,
//!   identity files, agent) → keyboard-interactive (with TOTP auto-answer)
//!   → password. Interactive prompts (host key, passphrase, KI) are routed
//!   through the [`SshCallbacks`] trait so the Tauri layer can forward them to
//!   the renderer and await the answer.
//! * Host key verification against the renderer-supplied `KnownHost` list.
//! * Shell channels with PTY, resize, env, agent forwarding; exec channels
//!   with captured stdout/stderr/exit status.
//! * Key pair generation (`ssh-key` crate).
//!
//! The public surface below is the contract the other crates compile
//! against; keep signatures stable and extend rather than change.

pub mod algorithms;
pub mod auth;
pub mod connection;
pub mod error;
pub mod exec;
pub mod handler;
pub mod keygen;
pub mod known_hosts;
pub mod options;
pub mod prompting;
pub mod proxy;
pub mod shell;

pub use auth::{totp_code, totp_code_at, AuthOutcome, KeySourceKind};
pub use connection::{build_client_config, connect, SshConnection};
pub use error::{SshError, SshResult};
pub use exec::ExecOutput;
pub use handler::ClientHandler;
pub use handler::{ChannelExit, HandlerChannels, HandlerShared};
pub use keygen::{default_key_files, generate_key_pair};
pub use known_hosts::{fingerprint_sha256, HostKeyDecision, HostKeyInfo};
pub use options::{ConnectOptions, HopOptions};
pub use shell::{ShellEvent, ShellOptions, ShellSession};

use async_trait::async_trait;
use netcatty_core::ipc::KeyboardInteractivePrompt;

/// Callbacks for everything that needs a human (or policy) decision while a
/// connection is being established. The Tauri layer implements this by
/// emitting events to the renderer and awaiting the matching response
/// command; tests implement it with canned answers.
#[async_trait]
pub trait SshCallbacks: Send + Sync + 'static {
    /// Decide whether to trust a host key that is unknown or has changed.
    /// Returning [`HostKeyDecision::Reject`] aborts the connection.
    async fn verify_host_key(&self, info: HostKeyInfo) -> HostKeyDecision;

    /// Answer a keyboard-interactive challenge. Return `None` to cancel.
    async fn keyboard_interactive(
        &self,
        name: String,
        instructions: String,
        prompts: Vec<KeyboardInteractivePrompt>,
    ) -> Option<Vec<String>>;

    /// Ask for the passphrase of an encrypted private key. `key_name` is a
    /// human label (vault key label or file path). `invalid` is set when a
    /// previous attempt failed. Return `None` to skip this key.
    async fn request_passphrase(&self, key_name: String, invalid: bool) -> Option<String>;

    /// Informational progress (jump chain hops, auth method attempts).
    /// Default implementation ignores it.
    async fn progress(&self, _message: String) {}

    /// Prepare a FIDO2 security-key (`sk-*`) key for signing: load its
    /// handle into an agent that can reach the hardware and return that
    /// agent's socket. `Ok(None)` means security keys are not supported by
    /// this caller (unattended connections); the key is skipped.
    async fn prepare_security_key(
        &self,
        _request: SecurityKeyRequest,
    ) -> Result<Option<SecurityKeyAgent>, String> {
        Ok(None)
    }

    /// A hardware signature for `key_label` starts (signatures are
    /// serialised and PIN / touch prompts attributed to it).
    async fn security_key_sign_begin(&self, _key_label: String) {}

    /// The signature started by [`Self::security_key_sign_begin`] ended.
    /// Returns `true` when the user cancelled the PIN prompt (no recovery
    /// dialog then).
    async fn security_key_sign_end(&self) -> bool {
        false
    }

    /// The hardware signature failed: retry, fall back to the password, or
    /// cancel the connection.
    async fn security_key_recovery(
        &self,
        _key_label: String,
        _allow_password_fallback: bool,
    ) -> SecurityKeyRecovery {
        SecurityKeyRecovery::Cancel
    }
}

/// Key handle to prepare (see [`SshCallbacks::prepare_security_key`]).
#[derive(Debug, Clone)]
pub struct SecurityKeyRequest {
    /// OpenSSH private key handle text (vault key or identity file).
    pub private_key: String,
    /// OpenSSH certificate for the key, if any.
    pub certificate: Option<String>,
    /// Human label (vault key label or file path).
    pub label: String,
    /// Identity file the handle came from (`None` for vault keys).
    pub path: Option<String>,
}

/// Agent prepared for a security key.
#[derive(Debug, Clone)]
pub struct SecurityKeyAgent {
    /// Agent socket (Unix socket path or Windows named pipe).
    pub socket: String,
    /// Base64 wire blobs of the identities to offer (key and certificate).
    pub public_blobs: Vec<String>,
}

/// Answer to [`SshCallbacks::security_key_recovery`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityKeyRecovery {
    Retry,
    PasswordFallback,
    Cancel,
}

/// A callbacks implementation that trusts every host key, answers nothing,
/// and never prompts. Useful for tests and unattended tooling.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnattendedCallbacks;

#[async_trait]
impl SshCallbacks for UnattendedCallbacks {
    async fn verify_host_key(&self, _info: HostKeyInfo) -> HostKeyDecision {
        HostKeyDecision::Accept { remember: false }
    }
    async fn keyboard_interactive(
        &self,
        _name: String,
        _instructions: String,
        _prompts: Vec<KeyboardInteractivePrompt>,
    ) -> Option<Vec<String>> {
        None
    }
    async fn request_passphrase(&self, _key_name: String, _invalid: bool) -> Option<String> {
        None
    }
}
