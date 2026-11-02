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

pub mod auth;
pub mod connection;
pub mod error;
pub mod exec;
pub mod handler;
pub mod keygen;
pub mod known_hosts;
pub mod options;
pub mod proxy;
pub mod shell;

pub use connection::{connect, SshConnection};
pub use error::{SshError, SshResult};
pub use exec::ExecOutput;
pub use handler::ClientHandler;
pub use keygen::generate_key_pair;
pub use known_hosts::{fingerprint_sha256, HostKeyDecision, HostKeyInfo};
pub use options::{ConnectOptions, HopOptions};
pub use shell::ShellSession;

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
