//! Interactive shell channels.

use crate::error::SshResult;
use crate::SshConnection;
use bytes::Bytes;
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Options for opening a shell.
#[derive(Debug, Clone)]
pub struct ShellOptions {
    pub cols: u16,
    pub rows: u16,
    /// `TERM` value (`xterm-256color`).
    pub term: String,
    pub env: HashMap<String, String>,
    pub agent_forwarding: bool,
    pub x11_forwarding: bool,
    pub x11_display: Option<String>,
}

impl Default for ShellOptions {
    fn default() -> Self {
        Self {
            cols: 80,
            rows: 24,
            term: "xterm-256color".to_string(),
            env: HashMap::new(),
            agent_forwarding: false,
            x11_forwarding: false,
            x11_display: None,
        }
    }
}

/// Events produced by a running shell.
#[derive(Debug)]
pub enum ShellEvent {
    /// stdout / stderr bytes.
    Data(Bytes),
    /// Remote sent EOF.
    Eof,
    /// Channel closed; `exit_code` is `None` when no status was reported.
    Exit { exit_code: Option<i32>, signal: Option<String> },
}

/// A live shell channel. Output is delivered on [`ShellSession::events`];
/// input is written with [`ShellSession::write`].
pub struct ShellSession {
    pub(crate) inner: ShellInner,
    pub events: mpsc::Receiver<ShellEvent>,
}

pub(crate) struct ShellInner {
    pub(crate) write_tx: mpsc::Sender<Bytes>,
    pub(crate) control_tx: mpsc::UnboundedSender<ShellControl>,
}

pub(crate) enum ShellControl {
    Resize { cols: u16, rows: u16 },
    Signal(russh::Sig),
    Close,
}

impl ShellSession {
    /// Write raw bytes to the remote shell (applies back-pressure).
    pub async fn write(&self, data: Bytes) -> SshResult<()> {
        self.inner
            .write_tx
            .send(data)
            .await
            .map_err(|_| crate::SshError::Channel("shell channel closed".into()))
    }

    pub fn resize(&self, cols: u16, rows: u16) -> SshResult<()> {
        self.inner
            .control_tx
            .send(ShellControl::Resize { cols, rows })
            .map_err(|_| crate::SshError::Channel("shell channel closed".into()))
    }

    /// Send a signal (e.g. `Sig::INT`) to the remote process.
    pub fn signal(&self, sig: russh::Sig) -> SshResult<()> {
        self.inner
            .control_tx
            .send(ShellControl::Signal(sig))
            .map_err(|_| crate::SshError::Channel("shell channel closed".into()))
    }

    /// Close the channel. The `Exit` event is still delivered.
    pub fn close(&self) {
        let _ = self.inner.control_tx.send(ShellControl::Close);
    }
}

impl SshConnection {
    /// Open a PTY-backed shell on this connection.
    pub async fn open_shell(&self, options: ShellOptions) -> SshResult<ShellSession> {
        let _ = options;
        todo!("open session channel, set_env, request_pty, request_shell, spawn pump tasks (ssh agent task)")
    }
}
