//! Interactive shell channels.

use crate::error::{SshError, SshResult};
use crate::SshConnection;
use bytes::Bytes;
use russh::ChannelMsg;
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Capacity of the outbound event queue (remote → UI).
pub const SHELL_EVENT_QUEUE: usize = 1024;
/// Capacity of the inbound write queue (UI → remote).
pub const SHELL_WRITE_QUEUE: usize = 256;

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
    Exit {
        exit_code: Option<i32>,
        signal: Option<String>,
    },
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

    /// Whether the pump task is still running (channel not yet closed).
    pub fn is_open(&self) -> bool {
        !self.inner.write_tx.is_closed()
    }
}

/// Parse an X11 `DISPLAY` value (`host:display.screen`) into its screen
/// number (0 when absent or unparsable).
pub fn x11_screen_number(display: &str) -> u32 {
    display
        .rsplit_once(':')
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once('.').map(|(_, screen)| screen))
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// Random 128-bit MIT-MAGIC-COOKIE-1 in lowercase hex.
pub fn random_x11_cookie() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Name of a [`russh::Sig`] as it appears on the wire (`INT`, `TERM`, ...).
pub fn sig_name(sig: &russh::Sig) -> String {
    match sig {
        russh::Sig::Custom(name) => name.clone(),
        other => format!("{other:?}"),
    }
}

impl SshConnection {
    /// Open a PTY-backed shell on this connection.
    pub async fn open_shell(&self, options: ShellOptions) -> SshResult<ShellSession> {
        let channel = self.handle.channel_open_session().await.map_err(open_err)?;

        for (name, value) in &options.env {
            if name.trim().is_empty() {
                continue;
            }
            // Servers commonly reject env requests (AcceptEnv); never fatal.
            if let Err(e) = channel.set_env(false, name.as_str(), value.as_str()).await {
                tracing::debug!("set_env {name} failed: {e}");
            }
        }

        if options.agent_forwarding {
            if let Err(e) = channel.agent_forward(false).await {
                tracing::warn!("agent forwarding request failed: {e}");
            }
        }

        if options.x11_forwarding {
            let display = options
                .x11_display
                .clone()
                .or_else(|| std::env::var("DISPLAY").ok())
                .unwrap_or_else(|| ":0".to_string());
            let screen = x11_screen_number(&display);
            if let Err(e) = channel
                .request_x11(
                    false,
                    false,
                    "MIT-MAGIC-COOKIE-1",
                    random_x11_cookie(),
                    screen,
                )
                .await
            {
                tracing::warn!("x11 forwarding request failed: {e}");
            }
        }

        let term = if options.term.trim().is_empty() {
            "xterm-256color"
        } else {
            options.term.as_str()
        };
        channel
            .request_pty(
                true,
                term,
                options.cols.max(1) as u32,
                options.rows.max(1) as u32,
                0,
                0,
                &[],
            )
            .await
            .map_err(|e| SshError::Channel(format!("pty request failed: {e}")))?;
        channel
            .request_shell(true)
            .await
            .map_err(|e| SshError::Channel(format!("shell request failed: {e}")))?;

        let (events_tx, events_rx) = mpsc::channel::<ShellEvent>(SHELL_EVENT_QUEUE);
        let (write_tx, write_rx) = mpsc::channel::<Bytes>(SHELL_WRITE_QUEUE);
        let (control_tx, control_rx) = mpsc::unbounded_channel::<ShellControl>();

        tokio::spawn(pump(channel, events_tx, write_rx, control_rx));

        Ok(ShellSession {
            inner: ShellInner {
                write_tx,
                control_tx,
            },
            events: events_rx,
        })
    }
}

fn open_err(e: russh::Error) -> SshError {
    match e {
        russh::Error::ChannelOpenFailure(reason) => {
            SshError::Channel(format!("channel open failed: {reason:?}"))
        }
        russh::Error::SendError | russh::Error::Disconnect | russh::Error::HUP => {
            SshError::Disconnected("connection closed".into())
        }
        other => SshError::Russh(other),
    }
}

/// Drive a shell channel until it closes, then deliver exactly one `Exit`.
async fn pump(
    mut channel: russh::Channel<russh::client::Msg>,
    events: mpsc::Sender<ShellEvent>,
    mut write_rx: mpsc::Receiver<Bytes>,
    mut control_rx: mpsc::UnboundedReceiver<ShellControl>,
) {
    let mut exit_code: Option<i32> = None;
    let mut signal: Option<String> = None;
    let mut writes_open = true;
    let mut controls_open = true;
    let mut closing = false;

    loop {
        tokio::select! {
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        if events.send(ShellEvent::Data(Bytes::from(data.to_vec()))).await.is_err() {
                            // Consumer went away: tear the channel down.
                            let _ = channel.eof().await;
                            let _ = channel.close().await;
                            break;
                        }
                    }
                    Some(ChannelMsg::Eof) => {
                        let _ = events.send(ShellEvent::Eof).await;
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = Some(exit_status as i32);
                    }
                    Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                        signal = Some(sig_name(&signal_name));
                    }
                    Some(ChannelMsg::Close) | None => break,
                    Some(_) => {}
                }
            }
            w = write_rx.recv(), if writes_open && !closing => {
                match w {
                    Some(bytes) => {
                        if let Err(e) = channel.data_bytes(bytes).await {
                            tracing::debug!("shell write failed: {e}");
                            break;
                        }
                    }
                    None => {
                        // ShellSession dropped: close gracefully.
                        writes_open = false;
                        closing = true;
                        let _ = channel.eof().await;
                        let _ = channel.close().await;
                    }
                }
            }
            c = control_rx.recv(), if controls_open && !closing => {
                match c {
                    Some(ShellControl::Resize { cols, rows }) => {
                        if let Err(e) = channel.window_change(cols.max(1) as u32, rows.max(1) as u32, 0, 0).await {
                            tracing::debug!("window_change failed: {e}");
                        }
                    }
                    Some(ShellControl::Signal(sig)) => {
                        if let Err(e) = channel.signal(sig).await {
                            tracing::debug!("signal failed: {e}");
                        }
                    }
                    Some(ShellControl::Close) => {
                        closing = true;
                        let _ = channel.eof().await;
                        let _ = channel.close().await;
                    }
                    None => {
                        controls_open = false;
                    }
                }
            }
        }
    }

    let _ = events.send(ShellEvent::Exit { exit_code, signal }).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x11_screen_parsing() {
        assert_eq!(x11_screen_number(":0"), 0);
        assert_eq!(x11_screen_number(":0.1"), 1);
        assert_eq!(x11_screen_number("localhost:10.2"), 2);
        assert_eq!(x11_screen_number("/private/tmp/launch/org.xquartz:0"), 0);
        assert_eq!(x11_screen_number("garbage"), 0);
    }

    #[test]
    fn x11_cookie_is_32_hex_chars() {
        let c = random_x11_cookie();
        assert_eq!(c.len(), 32);
        assert!(c.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_ne!(c, random_x11_cookie());
    }

    #[test]
    fn signal_names() {
        assert_eq!(sig_name(&russh::Sig::INT), "INT");
        assert_eq!(sig_name(&russh::Sig::Custom("WINCH".into())), "WINCH");
    }
}
