//! The [`russh::client::Handler`] implementation shared by every connection.
//!
//! The handler is deliberately thin: it records the server banner / key,
//! defers host-key decisions to [`crate::SshCallbacks`] and routes
//! server-initiated channels (remote port forwards, agent forwarding, X11)
//! to whoever registered interest through the channels below.

use crate::known_hosts::{HostKeyDecision, HostKeyInfo};
use crate::options::HopOptions;
use crate::SshCallbacks;
use russh::client::{ChannelOpenHandle, Msg, Session};
use russh::keys::PublicKeyOrCertificate;
use russh::{Channel, ChannelId};
use std::sync::Arc;
use tokio::sync::mpsc;

/// A server-opened `forwarded-tcpip` channel (remote port forwarding).
pub struct ForwardedTcpip {
    pub channel: Channel<Msg>,
    pub connected_address: String,
    pub connected_port: u32,
    pub originator_address: String,
    pub originator_port: u32,
}

/// A server-opened `auth-agent@openssh.com` channel (agent forwarding).
pub struct AgentForwardRequest {
    pub channel: Channel<Msg>,
}

/// A server-opened `x11` channel.
pub struct X11Request {
    pub channel: Channel<Msg>,
    pub originator_address: String,
    pub originator_port: u32,
}

/// Shared handler state.
pub struct ClientHandler {
    pub(crate) hop: HopOptions,
    pub(crate) callbacks: Arc<dyn SshCallbacks>,
    /// Receives channels for remote forwards registered by `netcatty-forward`.
    pub(crate) forwarded_tx: mpsc::UnboundedSender<ForwardedTcpip>,
    pub(crate) agent_tx: Option<mpsc::UnboundedSender<AgentForwardRequest>>,
    pub(crate) x11_tx: Option<mpsc::UnboundedSender<X11Request>>,
    /// Set after `check_server_key` to the trust decision so the connection
    /// layer can persist a newly accepted key.
    pub(crate) last_host_key: parking_lot::Mutex<Option<(HostKeyInfo, HostKeyDecision)>>,
    /// Server identification string (`SSH-2.0-OpenSSH_9.6`), when observed.
    pub(crate) server_banner: parking_lot::Mutex<Option<String>>,
    /// Receives the exit status / signal of channels (`ChannelId` keyed) so
    /// shell/exec wrappers can report them even after the channel closed.
    pub(crate) exit_tx: mpsc::UnboundedSender<(ChannelId, ChannelExit)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelExit {
    Status(u32),
    Signal { name: String, core_dumped: bool, message: String },
    Eof,
    Close,
}

pub struct HandlerChannels {
    pub forwarded_rx: mpsc::UnboundedReceiver<ForwardedTcpip>,
    pub agent_rx: Option<mpsc::UnboundedReceiver<AgentForwardRequest>>,
    pub x11_rx: Option<mpsc::UnboundedReceiver<X11Request>>,
    pub exit_rx: mpsc::UnboundedReceiver<(ChannelId, ChannelExit)>,
}

impl ClientHandler {
    /// Create a handler plus the receiving ends of its routing channels.
    pub fn new(
        hop: HopOptions,
        callbacks: Arc<dyn SshCallbacks>,
        agent_forwarding: bool,
        x11_forwarding: bool,
    ) -> (Self, HandlerChannels) {
        let (forwarded_tx, forwarded_rx) = mpsc::unbounded_channel();
        let (exit_tx, exit_rx) = mpsc::unbounded_channel();
        let (agent_tx, agent_rx) = if agent_forwarding {
            let (tx, rx) = mpsc::unbounded_channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let (x11_tx, x11_rx) = if x11_forwarding {
            let (tx, rx) = mpsc::unbounded_channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        (
            Self {
                hop,
                callbacks,
                forwarded_tx,
                agent_tx,
                x11_tx,
                last_host_key: parking_lot::Mutex::new(None),
                server_banner: parking_lot::Mutex::new(None),
                exit_tx,
            },
            HandlerChannels { forwarded_rx, agent_rx, x11_rx, exit_rx },
        )
    }
}

impl russh::client::Handler for ClientHandler {
    type Error = crate::SshError;

    /// Verify the server key: trusted → accept; unknown/changed → ask the
    /// callbacks unless `verify_host_keys` is off or `host_key_unattended`
    /// forces a failure.
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let _ = server_public_key;
        todo!("host key verification (ssh agent task): compute fingerprint, match_known_hosts, consult callbacks")
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let _ = self.forwarded_tx.send(ForwardedTcpip {
            channel,
            connected_address: connected_address.to_string(),
            connected_port,
            originator_address: originator_address.to_string(),
            originator_port,
        });
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        if let Some(tx) = &self.agent_tx {
            let _ = tx.send(AgentForwardRequest { channel });
        }
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        channel: Channel<Msg>,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        if let Some(tx) = &self.x11_tx {
            let _ = tx.send(X11Request {
                channel,
                originator_address: originator_address.to_string(),
                originator_port,
            });
        }
        Ok(())
    }

    async fn exit_status(
        &mut self,
        channel: ChannelId,
        exit_status: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = self.exit_tx.send((channel, ChannelExit::Status(exit_status)));
        Ok(())
    }

    async fn exit_signal(
        &mut self,
        channel: ChannelId,
        signal_name: russh::Sig,
        core_dumped: bool,
        error_message: &str,
        _lang_tag: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = self.exit_tx.send((
            channel,
            ChannelExit::Signal {
                name: format!("{signal_name:?}"),
                core_dumped,
                message: error_message.to_string(),
            },
        ));
        Ok(())
    }
}
