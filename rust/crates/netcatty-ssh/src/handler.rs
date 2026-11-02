//! The [`russh::client::Handler`] implementation shared by every connection.
//!
//! The handler is deliberately thin: it records the server banner / key,
//! defers host-key decisions to [`crate::SshCallbacks`] and routes
//! server-initiated channels (remote port forwards, agent forwarding, X11)
//! to whoever registered interest through the channels below.

use crate::known_hosts::{
    fingerprint_sha256, match_known_hosts, public_key_base64, HostKeyDecision, HostKeyInfo,
    KnownHostMatch,
};
use crate::options::HopOptions;
use crate::SshCallbacks;
use russh::client::{ChannelOpenHandle, Msg, Session};
use russh::keys::{PublicKey, PublicKeyOrCertificate};
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
    pub(crate) last_host_key: Arc<parking_lot::Mutex<Option<(HostKeyInfo, HostKeyDecision)>>>,
    /// Server identification string (`SSH-2.0-OpenSSH_9.6`), when observed.
    pub(crate) server_banner: Arc<parking_lot::Mutex<Option<String>>>,
    /// Receives the exit status / signal of channels (`ChannelId` keyed) so
    /// shell/exec wrappers can report them even after the channel closed.
    pub(crate) exit_tx: mpsc::UnboundedSender<(ChannelId, ChannelExit)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelExit {
    Status(u32),
    Signal {
        name: String,
        core_dumped: bool,
        message: String,
    },
    Eof,
    Close,
}

pub struct HandlerChannels {
    pub forwarded_rx: mpsc::UnboundedReceiver<ForwardedTcpip>,
    pub agent_rx: Option<mpsc::UnboundedReceiver<AgentForwardRequest>>,
    pub x11_rx: Option<mpsc::UnboundedReceiver<X11Request>>,
    pub exit_rx: mpsc::UnboundedReceiver<(ChannelId, ChannelExit)>,
}

/// Handles to state the handler keeps updating after it has been moved into
/// the russh session (banner, host-key decision). Obtain with
/// [`ClientHandler::shared`] before calling `connect_stream`.
#[derive(Clone)]
pub struct HandlerShared {
    pub host_key: Arc<parking_lot::Mutex<Option<(HostKeyInfo, HostKeyDecision)>>>,
    pub server_banner: Arc<parking_lot::Mutex<Option<String>>>,
}

impl HandlerShared {
    pub fn host_key_decision(&self) -> Option<(HostKeyInfo, HostKeyDecision)> {
        self.host_key.lock().clone()
    }
    pub fn banner(&self) -> Option<String> {
        self.server_banner.lock().clone()
    }
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
                last_host_key: Arc::new(parking_lot::Mutex::new(None)),
                server_banner: Arc::new(parking_lot::Mutex::new(None)),
                exit_tx,
            },
            HandlerChannels {
                forwarded_rx,
                agent_rx,
                x11_rx,
                exit_rx,
            },
        )
    }

    /// Clone the shared state handles (see [`HandlerShared`]).
    pub fn shared(&self) -> HandlerShared {
        HandlerShared {
            host_key: self.last_host_key.clone(),
            server_banner: self.server_banner.clone(),
        }
    }

    /// Decide whether to trust `key` for this hop (see [`Handler::check_server_key`]).
    async fn decide_host_key(
        &self,
        key: &PublicKey,
        key_type: String,
    ) -> Result<bool, crate::SshError> {
        let fingerprint = fingerprint_sha256(key);
        let blob = public_key_base64(key);
        let hop = &self.hop;

        let (known_host_id, known_fingerprint, trusted) = match match_known_hosts(
            &hop.known_hosts,
            &hop.hostname,
            hop.port,
            &key_type,
            &blob,
            &fingerprint,
        ) {
            KnownHostMatch::Trusted { known_host_id } => (Some(known_host_id), None, true),
            KnownHostMatch::Changed {
                known_host_id,
                known_fingerprint,
            } => (Some(known_host_id), known_fingerprint, false),
            KnownHostMatch::Unknown => (None, None, false),
        };

        let info = HostKeyInfo {
            hostname: hop.hostname.clone(),
            port: hop.port,
            key_type: key_type.clone(),
            fingerprint: fingerprint.clone(),
            public_key: blob,
            known_host_id: if trusted { None } else { known_host_id },
            known_fingerprint: if trusted { None } else { known_fingerprint },
        };

        let decision = if trusted {
            tracing::debug!(
                "host key for {}:{} is trusted ({key_type} SHA256:{fingerprint})",
                hop.hostname,
                hop.port
            );
            HostKeyDecision::Accept { remember: false }
        } else if !hop.verify_host_keys {
            tracing::debug!(
                "host key verification disabled for {}:{}",
                hop.hostname,
                hop.port
            );
            HostKeyDecision::Accept { remember: false }
        } else if hop.host_key_unattended {
            HostKeyDecision::Reject
        } else {
            self.callbacks.verify_host_key(info.clone()).await
        };

        let changed = info.is_changed();
        *self.last_host_key.lock() = Some((info, decision));

        match decision {
            HostKeyDecision::Accept { .. } => Ok(true),
            HostKeyDecision::Reject => {
                let reason = if changed {
                    format!(
                        "host key for {}:{} has changed ({key_type} SHA256:{fingerprint}); refusing to connect",
                        hop.hostname, hop.port
                    )
                } else if hop.host_key_unattended {
                    format!(
                        "unknown host key for {}:{} ({key_type} SHA256:{fingerprint}); unattended mode refuses new keys",
                        hop.hostname, hop.port
                    )
                } else {
                    format!(
                        "host key for {}:{} ({key_type} SHA256:{fingerprint}) was rejected",
                        hop.hostname, hop.port
                    )
                };
                Err(crate::SshError::HostKeyRejected(reason))
            }
        }
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
        match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                let key_type = key.algorithm().to_string();
                self.decide_host_key(key, key_type).await
            }
            PublicKeyOrCertificate::Certificate(cert) => {
                // russh already verified the CA signature over the exchange;
                // the vault has no CA notion, so treat the certified key like
                // a bare host key (recorded under its plain algorithm name).
                let key = PublicKey::new(cert.public_key().clone(), "");
                let key_type = key.algorithm().to_string();
                tracing::debug!(
                    "server presented host certificate {:?} for {}",
                    cert.key_id(),
                    self.hop.hostname
                );
                self.decide_host_key(&key, key_type).await
            }
        }
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let banner = String::from_utf8_lossy(session.remote_sshid())
            .trim()
            .to_string();
        if !banner.is_empty() {
            *self.server_banner.lock() = Some(banner);
        }
        tracing::debug!(
            "kex done with {}: kex={} cipher={} mac={}",
            self.hop.hostname,
            names.kex.as_ref(),
            names.cipher.as_ref(),
            names.client_mac.as_ref()
        );
        Ok(())
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let text = banner.trim();
        if !text.is_empty() {
            self.callbacks.progress(text.to_string()).await;
        }
        Ok(())
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
        let _ = self
            .exit_tx
            .send((channel, ChannelExit::Status(exit_status)));
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
                name: crate::shell::sig_name(&signal_name),
                core_dumped,
                message: error_message.to_string(),
            },
        ));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnattendedCallbacks;
    use async_trait::async_trait;
    use netcatty_core::models::KnownHost;
    use russh::keys::parse_public_key_base64;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBIXa9JKkIZGyHdHHISz530BcYv8X4rtlYTFdmiyqBn9";
    const FP: &str = "taX4bHGWrEieYLp8ahhB8pyRp2l9NP083kFJSSqucrU";

    struct Recording {
        calls: AtomicUsize,
        decision: HostKeyDecision,
    }

    #[async_trait]
    impl SshCallbacks for Recording {
        async fn verify_host_key(&self, info: HostKeyInfo) -> HostKeyDecision {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(info.fingerprint, FP);
            self.decision
        }
        async fn keyboard_interactive(
            &self,
            _n: String,
            _i: String,
            _p: Vec<netcatty_core::ipc::KeyboardInteractivePrompt>,
        ) -> Option<Vec<String>> {
            None
        }
        async fn request_passphrase(&self, _k: String, _i: bool) -> Option<String> {
            None
        }
    }

    fn hop(known: Vec<KnownHost>, verify: bool, unattended: bool) -> HopOptions {
        HopOptions {
            hostname: "example.com".into(),
            port: 22,
            known_hosts: known,
            verify_host_keys: verify,
            host_key_unattended: unattended,
            ..Default::default()
        }
    }

    fn kh(blob: &str, fp: Option<&str>) -> KnownHost {
        KnownHost {
            id: "kh-1".into(),
            hostname: "example.com".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            public_key: blob.into(),
            fingerprint: fp.map(Into::into),
            discovered_at: 0,
            last_seen: None,
            converted_to_host_id: None,
            order: None,
        }
    }

    fn key() -> PublicKey {
        parse_public_key_base64(BLOB).unwrap()
    }

    #[tokio::test]
    async fn trusted_key_is_accepted_without_prompt() {
        let cb = Arc::new(Recording {
            calls: AtomicUsize::new(0),
            decision: HostKeyDecision::Reject,
        });
        let (h, _c) = ClientHandler::new(
            hop(vec![kh(BLOB, None)], true, false),
            cb.clone(),
            false,
            false,
        );
        assert!(h
            .decide_host_key(&key(), "ssh-ed25519".into())
            .await
            .unwrap());
        assert_eq!(cb.calls.load(Ordering::SeqCst), 0);
        let (info, d) = h.shared().host_key_decision().unwrap();
        assert_eq!(d, HostKeyDecision::Accept { remember: false });
        assert!(!info.is_changed());
        assert_eq!(info.fingerprint, FP);
    }

    #[tokio::test]
    async fn unknown_key_asks_callbacks() {
        let cb = Arc::new(Recording {
            calls: AtomicUsize::new(0),
            decision: HostKeyDecision::Accept { remember: true },
        });
        let (h, _c) = ClientHandler::new(hop(vec![], true, false), cb.clone(), false, false);
        assert!(h
            .decide_host_key(&key(), "ssh-ed25519".into())
            .await
            .unwrap());
        assert_eq!(cb.calls.load(Ordering::SeqCst), 1);
        let (_, d) = h.shared().host_key_decision().unwrap();
        assert_eq!(d, HostKeyDecision::Accept { remember: true });
    }

    #[tokio::test]
    async fn changed_key_reports_previous_record() {
        let cb = Arc::new(Recording {
            calls: AtomicUsize::new(0),
            decision: HostKeyDecision::Reject,
        });
        let (h, _c) = ClientHandler::new(
            hop(vec![kh("OTHERBLOB", Some("OLDFP"))], true, false),
            cb.clone(),
            false,
            false,
        );
        let err = h
            .decide_host_key(&key(), "ssh-ed25519".into())
            .await
            .err()
            .unwrap();
        assert!(matches!(err, crate::SshError::HostKeyRejected(m) if m.contains("has changed")));
        let (info, d) = h.shared().host_key_decision().unwrap();
        assert_eq!(d, HostKeyDecision::Reject);
        assert_eq!(info.known_host_id.as_deref(), Some("kh-1"));
        assert_eq!(info.known_fingerprint.as_deref(), Some("OLDFP"));
    }

    #[tokio::test]
    async fn verification_disabled_accepts_anything() {
        let cb = Arc::new(Recording {
            calls: AtomicUsize::new(0),
            decision: HostKeyDecision::Reject,
        });
        let (h, _c) = ClientHandler::new(hop(vec![], false, false), cb.clone(), false, false);
        assert!(h
            .decide_host_key(&key(), "ssh-ed25519".into())
            .await
            .unwrap());
        assert_eq!(cb.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unattended_rejects_unknown_without_prompt() {
        let (h, _c) = ClientHandler::new(
            hop(vec![], true, true),
            Arc::new(UnattendedCallbacks),
            false,
            false,
        );
        let err = h
            .decide_host_key(&key(), "ssh-ed25519".into())
            .await
            .err()
            .unwrap();
        assert!(matches!(err, crate::SshError::HostKeyRejected(m) if m.contains("unattended")));
    }
}
