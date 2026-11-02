//! Establishing and owning an authenticated SSH connection.

use crate::algorithms::build_preferred;
use crate::error::{SshError, SshResult};
use crate::handler::{ClientHandler, HandlerChannels};
use crate::known_hosts::{HostKeyDecision, HostKeyInfo};
use crate::options::{ConnectOptions, HopOptions};
use crate::prompting::{with_interactive_timeout, PromptState, PromptingCallbacks};
use crate::SshCallbacks;
use russh::client::Handle;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// An authenticated connection to the target host (through any jump hops).
///
/// Cloning is cheap: the handle is reference-counted. Dropping the last
/// clone does **not** disconnect; call [`SshConnection::disconnect`].
pub struct SshConnection {
    /// The russh session handle for the *target* hop.
    pub handle: Arc<Handle<ClientHandler>>,
    /// Handles of the jump hops, closest-to-client first. Kept alive so the
    /// tunnelled TCP stream stays open.
    pub jump_handles: Vec<Arc<Handle<ClientHandler>>>,
    /// Routing receivers for server-initiated channels of the target hop.
    /// Taken (once) by whoever needs them, e.g. the remote-forward manager.
    pub channels: Arc<Mutex<Option<HandlerChannels>>>,
    /// Server identification banner (`OpenSSH_9.6`), when observed.
    pub server_banner: Option<String>,
    pub options: ConnectOptions,
    /// Host-key decisions taken during the handshake, one per hop in
    /// connection order (jump hops first, target last). Entries with
    /// `HostKeyDecision::Accept { remember: true }` should be persisted by
    /// the caller.
    pub host_key_decisions: Vec<(HostKeyInfo, HostKeyDecision)>,
}

impl std::fmt::Debug for SshConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConnection")
            .field("target", &self.describe())
            .field("jump_hops", &self.jump_handles.len())
            .field("server_banner", &self.server_banner)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl SshConnection {
    /// Short description for logs: `user@host:port`.
    pub fn describe(&self) -> String {
        format!(
            "{}@{}:{}",
            self.options.target.username, self.options.target.hostname, self.options.target.port
        )
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// Host keys the user accepted during this connection and asked to
    /// remember.
    pub fn newly_trusted_host_keys(&self) -> Vec<&HostKeyInfo> {
        self.host_key_decisions
            .iter()
            .filter_map(|(info, d)| {
                matches!(d, HostKeyDecision::Accept { remember: true }).then_some(info)
            })
            .collect()
    }

    /// Disconnect the target hop and every jump hop.
    pub async fn disconnect(&self) -> SshResult<()> {
        let mut first_err: Option<SshError> = None;
        let mut all: Vec<&Arc<Handle<ClientHandler>>> =
            Vec::with_capacity(self.jump_handles.len() + 1);
        all.push(&self.handle);
        all.extend(self.jump_handles.iter().rev());
        for handle in all {
            if handle.is_closed() {
                continue;
            }
            match handle
                .disconnect(
                    russh::Disconnect::ByApplication,
                    "Netcatty session closed",
                    "en",
                )
                .await
            {
                Ok(()) => {}
                // Already gone: nothing to do.
                Err(russh::Error::SendError)
                | Err(russh::Error::Disconnect)
                | Err(russh::Error::HUP) => {}
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(SshError::Russh(e));
                    }
                }
            }
        }
        // `Handle::disconnect` only queues the message; the session task
        // winds down shortly after. Wait (bounded) so callers can rely on
        // `is_closed()` once this returns.
        let deadline = tokio::time::Instant::now() + DISCONNECT_SETTLE_TIMEOUT;
        while !self.handle.is_closed() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// Upper bound on how long [`SshConnection::disconnect`] waits for the
/// session task to observe the disconnect.
const DISCONNECT_SETTLE_TIMEOUT: Duration = Duration::from_secs(2);

/// Build the russh client configuration for one hop.
pub fn build_client_config(hop: &HopOptions) -> russh::client::Config {
    let mut config = russh::client::Config {
        client_id: russh::SshId::Standard(Cow::Owned(format!(
            "SSH-2.0-Netcatty_{}",
            env!("CARGO_PKG_VERSION")
        ))),
        preferred: build_preferred(hop),
        inactivity_timeout: None,
        keepalive_interval: hop.keepalive_interval,
        keepalive_max: hop.keepalive_count_max.max(1) as usize,
        nodelay: true,
        ..Default::default()
    };
    if hop.keepalive_interval.is_none() {
        config.keepalive_max = 3;
    }
    config
}

fn map_connect_error(hop: &HopOptions, err: SshError) -> SshError {
    match err {
        SshError::Russh(russh::Error::Disconnect) | SshError::Russh(russh::Error::HUP) => {
            SshError::Connect(format!("{}: connection closed during handshake", hop.address()))
        }
        SshError::Russh(russh::Error::NoCommonAlgo { kind, ours, theirs }) => SshError::Connect(format!(
            "{}: no common {kind:?} algorithm (ours: {}; theirs: {}). Enable legacy algorithms for this host if it is old equipment.",
            hop.address(),
            ours.join(","),
            theirs.join(",")
        )),
        SshError::Russh(russh::Error::Version) => {
            SshError::Connect(format!("{}: remote did not speak SSH (invalid version string)", hop.address()))
        }
        SshError::Russh(russh::Error::KexInit) | SshError::Russh(russh::Error::Kex) => {
            SshError::Connect(format!("{}: key exchange failed", hop.address()))
        }
        SshError::Russh(russh::Error::UnknownKey) => {
            SshError::HostKeyRejected(format!("{}: host key rejected", hop.address()))
        }
        SshError::Io(e) => SshError::Connect(format!("{}: {e}", hop.address())),
        other => other,
    }
}

/// Connect and authenticate.
///
/// Flow (see crate docs): proxy/TCP dial of the first hop with
/// `tcp_connect_timeout` → `russh::client::connect_stream` → auth within
/// `auth_ready_timeout` → for each subsequent hop open a `direct-tcpip`
/// channel on the previous hop and repeat with `connect_stream` over the
/// channel stream.
pub async fn connect(
    options: ConnectOptions,
    callbacks: Arc<dyn SshCallbacks>,
) -> SshResult<SshConnection> {
    let prompt_state = PromptState::new();
    let callbacks: Arc<dyn SshCallbacks> = PromptingCallbacks::new(callbacks, prompt_state.clone());

    let hops: Vec<&HopOptions> = options
        .jump_hosts
        .iter()
        .chain(std::iter::once(&options.target))
        .collect();
    let total = hops.len();
    let mut handles: Vec<Arc<Handle<ClientHandler>>> = Vec::with_capacity(total);
    let mut target_channels: Option<HandlerChannels> = None;
    let mut server_banner: Option<String> = None;
    let mut host_key_decisions: Vec<(HostKeyInfo, HostKeyDecision)> = Vec::with_capacity(total);

    for (index, hop) in hops.iter().enumerate() {
        let is_target = index + 1 == total;
        if hop.hostname.trim().is_empty() {
            return Err(SshError::InvalidArgument(format!(
                "hop {} has no hostname",
                index + 1
            )));
        }
        if total > 1 {
            callbacks
                .progress(format!(
                    "{} {}@{} (hop {}/{})",
                    if is_target {
                        "Connecting to"
                    } else {
                        "Connecting via"
                    },
                    hop.username,
                    hop.address(),
                    index + 1,
                    total
                ))
                .await;
        } else {
            callbacks
                .progress(format!("Connecting to {}@{}", hop.username, hop.address()))
                .await;
        }

        let config = Arc::new(build_client_config(hop));
        let (handler, channels) = ClientHandler::new(
            (*hop).clone(),
            callbacks.clone(),
            is_target && options.agent_forwarding,
            is_target && options.x11_forwarding,
        );
        let shared = handler.shared();

        let hop_result: SshResult<Handle<ClientHandler>> = async {
            let mut handle = if index == 0 {
                let stream = crate::proxy::dial(
                    &hop.hostname,
                    hop.port,
                    hop.proxy.as_ref(),
                    hop.tcp_connect_timeout,
                )
                .await?;
                with_interactive_timeout(
                    &prompt_state,
                    hop.auth_ready_timeout,
                    "SSH handshake",
                    async { russh::client::connect_stream(config, stream, handler).await },
                )
                .await?
                .map_err(|e| map_connect_error(hop, e))?
            } else {
                let previous = handles.last().expect("previous hop handle");
                let channel = tokio::time::timeout(
                    hop.tcp_connect_timeout,
                    previous.channel_open_direct_tcpip(
                        hop.hostname.clone(),
                        hop.port as u32,
                        "127.0.0.1",
                        0,
                    ),
                )
                .await
                .map_err(|_| {
                    SshError::Timeout(format!("timed out opening tunnel to {}", hop.address()))
                })?
                .map_err(|e| match e {
                    russh::Error::ChannelOpenFailure(reason) => SshError::Connect(format!(
                        "jump host could not reach {}: {reason:?}",
                        hop.address()
                    )),
                    other => SshError::Connect(format!(
                        "jump host could not reach {}: {other}",
                        hop.address()
                    )),
                })?;
                with_interactive_timeout(
                    &prompt_state,
                    hop.auth_ready_timeout,
                    "SSH handshake",
                    async {
                        russh::client::connect_stream(config, channel.into_stream(), handler).await
                    },
                )
                .await?
                .map_err(|e| map_connect_error(hop, e))?
            };

            callbacks
                .progress(format!(
                    "Authenticating as {}@{}",
                    hop.username,
                    hop.address()
                ))
                .await;
            let outcome = with_interactive_timeout(
                &prompt_state,
                hop.auth_ready_timeout,
                "SSH authentication",
                async { crate::auth::authenticate(&mut handle, hop, &callbacks).await },
            )
            .await??;
            tracing::info!(
                "authenticated {}@{} via {:?}",
                hop.username,
                hop.address(),
                outcome
            );
            Ok(handle)
        }
        .await;

        if let Some(decision) = shared.host_key_decision() {
            host_key_decisions.push(decision);
        }

        let handle = match hop_result {
            Ok(h) => h,
            Err(e) => {
                // Tear down the hops established so far.
                for h in handles.iter().rev() {
                    let _ = h
                        .disconnect(russh::Disconnect::ByApplication, "connection aborted", "en")
                        .await;
                }
                return Err(e);
            }
        };

        if is_target {
            server_banner = shared.banner();
            target_channels = Some(channels);
        }
        handles.push(Arc::new(handle));
    }

    let handle = handles.pop().expect("at least one hop");
    Ok(SshConnection {
        handle,
        jump_handles: handles,
        channels: Arc::new(Mutex::new(target_channels)),
        server_banner,
        options,
        host_key_decisions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnattendedCallbacks;
    use std::time::Duration;

    #[test]
    fn client_config_reflects_hop() {
        let hop = HopOptions {
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_count_max: 5,
            legacy_algorithms: true,
            ..Default::default()
        };
        let c = build_client_config(&hop);
        assert_eq!(c.keepalive_interval, Some(Duration::from_secs(15)));
        assert_eq!(c.keepalive_max, 5);
        assert!(c.nodelay);
        assert!(c.inactivity_timeout.is_none());
        assert!(c
            .preferred
            .kex
            .iter()
            .any(|k| k.as_ref() == "diffie-hellman-group14-sha1"));
        match &c.client_id {
            russh::SshId::Standard(id) => assert!(id.starts_with("SSH-2.0-Netcatty_")),
            other => panic!("unexpected id {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_rejects_missing_hostname() {
        let opts = ConnectOptions {
            target: HopOptions {
                username: "u".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = connect(opts, Arc::new(UnattendedCallbacks))
            .await
            .err()
            .unwrap();
        assert!(matches!(err, SshError::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn connect_reports_refused_tcp() {
        // Bind then drop a listener to get a port that is (very likely) closed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let opts = ConnectOptions {
            target: HopOptions {
                hostname: "127.0.0.1".into(),
                port,
                username: "u".into(),
                tcp_connect_timeout: Duration::from_secs(5),
                auth_ready_timeout: Duration::from_secs(5),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = connect(opts, Arc::new(UnattendedCallbacks))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(err, SshError::Connect(_) | SshError::Timeout(_)),
            "{err}"
        );
    }

    #[tokio::test]
    async fn connect_fails_cleanly_on_non_ssh_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            }
        });
        let opts = ConnectOptions {
            target: HopOptions {
                hostname: "127.0.0.1".into(),
                port,
                username: "u".into(),
                tcp_connect_timeout: Duration::from_secs(5),
                auth_ready_timeout: Duration::from_secs(5),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = connect(opts, Arc::new(UnattendedCallbacks))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(
                err,
                SshError::Connect(_) | SshError::Timeout(_) | SshError::Russh(_)
            ),
            "{err}"
        );
    }
}
