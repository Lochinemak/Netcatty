//! A single running tunnel.
//!
//! The accept/copy loops are generic over a [`ChannelOpener`] so the local
//! and dynamic paths can be exercised against a plain TCP target in tests;
//! [`SshChannelOpener`] is the production implementation (`direct-tcpip`).

use crate::dispatch::{self, RemoteRoute};
use crate::error::{ForwardError, ForwardResult};
use crate::socks5;
use netcatty_core::models::PortForwardingType;
use netcatty_ssh::handler::ForwardedTcpip;
use netcatty_ssh::{ClientHandler, SshConnection, SshError};
use russh::client::{Handle, Msg};
use russh::ChannelStream;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Time allowed for a SOCKS5 client to finish its handshake.
const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Back-off after a failed `accept` (e.g. EMFILE) so the loop does not spin.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
/// Bound for `cancel-tcpip-forward` on stop.
const CANCEL_FORWARD_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSpec {
    pub tunnel_id: String,
    pub rule_id: Option<String>,
    pub forward_type: PortForwardingType,
    pub bind_address: String,
    pub local_port: u16,
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
    pub host_id: Option<String>,
    pub hostname: String,
}

/// Opens the far end of a proxied connection (a `direct-tcpip` channel in
/// production, a plain socket in tests).
pub trait ChannelOpener: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn open(
        &self,
        host: &str,
        port: u16,
        originator: SocketAddr,
    ) -> impl Future<Output = ForwardResult<Self::Stream>> + Send;
}

/// [`ChannelOpener`] backed by an SSH session handle.
pub struct SshChannelOpener {
    pub handle: Arc<Handle<ClientHandler>>,
}

impl ChannelOpener for SshChannelOpener {
    type Stream = Pin<Box<ChannelStream<Msg>>>;

    async fn open(
        &self,
        host: &str,
        port: u16,
        originator: SocketAddr,
    ) -> ForwardResult<Self::Stream> {
        let channel = self
            .handle
            .channel_open_direct_tcpip(
                host,
                port as u32,
                originator.ip().to_string(),
                originator.port() as u32,
            )
            .await
            .map_err(|e| ForwardError::Ssh(SshError::from(e)))?;
        Ok(Box::pin(channel.into_stream()))
    }
}

/// Server-side binding of a remote forward, needed to cancel it.
#[derive(Debug, Clone)]
pub(crate) struct RemoteBinding {
    pub bind_address: String,
    pub port: u32,
}

/// Runtime handle for a tunnel. Dropping it does not stop the tunnel; call
/// [`Tunnel::stop`].
pub struct Tunnel {
    pub spec: TunnelSpec,
    pub connection: Arc<SshConnection>,
    pub(crate) cancel: CancellationToken,
    /// Resolves when every task of the tunnel has exited.
    pub(crate) finished: tokio::sync::watch::Receiver<bool>,
    /// Number of currently proxied client connections.
    pub(crate) active_connections: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) remote: Option<RemoteBinding>,
    /// Address the local listener actually bound (local/dynamic).
    pub(crate) local_addr: Option<SocketAddr>,
}

impl Tunnel {
    /// Start listening / request the remote forward. Returns once the local
    /// socket is bound (local/dynamic) or the server acknowledged the
    /// forward (remote), so an `Active` status can be published.
    pub async fn start(spec: TunnelSpec, connection: Arc<SshConnection>) -> ForwardResult<Tunnel> {
        let cancel = CancellationToken::new();
        let active = Arc::new(AtomicUsize::new(0));
        let (finished_tx, finished_rx) = watch::channel(false);
        let mut remote = None;
        let mut local_addr = None;

        match spec.forward_type {
            PortForwardingType::Local => {
                let (host, port) = require_remote_target(&spec)?;
                let listener = bind_listener(&spec.bind_address, spec.local_port).await?;
                local_addr = listener.local_addr().ok();
                let opener = Arc::new(SshChannelOpener {
                    handle: connection.handle.clone(),
                });
                let (cancel, active) = (cancel.clone(), active.clone());
                tokio::spawn(async move {
                    run_local_forward(listener, host, port, opener, cancel, active).await;
                    let _ = finished_tx.send(true);
                });
            }
            PortForwardingType::Dynamic => {
                let listener = bind_listener(&spec.bind_address, spec.local_port).await?;
                local_addr = listener.local_addr().ok();
                let opener = Arc::new(SshChannelOpener {
                    handle: connection.handle.clone(),
                });
                let (cancel, active) = (cancel.clone(), active.clone());
                tokio::spawn(async move {
                    run_dynamic_forward(listener, opener, cancel, active).await;
                    let _ = finished_tx.send(true);
                });
            }
            PortForwardingType::Remote => {
                let (host, port) = require_remote_target(&spec)?;
                // Start routing before the server can send us channels.
                dispatch::ensure_dispatcher(&connection).await?;
                let bound = match connection
                    .handle
                    .tcpip_forward(spec.bind_address.clone(), spec.local_port as u32)
                    .await
                {
                    Ok(port) => port,
                    Err(russh::Error::RequestDenied) => {
                        return Err(ForwardError::RemoteForwardRejected)
                    }
                    Err(err) => return Err(ForwardError::Ssh(SshError::from(err))),
                };
                // russh reports 0 when a specific port was requested.
                let bound_port = if bound == 0 {
                    spec.local_port as u32
                } else {
                    bound
                };
                let route = match dispatch::register(&connection, bound_port).await {
                    Ok(route) => route,
                    Err(err) => {
                        let _ = connection
                            .handle
                            .cancel_tcpip_forward(spec.bind_address.clone(), bound_port)
                            .await;
                        return Err(err);
                    }
                };
                remote = Some(RemoteBinding {
                    bind_address: spec.bind_address.clone(),
                    port: bound_port,
                });
                let (cancel, active) = (cancel.clone(), active.clone());
                tokio::spawn(async move {
                    run_remote_forward(route, host, port, cancel, active).await;
                    let _ = finished_tx.send(true);
                });
            }
        }

        tracing::info!(
            tunnel_id = %spec.tunnel_id,
            kind = ?spec.forward_type,
            bind = %spec.bind_address,
            port = spec.local_port,
            "tunnel started"
        );
        Ok(Tunnel {
            spec,
            connection,
            cancel,
            finished: finished_rx,
            active_connections: active,
            remote,
            local_addr,
        })
    }

    pub async fn stop(&self) -> ForwardResult<()> {
        self.cancel.cancel();
        let mut result = Ok(());
        if let Some(remote) = &self.remote {
            if self.connection.is_closed() {
                tracing::debug!(tunnel_id = %self.spec.tunnel_id, "connection already closed; skipping cancel-tcpip-forward");
            } else {
                let cancel = self
                    .connection
                    .handle
                    .cancel_tcpip_forward(remote.bind_address.clone(), remote.port);
                match tokio::time::timeout(CANCEL_FORWARD_TIMEOUT, cancel).await {
                    Ok(Ok(())) => {}
                    Ok(Err(russh::Error::Disconnect)) | Ok(Err(russh::Error::SendError)) => {
                        // Connection went away underneath us: nothing to clean.
                    }
                    Ok(Err(err)) => {
                        result = Err(ForwardError::Bind(format!(
                            "cancel-tcpip-forward failed: {err}"
                        )))
                    }
                    Err(_) => {
                        result = Err(ForwardError::Bind("cancel-tcpip-forward timed out".into()))
                    }
                }
            }
        }
        let mut finished = self.finished.clone();
        while !*finished.borrow_and_update() {
            if finished.changed().await.is_err() {
                break;
            }
        }
        tracing::info!(tunnel_id = %self.spec.tunnel_id, "tunnel stopped");
        result
    }

    pub fn active_connections(&self) -> usize {
        self.active_connections
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Bound listener address for local/dynamic tunnels.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }
}

fn require_remote_target(spec: &TunnelSpec) -> ForwardResult<(String, u16)> {
    let host = spec
        .remote_host
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| ForwardError::InvalidArgument("remote host is required".into()))?;
    let port = spec
        .remote_port
        .filter(|p| *p != 0)
        .ok_or_else(|| ForwardError::InvalidArgument("remote port is required".into()))?;
    Ok((host.to_string(), port))
}

/// Bind the local listener, mapping `EADDRINUSE` to
/// [`ForwardError::AddressInUse`].
pub async fn bind_listener(bind_address: &str, port: u16) -> ForwardResult<TcpListener> {
    let bind = if bind_address.trim().is_empty() {
        "127.0.0.1"
    } else {
        bind_address.trim()
    };
    TcpListener::bind((bind, port)).await.map_err(|err| {
        if err.kind() == std::io::ErrorKind::AddrInUse {
            ForwardError::AddressInUse(format!("{bind}:{port}"))
        } else {
            ForwardError::Bind(format!("{bind}:{port}: {err}"))
        }
    })
}

/// Decrements the active-connection counter when dropped.
struct ActiveGuard(Arc<AtomicUsize>);

impl ActiveGuard {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Shared accept loop: hands every accepted socket to `handle`, reaps
/// finished connection tasks, and aborts the rest when `cancel` fires.
async fn accept_loop<F, Fut>(listener: TcpListener, cancel: CancellationToken, mut handle: F)
where
    F: FnMut(TcpStream, SocketAddr) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut tasks: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((tcp, peer)) => {
                    let _ = tcp.set_nodelay(true);
                    tasks.spawn(handle(tcp, peer));
                }
                Err(err) => {
                    tracing::warn!(error = %err, "accept failed");
                    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                }
            },
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    drop(listener);
    tasks.shutdown().await;
}

async fn pipe<S>(mut tcp: TcpStream, mut far: S, cancel: CancellationToken)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::select! {
        _ = cancel.cancelled() => {}
        result = tokio::io::copy_bidirectional(&mut tcp, &mut far) => {
            if let Err(err) = result {
                tracing::debug!(error = %err, "proxied connection ended with error");
            }
        }
    }
}

/// Local (`-L`) forward: every accepted connection is proxied to
/// `remote_host:remote_port` through `opener`.
pub async fn run_local_forward<O: ChannelOpener>(
    listener: TcpListener,
    remote_host: String,
    remote_port: u16,
    opener: Arc<O>,
    cancel: CancellationToken,
    active: Arc<AtomicUsize>,
) {
    let loop_cancel = cancel.clone();
    accept_loop(listener, loop_cancel, move |tcp, peer| {
        let opener = opener.clone();
        let cancel = cancel.clone();
        let active = active.clone();
        let host = remote_host.clone();
        async move {
            let _guard = ActiveGuard::new(active);
            let far = tokio::select! {
                _ = cancel.cancelled() => return,
                opened = opener.open(&host, remote_port, peer) => opened,
            };
            match far {
                Ok(far) => pipe(tcp, far, cancel).await,
                Err(err) => {
                    tracing::debug!(error = %err, %host, remote_port, "direct-tcpip open failed");
                    // Dropping `tcp` resets the client connection.
                }
            }
        }
    })
    .await;
}

/// Dynamic (`-D`) forward: a SOCKS5 server whose CONNECT targets are opened
/// through `opener`.
pub async fn run_dynamic_forward<O: ChannelOpener>(
    listener: TcpListener,
    opener: Arc<O>,
    cancel: CancellationToken,
    active: Arc<AtomicUsize>,
) {
    let loop_cancel = cancel.clone();
    accept_loop(listener, loop_cancel, move |mut tcp, peer| {
        let opener = opener.clone();
        let cancel = cancel.clone();
        let active = active.clone();
        async move {
            let _guard = ActiveGuard::new(active);
            let target = tokio::select! {
                _ = cancel.cancelled() => return,
                result = tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, socks5::handshake(&mut tcp)) => match result {
                    Ok(Ok(target)) => target,
                    Ok(Err(err)) => {
                        tracing::debug!(error = %err, "socks5 handshake rejected");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!("socks5 handshake timed out");
                        return;
                    }
                },
            };
            let far = tokio::select! {
                _ = cancel.cancelled() => return,
                opened = opener.open(&target.host, target.port, peer) => opened,
            };
            match far {
                Ok(far) => {
                    if socks5::reply_success(&mut tcp).await.is_err() {
                        return;
                    }
                    pipe(tcp, far, cancel).await;
                }
                Err(err) => {
                    tracing::debug!(error = %err, host = %target.host, port = target.port, "socks5 target open failed");
                    let _ = socks5::reply_failure(&mut tcp, socks5::REPLY_CONNECTION_REFUSED).await;
                }
            }
        }
    })
    .await;
}

/// Remote (`-R`) forward: every `forwarded-tcpip` channel routed to us is
/// connected to `target_host:target_port` on the local network.
pub(crate) async fn run_remote_forward(
    mut route: RemoteRoute,
    target_host: String,
    target_port: u16,
    cancel: CancellationToken,
    active: Arc<AtomicUsize>,
) {
    let mut tasks: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            forwarded = route.rx.recv() => match forwarded {
                Some(forwarded) => {
                    let cancel = cancel.clone();
                    let active = active.clone();
                    let host = target_host.clone();
                    tasks.spawn(proxy_forwarded(forwarded, host, target_port, cancel, active));
                }
                None => break,
            },
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    drop(route);
    tasks.shutdown().await;
}

async fn proxy_forwarded(
    forwarded: ForwardedTcpip,
    host: String,
    port: u16,
    cancel: CancellationToken,
    active: Arc<AtomicUsize>,
) {
    let _guard = ActiveGuard::new(active);
    let connect = tokio::select! {
        _ = cancel.cancelled() => return,
        connected = TcpStream::connect((host.as_str(), port)) => connected,
    };
    match connect {
        Ok(tcp) => {
            let _ = tcp.set_nodelay(true);
            let far = Box::pin(forwarded.channel.into_stream());
            pipe(tcp, far, cancel).await;
        }
        Err(err) => {
            tracing::debug!(error = %err, %host, port, originator = %forwarded.originator_address, "remote forward target unreachable");
            let _ = forwarded.channel.close().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Opener that connects to a real TCP address and records the requested
    /// destination.
    struct TcpOpener {
        target: SocketAddr,
        requested: parking_lot::Mutex<Vec<(String, u16)>>,
        fail: bool,
    }

    impl ChannelOpener for TcpOpener {
        type Stream = TcpStream;
        async fn open(
            &self,
            host: &str,
            port: u16,
            _originator: SocketAddr,
        ) -> ForwardResult<TcpStream> {
            self.requested.lock().push((host.to_string(), port));
            if self.fail {
                return Err(ForwardError::Bind("simulated channel-open failure".into()));
            }
            Ok(TcpStream::connect(self.target).await?)
        }
    }

    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    async fn wait_for_active(counter: &Arc<AtomicUsize>, expected: usize) {
        for _ in 0..200 {
            if counter.load(Ordering::Relaxed) == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("active connections never reached {expected}");
    }

    #[tokio::test]
    async fn local_forward_proxies_bytes_and_counts_connections() {
        let echo = echo_server().await;
        let listener = bind_listener("127.0.0.1", 0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let opener = Arc::new(TcpOpener {
            target: echo,
            requested: Default::default(),
            fail: false,
        });
        let cancel = CancellationToken::new();
        let active = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(run_local_forward(
            listener,
            "db.internal".into(),
            5432,
            opener.clone(),
            cancel.clone(),
            active.clone(),
        ));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert_eq!(
            opener.requested.lock().as_slice(),
            &[("db.internal".to_string(), 5432)]
        );
        wait_for_active(&active, 1).await;

        drop(client);
        wait_for_active(&active, 0).await;

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(TcpStream::connect(addr).await.is_err() || active.load(Ordering::Relaxed) == 0);
    }

    #[tokio::test]
    async fn local_forward_open_failure_drops_client() {
        let listener = bind_listener("127.0.0.1", 0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let opener = Arc::new(TcpOpener {
            target: addr,
            requested: Default::default(),
            fail: true,
        });
        let cancel = CancellationToken::new();
        let active = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(run_local_forward(
            listener,
            "x".into(),
            1,
            opener,
            cancel.clone(),
            active.clone(),
        ));

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .unwrap();
        assert!(matches!(n, Ok(0) | Err(_)));
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn bind_reports_address_in_use() {
        let first = bind_listener("127.0.0.1", 0).await.unwrap();
        let port = first.local_addr().unwrap().port();
        let err = bind_listener("127.0.0.1", port).await.err().unwrap();
        assert!(matches!(err, ForwardError::AddressInUse(_)), "{err:?}");
        assert!(bind_listener("", 0).await.is_ok());
    }

    #[tokio::test]
    async fn dynamic_forward_speaks_socks5() {
        let echo = echo_server().await;
        let listener = bind_listener("127.0.0.1", 0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let opener = Arc::new(TcpOpener {
            target: echo,
            requested: Default::default(),
            fail: false,
        });
        let cancel = CancellationToken::new();
        let active = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(run_dynamic_forward(
            listener,
            opener.clone(),
            cancel.clone(),
            active.clone(),
        ));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 0]);
        let mut req = vec![5, 1, 0, 3, 7];
        req.extend_from_slice(b"example");
        req.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[..2], [5, 0]);
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        assert_eq!(
            opener.requested.lock().as_slice(),
            &[("example".to_string(), 80)]
        );

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn dynamic_forward_reports_connection_refused() {
        let listener = bind_listener("127.0.0.1", 0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let opener = Arc::new(TcpOpener {
            target: addr,
            requested: Default::default(),
            fail: true,
        });
        let cancel = CancellationToken::new();
        let active = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(run_dynamic_forward(
            listener,
            opener,
            cancel.clone(),
            active,
        ));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await.unwrap();
        client
            .write_all(&[5, 1, 0, 1, 10, 0, 0, 1, 0, 22])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], socks5::REPLY_CONNECTION_REFUSED);
        cancel.cancel();
        task.await.unwrap();
    }

    #[test]
    fn remote_target_validation() {
        let spec = TunnelSpec {
            tunnel_id: "t".into(),
            rule_id: None,
            forward_type: PortForwardingType::Local,
            bind_address: "127.0.0.1".into(),
            local_port: 8080,
            remote_host: Some(" ".into()),
            remote_port: Some(80),
            host_id: None,
            hostname: "h".into(),
        };
        assert!(matches!(
            require_remote_target(&spec),
            Err(ForwardError::InvalidArgument(_))
        ));
        let ok = TunnelSpec {
            remote_host: Some("db".into()),
            ..spec.clone()
        };
        assert_eq!(require_remote_target(&ok).unwrap(), ("db".to_string(), 80));
        let no_port = TunnelSpec {
            remote_host: Some("db".into()),
            remote_port: None,
            ..spec
        };
        assert!(matches!(
            require_remote_target(&no_port),
            Err(ForwardError::InvalidArgument(_))
        ));
    }
}
