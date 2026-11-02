//! Routing of server-initiated `forwarded-tcpip` channels to remote tunnels.
//!
//! `SshConnection.channels` holds a single `forwarded_rx` receiver that can
//! only be taken once, while several remote (`-R`) tunnels may share one SSH
//! connection. The first remote tunnel on a connection takes the receiver
//! and starts one dispatcher task per connection; every tunnel then
//! registers a route keyed by the server-side listening port and receives
//! only its own channels. The other receivers in `HandlerChannels`
//! (`exit_rx`, `agent_rx`, `x11_rx`) are put back together with a silent
//! placeholder `forwarded_rx`, so other consumers of that struct keep
//! working.
//!
//! Dispatchers are tracked in a process-wide map keyed by the connection's
//! `Arc` pointer; a `Weak` back-reference guards against address reuse after
//! a connection has been dropped.

use crate::error::{ForwardError, ForwardResult};
use dashmap::DashMap;
use netcatty_ssh::handler::{ForwardedTcpip, HandlerChannels};
use netcatty_ssh::SshConnection;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Weak};
use tokio::sync::mpsc;

type Routes = Arc<DashMap<u32, mpsc::UnboundedSender<ForwardedTcpip>>>;

static DISPATCHERS: LazyLock<DashMap<usize, Arc<ConnectionDispatcher>>> =
    LazyLock::new(DashMap::new);

pub(crate) struct ConnectionDispatcher {
    key: usize,
    connection: Weak<SshConnection>,
    routes: Routes,
    started: AtomicBool,
}

/// A registered route; dropping it unregisters the port.
pub(crate) struct RemoteRoute {
    pub port: u32,
    pub rx: mpsc::UnboundedReceiver<ForwardedTcpip>,
    dispatcher: Arc<ConnectionDispatcher>,
}

impl Drop for RemoteRoute {
    fn drop(&mut self) {
        self.dispatcher.routes.remove(&self.port);
    }
}

fn dispatcher_for(connection: &Arc<SshConnection>) -> Arc<ConnectionDispatcher> {
    let key = Arc::as_ptr(connection) as usize;
    if let Some(existing) = DISPATCHERS.get(&key) {
        let alive = existing
            .connection
            .upgrade()
            .is_some_and(|c| Arc::ptr_eq(&c, connection));
        if alive {
            return existing.clone();
        }
    }
    let fresh = Arc::new(ConnectionDispatcher {
        key,
        connection: Arc::downgrade(connection),
        routes: Arc::new(DashMap::new()),
        started: AtomicBool::new(false),
    });
    DISPATCHERS.insert(key, fresh.clone());
    fresh
}

impl ConnectionDispatcher {
    /// Take `forwarded_rx` from the connection (once) and start routing.
    async fn ensure_started(&self, connection: &Arc<SshConnection>) -> ForwardResult<()> {
        if self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut guard = connection.channels.lock().await;
        if self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        let Some(channels) = guard.take() else {
            return Err(ForwardError::Bind(
                "forwarded-tcpip receiver is not available on this connection".into(),
            ));
        };
        let HandlerChannels {
            forwarded_rx,
            agent_rx,
            x11_rx,
            exit_rx,
        } = channels;
        let (placeholder_tx, placeholder_rx) = mpsc::unbounded_channel();
        *guard = Some(HandlerChannels {
            forwarded_rx: placeholder_rx,
            agent_rx,
            x11_rx,
            exit_rx,
        });
        self.started.store(true, Ordering::Release);
        drop(guard);

        let routes = self.routes.clone();
        let key = self.key;
        let weak = self.connection.clone();
        tokio::spawn(async move {
            dispatch_loop(forwarded_rx, routes).await;
            // Keep the placeholder sender alive for the connection's lifetime
            // so a later taker sees an open-but-silent channel.
            drop(placeholder_tx);
            DISPATCHERS.remove_if(&key, |_, d| Weak::ptr_eq(&d.connection, &weak));
        });
        Ok(())
    }
}

async fn dispatch_loop(mut rx: mpsc::UnboundedReceiver<ForwardedTcpip>, routes: Routes) {
    while let Some(forwarded) = rx.recv().await {
        let port = forwarded.connected_port;
        let undelivered = match routes.get(&port) {
            Some(tx) => tx.send(forwarded).err().map(|e| e.0),
            None => Some(forwarded),
        };
        if let Some(forwarded) = undelivered {
            tracing::debug!(
                port,
                "forwarded-tcpip channel without a registered tunnel; closing"
            );
            let _ = forwarded.channel.close().await;
        }
    }
    tracing::debug!("forwarded-tcpip dispatcher ended (connection closed)");
}

/// Make sure the dispatcher for `connection` is running (call before
/// `tcpip_forward` so no early channel is lost).
pub(crate) async fn ensure_dispatcher(connection: &Arc<SshConnection>) -> ForwardResult<()> {
    dispatcher_for(connection).ensure_started(connection).await
}

/// Register interest in channels for server port `port`.
pub(crate) async fn register(
    connection: &Arc<SshConnection>,
    port: u32,
) -> ForwardResult<RemoteRoute> {
    let dispatcher = dispatcher_for(connection);
    dispatcher.ensure_started(connection).await?;
    let (tx, rx) = mpsc::unbounded_channel();
    match dispatcher.routes.entry(port) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return Err(ForwardError::AddressInUse(format!(
                "remote port {port} is already forwarded on this connection"
            )));
        }
        dashmap::mapref::entry::Entry::Vacant(slot) => {
            slot.insert(tx);
        }
    }
    Ok(RemoteRoute {
        port,
        rx,
        dispatcher,
    })
}
