//! Establishing and owning an authenticated SSH connection.

use crate::error::SshResult;
use crate::handler::{ClientHandler, HandlerChannels};
use crate::options::ConnectOptions;
use crate::SshCallbacks;
use russh::client::Handle;
use std::sync::Arc;
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

    /// Disconnect the target hop and every jump hop.
    pub async fn disconnect(&self) -> SshResult<()> {
        todo!("graceful disconnect of target then jump hops (ssh agent task)")
    }
}

/// Connect and authenticate.
///
/// Flow (see crate docs): proxy/TCP dial of the first hop with
/// `tcp_connect_timeout` → `russh::client::connect_stream` → auth within
/// `auth_ready_timeout` → for each subsequent hop open a `direct-tcpip`
/// channel on the previous hop and repeat with `connect_stream` over the
/// channel stream.
pub async fn connect(options: ConnectOptions, callbacks: Arc<dyn SshCallbacks>) -> SshResult<SshConnection> {
    let _ = (options, callbacks);
    todo!("connect pipeline (ssh agent task)")
}
