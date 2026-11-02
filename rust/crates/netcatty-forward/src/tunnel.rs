//! A single running tunnel.

use crate::error::ForwardResult;
use netcatty_core::models::PortForwardingType;
use netcatty_ssh::SshConnection;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

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
}

impl Tunnel {
    /// Start listening / request the remote forward. Returns once the local
    /// socket is bound (local/dynamic) or the server acknowledged the
    /// forward (remote), so an `Active` status can be published.
    pub async fn start(spec: TunnelSpec, connection: Arc<SshConnection>) -> ForwardResult<Tunnel> {
        let _ = (spec, connection);
        todo!("bind listener / tcpip_forward and spawn accept loop (forward agent task)")
    }

    pub async fn stop(&self) -> ForwardResult<()> {
        todo!("cancel token, cancel_tcpip_forward for remote, await finished (forward agent task)")
    }

    pub fn active_connections(&self) -> usize {
        self.active_connections.load(std::sync::atomic::Ordering::Relaxed)
    }
}
