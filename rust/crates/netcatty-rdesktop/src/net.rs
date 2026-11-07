//! Shared connection helpers.

use netcatty_core::{CoreError, CoreResult};
use std::future::Future;
use std::time::Duration;
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Upper bound for everything between the TCP connect and the first frame
/// (TLS, authentication, capability exchange). A server that accepts the
/// connection and then stalls must not leave the session "connecting" forever.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(45);

/// Open the TCP connection of a session, with a bounded wait.
pub(crate) async fn connect_tcp(host: &str, port: u16) -> CoreResult<TcpStream> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| CoreError::timeout(format!("connecting to {host}:{port} timed out")))?
        .map_err(|err| CoreError::network(format!("cannot connect to {host}:{port}: {err}")))?;
    // Input latency matters more than throughput for a desktop session.
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Run a protocol handshake with [`HANDSHAKE_TIMEOUT`]. `protocol` names the
/// protocol in the error message.
pub(crate) async fn with_handshake_timeout<T>(
    protocol: &str,
    handshake: impl Future<Output = CoreResult<T>>,
) -> CoreResult<T> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| {
            CoreError::timeout(format!(
                "{protocol} handshake timed out after {} seconds",
                HANDSHAKE_TIMEOUT.as_secs()
            ))
        })?
}
