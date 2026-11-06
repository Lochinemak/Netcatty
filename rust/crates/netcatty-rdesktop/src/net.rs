//! Shared connection helpers.

use netcatty_core::{CoreError, CoreResult};
use std::time::Duration;
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

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
