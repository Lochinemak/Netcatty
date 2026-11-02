//! Minimal SOCKS5 server side (RFC 1928): no-auth method, CONNECT command,
//! IPv4 / IPv6 / domain addresses. Used by dynamic forwarding.

use crate::error::ForwardResult;
use tokio::io::{AsyncRead, AsyncWrite};

/// Destination requested by a SOCKS5 client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksTarget {
    pub host: String,
    pub port: u16,
}

/// Perform the SOCKS5 greeting + request on `stream`. Returns the target the
/// client wants; the caller must then call [`reply_success`] or
/// [`reply_failure`].
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> ForwardResult<SocksTarget> {
    let _ = stream;
    todo!("socks5 negotiation (forward agent task)")
}

pub async fn reply_success<S: AsyncWrite + Unpin>(stream: &mut S) -> ForwardResult<()> {
    let _ = stream;
    todo!()
}

/// `code` is the RFC 1928 reply code (e.g. 0x05 connection refused).
pub async fn reply_failure<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> ForwardResult<()> {
    let _ = (stream, code);
    todo!()
}
