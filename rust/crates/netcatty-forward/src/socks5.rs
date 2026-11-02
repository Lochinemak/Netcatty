//! Minimal SOCKS5 server side (RFC 1928): no-auth method, CONNECT command,
//! IPv4 / IPv6 / domain addresses. Used by dynamic forwarding.

use crate::error::{ForwardError, ForwardResult};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// RFC 1928 reply codes.
pub const REPLY_SUCCEEDED: u8 = 0x00;
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
pub const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REPLY_HOST_UNREACHABLE: u8 = 0x04;
pub const REPLY_CONNECTION_REFUSED: u8 = 0x05;
pub const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Destination requested by a SOCKS5 client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksTarget {
    pub host: String,
    pub port: u16,
}

fn protocol_error(message: &str) -> ForwardError {
    ForwardError::InvalidArgument(format!("socks5: {message}"))
}

/// Perform the SOCKS5 greeting + request on `stream`. Returns the target the
/// client wants; the caller must then call [`reply_success`] or
/// [`reply_failure`].
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> ForwardResult<SocksTarget> {
    // Greeting: VER NMETHODS METHODS...
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(protocol_error(&format!("unsupported version {}", head[0])));
    }
    let count = head[1] as usize;
    if count == 0 {
        stream.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE]).await?;
        return Err(protocol_error("client offered no authentication methods"));
    }
    let mut methods = vec![0u8; count];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE]).await?;
        stream.flush().await?;
        return Err(protocol_error(
            "client requires authentication; only no-auth is supported",
        ));
    }
    stream.write_all(&[VERSION, METHOD_NO_AUTH]).await?;
    stream.flush().await?;

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != VERSION {
        return Err(protocol_error("bad request version"));
    }
    if request[1] != CMD_CONNECT {
        reply_failure(stream, REPLY_COMMAND_NOT_SUPPORTED).await?;
        return Err(protocol_error(&format!(
            "unsupported command {}",
            request[1]
        )));
    }
    let host = match request[3] {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            Ipv4Addr::from(addr).to_string()
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            Ipv6Addr::from(addr).to_string()
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                reply_failure(stream, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await?;
                return Err(protocol_error("empty domain name"));
            }
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await?;
            match String::from_utf8(name) {
                Ok(name) => name,
                Err(_) => {
                    reply_failure(stream, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await?;
                    return Err(protocol_error("domain name is not valid UTF-8"));
                }
            }
        }
        other => {
            reply_failure(stream, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Err(protocol_error(&format!("unsupported address type {other}")));
        }
    };
    let port = stream.read_u16().await?;
    Ok(SocksTarget { host, port })
}

async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> ForwardResult<()> {
    // BND.ADDR / BND.PORT: 0.0.0.0:0 (clients ignore them for CONNECT).
    let packet = [VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&packet).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn reply_success<S: AsyncWrite + Unpin>(stream: &mut S) -> ForwardResult<()> {
    reply(stream, REPLY_SUCCEEDED).await
}

/// `code` is the RFC 1928 reply code (e.g. 0x05 connection refused).
pub async fn reply_failure<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> ForwardResult<()> {
    reply(stream, code).await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(client_bytes: &[u8]) -> (ForwardResult<SocksTarget>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(256);
        client.write_all(client_bytes).await.unwrap();
        let result = handshake(&mut server).await;
        drop(server);
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        (result, reply)
    }

    #[tokio::test]
    async fn connect_ipv4() {
        let mut bytes = vec![5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1];
        bytes.extend_from_slice(&8080u16.to_be_bytes());
        let (result, reply) = run(&bytes).await;
        assert_eq!(
            result.unwrap(),
            SocksTarget {
                host: "127.0.0.1".into(),
                port: 8080
            }
        );
        assert_eq!(reply, vec![5, 0]);
    }

    #[tokio::test]
    async fn connect_domain_and_ipv6() {
        let mut bytes = vec![5, 2, 0, 2, 5, 1, 0, 3, 11];
        bytes.extend_from_slice(b"example.org");
        bytes.extend_from_slice(&443u16.to_be_bytes());
        let (result, _) = run(&bytes).await;
        assert_eq!(
            result.unwrap(),
            SocksTarget {
                host: "example.org".into(),
                port: 443
            }
        );

        let mut bytes = vec![5, 1, 0, 5, 1, 0, 4];
        bytes.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        bytes.extend_from_slice(&22u16.to_be_bytes());
        let (result, _) = run(&bytes).await;
        assert_eq!(
            result.unwrap(),
            SocksTarget {
                host: "::1".into(),
                port: 22
            }
        );
    }

    #[tokio::test]
    async fn rejects_auth_only_clients() {
        let (result, reply) = run(&[5, 1, 2]).await;
        assert!(matches!(result, Err(ForwardError::InvalidArgument(_))));
        assert_eq!(reply, vec![5, 0xFF]);
    }

    #[tokio::test]
    async fn rejects_bind_command_and_bad_version() {
        let (result, reply) = run(&[5, 1, 0, 5, 2, 0, 1, 1, 2, 3, 4, 0, 80]).await;
        assert!(result.is_err());
        assert_eq!(
            reply,
            vec![5, 0, 5, REPLY_COMMAND_NOT_SUPPORTED, 0, 1, 0, 0, 0, 0, 0, 0]
        );

        let (result, reply) = run(&[4, 1, 0]).await;
        assert!(result.is_err());
        assert!(reply.is_empty());
    }

    #[tokio::test]
    async fn replies_have_bound_address_zero() {
        let (mut client, mut server) = tokio::io::duplex(64);
        reply_success(&mut server).await.unwrap();
        reply_failure(&mut server, REPLY_CONNECTION_REFUSED)
            .await
            .unwrap();
        drop(server);
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        assert_eq!(
            out,
            vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }
}
