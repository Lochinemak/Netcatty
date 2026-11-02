//! Outbound proxies for the first hop: HTTP CONNECT, SOCKS5 (RFC 1928 with
//! optional username/password auth, RFC 1929) and `command` (ProxyCommand
//! style child process whose stdio carries the SSH stream).

use crate::error::SshResult;
use netcatty_core::models::ProxyConfig;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// Any bidirectional byte stream usable as an SSH transport.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Transport for T {}

pub type BoxedTransport = Box<dyn Transport>;

/// Dial `host:port` directly or through `proxy`, within `timeout`.
pub async fn dial(
    host: &str,
    port: u16,
    proxy: Option<&ProxyConfig>,
    timeout: Duration,
) -> SshResult<BoxedTransport> {
    let _ = (host, port, proxy, timeout);
    todo!("tcp / http-connect / socks5 / command dial (ssh agent task)")
}

/// Substitute `%h`, `%p`, `%r` in a ProxyCommand template.
pub fn expand_proxy_command(template: &str, host: &str, port: u16, user: &str) -> String {
    template
        .replace("%%", "\u{0}PERCENT\u{0}")
        .replace("%h", host)
        .replace("%p", &port.to_string())
        .replace("%r", user)
        .replace("\u{0}PERCENT\u{0}", "%")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_command_expansion() {
        assert_eq!(
            expand_proxy_command("nc -X 5 -x p:1080 %h %p %% %r", "example.com", 22, "root"),
            "nc -X 5 -x p:1080 example.com 22 % root"
        );
    }
}
