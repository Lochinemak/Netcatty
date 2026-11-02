//! Outbound proxies for the first hop: HTTP CONNECT, SOCKS5 (RFC 1928 with
//! optional username/password auth, RFC 1929) and `command` (ProxyCommand
//! style child process whose stdio carries the SSH stream).

use crate::error::{SshError, SshResult};
use netcatty_core::models::{ProxyConfig, ProxyType};
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::net::TcpStream;

/// Any bidirectional byte stream usable as an SSH transport.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Transport for T {}

pub type BoxedTransport = Box<dyn Transport>;

/// Upper bound for proxy handshake replies (headers / SOCKS frames).
const MAX_PROXY_REPLY_BYTES: usize = 64 * 1024;

/// Dial `host:port` directly or through `proxy`, within `timeout`.
pub async fn dial(
    host: &str,
    port: u16,
    proxy: Option<&ProxyConfig>,
    timeout: Duration,
) -> SshResult<BoxedTransport> {
    if host.trim().is_empty() {
        return Err(SshError::InvalidArgument("hostname is required".into()));
    }
    if port == 0 {
        return Err(SshError::InvalidArgument("port is required".into()));
    }
    match proxy {
        None => {
            let stream = tcp_connect(host, port, timeout).await?;
            Ok(Box::new(stream))
        }
        Some(p) => match p.proxy_type {
            ProxyType::Http => {
                let stream = tcp_connect(&p.host, p.port, timeout)
                    .await
                    .map_err(proxy_err)?;
                let stream = tokio::time::timeout(timeout, http_connect(stream, host, port, p))
                    .await
                    .map_err(|_| {
                        SshError::Timeout(format!("proxy connection timeout to {host}:{port}"))
                    })??;
                Ok(Box::new(stream))
            }
            ProxyType::Socks5 => {
                let stream = tcp_connect(&p.host, p.port, timeout)
                    .await
                    .map_err(proxy_err)?;
                let stream = tokio::time::timeout(timeout, socks5_connect(stream, host, port, p))
                    .await
                    .map_err(|_| {
                        SshError::Timeout(format!("proxy connection timeout to {host}:{port}"))
                    })??;
                Ok(Box::new(stream))
            }
            ProxyType::Command => {
                let template = p.command.as_deref().unwrap_or("").trim();
                if template.is_empty() {
                    return Err(SshError::Proxy("ProxyCommand is required".into()));
                }
                let command = expand_proxy_command_quoted(template, host, port, "");
                let transport = spawn_proxy_command(&command)?;
                Ok(Box::new(transport))
            }
        },
    }
}

fn proxy_err(err: SshError) -> SshError {
    match err {
        SshError::Connect(msg) => SshError::Proxy(msg),
        SshError::Timeout(msg) => SshError::Timeout(msg),
        other => other,
    }
}

/// Plain TCP connect with timeout and `TCP_NODELAY`.
pub async fn tcp_connect(host: &str, port: u16, timeout: Duration) -> SshResult<TcpStream> {
    let addr = (host.to_string(), port);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| SshError::Timeout(format!("connection timeout to {host}:{port}")))?
        .map_err(|e| SshError::Connect(format!("{host}:{port}: {e}")))?;
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!("set_nodelay failed: {e}");
    }
    Ok(stream)
}

// ---------------------------------------------------------------------------
// HTTP CONNECT
// ---------------------------------------------------------------------------

/// Build the `CONNECT` request for `host:port`, with Basic auth when both a
/// username and a password are configured.
pub fn http_connect_request(
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> String {
    use base64::Engine;
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let (Some(u), Some(p)) = (username, password) {
        if !u.is_empty() {
            let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
            req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
    }
    req.push_str("\r\n");
    req
}

/// Perform an HTTP CONNECT handshake over `stream`. Bytes that follow the
/// proxy reply (often the SSH banner) stay buffered in the returned reader.
pub async fn http_connect<S>(
    stream: S,
    host: &str,
    port: u16,
    proxy: &ProxyConfig,
) -> SshResult<BufReader<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufReader::new(stream);
    let request = http_connect_request(
        host,
        port,
        proxy.username.as_deref(),
        proxy.password.as_deref(),
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut status_line: Option<String> = None;
    let mut total = 0usize;
    loop {
        let mut line = Vec::new();
        let n = stream.read_until(b'\n', &mut line).await?;
        if n == 0 {
            return Err(SshError::Proxy(
                "HTTP proxy closed the connection during CONNECT".into(),
            ));
        }
        total += n;
        if total > MAX_PROXY_REPLY_BYTES {
            return Err(SshError::Proxy("HTTP proxy reply too large".into()));
        }
        let text = String::from_utf8_lossy(&line)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        if status_line.is_none() {
            status_line = Some(text);
            continue;
        }
        if text.is_empty() {
            break;
        }
    }
    let status = status_line.unwrap_or_default();
    if status.starts_with("HTTP/1.1 200") || status.starts_with("HTTP/1.0 200") {
        Ok(stream)
    } else {
        Err(SshError::Proxy(format!("HTTP proxy error: {status}")))
    }
}

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

/// SOCKS5 greeting: offer no-auth, plus username/password when configured.
pub fn socks5_greeting(with_auth: bool) -> Vec<u8> {
    if with_auth {
        vec![0x05, 0x02, 0x00, 0x02]
    } else {
        vec![0x05, 0x01, 0x00]
    }
}

/// RFC 1929 username/password sub-negotiation request.
pub fn socks5_auth_request(username: &str, password: &str) -> SshResult<Vec<u8>> {
    let u = username.as_bytes();
    let p = password.as_bytes();
    if u.is_empty() || u.len() > 255 || p.len() > 255 {
        return Err(SshError::Proxy(
            "SOCKS5 username/password must be 1..=255 bytes".into(),
        ));
    }
    let mut out = Vec::with_capacity(3 + u.len() + p.len());
    out.push(0x01);
    out.push(u.len() as u8);
    out.extend_from_slice(u);
    out.push(p.len() as u8);
    out.extend_from_slice(p);
    Ok(out)
}

/// SOCKS5 CONNECT request using domain-name addressing (ATYP 0x03).
pub fn socks5_connect_request(host: &str, port: u16) -> SshResult<Vec<u8>> {
    let h = host.as_bytes();
    if h.is_empty() || h.len() > 255 {
        return Err(SshError::Proxy(
            "SOCKS5 target host must be 1..=255 bytes".into(),
        ));
    }
    let mut out = Vec::with_capacity(7 + h.len());
    out.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, h.len() as u8]);
    out.extend_from_slice(h);
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

fn socks5_reply_message(code: u8) -> &'static str {
    match code {
        0x01 => "General failure",
        0x02 => "Connection not allowed",
        0x03 => "Network unreachable",
        0x04 => "Host unreachable",
        0x05 => "Connection refused",
        0x06 => "TTL expired",
        0x07 => "Command not supported",
        0x08 => "Address type not supported",
        _ => "Unknown",
    }
}

/// Perform a SOCKS5 CONNECT handshake over `stream`. Trailing bytes stay
/// buffered in the returned reader.
pub async fn socks5_connect<S>(
    stream: S,
    host: &str,
    port: u16,
    proxy: &ProxyConfig,
) -> SshResult<BufReader<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufReader::new(stream);
    let creds = match (proxy.username.as_deref(), proxy.password.as_deref()) {
        (Some(u), Some(p)) if !u.is_empty() => Some((u, p)),
        _ => None,
    };

    stream.write_all(&socks5_greeting(creds.is_some())).await?;
    stream.flush().await?;

    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Err(SshError::Proxy("Invalid SOCKS5 response".into()));
    }
    match greeting[1] {
        0x00 => {}
        0x02 => {
            let (u, p) = creds
                .ok_or_else(|| SshError::Proxy("SOCKS5 proxy requires authentication".into()))?;
            stream.write_all(&socks5_auth_request(u, p)?).await?;
            stream.flush().await?;
            let mut auth_reply = [0u8; 2];
            stream.read_exact(&mut auth_reply).await?;
            if auth_reply[1] != 0x00 {
                return Err(SshError::Proxy("SOCKS5 authentication failed".into()));
            }
        }
        0xff => {
            return Err(SshError::Proxy(
                "SOCKS5 proxy accepted none of the offered auth methods".into(),
            ))
        }
        _ => {
            return Err(SshError::Proxy(
                "SOCKS5 authentication method not supported".into(),
            ))
        }
    }

    stream
        .write_all(&socks5_connect_request(host, port)?)
        .await?;
    stream.flush().await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(SshError::Proxy("Invalid SOCKS5 connect reply".into()));
    }
    if head[1] != 0x00 {
        return Err(SshError::Proxy(format!(
            "SOCKS5 error: {}",
            socks5_reply_message(head[1])
        )));
    }
    // Consume BND.ADDR + BND.PORT.
    let addr_len = match head[3] {
        0x01 => 4usize,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            l[0] as usize
        }
        _ => return Err(SshError::Proxy("Invalid SOCKS5 connect reply".into())),
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest).await?;
    Ok(stream)
}

// ---------------------------------------------------------------------------
// ProxyCommand
// ---------------------------------------------------------------------------

/// Substitute `%h`, `%p`, `%r` in a ProxyCommand template.
pub fn expand_proxy_command(template: &str, host: &str, port: u16, user: &str) -> String {
    template
        .replace("%%", "\u{0}PERCENT\u{0}")
        .replace("%h", host)
        .replace("%p", &port.to_string())
        .replace("%r", user)
        .replace("\u{0}PERCENT\u{0}", "%")
}

/// Like [`expand_proxy_command`] but shell-quotes the substituted values so
/// a hostname cannot inject into the spawned shell (mirrors the Electron
/// bridge's `substituteProxyCommand`).
pub fn expand_proxy_command_quoted(template: &str, host: &str, port: u16, user: &str) -> String {
    expand_proxy_command(
        template,
        &quote_shell_arg(host),
        port,
        &quote_shell_arg(user),
    )
}

#[cfg(not(windows))]
fn quote_shell_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(windows)]
fn quote_shell_arg(value: &str) -> String {
    format!("\"{}\"", value)
}

/// A spawned ProxyCommand whose stdout/stdin carry the SSH stream. The child
/// is killed when the transport is dropped.
pub struct ProcessTransport {
    child: tokio::process::Child,
    io: tokio::io::Join<tokio::process::ChildStdout, tokio::process::ChildStdin>,
}

impl ProcessTransport {
    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }
}

impl AsyncRead for ProcessTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProcessTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

fn spawn_proxy_command(command: &str) -> SshResult<ProcessTransport> {
    let mut cmd = if cfg!(windows) {
        let mut c = tokio::process::Command::new("cmd");
        c.arg("/C").arg(command);
        c
    } else {
        let mut c = tokio::process::Command::new("sh");
        c.arg("-c").arg(command);
        c
    };
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| SshError::Proxy(format!("failed to spawn ProxyCommand: {e}")))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| SshError::Proxy("ProxyCommand stdin unavailable".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SshError::Proxy("ProxyCommand stdout unavailable".into()))?;
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::debug!(target: "netcatty_ssh::proxy_command", "{line}");
            }
        });
    }
    Ok(ProcessTransport {
        child,
        io: tokio::io::join(stdout, stdin),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(kind: ProxyType, user: Option<&str>, pass: Option<&str>) -> ProxyConfig {
        ProxyConfig {
            proxy_type: kind,
            host: "proxy".into(),
            port: 1080,
            command: None,
            identity_id: None,
            username: user.map(Into::into),
            password: pass.map(Into::into),
        }
    }

    #[test]
    fn proxy_command_expansion() {
        assert_eq!(
            expand_proxy_command("nc -X 5 -x p:1080 %h %p %% %r", "example.com", 22, "root"),
            "nc -X 5 -x p:1080 example.com 22 % root"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn proxy_command_quoting() {
        assert_eq!(
            expand_proxy_command_quoted("nc %h %p", "evil'; rm -rf /;'", 22, ""),
            "nc 'evil'\\''; rm -rf /;'\\''' 22"
        );
    }

    #[test]
    fn http_connect_request_shape() {
        let r = http_connect_request("example.com", 22, None, None);
        assert_eq!(
            r,
            "CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\r\n"
        );
        let r = http_connect_request("example.com", 22, Some("u"), Some("p"));
        assert!(r.contains("Proxy-Authorization: Basic dTpw\r\n"));
        assert!(r.ends_with("\r\n\r\n"));
    }

    #[test]
    fn socks5_frames() {
        assert_eq!(socks5_greeting(false), vec![5, 1, 0]);
        assert_eq!(socks5_greeting(true), vec![5, 2, 0, 2]);
        assert_eq!(
            socks5_auth_request("ab", "c").unwrap(),
            vec![1, 2, b'a', b'b', 1, b'c']
        );
        assert_eq!(
            socks5_connect_request("host", 2222).unwrap(),
            vec![5, 1, 0, 3, 4, b'h', b'o', b's', b't', 0x08, 0xae]
        );
        assert!(socks5_connect_request("", 22).is_err());
    }

    #[tokio::test]
    async fn http_connect_against_fake_server() {
        let (client, mut server) = tokio::io::duplex(4096);
        let p = cfg(ProxyType::Http, Some("user"), Some("secret"));
        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let mut got = Vec::new();
            loop {
                let n = server.read(&mut buf).await.unwrap();
                got.extend_from_slice(&buf[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8(got).unwrap();
            assert!(text.starts_with("CONNECT target:22 HTTP/1.1\r\n"));
            assert!(text.contains("Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n"));
            // Reply + trailing SSH banner in the same write.
            server
                .write_all(
                    b"HTTP/1.1 200 Connection established\r\nX-Foo: bar\r\n\r\nSSH-2.0-banner\r\n",
                )
                .await
                .unwrap();
            server
        });
        let mut stream = http_connect(client, "target", 22, &p).await.unwrap();
        let mut banner = vec![0u8; 16];
        stream.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-banner\r\n");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn http_connect_rejects_non_200() {
        let (client, mut server) = tokio::io::duplex(4096);
        let p = cfg(ProxyType::Http, None, None);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let err = http_connect(client, "target", 22, &p).await.err().unwrap();
        assert!(matches!(err, SshError::Proxy(m) if m.contains("407")));
    }

    #[tokio::test]
    async fn socks5_with_auth_against_fake_server() {
        let (client, mut server) = tokio::io::duplex(4096);
        let p = cfg(ProxyType::Socks5, Some("u"), Some("pw"));
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 4];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 2, 0, 2]);
            server.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0u8; 6];
            server.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth, [1, 1, b'u', 2, b'p', b'w']);
            server.write_all(&[1, 0]).await.unwrap();
            let mut req = [0u8; 4 + 1 + 6 + 2];
            server.read_exact(&mut req).await.unwrap();
            assert_eq!(&req[..5], &[5, 1, 0, 3, 6]);
            assert_eq!(&req[5..11], b"target");
            assert_eq!(&req[11..], &[0, 22]);
            // Reply with IPv4 bind address + trailing data.
            server
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 22, b'S', b'S', b'H'])
                .await
                .unwrap();
        });
        let mut stream = socks5_connect(client, "target", 22, &p).await.unwrap();
        let mut tail = [0u8; 3];
        stream.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"SSH");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_no_auth_and_error_reply() {
        let (client, mut server) = tokio::io::duplex(4096);
        let p = cfg(ProxyType::Socks5, None, None);
        tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            server.write_all(&[5, 0]).await.unwrap();
            let mut req = [0u8; 4 + 1 + 6 + 2];
            server.read_exact(&mut req).await.unwrap();
            server
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let err = socks5_connect(client, "target", 22, &p)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, SshError::Proxy(m) if m.contains("Connection refused")));
    }

    #[tokio::test]
    async fn direct_dial_rejects_bad_args() {
        assert!(matches!(
            dial("", 22, None, Duration::from_secs(1)).await,
            Err(SshError::InvalidArgument(_))
        ));
        assert!(matches!(
            dial("h", 0, None, Duration::from_secs(1)).await,
            Err(SshError::InvalidArgument(_))
        ));
    }

    #[tokio::test]
    async fn direct_dial_connects_to_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"hi").await.unwrap();
        });
        let mut t = dial("127.0.0.1", port, None, Duration::from_secs(5))
            .await
            .unwrap();
        let mut buf = [0u8; 2];
        t.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
        accept.await.unwrap();
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn command_proxy_round_trips_through_cat() {
        let p = ProxyConfig {
            proxy_type: ProxyType::Command,
            host: String::new(),
            port: 0,
            command: Some("cat".into()),
            identity_id: None,
            username: None,
            password: None,
        };
        let mut t = dial("example.com", 22, Some(&p), Duration::from_secs(5))
            .await
            .unwrap();
        t.write_all(b"ping").await.unwrap();
        t.flush().await.unwrap();
        let mut buf = [0u8; 4];
        t.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }
}
