//! X11 forwarding local proxy (Electron `x11Forwarding.cjs`).
//!
//! The shell channel requests X11 with a random *fake* MIT-MAGIC-COOKIE-1
//! ([`crate::shell::ShellOptions::x11_cookie`]). Every `x11` channel the
//! server opens afterwards (see [`crate::handler::X11Request`]) is piped to
//! the local X server named by `DISPLAY` (a unix socket such as
//! `/tmp/.X11-unix/X0` or XQuartz's launchd socket, or TCP `6000 + n` —
//! VcXsrv / Xming / X410 on Windows). When the local server has an
//! `xauth` cookie, the fake cookie in the client's connection-setup packet
//! is replaced by the real one before anything reaches the X server.

use crate::handler::X11Request;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

pub const X11_PORT_BASE: u16 = 6000;
pub const MIT_MAGIC_COOKIE_PROTOCOL: &str = "MIT-MAGIC-COOKIE-1";
/// Setup packets larger than this are passed through unmodified.
const MAX_SETUP_PACKET: usize = 64 * 1024;

/// Platform family for display defaults and hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X11Platform {
    Windows,
    MacOs,
    Other,
}

impl X11Platform {
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Other
        }
    }
}

/// Where the local X server listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayTarget {
    /// Unix domain socket path.
    Path(String),
    Tcp {
        host: String,
        port: u16,
    },
}

impl std::fmt::Display for DisplayTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path(path) => f.write_str(path),
            Self::Tcp { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

fn default_display(platform: X11Platform) -> &'static str {
    if platform == X11Platform::Windows {
        "localhost:0"
    } else {
        ":0"
    }
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `host:display[.screen]` → `(host, display)`; the host may contain colons.
fn split_display(raw: &str) -> Option<(String, u32)> {
    let (host, tail) = raw.rsplit_once(':')?;
    let (number, screen) = match tail.split_once('.') {
        Some((n, s)) => (n, Some(s)),
        None => (tail, None),
    };
    if !all_digits(number) || screen.is_some_and(|s| !all_digits(s)) {
        return None;
    }
    Some((host.to_string(), number.parse().ok()?))
}

/// Electron `resolveX11DisplaySpec`: the host's `x11Display`, else
/// `env_display` (`$DISPLAY`), else `:0` (`localhost:0` on Windows).
pub fn resolve_display_spec(
    spec: Option<&str>,
    env_display: Option<&str>,
    platform: X11Platform,
) -> DisplayTarget {
    let mut raw = spec
        .filter(|s| !s.trim().is_empty())
        .or(env_display.filter(|s| !s.trim().is_empty()))
        .unwrap_or(default_display(platform))
        .trim()
        .to_string();
    if raw == ":" {
        raw = ":0".to_string();
    }
    if raw.starts_with('/') {
        return DisplayTarget::Path(raw);
    }
    // `^(.*):(\d+)(?:\.(\d+))?$`
    let parsed = split_display(&raw);
    let Some((host, display)) = parsed else {
        return if platform == X11Platform::Windows {
            DisplayTarget::Tcp {
                host: raw,
                port: X11_PORT_BASE,
            }
        } else {
            DisplayTarget::Path(raw)
        };
    };
    let port = if display >= 100 {
        display.min(u16::MAX as u32) as u16
    } else {
        X11_PORT_BASE + display as u16
    };
    if host.eq_ignore_ascii_case("unix") && platform != X11Platform::Windows {
        return DisplayTarget::Path(format!("/tmp/.X11-unix/X{display}"));
    }
    if host.is_empty() {
        return if platform == X11Platform::Windows {
            DisplayTarget::Tcp {
                host: "localhost".to_string(),
                port,
            }
        } else {
            DisplayTarget::Path(format!("/tmp/.X11-unix/X{display}"))
        };
    }
    if host.starts_with('/') {
        return DisplayTarget::Path(host);
    }
    DisplayTarget::Tcp { host, port }
}

/// Install hint shown after a failed local connect.
pub fn platform_hint(platform: X11Platform) -> &'static str {
    match platform {
        X11Platform::Windows => "Install and start VcXsrv or Xming, then try again.",
        X11Platform::MacOs => "Install and start XQuartz, then try again.",
        X11Platform::Other => {
            "Check DISPLAY and make sure Xorg, Xwayland, or your X server is running."
        }
    }
}

/// Terminal lines written when the local X server cannot be reached.
pub fn connect_failure_message(
    error: &str,
    target: &DisplayTarget,
    platform: X11Platform,
) -> String {
    format!(
        "\r\n[X11] Could not connect to the local X11 server: {error}\r\n[X11] Display target: {target}\r\n[X11] {}\r\n",
        platform_hint(platform)
    )
}

/// Hex cookie text → bytes; anything else is taken as raw bytes.
pub fn normalize_cookie(cookie: &str) -> Vec<u8> {
    let value = cookie.trim();
    if !value.is_empty() && value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex_decode(value) {
            return bytes;
        }
    }
    value.as_bytes().to_vec()
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

/// Result of [`rewrite_auth_setup_packet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupRewrite {
    pub buffer: Vec<u8>,
    /// The whole setup packet is in `buffer` (or it is not an X11 setup).
    pub complete: bool,
    pub rewritten: bool,
}

/// Electron `rewriteX11AuthSetupPacket`: replace the fake cookie of a
/// complete MIT-MAGIC-COOKIE-1 connection-setup packet with `real`.
pub fn rewrite_auth_setup_packet(
    buffer: &[u8],
    fake: Option<&[u8]>,
    real: Option<&[u8]>,
) -> SetupRewrite {
    let unchanged = |complete: bool| SetupRewrite {
        buffer: buffer.to_vec(),
        complete,
        rewritten: false,
    };
    let Some(real) = real.filter(|r| !r.is_empty()) else {
        return unchanged(buffer.len() >= 12);
    };
    if buffer.len() < 12 {
        return unchanged(false);
    }
    let little = match buffer[0] {
        0x6c => true,
        0x42 => false,
        _ => return unchanged(true),
    };
    let read16 = |at: usize| -> usize {
        let pair = [buffer[at], buffer[at + 1]];
        (if little {
            u16::from_le_bytes(pair)
        } else {
            u16::from_be_bytes(pair)
        }) as usize
    };
    let protocol_len = read16(6);
    let data_len = read16(8);
    let data_start = 12 + pad4(protocol_len);
    let total = data_start + pad4(data_len);
    if buffer.len() < total {
        return unchanged(false);
    }
    let protocol = &buffer[12..12 + protocol_len];
    if protocol != MIT_MAGIC_COOKIE_PROTOCOL.as_bytes() || data_len != real.len() {
        return unchanged(true);
    }
    let current = &buffer[data_start..data_start + data_len];
    if let Some(fake) = fake {
        if current.len() == fake.len() && current != fake {
            return unchanged(true);
        }
    }
    let mut next = buffer.to_vec();
    next[data_start..data_start + data_len].copy_from_slice(real);
    SetupRewrite {
        buffer: next,
        complete: true,
        rewritten: true,
    }
}

/// Display number of `display` (`:0`, `host/unix:10`, `/tmp/.X11-unix/X1`).
pub fn display_number(display: &str) -> Option<u32> {
    let value = display.trim();
    let value = if value.is_empty() || value == ":" {
        ":0"
    } else {
        value
    };
    let digits_after = |s: &str| -> Option<u32> {
        let d: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        if d.is_empty() {
            None
        } else {
            d.parse().ok()
        }
    };
    let number = if let Some((_, tail)) = value.rsplit_once(':') {
        // `:N` or `:N.S` at the end.
        let n = digits_after(tail)?;
        let rest = &tail[n.to_string().len()..];
        if !(rest.is_empty()
            || (rest.starts_with('.') && rest[1..].bytes().all(|b| b.is_ascii_digit())))
        {
            return None;
        }
        n
    } else if let Some((_, tail)) = value.rsplit_once("/X") {
        if tail.is_empty() || !tail.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        tail.parse().ok()?
    } else {
        return None;
    };
    Some(if number >= X11_PORT_BASE as u32 {
        number - X11_PORT_BASE as u32
    } else {
        number
    })
}

/// Electron `parseXauthCookie`: the MIT cookie for `display` from
/// `xauth list` output.
pub fn parse_xauth_cookie(output: &str, display: &str) -> Option<Vec<u8>> {
    let wanted = display_number(display);
    for entry in output.lines() {
        let mut fields = entry.split_whitespace();
        let Some(target) = fields.next() else {
            continue;
        };
        let rest: Vec<&str> = fields.collect();
        let Some(pos) = rest.iter().position(|f| *f == MIT_MAGIC_COOKIE_PROTOCOL) else {
            continue;
        };
        let Some(cookie) = rest.get(pos + 1) else {
            continue;
        };
        if cookie.is_empty()
            || !cookie.bytes().all(|b| b.is_ascii_hexdigit())
            || cookie.len() % 2 != 0
        {
            continue;
        }
        if wanted.is_some() && display_number(target) != wanted {
            continue;
        }
        return hex_decode(cookie).ok();
    }
    None
}

/// `xauth` executable (XQuartz's on macOS when present).
pub fn xauth_command(platform: X11Platform) -> String {
    if platform == X11Platform::MacOs && std::path::Path::new("/opt/X11/bin/xauth").exists() {
        "/opt/X11/bin/xauth".to_string()
    } else {
        "xauth".to_string()
    }
}

/// Electron `readLocalX11AuthCookie`: `xauth list` with `DISPLAY` set,
/// 2 s bound. Blocking; call from `spawn_blocking`. `None` when xauth is
/// missing or has no cookie for the display.
pub fn read_local_auth_cookie(display: &str, platform: X11Platform) -> Option<Vec<u8>> {
    let display = match display.trim() {
        "" | ":" => ":0".to_string(),
        other => other.to_string(),
    };
    let mut child = std::process::Command::new(xauth_command(platform))
        .arg("list")
        .env("DISPLAY", &display)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    std::io::Read::read_to_string(child.stdout.as_mut()?, &mut out).ok()?;
    parse_xauth_cookie(&out, &display)
}

/// Copy the client's setup packet (rewriting the cookie), then pipe both
/// directions until either side closes.
pub async fn proxy_x11_stream<A, B>(
    mut remote: A,
    mut local: B,
    fake_cookie: Option<Vec<u8>>,
    real_cookie: Option<Vec<u8>>,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    if real_cookie.is_some() && fake_cookie.is_some() {
        let mut pending: Vec<u8> = Vec::with_capacity(64);
        let mut chunk = [0u8; 4096];
        loop {
            let n = remote.read(&mut chunk).await?;
            if n == 0 {
                if !pending.is_empty() {
                    local.write_all(&pending).await?;
                }
                let _ = local.shutdown().await;
                return Ok(());
            }
            pending.extend_from_slice(&chunk[..n]);
            let result =
                rewrite_auth_setup_packet(&pending, fake_cookie.as_deref(), real_cookie.as_deref());
            if result.complete || pending.len() > MAX_SETUP_PACKET {
                local.write_all(&result.buffer).await?;
                break;
            }
        }
    }
    tokio::io::copy_bidirectional(&mut remote, &mut local).await?;
    Ok(())
}

/// Boxed local X server connection.
pub trait LocalX11Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> LocalX11Stream for T {}

/// Connect to the local X server.
pub async fn connect_display(target: &DisplayTarget) -> std::io::Result<Box<dyn LocalX11Stream>> {
    match target {
        DisplayTarget::Tcp { host, port } => {
            let stream = tokio::net::TcpStream::connect((host.as_str(), *port)).await?;
            let _ = stream.set_nodelay(true);
            Ok(Box::new(stream))
        }
        #[cfg(unix)]
        DisplayTarget::Path(path) => Ok(Box::new(tokio::net::UnixStream::connect(path).await?)),
        #[cfg(not(unix))]
        DisplayTarget::Path(path) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("unix socket display {path} is not supported on this platform"),
        )),
    }
}

/// Settings of one X11-forwarding shell.
#[derive(Debug, Clone)]
pub struct X11ForwardConfig {
    /// Host `x11Display` setting (else `$DISPLAY`).
    pub display: Option<String>,
    /// The fake cookie sent in the `x11-req` (hex).
    pub fake_cookie: String,
    pub platform: X11Platform,
}

/// Serve the `x11` channels of a connection until it closes. `notify`
/// receives the user-facing terminal message when the local X server
/// cannot be reached. The local `xauth` cookie is read once, on the first
/// channel, and reused.
pub fn spawn_x11_forwarder(
    mut rx: mpsc::UnboundedReceiver<X11Request>,
    config: X11ForwardConfig,
    notify: Arc<dyn Fn(String) + Send + Sync>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let env_display = std::env::var("DISPLAY").ok();
        let display_text = config
            .display
            .clone()
            .filter(|d| !d.trim().is_empty())
            .or(env_display.clone())
            .unwrap_or_else(|| default_display(config.platform).to_string());
        let target = resolve_display_spec(
            config.display.as_deref(),
            env_display.as_deref(),
            config.platform,
        );
        let fake = normalize_cookie(&config.fake_cookie);
        let real_cookie: Arc<tokio::sync::OnceCell<Option<Vec<u8>>>> =
            Arc::new(tokio::sync::OnceCell::new());
        while let Some(request) = rx.recv().await {
            let target = target.clone();
            let fake = fake.clone();
            let real_cookie = real_cookie.clone();
            let display_text = display_text.clone();
            let notify = notify.clone();
            let platform = config.platform;
            tokio::spawn(async move {
                let local = match connect_display(&target).await {
                    Ok(local) => local,
                    Err(err) => {
                        let _ = request.channel.close().await;
                        notify(connect_failure_message(&err.to_string(), &target, platform));
                        return;
                    }
                };
                let real = real_cookie
                    .get_or_init(|| async move {
                        tokio::task::spawn_blocking(move || {
                            read_local_auth_cookie(&display_text, platform)
                        })
                        .await
                        .ok()
                        .flatten()
                    })
                    .await
                    .clone();
                let remote = request.channel.into_stream();
                if let Err(err) = proxy_x11_stream(remote, local, Some(fake), real).await {
                    tracing::debug!(%err, "x11 channel ended with an error");
                }
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_packet(cookie_hex: &str, little: bool) -> Vec<u8> {
        let protocol = MIT_MAGIC_COOKIE_PROTOCOL.as_bytes();
        let cookie = hex_decode(cookie_hex).unwrap();
        let mut p = vec![0u8; 12 + pad4(protocol.len()) + pad4(cookie.len())];
        p[0] = if little { b'l' } else { b'B' };
        let w = |p: &mut Vec<u8>, at: usize, v: u16| {
            let b = if little {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            };
            p[at..at + 2].copy_from_slice(&b);
        };
        w(&mut p, 2, 11);
        w(&mut p, 6, protocol.len() as u16);
        w(&mut p, 8, cookie.len() as u16);
        p[12..12 + protocol.len()].copy_from_slice(protocol);
        let ds = 12 + pad4(protocol.len());
        p[ds..ds + cookie.len()].copy_from_slice(&cookie);
        p
    }

    #[test]
    fn display_specs_resolve_like_electron() {
        use DisplayTarget::*;
        let linux = X11Platform::Other;
        assert_eq!(
            resolve_display_spec(Some(":2"), None, linux),
            Path("/tmp/.X11-unix/X2".into())
        );
        assert_eq!(
            resolve_display_spec(Some(":"), None, X11Platform::MacOs),
            Path("/tmp/.X11-unix/X0".into())
        );
        assert_eq!(
            resolve_display_spec(Some("localhost:1"), None, X11Platform::Windows),
            Tcp {
                host: "localhost".into(),
                port: 6001
            }
        );
        assert_eq!(
            resolve_display_spec(
                Some("/private/tmp/com.apple.launchd.test/org.xquartz:0"),
                None,
                X11Platform::MacOs
            ),
            Path("/private/tmp/com.apple.launchd.test/org.xquartz:0".into())
        );
        assert_eq!(
            resolve_display_spec(Some("unix:1"), None, linux),
            Path("/tmp/.X11-unix/X1".into())
        );
        assert_eq!(
            resolve_display_spec(Some("10.0.0.5:0.0"), None, linux),
            Tcp {
                host: "10.0.0.5".into(),
                port: 6000
            }
        );
        assert_eq!(
            resolve_display_spec(Some(":0.1"), None, linux),
            Path("/tmp/.X11-unix/X0".into())
        );
        assert_eq!(
            resolve_display_spec(None, Some(":3"), linux),
            Path("/tmp/.X11-unix/X3".into())
        );
        assert_eq!(
            resolve_display_spec(None, None, X11Platform::Windows),
            Tcp {
                host: "localhost".into(),
                port: 6000
            }
        );
        assert_eq!(
            resolve_display_spec(Some("x410"), None, X11Platform::Windows),
            Tcp {
                host: "x410".into(),
                port: 6000
            }
        );
        assert_eq!(
            resolve_display_spec(Some("h:6010"), None, linux),
            Tcp {
                host: "h".into(),
                port: 6010
            }
        );
    }

    #[test]
    fn setup_packet_cookie_is_rewritten_in_both_byte_orders() {
        let fake = "11111111111111111111111111111111";
        let real = hex_decode("22222222222222222222222222222222").unwrap();
        for little in [true, false] {
            let out = rewrite_auth_setup_packet(
                &setup_packet(fake, little),
                Some(&normalize_cookie(fake)),
                Some(&real),
            );
            assert!(out.complete && out.rewritten);
            let hex: String = out.buffer.iter().map(|b| format!("{b:02x}")).collect();
            assert!(hex.contains("22222222222222222222222222222222"));
            assert!(!hex.contains(fake));
        }
    }

    #[test]
    fn foreign_or_partial_packets_are_not_rewritten() {
        let fake = normalize_cookie("11111111111111111111111111111111");
        let real = normalize_cookie("22222222222222222222222222222222");
        let packet = setup_packet("33333333333333333333333333333333", true);
        let out = rewrite_auth_setup_packet(&packet, Some(&fake), Some(&real));
        assert!(out.complete && !out.rewritten);
        let partial = rewrite_auth_setup_packet(&packet[..20], Some(&fake), Some(&real));
        assert!(!partial.complete);
        let none = rewrite_auth_setup_packet(&packet, Some(&fake), None);
        assert!(none.complete && !none.rewritten);
    }

    #[test]
    fn xauth_cookie_follows_the_requested_display() {
        let c0 = "00000000000000000000000000000000";
        let c1 = "11111111111111111111111111111111";
        let c10 = "10101010101010101010101010101010";
        let out = format!(
            "host/unix:10  MIT-MAGIC-COOKIE-1  {c10}\nhost/unix:0  MIT-MAGIC-COOKIE-1  {c0}\nhost/unix:1  MIT-MAGIC-COOKIE-1  {c1}\n"
        );
        assert_eq!(parse_xauth_cookie(&out, ":0"), hex_decode(c0).ok());
        assert_eq!(
            parse_xauth_cookie(&out, "/tmp/.X11-unix/X1"),
            hex_decode(c1).ok()
        );
        assert_eq!(
            parse_xauth_cookie(&out, "localhost:10.0"),
            hex_decode(c10).ok()
        );
        assert_eq!(parse_xauth_cookie("", ":0"), None);
    }

    #[test]
    fn failure_message_names_target_and_hint() {
        let target = DisplayTarget::Tcp {
            host: "localhost".into(),
            port: 6000,
        };
        let msg = connect_failure_message("ECONNREFUSED", &target, X11Platform::Windows);
        assert!(msg.contains("Could not connect to the local X11 server: ECONNREFUSED"));
        assert!(msg.contains("localhost:6000"));
        assert!(msg.contains("VcXsrv"));
        assert!(connect_failure_message("x", &target, X11Platform::MacOs).contains("XQuartz"));
    }

    #[tokio::test]
    async fn proxy_rewrites_the_setup_and_pipes_both_ways() {
        let fake = "11111111111111111111111111111111";
        let real = normalize_cookie("22222222222222222222222222222222");
        let (remote_app, remote_proxy) = tokio::io::duplex(4096);
        let (local_proxy, mut local_server) = tokio::io::duplex(4096);
        let task = tokio::spawn(proxy_x11_stream(
            remote_proxy,
            local_proxy,
            Some(normalize_cookie(fake)),
            Some(real.clone()),
        ));
        let (mut remote_read, mut remote_write) = tokio::io::split(remote_app);
        let packet = setup_packet(fake, true);
        // Split the setup across two writes.
        remote_write.write_all(&packet[..10]).await.unwrap();
        remote_write.write_all(&packet[10..]).await.unwrap();
        remote_write.write_all(b"after").await.unwrap();
        let mut got = vec![0u8; packet.len() + 5];
        local_server.read_exact(&mut got).await.unwrap();
        assert!(got.windows(real.len()).any(|w| w == real.as_slice()));
        assert!(got.ends_with(b"after"));
        local_server.write_all(b"reply").await.unwrap();
        let mut reply = [0u8; 5];
        remote_read.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        drop(remote_write);
        drop(remote_read);
        drop(local_server);
        let _ = task.await;
    }

    #[tokio::test]
    async fn without_a_local_cookie_bytes_pass_through() {
        let (remote_app, remote_proxy) = tokio::io::duplex(1024);
        let (local_proxy, mut local_server) = tokio::io::duplex(1024);
        let task = tokio::spawn(proxy_x11_stream(
            remote_proxy,
            local_proxy,
            Some(vec![1; 16]),
            None,
        ));
        let (_r, mut w) = tokio::io::split(remote_app);
        w.write_all(b"remote").await.unwrap();
        let mut got = [0u8; 6];
        local_server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"remote");
        drop(w);
        drop(_r);
        drop(local_server);
        let _ = task.await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_display_sockets_are_reachable() {
        let dir = std::env::temp_dir().join(format!("nc-x11-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("X9");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let target = DisplayTarget::Path(path.to_string_lossy().into_owned());
        let (accepted, connected) = tokio::join!(listener.accept(), connect_display(&target));
        assert!(accepted.is_ok() && connected.is_ok());
        let missing = DisplayTarget::Path(dir.join("nope").to_string_lossy().into_owned());
        assert!(connect_display(&missing).await.is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
