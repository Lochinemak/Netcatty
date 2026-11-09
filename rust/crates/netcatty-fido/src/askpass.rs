//! `SSH_ASKPASS` bridge for FIDO2 (Electron `fidoAskpass.cjs`).
//!
//! OpenSSH (`ssh-add`, `ssh-keygen`, and the `ssh-sk-helper` that our owned
//! `ssh-agent` spawns) runs `$SSH_ASKPASS <prompt>` without a TTY. That
//! program is the Netcatty executable itself in helper mode
//! ([`run_helper_if_requested`]): it connects to the app's askpass socket
//! (Unix socket / Windows named pipe), sends one JSON line
//! `{ prompt, type: "askpass", leaseId, mode }` and prints the answer from
//! `{ ok, response }`. The server side turns each request into a FIDO
//! prompt for the renderer. OpenSSH kills a `SSH_ASKPASS_PROMPT=none`
//! notification helper when the key is touched; the closed connection
//! dismisses that hint.

use crate::prompt::{classify_askpass_prompt, PromptBroker, PromptKind, PromptOptions, PromptOutcome, Signal};
use parking_lot::Mutex;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Set to `1` when the executable runs as the FIDO askpass helper.
pub const HELPER_ENV: &str = "NETCATTY_FIDO_ASKPASS";
pub const SOCK_ENV: &str = "NETCATTY_FIDO_ASKPASS_SOCK";
pub const LEASE_ENV: &str = "NETCATTY_FIDO_ASKPASS_LEASE";
const MAX_LINE: usize = 64 * 1024;
#[cfg(unix)]
const HELPER_TIMEOUT_SECS: u64 = 170;

/// The hardware signature currently in progress (signatures are
/// serialised, so there is at most one). Prompts that arrive from the
/// shared agent's `ssh-sk-helper` are attributed to it.
#[derive(Debug, Default)]
pub struct SigningAttempt {
    pub lease_id: String,
    pub key_name: String,
    /// Aborted when the signature callback settles (dismisses touch hints).
    pub done: Signal,
    pub pin_submitted: AtomicBool,
    pub cancelled: AtomicBool,
}

impl SigningAttempt {
    pub fn new(lease_id: impl Into<String>, key_name: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            lease_id: lease_id.into(),
            key_name: key_name.into(),
            ..Default::default()
        })
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct AskpassMessage {
    #[serde(default)]
    prompt: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    lease_id: String,
    #[serde(default)]
    mode: String,
}

/// Shared state the connection handler needs.
pub struct AskpassContext {
    pub broker: Arc<PromptBroker>,
    pub current_signing: Mutex<Option<Arc<SigningAttempt>>>,
    pub windows: bool,
}

fn reply_json(ok: bool, response: Option<&str>, error: Option<&str>) -> String {
    let mut value = serde_json::json!({ "ok": ok });
    if let Some(r) = response {
        value["response"] = r.into();
    }
    if let Some(e) = error {
        value["error"] = e.into();
    }
    format!("{value}\n")
}

/// Serve one askpass helper connection.
pub async fn handle_client<S>(ctx: Arc<AskpassContext>, stream: S)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let mut line = Vec::new();
    let read_line = async {
        let mut limited = (&mut reader).take(MAX_LINE as u64);
        limited.read_until(b'\n', &mut line).await
    };
    match read_line.await {
        Ok(n) if n > 0 && line.ends_with(b"\n") => {}
        _ => return,
    }
    let Ok(msg) = serde_json::from_slice::<AskpassMessage>(&line) else {
        let _ = write.write_all(reply_json(false, None, Some("bad_json")).as_bytes()).await;
        return;
    };
    if msg.kind == "sk-helper" {
        // No helper error observer in this build: acknowledge immediately.
        let _ = write.write_all(b"{\"ack\":true}\n").await;
        return;
    }

    // The helper closing its end (OpenSSH killed it after a touch) aborts
    // the prompt.
    let helper_exited = Signal::new();
    {
        let helper_exited = helper_exited.clone();
        tokio::spawn(async move {
            let mut sink = [0u8; 256];
            loop {
                match reader.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            helper_exited.abort();
        });
    }

    let notification_only = msg.mode == "none";
    let kind = if notification_only {
        PromptKind::Touch
    } else if msg.mode == "confirm" {
        PromptKind::Confirm
    } else {
        classify_askpass_prompt(&msg.prompt)
    };
    let signing = ctx.current_signing.lock().clone();
    let owner_lease = if !msg.lease_id.is_empty() {
        msg.lease_id.clone()
    } else {
        signing.as_ref().map(|s| s.lease_id.clone()).unwrap_or_default()
    };
    let signing = signing.filter(|s| s.lease_id == owner_lease);
    let key_name = signing.as_ref().map(|s| s.key_name.clone()).unwrap_or_default();

    if kind == PromptKind::Pin && ctx.windows {
        ctx.broker.cancel_lease(&owner_lease, "pin-requested", true);
    }
    let detached = notification_only && ctx.windows;
    let signal = if detached {
        signing.as_ref().map(|s| s.done.clone())
    } else {
        Some(helper_exited.clone())
    };
    let options = PromptOptions {
        kind: Some(kind),
        message: msg.prompt.clone(),
        key_name: key_name.clone(),
        notification_only,
        lease_id: owner_lease.clone(),
        ..Default::default()
    };
    if detached {
        // MSYS cannot reliably kill a native notification helper: answer
        // now and keep the hint until the signing attempt ends.
        let broker = ctx.broker.clone();
        tokio::spawn(async move {
            broker.request(options, signal).await;
        });
        let _ = write.write_all(reply_json(true, Some(""), None).as_bytes()).await;
        return;
    }
    let outcome = ctx.broker.request(options, signal).await;
    if helper_exited.is_aborted() {
        return;
    }
    let response = match outcome {
        PromptOutcome::Cancelled => {
            if kind == PromptKind::Pin {
                if let Some(s) = &signing {
                    s.cancelled.store(true, Ordering::SeqCst);
                }
            }
            let _ = write.write_all(reply_json(false, None, Some("cancelled")).as_bytes()).await;
            return;
        }
        PromptOutcome::Answered(text) => text,
    };
    let response = if kind == PromptKind::Pin { response } else { String::new() };
    if kind == PromptKind::Pin {
        if let Some(s) = &signing {
            s.pin_submitted.store(true, Ordering::SeqCst);
        }
        let presence = {
            let p = msg.prompt.to_lowercase();
            p.contains("user presence") || p.contains("touch") || p.contains("tap")
        };
        if let Some(s) = signing.as_ref().filter(|s| !response.is_empty() && (ctx.windows || presence) && !s.done.is_aborted()) {
            // ssh-agent ends its first notification before asking for the
            // PIN: keep a device-only hint until the signature settles.
            let broker = ctx.broker.clone();
            let options = PromptOptions {
                kind: Some(PromptKind::Touch),
                notification_only: true,
                message: msg.prompt.clone(),
                key_name,
                lease_id: owner_lease,
                ..Default::default()
            };
            let done = s.done.clone();
            tokio::spawn(async move {
                broker.request(options, Some(done)).await;
            });
        }
    }
    let _ = write.write_all(reply_json(true, Some(&response), None).as_bytes()).await;
}

/// A running askpass server (socket path + listener task).
pub struct AskpassServer {
    pub socket_path: String,
    dir: Option<PathBuf>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for AskpassServer {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

impl AskpassServer {
    /// Listen under `temp_base` (Unix) or on a fresh named pipe (Windows).
    pub fn start(ctx: Arc<AskpassContext>, temp_base: &Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            let dir = temp_base.join(format!("netcatty-fido-askpass-{}", short_id()));
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&dir)?;
            let path = dir.join("askpass.sock");
            let listener = tokio::net::UnixListener::bind(&path)?;
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            let task = tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            tokio::spawn(handle_client(ctx.clone(), stream));
                        }
                        Err(e) => {
                            tracing::warn!("fido askpass accept failed: {e}");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            });
            Ok(Self {
                socket_path: path.to_string_lossy().into_owned(),
                dir: Some(dir),
                task,
            })
        }
        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ServerOptions;
            let _ = temp_base;
            let name = format!(r"\\.\pipe\netcatty-fido-askpass-{}", short_id());
            let mut server = ServerOptions::new().first_pipe_instance(true).create(&name)?;
            let pipe_name = name.clone();
            let task = tokio::spawn(async move {
                loop {
                    if server.connect().await.is_err() {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    let next = match ServerOptions::new().create(&pipe_name) {
                        Ok(next) => next,
                        Err(e) => {
                            tracing::warn!("fido askpass pipe failed: {e}");
                            return;
                        }
                    };
                    let connected = std::mem::replace(&mut server, next);
                    tokio::spawn(handle_client(ctx.clone(), connected));
                }
            });
            Ok(Self {
                socket_path: name,
                dir: None,
                task,
            })
        }
    }
}

/// Environment for `ssh-add` / `ssh-keygen` / the owned agent so OpenSSH
/// asks through Netcatty. `lease` is omitted for the long-lived agent (its
/// helper must not inherit one caller's lease).
pub fn askpass_env(helper_exe: &Path, socket_path: &str, lease: Option<&str>) -> Vec<(String, String)> {
    let mut env = vec![
        ("SSH_ASKPASS".to_string(), helper_exe.to_string_lossy().into_owned()),
        ("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()),
        (HELPER_ENV.to_string(), "1".to_string()),
        (SOCK_ENV.to_string(), socket_path.to_string()),
    ];
    if let Some(lease) = lease.filter(|l| !l.is_empty()) {
        env.push((LEASE_ENV.to_string(), lease.to_string()));
    }
    if cfg!(target_os = "linux") && std::env::var_os("DISPLAY").is_none() {
        env.push(("DISPLAY".to_string(), ":0".to_string()));
    }
    env
}

/// Helper-mode entry point: `Some(exit_code)` when this process was
/// started by OpenSSH as `SSH_ASKPASS` for a FIDO prompt.
pub fn run_helper_if_requested() -> Option<i32> {
    if std::env::var(HELPER_ENV).ok().as_deref() != Some("1") {
        return None;
    }
    let Ok(socket) = std::env::var(SOCK_ENV) else {
        return Some(1);
    };
    let prompt = {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            std::env::var("SSH_ASKPASS_PROMPT").unwrap_or_default()
        } else {
            args.join(" ")
        }
    };
    let payload = serde_json::json!({
        "prompt": prompt,
        "type": "askpass",
        "leaseId": std::env::var(LEASE_ENV).unwrap_or_default(),
        "mode": std::env::var("SSH_ASKPASS_PROMPT").unwrap_or_default(),
    });
    match helper_round_trip(&socket, &format!("{payload}\n")) {
        Some(answer) => {
            use std::io::Write;
            let mut out = std::io::stdout();
            let _ = out.write_all(answer.as_bytes());
            let _ = out.write_all(b"\n");
            let _ = out.flush();
            Some(0)
        }
        None => Some(1),
    }
}

fn parse_reply(line: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if value.get("ok") != Some(&serde_json::Value::Bool(true)) {
        return None;
    }
    Some(value.get("response").and_then(|v| v.as_str()).unwrap_or("").to_string())
}

fn helper_round_trip(socket: &str, payload: &str) -> Option<String> {
    use std::io::{BufRead, Write};
    #[cfg(unix)]
    let stream = {
        let s = std::os::unix::net::UnixStream::connect(socket).ok()?;
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(HELPER_TIMEOUT_SECS)));
        s
    };
    #[cfg(windows)]
    let stream = std::fs::OpenOptions::new().read(true).write(true).open(socket).ok()?;
    let mut writer = stream.try_clone().ok()?;
    writer.write_all(payload.as_bytes()).ok()?;
    writer.flush().ok()?;
    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    parse_reply(&line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::PromptSink;

    #[derive(Default)]
    struct Captured(Mutex<Vec<(String, serde_json::Value)>>);
    impl PromptSink for Captured {
        fn emit(&self, event: &str, payload: serde_json::Value) {
            self.0.lock().push((event.to_string(), payload));
        }
    }

    fn ctx(sink: Arc<Captured>) -> Arc<AskpassContext> {
        Arc::new(AskpassContext {
            broker: PromptBroker::new(sink),
            current_signing: Mutex::new(None),
            windows: false,
        })
    }

    async fn wait_request(sink: &Captured) -> serde_json::Value {
        for _ in 0..500 {
            if let Some((_, p)) = sink.0.lock().iter().find(|(e, _)| e == crate::prompt::EVENT_REQUEST) {
                return p.clone();
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        panic!("no prompt request");
    }

    #[test]
    fn reply_parsing() {
        assert_eq!(parse_reply("{\"ok\":true,\"response\":\"1234\"}\n"), Some("1234".into()));
        assert_eq!(parse_reply("{\"ok\":true}"), Some(String::new()));
        assert_eq!(parse_reply("{\"ok\":false,\"error\":\"cancelled\"}"), None);
        assert_eq!(parse_reply("garbage"), None);
    }

    #[test]
    fn env_carries_socket_and_lease() {
        let env = askpass_env(Path::new("/app/netcatty"), "/tmp/s.sock", Some("lease1"));
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("SSH_ASKPASS").as_deref(), Some("/app/netcatty"));
        assert_eq!(get("SSH_ASKPASS_REQUIRE").as_deref(), Some("force"));
        assert_eq!(get(HELPER_ENV).as_deref(), Some("1"));
        assert_eq!(get(LEASE_ENV).as_deref(), Some("lease1"));
        let env = askpass_env(Path::new("/app/netcatty"), "/tmp/s.sock", None);
        assert!(!env.iter().any(|(n, _)| n == LEASE_ENV));
    }

    #[tokio::test]
    async fn pin_prompt_round_trip() {
        let sink = Arc::new(Captured::default());
        let ctx = ctx(sink.clone());
        let attempt = SigningAttempt::new("lease-a", "My YubiKey");
        *ctx.current_signing.lock() = Some(attempt.clone());
        let (client, server) = tokio::io::duplex(4096);
        let handler = tokio::spawn(handle_client(ctx.clone(), server));
        let (mut cr, mut cw) = tokio::io::split(client);
        cw.write_all(b"{\"prompt\":\"Enter PIN for ECDSA-SK key\",\"type\":\"askpass\",\"leaseId\":\"\",\"mode\":\"\"}\n")
            .await
            .unwrap();
        let request = wait_request(&sink).await;
        assert_eq!(request["kind"], "pin");
        assert_eq!(request["keyName"], "My YubiKey");
        ctx.broker
            .respond(request["requestId"].as_str().unwrap(), Some("123456".into()), false)
            .unwrap();
        let mut out = String::new();
        let mut buf = BufReader::new(&mut cr);
        buf.read_line(&mut out).await.unwrap();
        assert_eq!(parse_reply(&out), Some("123456".into()));
        assert!(attempt.pin_submitted.load(Ordering::SeqCst));
        drop(cw);
        handler.await.unwrap();
    }

    #[tokio::test]
    async fn notification_closes_when_helper_exits() {
        let sink = Arc::new(Captured::default());
        let ctx = ctx(sink.clone());
        let (client, server) = tokio::io::duplex(4096);
        let handler = tokio::spawn(handle_client(ctx.clone(), server));
        let (_cr, mut cw) = tokio::io::split(client);
        cw.write_all(b"{\"prompt\":\"Confirm user presence for key\",\"type\":\"askpass\",\"mode\":\"none\"}\n")
            .await
            .unwrap();
        let request = wait_request(&sink).await;
        assert_eq!(request["kind"], "touch");
        assert_eq!(request["notificationOnly"], true);
        drop(cw);
        drop(_cr);
        handler.await.unwrap();
        let last = sink.0.lock().last().cloned().unwrap();
        assert_eq!(last.0, crate::prompt::EVENT_CANCELLED);
        assert_eq!(last.1["reason"], "helper-exited");
    }

    #[tokio::test]
    async fn cancelled_pin_marks_attempt() {
        let sink = Arc::new(Captured::default());
        let ctx = ctx(sink.clone());
        let attempt = SigningAttempt::new("l", "k");
        *ctx.current_signing.lock() = Some(attempt.clone());
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(handle_client(ctx.clone(), server));
        let (mut cr, mut cw) = tokio::io::split(client);
        cw.write_all(b"{\"prompt\":\"Enter PIN\",\"type\":\"askpass\"}\n").await.unwrap();
        let request = wait_request(&sink).await;
        ctx.broker.respond(request["requestId"].as_str().unwrap(), None, true).unwrap();
        let mut out = String::new();
        BufReader::new(&mut cr).read_line(&mut out).await.unwrap();
        assert_eq!(parse_reply(&out), None);
        assert!(out.contains("cancelled"));
        assert!(attempt.cancelled.load(Ordering::SeqCst));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_server_accepts_helper_connections() {
        let sink = Arc::new(Captured::default());
        let ctx = ctx(sink.clone());
        let base = tempfile::tempdir().unwrap();
        let server = AskpassServer::start(ctx.clone(), base.path()).unwrap();
        let socket = server.socket_path.clone();
        let client = tokio::task::spawn_blocking(move || {
            helper_round_trip(&socket, "{\"prompt\":\"Enter PIN\",\"type\":\"askpass\"}\n")
        });
        let request = wait_request(&sink).await;
        ctx.broker
            .respond(request["requestId"].as_str().unwrap(), Some("9999".into()), false)
            .unwrap();
        assert_eq!(client.await.unwrap(), Some("9999".into()));
        let dir = PathBuf::from(&server.socket_path).parent().unwrap().to_path_buf();
        drop(server);
        assert!(!dir.exists());
    }
}
