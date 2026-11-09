//! SSH diagnostic log (Electron `sshBridge.cjs`: `appendSshDiagnosticLog`,
//! `attachSshDebugLogger`, `getSshDebugLogInfo`, `openSshDebugLogDir`).
//!
//! Settings → System → "SSH debug logs" makes the renderer start SSH
//! sessions with `sshDebugLogEnabled: true` (and `NETCATTY_SSH_DEBUG=1`
//! enables it for every session). While such a connection is being
//! established, a `tracing` layer appends the SSH stack's handshake /
//! authentication events to `<temp>/netcatty-ssh.log`:
//!
//! * `netcatty_ssh` / connection lifecycle events at DEBUG and above;
//! * `russh` DEBUG events whose message matches Electron's filter
//!   (`auth|publickey|keyboard|handshake|kex|newkeys|dh gex`).
//!
//! TRACE events (packet dumps) are never written, and the lines written by
//! [`begin`] only carry non-secret connection facts (host, port, user, auth
//! method, which credential kinds are present). The file rotates to
//! `netcatty-ssh.log.1` at 5 MiB.

use netcatty_core::ipc::SshSessionOptions;
use parking_lot::Mutex;
use regex::Regex;
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use tauri::{AppHandle, Runtime};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Filter, Layer};

pub const LOG_FILE_NAME: &str = "netcatty-ssh.log";
const ROTATE_BYTES: u64 = 5 * 1024 * 1024;

pub struct SshDebugLog {
    /// Connections currently being established with debug logging on.
    active: AtomicUsize,
    path: Mutex<Option<PathBuf>>,
    write: Mutex<()>,
}

fn global() -> &'static SshDebugLog {
    static LOG: OnceLock<SshDebugLog> = OnceLock::new();
    LOG.get_or_init(|| SshDebugLog {
        active: AtomicUsize::new(0),
        path: Mutex::new(None),
        write: Mutex::new(()),
    })
}

fn env_enabled() -> bool {
    std::env::var("NETCATTY_SSH_DEBUG").ok().as_deref() == Some("1")
}

fn log_path<R: Runtime>(app: &AppHandle<R>) -> PathBuf {
    let path = crate::commands::tempdir::current(app).join(LOG_FILE_NAME);
    *global().path.lock() = Some(path.clone());
    path
}

/// Resolve the log path once the temp directory state exists.
pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    log_path(app.handle());
}

impl SshDebugLog {
    fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed) > 0
    }

    fn append(&self, line: &str) {
        let Some(path) = self.path.lock().clone() else { return };
        let _guard = self.write.lock();
        if std::fs::metadata(&path).map(|m| m.len() > ROTATE_BYTES).unwrap_or(false) {
            let _ = std::fs::rename(&path, path.with_extension("log.1"));
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if let Ok(mut file) = options.open(&path) {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

fn timestamp() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn write_line(message: &str, data: Option<serde_json::Value>) {
    let data = data.map(|d| format!(" {d}")).unwrap_or_default();
    global().append(&format!("[{}] {message}{data}\n", timestamp()));
}

/// Does this session want debug logging?
pub fn wanted(payload: &SshSessionOptions) -> bool {
    env_enabled() || payload.extra.get("sshDebugLogEnabled") == Some(&serde_json::Value::Bool(true))
}

/// Active while a debug-enabled connection is being established.
pub struct DebugGuard {
    finished: bool,
}

impl DebugGuard {
    /// Record the outcome (`error` is the SSH error text, never a secret).
    pub fn finish(mut self, error: Option<&str>) {
        match error {
            None => write_line("SSH connection established", None),
            Some(e) => write_line("SSH connection failed", Some(serde_json::json!({ "error": e }))),
        }
        self.finished = true;
    }
}

impl Drop for DebugGuard {
    fn drop(&mut self) {
        if !self.finished {
            write_line("SSH connection attempt ended", None);
        }
        global().active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Start capturing for a connection (no-op unless [`wanted`]).
pub fn begin(payload: &SshSessionOptions, session_id: &str) -> Option<DebugGuard> {
    if !wanted(payload) {
        return None;
    }
    global().active.fetch_add(1, Ordering::SeqCst);
    let non_empty = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.is_empty());
    write_line(
        "Starting SSH connection",
        Some(serde_json::json!({
            "sessionId": session_id,
            "hostname": payload.hostname.trim(),
            "port": payload.port(),
            "username": payload.username,
            "authMethod": payload.auth_method,
            "hasPassword": non_empty(&payload.password),
            "hasPrivateKey": non_empty(&payload.private_key),
            "hasCertificate": non_empty(&payload.certificate),
            "jumpHosts": payload.jump_hosts.as_ref().map(|j| j.len()).unwrap_or(0),
        })),
    );
    Some(DebugGuard { finished: false })
}

// ---------------------------------------------------------------------------
// tracing layer
// ---------------------------------------------------------------------------

fn russh_message_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)auth|publickey|keyboard|handshake|kex|newkeys|dh gex").unwrap())
}

#[derive(Default)]
struct Fields {
    message: String,
    rest: Vec<String>,
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.rest.push(format!("{}={value}", field.name()));
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.rest.push(format!("{}={value:?}", field.name()));
        }
    }
}

fn is_ssh_target(target: &str) -> (bool, bool) {
    let russh = target == "russh" || target.starts_with("russh::");
    let ours = target.starts_with("netcatty_ssh") || target.starts_with("netcatty_desktop_lib::connect");
    (russh, ours)
}

/// Line for an event, or `None` when it must not be written.
fn format_event(target: &str, level: &Level, fields: &Fields) -> Option<String> {
    let (russh, ours) = is_ssh_target(target);
    if (!russh && !ours) || *level > Level::DEBUG {
        return None;
    }
    if russh && !russh_message_re().is_match(&fields.message) {
        return None;
    }
    let rest = if fields.rest.is_empty() {
        String::new()
    } else {
        format!(" {}", fields.rest.join(" "))
    };
    let label = if russh { "ssh2 debug" } else { target };
    Some(format!("[{}] {level} {label}: {}{rest}\n", timestamp(), fields.message))
}

struct DebugLayer;

impl<S: Subscriber> Layer<S> for DebugLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut fields = Fields::default();
        event.record(&mut fields);
        if let Some(line) = format_event(meta.target(), meta.level(), &fields) {
            global().append(&line);
        }
    }
}

/// Only SSH-stack events at DEBUG or above, and only while a debug-enabled
/// connection is in progress (checked per event, so idle cost is one load).
struct DebugFilter;

impl<S: Subscriber> Filter<S> for DebugFilter {
    fn enabled(&self, meta: &tracing::Metadata<'_>, _cx: &Context<'_, S>) -> bool {
        if *meta.level() > Level::DEBUG || !global().is_active() {
            return false;
        }
        let (russh, ours) = is_ssh_target(meta.target());
        russh || ours
    }

    fn callsite_enabled(&self, meta: &'static tracing::Metadata<'static>) -> tracing::subscriber::Interest {
        let (russh, ours) = is_ssh_target(meta.target());
        if (russh || ours) && *meta.level() <= Level::DEBUG {
            tracing::subscriber::Interest::sometimes()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::DEBUG)
    }
}

/// The layer `lib.rs::init_tracing` installs next to the console output.
pub fn layer<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    DebugLayer.with_filter(DebugFilter)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SshDebugLogInfo {
    enabled: bool,
    path: String,
    exists: bool,
    size: u64,
}

/// `getSshDebugLogInfo()`. `enabled` reflects `NETCATTY_SSH_DEBUG=1` (the
/// per-session toggle lives in the renderer settings), like Electron.
#[tauri::command]
pub fn ssh_debug_log_info<R: Runtime>(app: AppHandle<R>) -> SshDebugLogInfo {
    let path = log_path(&app);
    let meta = std::fs::metadata(&path).ok().filter(|m| m.is_file());
    SshDebugLogInfo {
        enabled: env_enabled(),
        path: path.to_string_lossy().into_owned(),
        exists: meta.is_some(),
        size: meta.map(|m| m.len()).unwrap_or(0),
    }
}

#[derive(Debug, Serialize)]
pub struct OpenResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// `openSshDebugLogDir()`: reveal the log's folder in the file manager.
#[tauri::command]
pub fn ssh_debug_log_open_dir<R: Runtime>(app: AppHandle<R>) -> OpenResult {
    use tauri_plugin_opener::OpenerExt;
    let path = log_path(&app);
    let Some(dir) = path.parent().map(|p| p.to_path_buf()) else {
        return OpenResult {
            success: false,
            error: Some("no log directory".into()),
        };
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return OpenResult {
            success: false,
            error: Some(e.to_string()),
        };
    }
    match app.opener().open_path(dir.to_string_lossy(), None::<&str>) {
        Ok(()) => OpenResult {
            success: true,
            error: None,
        },
        Err(e) => OpenResult {
            success: false,
            error: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(message: &str) -> Fields {
        Fields {
            message: message.into(),
            rest: Vec::new(),
        }
    }

    #[test]
    fn russh_events_are_filtered_like_electron() {
        assert!(format_event("russh::client::encrypted", &Level::DEBUG, &fields("userauth_failure")).is_some());
        assert!(format_event("russh::client::kex", &Level::DEBUG, &fields("negotiated algorithms: [..]")).is_none());
        assert!(format_event("russh::negotiation", &Level::DEBUG, &fields("strict kex enabled")).is_some());
        assert!(format_event("russh::keys::agent::client", &Level::DEBUG, &fields("sign_request: [1, 2]")).is_none());
        // TRACE never reaches the file.
        assert!(format_event("russh::client::encrypted", &Level::TRACE, &fields("waiting auth request")).is_none());
        // Other crates are ignored.
        assert!(format_event("netcatty_sftp", &Level::INFO, &fields("auth")).is_none());
    }

    #[test]
    fn own_events_are_written_with_fields() {
        let mut f = fields("trying agent identity");
        f.rest.push("count=2".into());
        let line = format_event("netcatty_ssh::auth", &Level::DEBUG, &f).unwrap();
        assert!(line.contains("DEBUG netcatty_ssh::auth: trying agent identity count=2"));
        assert!(line.starts_with('['));
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn wanted_reads_the_session_flag() {
        let mut payload = SshSessionOptions {
            hostname: "h".into(),
            username: "u".into(),
            ..Default::default()
        };
        if !env_enabled() {
            assert!(!wanted(&payload));
        }
        payload
            .extra
            .insert("sshDebugLogEnabled".into(), serde_json::Value::Bool(true));
        assert!(wanted(&payload));
    }

    #[test]
    fn append_rotates_large_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOG_FILE_NAME);
        std::fs::write(&path, vec![b'x'; (ROTATE_BYTES + 1) as usize]).unwrap();
        let log = SshDebugLog {
            active: AtomicUsize::new(0),
            path: Mutex::new(Some(path.clone())),
            write: Mutex::new(()),
        };
        log.append("hello\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello\n");
        assert!(dir.path().join("netcatty-ssh.log.1").exists());
    }
}
