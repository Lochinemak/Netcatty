//! Mosh (`startMoshSession`, `onMoshSessionReady`) and EternalTerminal
//! (`startEtSession`) sessions: external clients running in a local PTY.
//!
//! Port of `electron/bridges/terminalBridge/moshSession.cjs` and
//! `etSession.cjs`:
//!
//! * Mosh: the system `ssh` runs `mosh-server new` in a PTY sized like the
//!   terminal (password / 2FA / host-key prompts render natively; saved
//!   secrets are typed by [`netcatty_mosh::prompts::MoshPasswordResponder`]).
//!   Its output is tagged `meta.moshHandshake` and the `MOSH CONNECT` line is
//!   hidden. When ssh exits, `mosh-client` is started in a fresh PTY that is
//!   swapped into the same session and `netcatty:mosh:ready` fires.
//! * ET: the `et` client performs its own SSH bootstrap; Netcatty prepares a
//!   private ssh config / askpass map ([`netcatty_mosh::et`]) and runs it.
//!
//! Client binaries: the bundled `mosh-client` / `et` (Tauri resources
//! `mosh/` and `et/`, or `resources/<tool>/<platform-arch>/` in development),
//! else the one on `PATH`.

use super::telnet::{ensure_free, session_id_or_new, SessionBootEvent, STREAM_CHANNEL_CAPACITY};
use super::CmdResult;
use crate::decoder::{Charset, StreamDecoder};
use crate::sessions::{SessionBackend, SessionEntry};
use crate::state::Ctx;
use crate::stream::{InputMeta, SessionInput, StreamEvent, StreamExit, StreamTransport};
use bytes::Bytes;
use netcatty_core::ipc::{events as ev, JumpHost, SessionDataMeta, StartSessionResult};
use netcatty_core::models::{HostAuthMethod, KnownHost};
use netcatty_core::{CoreError, CoreResult};
use netcatty_mosh::auth::{ExternalSshAuth, KnownHostPin, SecretFiles};
use netcatty_mosh::binaries::{self, Client};
use netcatty_mosh::handshake::{self, MoshConnectSniffer};
use netcatty_mosh::prompts::MoshPasswordResponder;
use netcatty_pty::{LocalPtyOptions, PtyEvent, PtySession};
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub const MOSH_CLIENT_NOT_FOUND: &str = "Bundled mosh-client not found. Run `npm run fetch:mosh:dev` for local dev, or ensure release packaging downloads the mosh binary release before building.";
pub const SSH_NOT_FOUND: &str =
    "OpenSSH client not found. Netcatty needs ssh to start the remote mosh-server handshake.";
pub const ET_CLIENT_NOT_FOUND: &str = "Bundled et client not found. Run `npm run fetch:et:dev` for local dev, or ensure release packaging downloads the et binary release before building.";
const AGENT_UNAVAILABLE: &str =
    "System SSH agent is unavailable. Start or unlock it, or configure a valid agent socket.";

/// Options shared by `startMoshSession` and `startEtSession`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSessionOptions {
    #[serde(default)]
    pub session_id: Option<String>,
    pub hostname: String,
    #[serde(default)]
    pub host_id: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub auth_method: Option<HostAuthMethod>,
    #[serde(default)]
    pub requires_mfa: Option<bool>,
    #[serde(default)]
    pub identity_file_paths: Option<Vec<String>>,
    #[serde(default)]
    pub use_ssh_agent: Option<bool>,
    #[serde(default)]
    pub agent_public_keys: Option<Vec<String>>,
    #[serde(default)]
    pub identity_agent: Option<String>,
    #[serde(default)]
    pub identities_only: Option<bool>,
    #[serde(default)]
    pub port: Option<u16>,
    /// ET server port (default 2022).
    #[serde(default)]
    pub et_port: Option<u16>,
    #[serde(default)]
    pub mosh_server_path: Option<String>,
    #[serde(default)]
    pub agent_forwarding: Option<bool>,
    #[serde(default)]
    pub legacy_algorithms: Option<bool>,
    #[serde(default)]
    pub known_hosts: Option<Vec<KnownHost>>,
    #[serde(default)]
    pub verify_host_keys: Option<bool>,
    #[serde(default)]
    pub jump_hosts: Option<Vec<JumpHost>>,
    #[serde(default)]
    pub cols: Option<u16>,
    #[serde(default)]
    pub rows: Option<u16>,
    #[serde(default)]
    pub charset: Option<String>,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    #[serde(default)]
    pub boot_epoch: Option<u64>,
    /// Automatic session log (`sessionLog` of the start options).
    #[serde(default)]
    pub session_log: Option<netcatty_core::ipc::SessionLogConfig>,
}

fn auth_method_str(method: Option<HostAuthMethod>) -> Option<String> {
    method.map(|m| {
        match m {
            HostAuthMethod::Auto => "auto",
            HostAuthMethod::Password => "password",
            HostAuthMethod::Key => "key",
            HostAuthMethod::Certificate => "certificate",
        }
        .to_string()
    })
}

fn known_host_pins(hosts: Option<&Vec<KnownHost>>) -> Vec<KnownHostPin> {
    hosts
        .map(|hosts| {
            hosts
                .iter()
                .map(|h| KnownHostPin {
                    hostname: h.hostname.clone(),
                    port: h.port,
                    key_type: h.key_type.clone(),
                    public_key: h.public_key.clone(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Agent socket for the external ssh: `identityAgent`, else
/// `SSH_AUTH_SOCK`, else (Windows) the OpenSSH agent pipe.
fn agent_socket(identity_agent: Option<&str>) -> Option<String> {
    let home = dirs::home_dir();
    if let Some(agent) = identity_agent.map(str::trim).filter(|a| !a.is_empty()) {
        if agent.eq_ignore_ascii_case("none") {
            return None;
        }
        if agent != "SSH_AUTH_SOCK" {
            return netcatty_mosh::auth::expand_home(agent, home.as_deref());
        }
    }
    if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
        if !sock.is_empty() {
            return Some(sock);
        }
    }
    cfg!(windows).then(|| r"\\.\pipe\openssh-ssh-agent".to_string())
}

fn external_auth(options: &ExternalSessionOptions) -> CoreResult<ExternalSshAuth> {
    let use_agent = options.use_ssh_agent;
    let agent = if use_agent == Some(true) {
        let socket = agent_socket(options.identity_agent.as_deref());
        if socket.is_none() {
            return Err(CoreError::auth(AGENT_UNAVAILABLE));
        }
        socket
    } else {
        None
    };
    let forwarding = if options.agent_forwarding == Some(true) {
        agent_socket(options.identity_agent.as_deref())
    } else {
        None
    };
    Ok(ExternalSshAuth {
        hostname: options.hostname.trim().to_string(),
        port: options.port.filter(|p| *p != 0).unwrap_or(22),
        username: options.username.clone().filter(|u| !u.is_empty()),
        auth_method: auth_method_str(options.auth_method),
        requires_mfa: options.requires_mfa.unwrap_or(false),
        password: options.password.clone(),
        passphrase: options.passphrase.clone(),
        private_key: options.private_key.clone(),
        certificate: options.certificate.clone(),
        agent_public_keys: options.agent_public_keys.clone().unwrap_or_default(),
        identity_file_paths: options.identity_file_paths.clone().unwrap_or_default(),
        use_ssh_agent: use_agent,
        identities_only: options.identities_only.unwrap_or(false),
        agent_socket: agent,
        forwarding_socket: forwarding,
        known_hosts: known_host_pins(options.known_hosts.as_ref()),
        verify_host_keys: options.verify_host_keys != Some(false),
        legacy_algorithms: options.legacy_algorithms.unwrap_or(false),
    })
}

fn jump_auth(jump: &JumpHost) -> ExternalSshAuth {
    ExternalSshAuth {
        hostname: jump.hostname.trim().to_string(),
        port: if jump.port == 0 { 22 } else { jump.port },
        username: Some(jump.username.clone()).filter(|u| !u.is_empty()),
        auth_method: auth_method_str(jump.auth_method),
        requires_mfa: jump.requires_mfa.unwrap_or(false),
        password: jump.password.clone(),
        passphrase: jump.passphrase.clone(),
        private_key: jump.private_key.clone(),
        certificate: jump.certificate.clone(),
        agent_public_keys: jump.agent_public_keys.clone().unwrap_or_default(),
        identity_file_paths: jump.identity_file_paths.clone().unwrap_or_default(),
        use_ssh_agent: jump.use_ssh_agent,
        identities_only: jump.identities_only.unwrap_or(false),
        agent_socket: if jump.use_ssh_agent == Some(true) {
            agent_socket(jump.identity_agent.as_deref())
        } else {
            None
        },
        forwarding_socket: None,
        known_hosts: Vec::new(),
        verify_host_keys: jump.verify_host_keys != Some(false),
        legacy_algorithms: jump.legacy_algorithms.unwrap_or(false),
    }
}

/// Bundled client lookup: Tauri resources, the dev layout, then `PATH`.
fn resolve_client<R: Runtime>(
    app: &AppHandle<R>,
    client: Client,
    path_override: Option<&str>,
) -> Option<PathBuf> {
    let resource_dir = app.path().resource_dir().ok();
    let project_root = cfg!(debug_assertions).then(|| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("..")
    });
    binaries::resolve_client(
        client,
        resource_dir.as_deref(),
        project_root.as_deref(),
        path_override,
    )
}

/// PATH the spawned PTY will see (host env overrides included).
fn effective_path(env: &HashMap<String, String>) -> Option<String> {
    env.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("path"))
        .map(|(_, v)| v.clone())
        .or_else(|| std::env::var("PATH").ok())
}

/// Private files of one session, removed when it ends.
struct SessionFiles {
    dir: PathBuf,
    prefix: String,
    written: Vec<PathBuf>,
}

impl SessionFiles {
    fn new(dir: PathBuf, session_id: &str) -> Self {
        let safe: String = session_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .take(80)
            .collect();
        Self {
            dir,
            prefix: format!("mosh-auth-{safe}"),
            written: Vec::new(),
        }
    }
}

impl SecretFiles for SessionFiles {
    fn write(&mut self, suffix: &str, content: &str) -> Result<PathBuf, String> {
        let path = self.dir.join(format!(
            "{}-{}{suffix}",
            self.prefix,
            netcatty_core::new_id()
        ));
        let normalized = if content.ends_with('\n') || content.is_empty() {
            content.to_string()
        } else {
            format!("{content}\n")
        };
        netcatty_mosh::et::write_secure(&path, &normalized, 0o600)?;
        self.written.push(path.clone());
        Ok(path)
    }
}

fn remove_paths(paths: &[PathBuf]) {
    for path in paths {
        let result = if path.is_dir() {
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_file(path)
        };
        if let Err(err) = result {
            if err.kind() != std::io::ErrorKind::NotFound {
                tracing::debug!(path = %path.display(), %err, "temp file cleanup failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PTY transport (shared by Mosh and ET)
// ---------------------------------------------------------------------------

pub struct PtyTransport {
    session_id: String,
    pty: parking_lot::RwLock<Option<Arc<PtySession>>>,
    size: parking_lot::Mutex<(u16, u16)>,
    cancel: CancellationToken,
    /// Removed on exit / close (key files, ET session home).
    cleanup: parking_lot::Mutex<Vec<PathBuf>>,
}

impl PtyTransport {
    fn new(session_id: String, cols: u16, rows: u16, cleanup: Vec<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            session_id,
            pty: parking_lot::RwLock::new(None),
            size: parking_lot::Mutex::new((cols, rows)),
            cancel: CancellationToken::new(),
            cleanup: parking_lot::Mutex::new(cleanup),
        })
    }

    fn current(&self) -> Option<Arc<PtySession>> {
        self.pty.read().clone()
    }

    /// Install `pty` as the session's PTY (the Mosh swap is atomic for
    /// input: later writes / resizes reach the new process).
    fn install(&self, pty: Arc<PtySession>) {
        let old = self.pty.write().replace(pty);
        if let Some(old) = old {
            old.kill();
        }
    }

    fn run_cleanup(&self) {
        let paths = std::mem::take(&mut *self.cleanup.lock());
        remove_paths(&paths);
    }

    async fn write_raw(&self, bytes: Bytes) -> CoreResult<()> {
        match self.current() {
            Some(pty) => pty.write(bytes).await.map_err(CoreError::from),
            None => Err(CoreError::not_found(format!(
                "session {} not found",
                self.session_id
            ))),
        }
    }
}

#[async_trait::async_trait]
impl StreamTransport for PtyTransport {
    async fn write_input(
        &self,
        input: SessionInput,
        _meta: &InputMeta,
        _charset: Charset,
    ) -> CoreResult<()> {
        // Like Electron, Mosh / ET input is sent as UTF-8 (the clients
        // speak UTF-8 regardless of the host charset setting).
        let bytes = match input {
            SessionInput::Text(text) => Bytes::from(text.into_bytes()),
            SessionInput::Bytes(bytes) => bytes,
        };
        self.write_raw(bytes).await
    }

    fn resize(&self, cols: u16, rows: u16) -> CoreResult<()> {
        *self.size.lock() = (cols, rows);
        match self.current() {
            Some(pty) => pty.resize(cols, rows).map_err(CoreError::from),
            None => Ok(()),
        }
    }

    fn close(&self) {
        self.cancel.cancel();
        if let Some(pty) = self.pty.write().take() {
            pty.kill();
        }
        self.run_cleanup();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Spawn a client in a PTY; returns the session and its event receiver.
async fn spawn_pty(
    program: &Path,
    args: Vec<String>,
    env: HashMap<String, String>,
    env_remove: Vec<String>,
    cols: u16,
    rows: u16,
) -> CoreResult<(Arc<PtySession>, mpsc::Receiver<PtyEvent>)> {
    let mut pty = PtySession::spawn(LocalPtyOptions {
        shell: Some(program.to_string_lossy().into_owned()),
        shell_args: args,
        cwd: None,
        env,
        cols,
        rows,
        term: Some("xterm-256color".into()),
        env_remove,
        skip_locale_defaults: true,
    })
    .await
    .map_err(CoreError::from)?;
    let (_tx, placeholder) = mpsc::channel(1);
    let events = std::mem::replace(&mut pty.events, placeholder);
    Ok((Arc::new(pty), events))
}

fn locale_and_agent_removals() -> Vec<String> {
    let mut keys: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| k == "LANG" || k == "LANGUAGE" || k.starts_with("LC_"))
        .collect();
    keys.push("SSH_AUTH_SOCK".into());
    keys
}

/// `applyMoshSshAgentEnvironment` / `applyEtSshAgentEnvironment`.
fn apply_agent_env(env: &mut HashMap<String, String>, auth: &ExternalSshAuth) {
    env.remove("SSH_AUTH_SOCK");
    if cfg!(windows) {
        if let Some(socket) = &auth.forwarding_socket {
            env.insert("SSH_AUTH_SOCK".into(), socket.clone());
            return;
        }
    }
    if auth.use_ssh_agent == Some(false) {
        return;
    }
    let socket = auth.agent_socket.clone().or_else(|| {
        std::env::var("SSH_AUTH_SOCK")
            .ok()
            .filter(|s| !s.is_empty())
    });
    if let Some(socket) = socket {
        env.insert("SSH_AUTH_SOCK".into(), socket);
    }
}

// ---------------------------------------------------------------------------
// Mosh
// ---------------------------------------------------------------------------

/// Start a Mosh session. Resolves once the ssh bootstrap PTY runs; the
/// renderer waits for `netcatty:mosh:ready` before startup commands.
#[tauri::command]
pub async fn mosh_start<R: Runtime>(
    state: Ctx<'_, R>,
    payload: ExternalSessionOptions,
) -> CmdResult<StartSessionResult> {
    let session_id = session_id_or_new(payload.session_id.as_ref());
    ensure_free(&state, &session_id)?;
    // Stats companion credentials (connects only after `netcatty:mosh:ready`).
    super::transfers2::remember_companion(&state.app, &session_id, &payload, "mosh");
    if payload.hostname.trim().is_empty() {
        return Err(CoreError::invalid("hostname is required"));
    }
    let options_env = payload.env.clone().unwrap_or_default();
    let path_for_lookup = effective_path(&options_env);
    let client = resolve_client(&state.app, Client::Mosh, path_for_lookup.as_deref())
        .ok_or_else(|| CoreError::not_found(MOSH_CLIENT_NOT_FOUND))?;
    let ssh = binaries::resolve_ssh(path_for_lookup.as_deref())
        .ok_or_else(|| CoreError::not_found(SSH_NOT_FOUND))?;
    let auth = external_auth(&payload)?;
    let cols = payload.cols.filter(|c| *c > 0).unwrap_or(80);
    let rows = payload.rows.filter(|r| *r > 0).unwrap_or(24);
    let lang = options_env
        .get("LANG")
        .cloned()
        .unwrap_or_else(|| handshake::resolve_lang_from_charset(payload.charset.as_deref()));

    let temp_dir = state.paths.temp_dir();
    let mut files = SessionFiles::new(temp_dir, &session_id);
    let home = dirs::home_dir();
    let default_identities = home
        .as_ref()
        .map(|h| netcatty_mosh::auth::discover_identity_paths(&h.join(".ssh")))
        .unwrap_or_default();
    let plan = match netcatty_mosh::auth::plan_mosh_ssh_args(
        &auth,
        &mut files,
        &default_identities,
        home.as_deref(),
        cfg!(windows),
    ) {
        Ok(plan) => plan,
        Err(err) => {
            remove_paths(&files.written);
            return Err(CoreError::io(err));
        }
    };
    let mosh_server = handshake::build_mosh_server_command(payload.mosh_server_path.as_deref());
    let ssh_args = handshake::build_ssh_handshake_args(&handshake::SshHandshakeOptions {
        host: &auth.hostname,
        port: Some(auth.port),
        username: auth.username.as_deref(),
        lang: Some(&lang),
        locales: Some(&options_env),
        mosh_server: Some(&mosh_server),
        ssh_args: &plan.ssh_args,
    })
    .map_err(CoreError::invalid)?;

    let mut ssh_env = options_env.clone();
    handshake::strip_locale_env(&mut ssh_env);
    ssh_env.insert("TERM".into(), "xterm-256color".into());
    apply_agent_env(&mut ssh_env, &auth);

    let transport = PtyTransport::new(session_id.clone(), cols, rows, files.written.clone());
    let (ssh_pty, ssh_events) = match spawn_pty(
        &ssh,
        ssh_args,
        ssh_env,
        locale_and_agent_removals(),
        cols,
        rows,
    )
    .await
    {
        Ok(spawned) => spawned,
        Err(err) => {
            transport.run_cleanup();
            return Err(err);
        }
    };
    transport.install(ssh_pty.clone());
    if state.sessions.contains(&session_id) {
        transport.close();
        return Err(CoreError::invalid(format!(
            "session {session_id} already exists"
        )));
    }

    let (events_tx, events_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
    let driver = MoshDriver {
        app: state.app.clone(),
        session_id: session_id.clone(),
        boot_epoch: payload.boot_epoch,
        transport: transport.clone(),
        events: events_tx,
        client,
        hostname: auth.hostname.clone(),
        options_env,
        lang,
        auth: auth.clone(),
        password: payload.password.clone(),
        passphrase: payload.passphrase.clone(),
    };
    tauri::async_runtime::spawn(driver.run(ssh_pty, ssh_events));

    // Session-log hook (automatic log of this session).
    {
        let host = payload.hostname.trim();
        let label = payload
            .label
            .as_deref()
            .map(str::trim)
            .filter(|l| !l.is_empty());
        super::sessionlog::session_starting(
            &state.app,
            &session_id,
            payload.session_log.as_ref(),
            label.unwrap_or(host),
            host,
        );
    }
    state.sessions.insert(SessionEntry {
        session_id: session_id.clone(),
        host_id: payload.host_id.clone(),
        label: payload
            .label
            .clone()
            .filter(|l| !l.trim().is_empty())
            .unwrap_or_else(|| auth.hostname.clone()),
        protocol: "mosh",
        backend: SessionBackend::Stream {
            transport,
            events: events_rx,
        },
        // Mosh output is UTF-8 whatever the host charset says.
        charset: crate::decoder::DEFAULT_CHARSET.to_string(),
        connection: None,
        created_at: netcatty_core::ids::now_ms(),
    });
    Ok(StartSessionResult { session_id })
}

struct MoshDriver<R: Runtime> {
    app: AppHandle<R>,
    session_id: String,
    boot_epoch: Option<u64>,
    transport: Arc<PtyTransport>,
    events: mpsc::Sender<StreamEvent>,
    client: PathBuf,
    hostname: String,
    options_env: HashMap<String, String>,
    lang: String,
    auth: ExternalSshAuth,
    password: Option<String>,
    passphrase: Option<String>,
}

fn handshake_meta(requires_user_input: bool) -> Option<SessionDataMeta> {
    Some(SessionDataMeta {
        mosh_handshake: Some(true),
        mosh_handshake_requires_user_input: requires_user_input.then_some(true),
    })
}

impl<R: Runtime> MoshDriver<R> {
    async fn send(&self, event: StreamEvent) -> bool {
        self.events.send(event).await.is_ok()
    }

    async fn text(&self, text: &str, meta: Option<SessionDataMeta>) -> bool {
        if text.is_empty() {
            return true;
        }
        self.send(StreamEvent::Text {
            text: text.to_string(),
            meta,
        })
        .await
    }

    async fn run(self, ssh_pty: Arc<PtySession>, mut ssh_events: mpsc::Receiver<PtyEvent>) {
        let cancel = self.transport.cancel.clone();
        let mut decoder = StreamDecoder::new(Some("utf-8"));
        let mut sniffer = MoshConnectSniffer::new();
        let mut responder =
            MoshPasswordResponder::new(self.password.clone(), self.passphrase.clone());
        let mut parsed = None;
        let (ssh_code, ssh_signal) = loop {
            let event = tokio::select! {
                _ = cancel.cancelled() => {
                    self.transport.run_cleanup();
                    return;
                }
                event = ssh_events.recv() => event,
            };
            match event {
                Some(PtyEvent::Data(bytes)) => {
                    let text = decoder.decode(&bytes, false);
                    let out = sniffer.feed(&text);
                    if !out.visible.is_empty() {
                        let reply = responder.feed(&out.visible);
                        if let Some(secret) = reply.write {
                            let _ = ssh_pty.write(Bytes::from(secret.into_bytes())).await;
                        }
                        if !self
                            .text(&out.visible, handshake_meta(reply.requires_user_input))
                            .await
                        {
                            return;
                        }
                    }
                    if out.parsed.is_some() && parsed.is_none() {
                        parsed = out.parsed;
                    }
                }
                Some(PtyEvent::Exit { exit_code, signal }) => break (exit_code, signal),
                None => break (None, None),
            }
        };
        // Key / known_hosts files are only needed by the bootstrap ssh.
        self.transport.run_cleanup();
        if cancel.is_cancelled() {
            return;
        }

        if parsed.is_none() {
            let tail = decoder.decode(&[], true);
            let mut out = sniffer.feed(&tail);
            let flushed = sniffer.flush();
            out.visible.push_str(&flushed.visible);
            if !self.text(&out.visible, handshake_meta(false)).await {
                return;
            }
            parsed = out.parsed.or(flushed.parsed);
        }

        let Some(connect) = parsed else {
            let _ = self
                .text(handshake::MOSH_HANDSHAKE_FAILED_HINT, handshake_meta(false))
                .await;
            let mut exit = StreamExit::process(ssh_code, ssh_signal);
            exit.reason = netcatty_core::ipc::ExitReason::Error;
            exit.error = Some(handshake::MOSH_HANDSHAKE_FAILED_ERROR.to_string());
            let _ = self.send(StreamEvent::Exit(exit)).await;
            return;
        };

        // Swap to mosh-client.
        let target = connect
            .host
            .clone()
            .unwrap_or_else(|| self.hostname.clone());
        let fallback = connect
            .host
            .as_deref()
            .filter(|h| *h != self.hostname)
            .map(|_| self.hostname.clone());
        let mut base_env: HashMap<String, String> = std::env::vars().collect();
        base_env.extend(self.options_env.clone());
        base_env.insert("TERM".into(), "xterm-256color".into());
        let mut env = handshake::build_mosh_client_env(
            &base_env,
            &connect.key,
            Some(&self.lang),
            fallback.as_deref(),
        );
        // Netcatty owns the scrollback: keep MoshCatty on the primary screen.
        env.insert("MOSH_NO_TERM_INIT".into(), "1".into());
        apply_agent_env(&mut env, &self.auth);
        let remove = if env.contains_key("SSH_AUTH_SOCK") {
            Vec::new()
        } else {
            vec!["SSH_AUTH_SOCK".to_string()]
        };
        let (cols, rows) = *self.transport.size.lock();
        let client_path = self.client.to_string_lossy().into_owned();
        let spawned = match handshake::build_mosh_client_args(&client_path, &target, connect.port) {
            Ok((_, args)) => spawn_pty(&self.client, args, env, remove, cols, rows).await,
            Err(err) => Err(CoreError::invalid(err)),
        };
        let (client_pty, mut client_events) = match spawned {
            Ok(spawned) => spawned,
            Err(err) => {
                let _ = self
                    .send(StreamEvent::Exit(StreamExit {
                        exit_code: None,
                        signal: None,
                        error: Some(format!("Failed to spawn mosh-client: {}", err.message)),
                        reason: netcatty_core::ipc::ExitReason::Error,
                    }))
                    .await;
                return;
            }
        };
        if cancel.is_cancelled() {
            client_pty.kill();
            return;
        }
        self.transport.install(client_pty);
        if !self
            .text(handshake::MOSH_HANDSHAKE_VIEWPORT_RESET, None)
            .await
        {
            return;
        }
        // The handshake vetted the host: the stats companion may connect.
        super::transfers2::companion_ready(&self.app, &self.session_id);
        crate::events::emit(
            &self.app,
            ev::MOSH_READY,
            SessionBootEvent {
                session_id: self.session_id.clone(),
                boot_epoch: self.boot_epoch,
            },
        );

        loop {
            let event = tokio::select! {
                _ = cancel.cancelled() => return,
                event = client_events.recv() => event,
            };
            match event {
                Some(PtyEvent::Data(bytes)) => {
                    if !self.send(StreamEvent::Data(bytes)).await {
                        return;
                    }
                }
                Some(PtyEvent::Exit { exit_code, signal }) => {
                    let _ = self.text(handshake::MOSH_PRIMARY_SCREEN_RESET, None).await;
                    let _ = self
                        .send(StreamEvent::Exit(StreamExit::process(exit_code, signal)))
                        .await;
                    return;
                }
                None => {
                    let _ = self
                        .send(StreamEvent::Exit(StreamExit::process(None, None)))
                        .await;
                    return;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EternalTerminal
// ---------------------------------------------------------------------------

/// Start an EternalTerminal session.
#[tauri::command]
pub async fn et_start<R: Runtime>(
    state: Ctx<'_, R>,
    payload: ExternalSessionOptions,
) -> CmdResult<StartSessionResult> {
    let session_id = session_id_or_new(payload.session_id.as_ref());
    ensure_free(&state, &session_id)?;
    if payload.hostname.trim().is_empty() {
        return Err(CoreError::invalid("hostname is required"));
    }
    let options_env = payload.env.clone().unwrap_or_default();
    let et = resolve_client(
        &state.app,
        Client::Et,
        effective_path(&options_env).as_deref(),
    )
    .ok_or_else(|| CoreError::not_found(ET_CLIENT_NOT_FOUND))?;
    let auth = external_auth(&payload)?;
    let jumps: Vec<ExternalSshAuth> = payload
        .jump_hosts
        .as_ref()
        .map(|j| j.iter().map(jump_auth).collect())
        .unwrap_or_default();
    let cols = payload.cols.filter(|c| *c > 0).unwrap_or(80);
    let rows = payload.rows.filter(|r| *r > 0).unwrap_or(24);

    let home = dirs::home_dir().unwrap_or_default();
    let real_ssh_dir = home.join(".ssh");
    let _ = std::fs::create_dir_all(&real_ssh_dir);
    let temp_home = state
        .paths
        .temp_dir()
        .join(format!("et-ssh-home-{session_id}"));
    let mut include_configs = Vec::new();
    if real_ssh_dir.join("config").is_file() {
        include_configs.push(real_ssh_dir.join("config"));
    }
    let system_config = if cfg!(windows) {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into()))
            .join("ssh")
            .join("ssh_config")
    } else {
        PathBuf::from("/etc/ssh/ssh_config")
    };
    if system_config.is_file() {
        include_configs.push(system_config);
    }
    let path_key = options_env
        .keys()
        .find(|k| k.eq_ignore_ascii_case("path"))
        .cloned()
        .or_else(|| {
            std::env::vars()
                .map(|(k, _)| k)
                .find(|k| k.eq_ignore_ascii_case("path"))
        })
        .unwrap_or_else(|| "PATH".into());
    let base_path = effective_path(&options_env);
    let environment = netcatty_mosh::et::EtEnvironment {
        temp_home: temp_home.clone(),
        real_ssh_dir: real_ssh_dir.clone(),
        default_identities: netcatty_mosh::auth::discover_identity_paths(&real_ssh_dir),
        include_configs,
        real_ssh: binaries::resolve_ssh(base_path.as_deref()),
        base_path,
        path_key: path_key.clone(),
        local_username: std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_default(),
        askpass_exe: std::env::current_exe().ok(),
        display: std::env::var("DISPLAY").ok().filter(|d| !d.is_empty()),
        windows: cfg!(windows),
    };
    let plan =
        match netcatty_mosh::et::plan_et(&auth, payload.et_port, &jumps, &environment, &session_id)
        {
            Ok(plan) => plan,
            Err(err) => {
                remove_paths(&[temp_home]);
                return Err(CoreError::invalid(err));
            }
        };

    let mut env = options_env.clone();
    env.extend(plan.env.iter().cloned());
    env.insert("TERM".into(), "xterm-256color".into());
    // et prints a telemetry notice on every "first run" (each session has
    // a fresh HOME); opt out like Electron.
    env.insert("ET_NO_TELEMETRY".into(), "1".into());
    apply_agent_env(&mut env, &auth);
    if cfg!(windows) {
        if let Some(dir) = et.parent() {
            let arch = if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            };
            let dll_dir = dir.join(format!("et-win32-{arch}-dlls"));
            if dll_dir.is_dir() {
                let current = env
                    .get(&path_key)
                    .cloned()
                    .or_else(|| std::env::var("PATH").ok())
                    .unwrap_or_default();
                let dll = dll_dir.to_string_lossy().into_owned();
                env.insert(
                    path_key.clone(),
                    if current.is_empty() {
                        dll
                    } else {
                        format!("{dll};{current}")
                    },
                );
            }
        }
    }
    let remove = if env.contains_key("SSH_AUTH_SOCK") {
        Vec::new()
    } else {
        vec!["SSH_AUTH_SOCK".to_string()]
    };

    let transport = PtyTransport::new(session_id.clone(), cols, rows, vec![temp_home]);
    let (pty, mut pty_events) = match spawn_pty(&et, plan.args, env, remove, cols, rows).await {
        Ok(spawned) => spawned,
        Err(err) => {
            transport.run_cleanup();
            return Err(err);
        }
    };
    transport.install(pty);
    if state.sessions.contains(&session_id) {
        transport.close();
        return Err(CoreError::invalid(format!(
            "session {session_id} already exists"
        )));
    }

    let (events_tx, events_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
    let forward = transport.clone();
    tauri::async_runtime::spawn(async move {
        let cancel = forward.cancel.clone();
        loop {
            let event = tokio::select! {
                _ = cancel.cancelled() => break,
                event = pty_events.recv() => event,
            };
            match event {
                Some(PtyEvent::Data(bytes)) => {
                    if events_tx.send(StreamEvent::Data(bytes)).await.is_err() {
                        break;
                    }
                }
                Some(PtyEvent::Exit { exit_code, signal }) => {
                    forward.run_cleanup();
                    let _ = events_tx
                        .send(StreamEvent::Exit(StreamExit::process(exit_code, signal)))
                        .await;
                    break;
                }
                None => {
                    forward.run_cleanup();
                    let _ = events_tx
                        .send(StreamEvent::Exit(StreamExit::process(None, None)))
                        .await;
                    break;
                }
            }
        }
        forward.run_cleanup();
    });

    // Session-log hook (automatic log of this session).
    {
        let host = payload.hostname.trim();
        let label = payload
            .label
            .as_deref()
            .map(str::trim)
            .filter(|l| !l.is_empty());
        super::sessionlog::session_starting(
            &state.app,
            &session_id,
            payload.session_log.as_ref(),
            label.unwrap_or(host),
            host,
        );
    }
    // Stats companion credentials for host info (commands/transfers2.rs).
    super::transfers2::remember_companion(&state.app, &session_id, &payload, "et");
    state.sessions.insert(SessionEntry {
        session_id: session_id.clone(),
        host_id: payload.host_id.clone(),
        label: payload
            .label
            .clone()
            .filter(|l| !l.trim().is_empty())
            .unwrap_or_else(|| auth.hostname.clone()),
        protocol: "et",
        backend: SessionBackend::Stream {
            transport,
            events: events_rx,
        },
        charset: crate::decoder::DEFAULT_CHARSET.to_string(),
        connection: None,
        created_at: netcatty_core::ids::now_ms(),
    });
    Ok(StartSessionResult { session_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_deserialize_from_renderer_json() {
        let options: ExternalSessionOptions = serde_json::from_value(serde_json::json!({
            "sessionId": "s1",
            "hostname": "example.com",
            "username": "alice",
            "authMethod": "password",
            "port": 2222,
            "etPort": 2023,
            "moshServerPath": "/opt/mosh-server",
            "knownHosts": [],
            "jumpHosts": [{ "hostname": "bastion", "port": 22, "username": "bob" }],
            "env": { "LANG": "C" },
            "bootEpoch": 3,
            "unknownField": true
        }))
        .unwrap();
        let auth = external_auth(&options).unwrap();
        assert_eq!(auth.auth_method.as_deref(), Some("password"));
        assert_eq!(auth.port, 2222);
        assert!(auth.verify_host_keys);
        assert_eq!(
            jump_auth(&options.jump_hosts.unwrap()[0]).hostname,
            "bastion"
        );
    }

    #[test]
    fn agent_socket_resolution() {
        assert_eq!(agent_socket(Some("none")), None);
        assert_eq!(
            agent_socket(Some("/tmp/a.sock")).as_deref(),
            Some("/tmp/a.sock")
        );
    }

    #[test]
    fn session_files_are_private_and_removed() {
        let dir = std::env::temp_dir().join(format!("nc-mosh-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut files = SessionFiles::new(dir.clone(), "a/b");
        let path = files.write(".pem", "KEY").unwrap();
        assert!(path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("mosh-auth-a_b-"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "KEY\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        remove_paths(&files.written);
        assert!(!path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
