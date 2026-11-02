//! Authentication strategy (mirrors `sshAuthHelper.cjs`).
//!
//! Order for `HostAuthMethod::Auto`:
//! 1. `none` (to learn the server's allowed methods),
//! 2. publickey: explicit `private_key` (+certificate), then
//!    `identity_file_paths`, then agent identities (unless `identities_only`),
//! 3. keyboard-interactive (TOTP prompts auto-answered from `totp.uri`),
//! 4. password.
//!
//! `Password` tries KI first when `requires_mfa`, otherwise password then KI.
//! `Key`/`Certificate` skip password entirely.

use crate::error::{SshError, SshResult};
use crate::handler::ClientHandler;
use crate::options::HopOptions;
use crate::SshCallbacks;
use netcatty_core::ipc::KeyboardInteractivePrompt;
use netcatty_core::models::HostAuthMethod;
use regex::Regex;
use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::agent::AgentIdentity;
use russh::keys::{Certificate, HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use russh::{MethodKind, MethodSet};
use std::sync::{Arc, OnceLock};

/// Maximum number of passphrase prompts per encrypted key.
pub const MAX_PASSPHRASE_ATTEMPTS: usize = 3;
/// Maximum keyboard-interactive info-request round trips per attempt.
const MAX_KI_ROUNDS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    None,
    PublicKey { source: KeySourceKind },
    KeyboardInteractive,
    Password,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySourceKind {
    Inline,
    File(String),
    Agent,
}

/// Which SSH user-auth methods the strategy drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    PublicKey,
    KeyboardInteractive,
    Password,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::PublicKey => "publickey",
            Method::KeyboardInteractive => "keyboard-interactive",
            Method::Password => "password",
        }
    }
    fn kind(self) -> MethodKind {
        match self {
            Method::PublicKey => MethodKind::PublicKey,
            Method::KeyboardInteractive => MethodKind::KeyboardInteractive,
            Method::Password => MethodKind::Password,
        }
    }
}

/// Order of methods for a hop (see module docs).
fn method_order(hop: &HopOptions) -> Vec<Method> {
    match hop.auth_method {
        HostAuthMethod::Auto => vec![
            Method::PublicKey,
            Method::KeyboardInteractive,
            Method::Password,
        ],
        HostAuthMethod::Password if hop.requires_mfa => {
            vec![Method::KeyboardInteractive, Method::Password]
        }
        HostAuthMethod::Password => vec![Method::Password, Method::KeyboardInteractive],
        // Keys never fall back to a password; keyboard-interactive stays for
        // second-factor servers (publickey + OTP).
        HostAuthMethod::Key | HostAuthMethod::Certificate => {
            vec![Method::PublicKey, Method::KeyboardInteractive]
        }
    }
}

/// Bookkeeping across method attempts.
struct AuthState<'a> {
    hop: &'a HopOptions,
    callbacks: &'a Arc<dyn SshCallbacks>,
    /// Methods the server currently advertises (`None` before the first reply).
    remaining: Option<MethodSet>,
    /// Methods tried, in order, for the failure summary.
    tried: Vec<&'static str>,
    /// Human-readable reasons, one per failed method (never contains secrets).
    reasons: Vec<String>,
    /// Best RSA hash the server accepts, resolved lazily once.
    rsa_hash: Option<Option<HashAlg>>,
    /// Saved password already consumed by a keyboard-interactive auto-fill or
    /// a successful password factor; never auto-filled twice.
    password_used: bool,
}

impl AuthState<'_> {
    fn server_allows(&self, method: Method) -> bool {
        match &self.remaining {
            None => true,
            Some(set) => set.contains(&method.kind()),
        }
    }

    fn note_result(&mut self, result: &AuthResult) {
        if let AuthResult::Failure {
            remaining_methods,
            partial_success,
        } = result
        {
            if *partial_success {
                tracing::debug!(
                    "partial success; remaining methods: {:?}",
                    remaining_methods
                );
            }
            self.remaining = Some(remaining_methods.clone());
        }
    }

    async fn progress(&self, message: String) {
        self.callbacks.progress(message).await;
    }

    async fn rsa_hash(&mut self, handle: &Handle<ClientHandler>) -> Option<HashAlg> {
        if let Some(h) = self.rsa_hash {
            return h;
        }
        let h = match handle.best_supported_rsa_hash().await {
            Ok(h) => h.flatten(),
            Err(e) => {
                tracing::debug!("best_supported_rsa_hash failed: {e}");
                None
            }
        };
        self.rsa_hash = Some(h);
        h
    }
}

/// Authenticate `handle` for `hop`. Returns the method that succeeded.
///
/// Note: russh's authentication calls take `&mut Handle`, hence the mutable
/// borrow (the skeleton originally declared `&Handle`).
pub async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    hop: &HopOptions,
    callbacks: &Arc<dyn SshCallbacks>,
) -> SshResult<AuthOutcome> {
    if hop.username.trim().is_empty() {
        return Err(SshError::InvalidArgument("username is required".into()));
    }
    let user = hop.username.clone();
    let mut state = AuthState {
        hop,
        callbacks,
        remaining: None,
        tried: Vec::new(),
        reasons: Vec::new(),
        rsa_hash: None,
        password_used: false,
    };

    // 1. "none": learns the allowed methods and succeeds on open servers.
    let none = handle.authenticate_none(user.clone()).await?;
    if none.success() {
        return Ok(AuthOutcome::None);
    }
    state.note_result(&none);

    for method in method_order(hop) {
        if !state.server_allows(method) {
            tracing::debug!("server does not offer {}; skipping", method.name());
            continue;
        }
        state.tried.push(method.name());
        let outcome = match method {
            Method::PublicKey => try_public_key(handle, &user, &mut state).await?,
            Method::KeyboardInteractive => {
                try_keyboard_interactive(handle, &user, &mut state).await?
            }
            Method::Password => try_password(handle, &user, &mut state).await?,
        };
        if let Some(outcome) = outcome {
            return Ok(outcome);
        }
    }

    let mut summary = if state.tried.is_empty() {
        "Authentication failed (no applicable method)".to_string()
    } else {
        format!("Authentication failed (tried {})", state.tried.join(", "))
    };
    if !state.reasons.is_empty() {
        summary.push_str(": ");
        summary.push_str(&state.reasons.join("; "));
    }
    if let Some(remaining) = &state.remaining {
        let names: Vec<String> = remaining.iter().map(String::from).collect();
        if !names.is_empty() {
            summary.push_str(&format!(" [server accepts: {}]", names.join(", ")));
        }
    }
    Err(SshError::AuthFailed(summary))
}

// ---------------------------------------------------------------------------
// publickey
// ---------------------------------------------------------------------------

struct LoadedKey {
    key: Arc<PrivateKey>,
    source: KeySourceKind,
    label: String,
}

async fn try_public_key(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    state: &mut AuthState<'_>,
) -> SshResult<Option<AuthOutcome>> {
    let hop = state.hop;
    let mut failures: Vec<String> = Vec::new();
    let mut tried_any = false;

    // Explicit key material and identity files.
    let candidates = collect_key_candidates(hop);
    let has_explicit_keys = !candidates.is_empty();
    for cand in candidates {
        let Some(loaded) = load_candidate(&cand, hop, state.callbacks).await? else {
            failures.push(format!("{}: skipped (no passphrase)", cand.label));
            continue;
        };
        tried_any = true;
        state
            .progress(format!("Trying public key {}", loaded.label))
            .await;
        let hash = if loaded.key.algorithm().is_rsa() {
            state.rsa_hash(handle).await
        } else {
            None
        };

        let result = match cand.certificate.as_deref() {
            Some(cert_text) if !cert_text.trim().is_empty() => {
                match Certificate::from_openssh(cert_text.trim()) {
                    Ok(cert) => {
                        handle
                            .authenticate_openssh_cert(user, loaded.key.clone(), cert)
                            .await?
                    }
                    Err(e) => {
                        failures.push(format!("{}: invalid certificate ({e})", loaded.label));
                        // Fall back to the bare key.
                        handle
                            .authenticate_publickey(
                                user,
                                PrivateKeyWithHashAlg::new(loaded.key.clone(), hash),
                            )
                            .await?
                    }
                }
            }
            _ => {
                handle
                    .authenticate_publickey(
                        user,
                        PrivateKeyWithHashAlg::new(loaded.key.clone(), hash),
                    )
                    .await?
            }
        };
        if result.success() {
            return Ok(Some(AuthOutcome::PublicKey {
                source: loaded.source,
            }));
        }
        state.note_result(&result);
        failures.push(format!("{}: rejected by server", loaded.label));
        if !state.server_allows(Method::PublicKey) {
            break;
        }
    }

    // Agent identities.
    let use_agent = state.server_allows(Method::PublicKey)
        && !hop.identities_only
        && (hop.use_ssh_agent
            || hop.identity_agent.is_some()
            || (hop.auth_method == HostAuthMethod::Auto && !has_explicit_keys));
    if use_agent {
        match try_agent(handle, user, state).await {
            Ok(Some(outcome)) => return Ok(Some(outcome)),
            Ok(None) => {
                tried_any = true;
                failures.push("agent: no identity accepted".into());
            }
            Err(e) => failures.push(format!("agent: {e}")),
        }
    }

    if !tried_any && failures.is_empty() {
        failures.push("no keys configured".into());
    }
    state
        .reasons
        .push(format!("publickey: {}", failures.join(", ")));
    Ok(None)
}

struct KeyCandidate {
    text: String,
    certificate: Option<String>,
    source: KeySourceKind,
    label: String,
}

fn collect_key_candidates(hop: &HopOptions) -> Vec<KeyCandidate> {
    let mut out = Vec::new();
    if let Some(text) = hop.private_key.as_deref().filter(|t| !t.trim().is_empty()) {
        out.push(KeyCandidate {
            text: text.to_string(),
            certificate: hop.certificate.clone(),
            source: KeySourceKind::Inline,
            label: hop
                .key_label
                .clone()
                .filter(|l| !l.is_empty())
                .unwrap_or_else(|| "private key".to_string()),
        });
    }
    for path in hop
        .identity_file_paths
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
    {
        let expanded = expand_tilde(path);
        match std::fs::read_to_string(&expanded) {
            Ok(text) => {
                // OpenSSH convention: `<key>-cert.pub` next to the key.
                let cert = std::fs::read_to_string(format!("{expanded}-cert.pub")).ok();
                out.push(KeyCandidate {
                    text,
                    certificate: cert,
                    source: KeySourceKind::File(expanded.clone()),
                    label: expanded,
                });
            }
            Err(e) => tracing::warn!("cannot read identity file {expanded}: {e}"),
        }
    }
    // Default OpenSSH identities when nothing explicit was configured.
    if out.is_empty()
        && !hop.identities_only
        && matches!(hop.auth_method, HostAuthMethod::Auto | HostAuthMethod::Key)
    {
        for (name, path) in crate::keygen::default_key_files() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                let cert = std::fs::read_to_string(format!("{path}-cert.pub")).ok();
                out.push(KeyCandidate {
                    text,
                    certificate: cert,
                    source: KeySourceKind::File(path.clone()),
                    label: format!("~/.ssh/{name}"),
                });
            }
        }
    }
    out
}

async fn load_candidate(
    cand: &KeyCandidate,
    hop: &HopOptions,
    callbacks: &Arc<dyn SshCallbacks>,
) -> SshResult<Option<LoadedKey>> {
    let configured = if cand.source == KeySourceKind::Inline {
        hop.passphrase.as_deref()
    } else {
        None
    };
    match load_private_key(&cand.text, configured, &cand.label, callbacks).await? {
        Some(key) => Ok(Some(LoadedKey {
            key: Arc::new(key),
            source: cand.source.clone(),
            label: cand.label.clone(),
        })),
        None => Ok(None),
    }
}

/// Parse `text` (OpenSSH / PKCS#8 / PKCS#1 / PuTTY), prompting for a
/// passphrase through `callbacks` when the key is encrypted and the
/// configured passphrase is missing or wrong. `Ok(None)` means the user
/// declined to provide one.
pub async fn load_private_key(
    text: &str,
    configured_passphrase: Option<&str>,
    label: &str,
    callbacks: &Arc<dyn SshCallbacks>,
) -> SshResult<Option<PrivateKey>> {
    let text = normalize_key_text(text);
    // Unencrypted (or PuTTY/PKCS#8 keys that do not need a passphrase)?
    match russh::keys::decode_secret_key(&text, None) {
        Ok(key) => return Ok(Some(key)),
        Err(russh::keys::Error::KeyIsEncrypted) => {}
        Err(e) if configured_passphrase.is_none() && !looks_encrypted(&text) => {
            return Err(SshError::Key(format!(
                "{label}: {}",
                describe_key_error(&e)
            )));
        }
        Err(_) => {}
    }

    let mut passphrase: Option<String> = configured_passphrase
        .filter(|p| !p.is_empty())
        .map(str::to_string);
    let mut invalid = false;
    let mut prompts = 0usize;
    loop {
        if let Some(pw) = passphrase.as_deref() {
            match russh::keys::decode_secret_key(&text, Some(pw)) {
                Ok(key) => return Ok(Some(key)),
                Err(e) => {
                    tracing::debug!(
                        "passphrase rejected for {label}: {}",
                        describe_key_error(&e)
                    );
                    invalid = true;
                }
            }
        }
        if prompts >= MAX_PASSPHRASE_ATTEMPTS {
            return Err(SshError::Key(format!(
                "{label}: passphrase rejected {MAX_PASSPHRASE_ATTEMPTS} times"
            )));
        }
        prompts += 1;
        match callbacks
            .request_passphrase(label.to_string(), invalid)
            .await
        {
            Some(pw) => passphrase = Some(pw),
            None => return Ok(None),
        }
    }
}

/// Normalise line endings / stray whitespace so PEM parsers accept keys
/// pasted from Windows editors.
pub fn normalize_key_text(text: &str) -> String {
    let mut s = text.replace("\r\n", "\n").replace('\r', "\n");
    s = s.lines().map(str::trim_end).collect::<Vec<_>>().join("\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s.trim_start().to_string()
}

fn looks_encrypted(text: &str) -> bool {
    text.contains("ENCRYPTED")
        || text.contains("Proc-Type: 4,ENCRYPTED")
        || text.contains("Encryption: aes")
}

fn describe_key_error(e: &russh::keys::Error) -> String {
    match e {
        russh::keys::Error::KeyIsEncrypted => "key is encrypted".into(),
        russh::keys::Error::CouldNotReadKey => "unrecognised private key format".into(),
        other => other.to_string(),
    }
}

pub fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).to_string_lossy().into_owned();
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home.to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

async fn try_agent(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    state: &mut AuthState<'_>,
) -> SshResult<Option<AuthOutcome>> {
    let mut agent = connect_agent(state.hop.identity_agent.as_deref()).await?;
    let identities = agent
        .request_identities()
        .await
        .map_err(|e| SshError::Key(format!("agent: {e}")))?;
    if identities.is_empty() {
        return Err(SshError::Key("agent has no identities".into()));
    }
    state
        .progress(format!(
            "Trying {} agent identit{}",
            identities.len(),
            if identities.len() == 1 { "y" } else { "ies" }
        ))
        .await;

    for identity in identities {
        let (comment, is_rsa) = match &identity {
            AgentIdentity::PublicKey { key, comment } => {
                (comment.clone(), key.algorithm().is_rsa())
            }
            AgentIdentity::Certificate {
                certificate,
                comment,
            } => (comment.clone(), certificate.algorithm().is_rsa()),
        };
        let hash = if is_rsa {
            state.rsa_hash(handle).await
        } else {
            None
        };
        let result = match identity {
            AgentIdentity::PublicKey { key, .. } => {
                handle
                    .authenticate_publickey_with(user, key, hash, &mut agent)
                    .await
            }
            AgentIdentity::Certificate { certificate, .. } => {
                handle
                    .authenticate_certificate_with(user, certificate, hash, &mut agent)
                    .await
            }
        };
        match result {
            Ok(r) if r.success() => {
                return Ok(Some(AuthOutcome::PublicKey {
                    source: KeySourceKind::Agent,
                }))
            }
            Ok(r) => {
                state.note_result(&r);
                tracing::debug!("agent identity {comment:?} rejected");
                if !state.server_allows(Method::PublicKey) {
                    break;
                }
            }
            Err(e) => tracing::debug!("agent identity {comment:?} failed to sign: {e}"),
        }
    }
    Ok(None)
}

#[cfg(unix)]
type Agent = russh::keys::agent::client::AgentClient<tokio::net::UnixStream>;
#[cfg(windows)]
type Agent = russh::keys::agent::client::AgentClient<
    Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin>,
>;

#[cfg(unix)]
async fn connect_agent(identity_agent: Option<&str>) -> SshResult<Agent> {
    use russh::keys::agent::client::AgentClient;
    match identity_agent.map(str::trim).filter(|s| !s.is_empty()) {
        Some(path) if path.eq_ignore_ascii_case("none") => {
            Err(SshError::Key("IdentityAgent none".into()))
        }
        Some(path) => AgentClient::connect_uds(expand_tilde(path))
            .await
            .map_err(|e| SshError::Key(format!("cannot connect to agent {path}: {e}"))),
        None => AgentClient::connect_env()
            .await
            .map_err(|e| SshError::Key(format!("cannot connect to agent: {e}"))),
    }
}

#[cfg(windows)]
async fn connect_agent(identity_agent: Option<&str>) -> SshResult<Agent> {
    use russh::keys::agent::client::AgentClient;
    let pipe = identity_agent
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .unwrap_or_else(|| r"\\.\pipe\openssh-ssh-agent".to_string());
    if pipe.eq_ignore_ascii_case("none") {
        return Err(SshError::Key("IdentityAgent none".into()));
    }
    match AgentClient::connect_named_pipe(&pipe).await {
        Ok(c) => Ok(c.dynamic()),
        Err(pipe_err) => AgentClient::connect_pageant()
            .await
            .map(|c| c.dynamic())
            .map_err(|e| {
                SshError::Key(format!(
                    "cannot connect to agent ({pipe}: {pipe_err}; pageant: {e})"
                ))
            }),
    }
}

// ---------------------------------------------------------------------------
// keyboard-interactive
// ---------------------------------------------------------------------------

async fn try_keyboard_interactive(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    state: &mut AuthState<'_>,
) -> SshResult<Option<AuthOutcome>> {
    state
        .progress("Trying keyboard-interactive".to_string())
        .await;
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await?;
    let mut rounds = 0usize;
    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => {
                return Ok(Some(AuthOutcome::KeyboardInteractive))
            }
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                state.note_result(&AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                });
                state
                    .reasons
                    .push("keyboard-interactive: rejected by server".into());
                return Ok(None);
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                rounds += 1;
                if rounds > MAX_KI_ROUNDS {
                    return Err(SshError::AuthFailed(
                        "keyboard-interactive: too many prompt rounds".into(),
                    ));
                }
                let answers = if prompts.is_empty() {
                    Vec::new()
                } else {
                    let ki_prompts: Vec<KeyboardInteractivePrompt> = prompts
                        .iter()
                        .map(|p| KeyboardInteractivePrompt {
                            prompt: p.prompt.clone(),
                            echo: p.echo,
                        })
                        .collect();
                    match auto_answer(state, &ki_prompts) {
                        Some(answers) => {
                            tracing::debug!("keyboard-interactive prompts answered automatically");
                            answers
                        }
                        None => match state
                            .callbacks
                            .keyboard_interactive(name, instructions, ki_prompts)
                            .await
                        {
                            Some(answers) => answers,
                            None => {
                                return Err(SshError::Cancelled(
                                    "keyboard-interactive authentication cancelled".into(),
                                ))
                            }
                        },
                    }
                };
                let mut answers = answers;
                answers.resize(prompts.len(), String::new());
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
}

/// Answer every prompt from configuration (TOTP / saved password) or return
/// `None` when at least one prompt needs the user.
fn auto_answer(
    state: &mut AuthState<'_>,
    prompts: &[KeyboardInteractivePrompt],
) -> Option<Vec<String>> {
    let hop = state.hop;
    let totp = hop
        .totp
        .as_ref()
        .filter(|t| t.auto_submit != Some(false) && !t.uri.trim().is_empty());
    let extra_pattern = hop.totp.as_ref().and_then(|t| t.prompt_pattern.as_deref());
    let mut answers = Vec::with_capacity(prompts.len());
    let mut uses_password = false;
    for p in prompts {
        if is_otp_prompt(&p.prompt, extra_pattern) {
            let t = totp?;
            match totp_code(&t.uri) {
                Ok(code) => answers.push(code),
                Err(e) => {
                    tracing::warn!("TOTP generation failed: {e}");
                    return None;
                }
            }
        } else if is_password_prompt(&p.prompt) && !state.password_used {
            let pw = hop.password.as_deref().filter(|pw| !pw.is_empty())?;
            answers.push(pw.to_string());
            uses_password = true;
        } else {
            return None;
        }
    }
    if uses_password {
        state.password_used = true;
    }
    Some(answers)
}

// ---------------------------------------------------------------------------
// password
// ---------------------------------------------------------------------------

async fn try_password(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    state: &mut AuthState<'_>,
) -> SshResult<Option<AuthOutcome>> {
    let Some(password) = state.hop.password.as_deref().filter(|p| !p.is_empty()) else {
        state
            .reasons
            .push("password: no password configured".into());
        return Ok(None);
    };
    state.progress("Trying password".to_string()).await;
    let result = handle.authenticate_password(user, password).await?;
    if result.success() {
        return Ok(Some(AuthOutcome::Password));
    }
    state.note_result(&result);
    state.password_used = true;
    state.reasons.push("password: rejected by server".into());
    Ok(None)
}

// ---------------------------------------------------------------------------
// prompt heuristics & TOTP
// ---------------------------------------------------------------------------

const OTP_PATTERN: &str = concat!(
    r"(?i)verification\s*code|one[\s-]?time|\botp\b|\btoken\b|authenticator|\b2fa\b|\bmfa\b|\btotp\b|google\s*auth",
    r"|passcode|two[\s-]?factor|multi[\s-]?factor|second\s+factor|\bduo\b",
    r"|动态|一次性|验证码|令牌|双因素|多因素|二次|挑战码",
);

const PASSWORD_PATTERN: &str = r"(?i)passw(or)?d|密\s*码|口\s*令";

fn otp_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(OTP_PATTERN).expect("valid OTP regex"))
}

fn password_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(PASSWORD_PATTERN).expect("valid password regex"))
}

/// Heuristic: does a keyboard-interactive prompt ask for an OTP code?
pub fn is_otp_prompt(prompt: &str, extra_pattern: Option<&str>) -> bool {
    if otp_regex().is_match(prompt) {
        return true;
    }
    match extra_pattern.map(str::trim).filter(|p| !p.is_empty()) {
        Some(p) => match Regex::new(&format!("(?i){p}")) {
            Ok(re) => re.is_match(prompt),
            Err(_) => prompt.to_lowercase().contains(&p.to_lowercase()),
        },
        None => false,
    }
}

/// Heuristic: does a keyboard-interactive prompt ask for the login password?
/// OTP vocabulary wins, so "One-time password" is *not* a password prompt.
pub fn is_password_prompt(prompt: &str) -> bool {
    !otp_regex().is_match(prompt) && password_regex().is_match(prompt)
}

/// Compute the current TOTP code from an `otpauth://` URI.
pub fn totp_code(uri: &str) -> SshResult<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| SshError::InvalidArgument(format!("system clock error: {e}")))?
        .as_secs();
    totp_code_at(uri, now)
}

/// Compute the TOTP code for an `otpauth://` URI at a given unix time.
pub fn totp_code_at(uri: &str, unix_time: u64) -> SshResult<String> {
    let uri = uri.trim();
    if uri.is_empty() {
        return Err(SshError::InvalidArgument("TOTP URI is empty".into()));
    }
    if uri.starts_with("enc:") {
        return Err(SshError::InvalidArgument(
            "TOTP URI is still encrypted".into(),
        ));
    }
    let totp = totp_rs::Totp::from_url_unchecked(uri)
        .map_err(|e| SshError::InvalidArgument(format!("invalid TOTP URI: {e}")))?;
    Ok(totp.generate(unix_time).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnattendedCallbacks;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn otp_prompt_detection() {
        for p in [
            "Verification code: ",
            "One-time password:",
            "Enter OTP",
            "Duo passcode or option (1-4):",
            "Token:",
            "Google Authenticator code",
            "2FA code",
            "MFA Code",
            "TOTP:",
            "请输入验证码",
            "动态密码：",
        ] {
            assert!(is_otp_prompt(p, None), "{p}");
            assert!(
                !is_password_prompt(p),
                "{p} should not be a password prompt"
            );
        }
        for p in ["Password: ", "user@host's password:", "密码：", "口令:"] {
            assert!(!is_otp_prompt(p, None), "{p}");
            assert!(is_password_prompt(p), "{p}");
        }
        assert!(!is_otp_prompt("Enter your pin", None));
        assert!(is_otp_prompt("Enter your pin", Some("pin")));
        assert!(is_otp_prompt("Enter your pin", Some(r"\bPIN\b")));
        assert!(!is_otp_prompt("Enter your pin", Some("[invalid")));
        assert!(is_otp_prompt("Enter your [invalid thing", Some("[invalid")));
    }

    #[test]
    fn totp_from_fixed_secret_and_time() {
        // RFC 6238 test vector (SHA1, 8 digits, ASCII secret "12345678901234567890").
        let uri = "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&digits=8&period=30&algorithm=SHA1";
        assert_eq!(totp_code_at(uri, 59).unwrap(), "94287082");
        assert_eq!(totp_code_at(uri, 1111111109).unwrap(), "07081804");
        assert_eq!(totp_code_at(uri, 1234567890).unwrap(), "89005924");
        // Default 6 digits.
        let uri6 =
            "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";
        assert_eq!(totp_code_at(uri6, 59).unwrap(), "287082");
        assert!(totp_code(uri6).unwrap().len() == 6);
        assert!(totp_code_at("", 0).is_err());
        assert!(totp_code_at("enc:v1:abc", 0).is_err());
        assert!(totp_code_at("otpauth://totp/x?issuer=y", 0).is_err());
    }

    #[test]
    fn method_order_follows_auth_method() {
        let mut hop = HopOptions::default();
        assert_eq!(
            method_order(&hop),
            vec![
                Method::PublicKey,
                Method::KeyboardInteractive,
                Method::Password
            ]
        );
        hop.auth_method = HostAuthMethod::Password;
        assert_eq!(
            method_order(&hop),
            vec![Method::Password, Method::KeyboardInteractive]
        );
        hop.requires_mfa = true;
        assert_eq!(
            method_order(&hop),
            vec![Method::KeyboardInteractive, Method::Password]
        );
        hop.auth_method = HostAuthMethod::Key;
        assert_eq!(
            method_order(&hop),
            vec![Method::PublicKey, Method::KeyboardInteractive]
        );
    }

    #[test]
    fn auto_answer_fills_password_once_and_totp() {
        let uri =
            "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";
        let hop = HopOptions {
            password: Some("pw".into()),
            totp: Some(netcatty_core::models::HostTotpConfig {
                uri: uri.into(),
                auto_submit: None,
                prompt_pattern: None,
            }),
            ..Default::default()
        };
        let cb: Arc<dyn SshCallbacks> = Arc::new(UnattendedCallbacks);
        let mut state = AuthState {
            hop: &hop,
            callbacks: &cb,
            remaining: None,
            tried: vec![],
            reasons: vec![],
            rsa_hash: None,
            password_used: false,
        };
        let prompts = vec![
            KeyboardInteractivePrompt {
                prompt: "Password: ".into(),
                echo: false,
            },
            KeyboardInteractivePrompt {
                prompt: "Verification code: ".into(),
                echo: true,
            },
        ];
        let answers = auto_answer(&mut state, &prompts).unwrap();
        assert_eq!(answers[0], "pw");
        assert_eq!(answers[1].len(), 6);
        // Second password prompt is not auto-filled (wrong saved password loop guard).
        assert!(auto_answer(&mut state, &prompts[..1]).is_none());
        // Unknown prompt needs the user.
        state.password_used = false;
        let other = vec![KeyboardInteractivePrompt {
            prompt: "Favourite colour?".into(),
            echo: true,
        }];
        assert!(auto_answer(&mut state, &other).is_none());
        // OTP prompt without TOTP configured needs the user.
        let hop2 = HopOptions {
            password: Some("pw".into()),
            ..Default::default()
        };
        let mut state2 = AuthState {
            hop: &hop2,
            callbacks: &cb,
            remaining: None,
            tried: vec![],
            reasons: vec![],
            rsa_hash: None,
            password_used: false,
        };
        assert!(auto_answer(&mut state2, &prompts[1..]).is_none());
    }

    #[test]
    fn key_text_normalisation() {
        let s = normalize_key_text("  -----BEGIN X-----\r\nabc  \r\n-----END X-----");
        assert_eq!(s, "-----BEGIN X-----\nabc\n-----END X-----\n");
        assert!(expand_tilde("~/.ssh/id_rsa").ends_with(".ssh/id_rsa"));
        assert!(!expand_tilde("~/.ssh/id_rsa").starts_with('~'));
        assert_eq!(expand_tilde("/abs"), "/abs");
    }

    struct CountingPassphrase {
        answers: std::sync::Mutex<Vec<Option<String>>>,
        calls: AtomicUsize,
        last_invalid: std::sync::Mutex<Option<bool>>,
    }

    #[async_trait]
    impl SshCallbacks for CountingPassphrase {
        async fn verify_host_key(&self, _i: crate::HostKeyInfo) -> crate::HostKeyDecision {
            crate::HostKeyDecision::Reject
        }
        async fn keyboard_interactive(
            &self,
            _n: String,
            _i: String,
            _p: Vec<KeyboardInteractivePrompt>,
        ) -> Option<Vec<String>> {
            None
        }
        async fn request_passphrase(&self, _k: String, invalid: bool) -> Option<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.last_invalid.lock().unwrap() = Some(invalid);
            let mut a = self.answers.lock().unwrap();
            if a.is_empty() {
                None
            } else {
                a.remove(0)
            }
        }
    }

    fn encrypted_key() -> String {
        let r = crate::keygen::generate_key_pair(&netcatty_core::ipc::GenerateKeyPairOptions {
            key_type: netcatty_core::models::KeyType::Ed25519,
            bits: None,
            comment: None,
            passphrase: Some("correct".into()),
        })
        .unwrap();
        r.private_key.unwrap()
    }

    #[tokio::test]
    async fn load_private_key_prompts_until_correct() {
        let text = encrypted_key();
        let cb = Arc::new(CountingPassphrase {
            answers: std::sync::Mutex::new(vec![Some("wrong".into()), Some("correct".into())]),
            calls: AtomicUsize::new(0),
            last_invalid: std::sync::Mutex::new(None),
        });
        let dynamic: Arc<dyn SshCallbacks> = cb.clone();
        let key = load_private_key(&text, None, "test key", &dynamic)
            .await
            .unwrap();
        assert!(key.is_some());
        assert_eq!(cb.calls.load(Ordering::SeqCst), 2);
        assert_eq!(*cb.last_invalid.lock().unwrap(), Some(true));
    }

    #[tokio::test]
    async fn load_private_key_uses_configured_passphrase_then_gives_up() {
        let text = encrypted_key();
        let cb: Arc<dyn SshCallbacks> = Arc::new(UnattendedCallbacks);
        assert!(load_private_key(&text, Some("correct"), "k", &cb)
            .await
            .unwrap()
            .is_some());
        // Wrong configured passphrase, user declines → skipped (None).
        assert!(load_private_key(&text, Some("nope"), "k", &cb)
            .await
            .unwrap()
            .is_none());
        // Three wrong answers → error.
        let cb3 = Arc::new(CountingPassphrase {
            answers: std::sync::Mutex::new(vec![
                Some("a".into()),
                Some("b".into()),
                Some("c".into()),
                Some("d".into()),
            ]),
            calls: AtomicUsize::new(0),
            last_invalid: std::sync::Mutex::new(None),
        });
        let dynamic: Arc<dyn SshCallbacks> = cb3.clone();
        let err = load_private_key(&text, None, "k", &dynamic)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, SshError::Key(m) if m.contains("3 times")));
        assert_eq!(cb3.calls.load(Ordering::SeqCst), MAX_PASSPHRASE_ATTEMPTS);
        // Garbage is an error, not a prompt.
        assert!(matches!(
            load_private_key("not a key", None, "k", &cb).await,
            Err(SshError::Key(_))
        ));
    }
}
