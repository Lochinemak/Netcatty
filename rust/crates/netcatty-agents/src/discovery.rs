//! Agent discovery, CLI resolution and Codex integration / login (Electron:
//! `aiBridge/agentDiscoveryHandlers.cjs`, `agentCliHelpers.cjs`).
//!
//! The Cursor SDK (`@cursor/sdk`, API-key mode) is a Node package and is not
//! available in the Rust build, so Cursor is discovered through the Cursor
//! Agent CLI login only (`sdkInstalled: false`).

use crate::auth::{
    probe_claude_auth, probe_codebuddy_auth, probe_copilot_auth, probe_cursor_cli_auth, probe_grok_auth, probe_home,
    AuthProbe, CursorCliAuth, ProbeIo,
};
use crate::cli::{
    add_codex_executable_env_for_sdk, is_plausible_cli_version_output, normalize_cli_path_for_platform,
    probe_cli_version, resolve_cli_from_path, resolve_codex_executable_for_sdk, run_command, CommandResult,
    DEFAULT_CODEX_CLI_TIMEOUT,
};
use crate::codex_helpers::{
    append_codex_chatgpt_validation_failure, append_codex_login_output, is_codex_auth_error,
    normalize_codex_integration_state, prune_codex_login_sessions, read_codex_custom_provider_config,
    CodexLoginSession, CodexLoginSessionResponse, CodexLoginState, CODEX_LOGIN_KILL_GRACE_MS,
};
use crate::EnvMap;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;

struct KnownAgent {
    command: &'static str,
    name: &'static str,
    icon: &'static str,
    description: &'static str,
    sdk_backend: &'static str,
}

const KNOWN_AGENTS: &[KnownAgent] = &[
    KnownAgent { command: "claude", name: "Claude Code", icon: "claude", description: "Anthropic's agentic coding assistant", sdk_backend: "claude" },
    KnownAgent { command: "codex", name: "Codex CLI", icon: "openai", description: "OpenAI's coding agent", sdk_backend: "codex" },
    KnownAgent { command: "copilot", name: "GitHub Copilot CLI", icon: "copilot", description: "GitHub's coding agent CLI", sdk_backend: "copilot" },
    KnownAgent { command: "cursor", name: "Cursor", icon: "cursor", description: "Cursor's coding agent via Cursor SDK", sdk_backend: "cursor" },
    KnownAgent { command: "codebuddy", name: "CodeBuddy Code", icon: "codebuddy", description: "Tencent's coding agent CLI (Agent SDK)", sdk_backend: "codebuddy" },
    KnownAgent { command: "opencode", name: "OpenCode", icon: "opencode", description: "Open source coding agent via the official OpenCode SDK", sdk_backend: "opencode" },
    KnownAgent { command: "grok", name: "Grok Build", icon: "grok", description: "xAI's Grok Build coding agent CLI", sdk_backend: "grok" },
    KnownAgent { command: "mimo", name: "MiMo Code", icon: "mimo", description: "Xiaomi's MiMo Code CLI, an OpenCode fork", sdk_backend: "mimo" },
];

/// `probeCursorSdkAvailability` without the Node SDK.
#[derive(Debug, Clone, Default)]
pub struct CursorStatus {
    pub installed: bool,
    pub sdk_installed: bool,
    pub available: bool,
    pub authenticated: bool,
    pub auth_source: Option<String>,
    pub api_key_ok: bool,
    pub cli_login_ok: bool,
    pub version: Option<String>,
    pub cli_bin_path: Option<String>,
    pub cli_email: Option<String>,
}

/// Compute the Cursor status from the probes (SDK never importable here).
pub fn compute_cursor_status(shell_env: &EnvMap, api_key_present: bool, cli: CursorCliAuth) -> CursorStatus {
    let has_env_key = shell_env.get("CURSOR_API_KEY").map(|v| !v.is_empty()).unwrap_or(false);
    let api_key_ok = api_key_present || has_env_key;
    let cli_login_ok = cli.authenticated;
    let auth_source = if api_key_present {
        Some("settings".to_string())
    } else if has_env_key {
        Some("CURSOR_API_KEY".to_string())
    } else if cli_login_ok {
        Some("cli-login".to_string())
    } else {
        None
    };
    let sdk_installed = false;
    CursorStatus {
        installed: cli.bin_path.is_some() || cli_login_ok,
        sdk_installed,
        available: (api_key_ok && sdk_installed) || cli_login_ok,
        authenticated: api_key_ok || cli_login_ok,
        auth_source,
        api_key_ok,
        cli_login_ok,
        version: (cli_login_ok || cli.bin_path.is_some()).then(|| "Cursor Agent CLI".to_string()),
        cli_bin_path: cli.bin_path,
        cli_email: cli.email,
    }
}

pub async fn probe_cursor_status(shell_env: &EnvMap, api_key_present: bool) -> CursorStatus {
    compute_cursor_status(shell_env, api_key_present, probe_cursor_cli_auth(shell_env).await)
}

/// `netcatty:ai:agents:discover`.
pub async fn discover_agents(shell_env: &EnvMap, api_key_present: bool) -> Vec<Value> {
    let mut agents = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let home = probe_home(shell_env);
    for agent in KNOWN_AGENTS {
        let mut cursor: Option<CursorStatus> = None;
        if agent.command == "cursor" {
            let status = probe_cursor_status(shell_env, api_key_present).await;
            if !status.available {
                continue;
            }
            cursor = Some(status);
        }
        let resolved = match &cursor {
            Some(status) => Some(if status.cli_login_ok {
                status.cli_bin_path.clone().unwrap_or_else(|| "cursor".into())
            } else {
                status.cli_bin_path.clone().unwrap_or_else(|| "cursor".into())
            }),
            None => resolve_cli_from_path(agent.command, shell_env).await,
        };
        let Some(resolved) = resolved else { continue };
        if seen.contains(&resolved) {
            continue;
        }
        let (exit_code, version) = match &cursor {
            Some(status) => (Some(0), status.version.clone().unwrap_or_default()),
            None => {
                let probe = probe_cli_version(&resolved, &["--version".into()], shell_env).await;
                (probe.exit_code, probe.version)
            }
        };
        let plausible = if cursor.is_some() { exit_code == Some(0) } else { exit_code == Some(0) && is_plausible_cli_version_output(&version) };
        if !plausible {
            continue;
        }
        let auth = match agent.command {
            "claude" => probe_claude_auth(shell_env, &ProbeIo { home: home.clone(), ..ProbeIo::default() }),
            "copilot" => probe_copilot_auth(shell_env).await,
            "codex" => AuthProbe::no(),
            "cursor" => {
                let status = cursor.as_ref().unwrap();
                AuthProbe { authenticated: status.authenticated, auth_source: status.auth_source.clone() }
            }
            "codebuddy" => probe_codebuddy_auth(shell_env, &home),
            "opencode" => AuthProbe::yes("opencode-config"),
            "mimo" => AuthProbe::yes("mimo-config"),
            "grok" => probe_grok_auth(shell_env, &home),
            _ => AuthProbe::no(),
        };
        let mut entry = json!({
            "command": agent.command,
            "name": agent.name,
            "icon": agent.icon,
            "description": agent.description,
            "sdkBackend": agent.sdk_backend,
            "args": [],
            "path": resolved,
            "binPath": resolved,
            "version": version,
            "installed": cursor.as_ref().map(|c| c.installed).unwrap_or(true),
            "available": true,
            "authenticated": auth.authenticated,
            "authSource": auth.auth_source,
        });
        if let Some(status) = &cursor {
            let obj = entry.as_object_mut().unwrap();
            obj.insert("cliEmail".into(), json!(status.cli_email));
            obj.insert("cliBinPath".into(), json!(status.cli_bin_path));
            obj.insert("cliLoginOk".into(), json!(status.cli_login_ok));
            obj.insert("apiKeyOk".into(), json!(status.api_key_ok));
            obj.insert("sdkInstalled".into(), json!(status.sdk_installed));
        }
        agents.push(entry);
        seen.insert(resolved);
    }
    agents
}

/// `netcatty:ai:resolve-cli`.
pub async fn resolve_cli(command: &str, custom_path: Option<&str>, shell_env: &EnvMap, api_key_present: bool) -> Value {
    let custom = custom_path.map(str::trim).filter(|p| !p.is_empty());
    if command == "cursor" {
        let status = probe_cursor_status(shell_env, api_key_present).await;
        let resolved_sdk = resolve_cli_from_path(command, shell_env).await;
        let cursor_path = if status.cli_login_ok {
            status.cli_bin_path.clone().or(resolved_sdk).unwrap_or_else(|| "cursor".into())
        } else {
            resolved_sdk.unwrap_or_else(|| "cursor".into())
        };
        let has = status.sdk_installed || status.installed || status.available;
        return json!({
            "path": has.then(|| cursor_path.clone()),
            "binPath": has.then_some(cursor_path),
            "version": status.version,
            "available": status.available,
            "installed": status.installed,
            "authenticated": status.authenticated,
            "authSource": status.auth_source,
            "cliEmail": status.cli_email,
            "cliBinPath": status.cli_bin_path,
            "cliLoginOk": status.cli_login_ok,
            "apiKeyOk": status.api_key_ok,
            "sdkInstalled": status.sdk_installed,
        });
    }
    let resolved = match custom {
        Some(path) => normalize_cli_path_for_platform(path),
        None => resolve_cli_from_path(command, shell_env).await,
    };
    let Some(resolved) = resolved else {
        return json!({ "path": null, "binPath": null, "version": null, "available": false, "installed": false });
    };
    let probe = probe_cli_version(&resolved, &["--version".into()], shell_env).await;
    if !(probe.exit_code == Some(0) && is_plausible_cli_version_output(&probe.version)) {
        return json!({ "path": resolved, "binPath": resolved, "version": null, "available": false, "installed": true });
    }
    json!({ "path": resolved, "binPath": resolved, "version": probe.version, "available": true, "installed": true })
}

// ── Codex CLI ──

/// `runCodexCli`: configured path (validated), else PATH, else `codex`.
pub async fn run_codex_cli(args: &[&str], codex_path: Option<&str>, env: &EnvMap, timeout: Duration) -> Result<CommandResult, String> {
    let requested = codex_path.map(str::trim).filter(|p| !p.is_empty());
    let configured = match requested {
        Some(path) => Some(normalize_cli_path_for_platform(path).ok_or_else(|| format!("Codex CLI path not found: {path}"))?),
        None => None,
    };
    let cli = match configured {
        Some(p) => p,
        None => resolve_cli_from_path("codex", env).await.unwrap_or_else(|| "codex".into()),
    };
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    run_command(&cli, &args, env, None, Some(timeout)).await.map_err(|e| e.to_string())
}

#[derive(Debug, Clone)]
pub struct CodexValidation {
    pub ok: bool,
    pub checked_at: Instant,
    pub error: Option<String>,
    pub code: Option<String>,
}

/// Validation cache keyed by (codexPath, sha256(sorted env)); raw env never kept.
#[derive(Default)]
pub struct CodexValidationCache {
    inner: tokio::sync::Mutex<Option<(String, CodexValidation)>>,
}

impl CodexValidationCache {
    pub fn invalidate(&self) {
        if let Ok(mut guard) = self.inner.try_lock() {
            *guard = None;
        }
    }
}

fn env_hash(env: &EnvMap) -> String {
    hex::encode(Sha256::digest(serde_json::to_string(env).unwrap_or_default().as_bytes()))
}

/// Minimal read-only probe turn (`codex exec --experimental-json` "ping") to
/// confirm ChatGPT auth works (`validateCodexChatGptAuth`).
pub async fn validate_codex_chatgpt_auth(cache: &CodexValidationCache, codex_path: Option<&str>, env: &EnvMap, max_age: Duration) -> CodexValidation {
    let now = Instant::now();
    let raw_requested = codex_path.map(str::trim).filter(|p| !p.is_empty());
    let requested = raw_requested.and_then(normalize_cli_path_for_platform);
    if let (Some(raw), None) = (raw_requested, &requested) {
        return CodexValidation { ok: false, checked_at: now, error: Some(format!("Codex CLI path not found: {raw}")), code: Some("ENOENT".into()) };
    }
    let key = format!("{}\0{}", requested.clone().unwrap_or_default(), env_hash(env));
    let mut guard = cache.inner.lock().await;
    if let Some((cached_key, cached)) = guard.as_ref() {
        if *cached_key == key && cached.checked_at.elapsed() < max_age {
            return cached.clone();
        }
    }
    let raw = match requested {
        Some(p) => Some(p),
        None => crate::cli::resolve_sdk_bin_path("codex", env).await,
    };
    let codex = raw.as_deref().and_then(resolve_codex_executable_for_sdk);
    let result = match codex {
        None => CodexValidation { ok: false, checked_at: now, error: Some("codex binary not found".into()), code: Some("ENOENT".into()) },
        Some(codex) => {
            let probe_env = add_codex_executable_env_for_sdk(env.clone(), Some(&codex));
            match tokio::time::timeout(Duration::from_millis(10_000), codex_ping(&codex, &probe_env)).await {
                Ok(Ok(())) => CodexValidation { ok: true, checked_at: now, error: None, code: None },
                Ok(Err(message)) => CodexValidation { ok: false, checked_at: now, error: Some(message), code: None },
                Err(_) => CodexValidation { ok: false, checked_at: now, error: Some("Codex ChatGPT auth validation timed out after 10000ms".into()), code: Some("ETIMEDOUT".into()) },
            }
        }
    };
    *guard = Some((key, result.clone()));
    result
}

async fn codex_ping(codex: &str, env: &EnvMap) -> Result<(), String> {
    let mut env = env.clone();
    env.entry("CODEX_INTERNAL_ORIGINATOR_OVERRIDE".into()).or_insert_with(|| "codex_sdk_ts".into());
    let spec = crate::cli::SpawnSpec {
        command: codex.to_string(),
        args: ["exec", "--experimental-json", "--sandbox", "read-only", "--skip-git-repo-check"].iter().map(|s| s.to_string()).collect(),
        shell: false,
    };
    let mut spawned = crate::process::spawn_lines(&spec, &env, None, crate::process::Stdin::Piped, 16 * 1024 * 1024, 16 * 1024).map_err(|e| e.to_string())?;
    if let Some(mut stdin) = spawned.child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let _ = stdin.write_all(b"ping").await;
    }
    let mut failed: Option<String> = None;
    while let Ok(Some(line)) = spawned.stdout.next_line().await {
        let Ok(event) = serde_json::from_str::<Value>(&line) else { continue };
        match event.get("type").and_then(|t| t.as_str()) {
            Some("turn.failed") => {
                failed = Some(event["error"]["message"].as_str().unwrap_or("Codex turn failed").to_string());
                break;
            }
            Some("turn.completed") | Some("item.completed") => break,
            _ => {}
        }
    }
    crate::process::terminate_child(&mut spawned.child, Duration::from_millis(500)).await;
    match failed {
        Some(message) => Err(message),
        None => Ok(()),
    }
}

/// `netcatty:ai:codex:get-integration`.
pub async fn codex_get_integration(cache: &CodexValidationCache, codex_path: Option<&str>, env: &EnvMap, validate_chatgpt: bool) -> Value {
    let result = match run_codex_cli(&["login", "status"], codex_path, env, DEFAULT_CODEX_CLI_TIMEOUT).await {
        Ok(result) => result,
        Err(message) => {
            return json!({ "state": "unknown", "isConnected": false, "rawOutput": message, "exitCode": null, "customConfig": null });
        }
    };
    let raw_output = result.output();
    let mut state = normalize_codex_integration_state(&raw_output);
    let mut effective_raw = raw_output.clone();
    if state == "connected_chatgpt" && validate_chatgpt {
        let validation = validate_codex_chatgpt_auth(cache, codex_path, env, Duration::from_millis(10_000)).await;
        if !validation.ok {
            let message = validation.error.clone().unwrap_or_default();
            if is_codex_auth_error(validation.code.as_deref(), &message) {
                let _ = run_codex_cli(&["logout"], codex_path, env, DEFAULT_CODEX_CLI_TIMEOUT).await;
                cache.invalidate();
                state = "not_logged_in";
            }
            effective_raw = append_codex_chatgpt_validation_failure(&raw_output, &message);
        }
    }
    let custom = read_codex_custom_provider_config(env);
    if custom.is_some() && state != "connected_chatgpt" {
        state = "connected_custom_config";
    }
    json!({
        "state": state,
        "isConnected": matches!(state, "connected_chatgpt" | "connected_api_key" | "connected_custom_config"),
        "rawOutput": effective_raw,
        "exitCode": result.exit_code,
        "customConfig": custom,
    })
}

/// `netcatty:ai:codex:logout`.
pub async fn codex_logout(cache: &CodexValidationCache, codex_path: Option<&str>, env: &EnvMap) -> Value {
    let logout = match run_codex_cli(&["logout"], codex_path, env, DEFAULT_CODEX_CLI_TIMEOUT).await {
        Ok(r) => r,
        Err(error) => return json!({ "ok": false, "error": error }),
    };
    cache.invalidate();
    let status = match run_codex_cli(&["login", "status"], codex_path, env, DEFAULT_CODEX_CLI_TIMEOUT).await {
        Ok(r) => r,
        Err(error) => return json!({ "ok": false, "error": error }),
    };
    let raw = status.output();
    let state = normalize_codex_integration_state(&raw);
    json!({
        "ok": true,
        "state": state,
        "isConnected": matches!(state, "connected_chatgpt" | "connected_api_key" | "connected_custom_config"),
        "rawOutput": raw,
        "logoutOutput": logout.output(),
    })
}

// ── `codex login` sessions ──

struct LoginEntry {
    session: CodexLoginSession,
    pid: Option<u32>,
}

/// Running / finished `codex login` processes.
#[derive(Default)]
pub struct CodexLoginManager {
    entries: Arc<parking_lot::Mutex<Vec<LoginEntry>>>,
}

impl CodexLoginManager {
    fn with_session<T>(&self, id: &str, f: impl FnOnce(&mut CodexLoginSession) -> T) -> Option<T> {
        let mut entries = self.entries.lock();
        entries.iter_mut().find(|e| e.session.id == id).map(|e| f(&mut e.session))
    }

    fn record(&self) {
        let mut entries = self.entries.lock();
        let mut sessions: Vec<CodexLoginSession> = entries.iter().map(|e| e.session.clone()).collect();
        prune_codex_login_sessions(&mut sessions);
        entries.retain(|e| sessions.iter().any(|s| s.id == e.session.id));
    }

    pub fn get(&self, id: &str) -> Option<CodexLoginSessionResponse> {
        self.entries.lock().iter().find(|e| e.session.id == id).map(|e| e.session.response())
    }

    /// `netcatty:ai:codex:start-login`.
    pub async fn start(&self, codex_path: Option<&str>, env: &EnvMap, cache: &CodexValidationCache) -> Value {
        let requested = codex_path.map(str::trim).filter(|p| !p.is_empty());
        let requested_path = match requested {
            Some(path) => match normalize_cli_path_for_platform(path) {
                Some(p) => Some(p),
                None => return json!({ "ok": false, "error": format!("Codex CLI path not found: {path}") }),
            },
            None => None,
        };
        let cli = match requested_path {
            Some(p) => p,
            None => resolve_cli_from_path("codex", env).await.unwrap_or_else(|| "codex".into()),
        };
        let credential_home_key = env
            .get("CODEX_HOME")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| crate::env::env_home(env).join(".codex").to_string_lossy().into_owned());
        {
            let entries = self.entries.lock();
            if let Some(active) = entries.iter().find(|e| e.session.state == CodexLoginState::Running && e.session.process_alive) {
                if active.session.codex_path.as_deref().map(|p| p != cli).unwrap_or(false) {
                    return json!({ "ok": false, "error": "A Codex login is already running for a different CLI path." });
                }
                if active.session.credential_home_key != credential_home_key {
                    return json!({ "ok": false, "error": "A Codex login is already running for a different credential home." });
                }
                return json!({ "ok": true, "session": active.session.response() });
            }
        }
        let id = format!("codex_login_{}", uuid::Uuid::new_v4());
        let spec = crate::cli::prepare_command_for_spawn(&cli, &["login".into()], true);
        let mut cmd = crate::process::build_command(&spec, env, None, crate::process::Stdin::Null);
        let mut session = CodexLoginSession {
            id: id.clone(),
            state: CodexLoginState::Running,
            output: String::new(),
            url: None,
            error: None,
            exit_code: None,
            codex_path: Some(cli.clone()),
            credential_home_key,
            process_alive: true,
        };
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(error) => {
                session.state = CodexLoginState::Error;
                session.error = Some(format!("[codex] Failed to start login flow: {error}"));
                session.process_alive = false;
                let response = session.response();
                self.entries.lock().push(LoginEntry { session, pid: None });
                self.record();
                return json!({ "ok": true, "session": response });
            }
        };
        let pid = child.id();
        let response = session.response();
        self.entries.lock().push(LoginEntry { session, pid });
        self.record();
        cache.invalidate();
        let entries = self.entries.clone();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let pump = |reader: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>>, entries: Arc<parking_lot::Mutex<Vec<LoginEntry>>>, id: String| async move {
            let Some(mut reader) = reader else { return };
            let mut buf = [0u8; 4096];
            let mut pending: Vec<u8> = Vec::new();
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        pending.extend_from_slice(&buf[..n]);
                        let valid = match std::str::from_utf8(&pending) {
                            Ok(_) => pending.len(),
                            Err(e) => e.valid_up_to(),
                        };
                        let text = String::from_utf8_lossy(&pending[..valid]).into_owned();
                        pending.drain(..valid);
                        let mut guard = entries.lock();
                        if let Some(entry) = guard.iter_mut().find(|e| e.session.id == id) {
                            append_codex_login_output(&mut entry.session, &text);
                        }
                    }
                }
            }
        };
        let out_task = tokio::spawn(pump(stdout.map(|s| Box::new(s) as _), entries.clone(), id.clone()));
        let err_task = tokio::spawn(pump(stderr.map(|s| Box::new(s) as _), entries.clone(), id.clone()));
        let entries_for_exit = entries.clone();
        tokio::spawn(async move {
            let status = child.wait().await;
            let _ = out_task.await;
            let _ = err_task.await;
            let mut guard = entries_for_exit.lock();
            if let Some(entry) = guard.iter_mut().find(|e| e.session.id == id) {
                let code = status.ok().and_then(|s| s.code());
                entry.session.exit_code = code;
                entry.session.process_alive = false;
                entry.pid = None;
                if entry.session.state != CodexLoginState::Cancelled {
                    if code == Some(0) {
                        entry.session.state = CodexLoginState::Success;
                        entry.session.error = None;
                    } else {
                        entry.session.state = CodexLoginState::Error;
                        if entry.session.error.is_none() {
                            entry.session.error = Some(format!(
                                "Codex login exited with code {}",
                                code.map(|c| c.to_string()).unwrap_or_else(|| "unknown".into())
                            ));
                        }
                    }
                }
            }
        });
        json!({ "ok": true, "session": response })
    }

    /// `netcatty:ai:codex:cancel-login`: SIGTERM, SIGKILL after the grace period.
    pub fn cancel(&self, id: &str, cache: &CodexValidationCache) -> Value {
        let pid = {
            let mut entries = self.entries.lock();
            let Some(entry) = entries.iter_mut().find(|e| e.session.id == id) else {
                return json!({ "ok": true, "found": false });
            };
            entry.session.state = CodexLoginState::Cancelled;
            entry.session.error = None;
            entry.pid
        };
        if pid.is_some() {
            crate::process::signal_process_tree(pid, false);
            let entries = self.entries.clone();
            let id_owned = id.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(CODEX_LOGIN_KILL_GRACE_MS)).await;
                let still = entries.lock().iter().find(|e| e.session.id == id_owned).and_then(|e| e.pid);
                if still.is_some() {
                    crate::process::signal_process_tree(still, true);
                }
            });
        }
        cache.invalidate();
        let response = self.with_session(id, |s| s.response());
        json!({ "ok": true, "found": true, "session": response })
    }

    /// Kill every running login (app shutdown).
    pub fn shutdown(&self) {
        for entry in self.entries.lock().iter() {
            crate::process::signal_process_tree(entry.pid, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_status_without_sdk() {
        let env = EnvMap::new();
        let none = compute_cursor_status(&env, true, CursorCliAuth::default());
        assert!(!none.available);
        assert!(none.api_key_ok);
        assert_eq!(none.auth_source.as_deref(), Some("settings"));
        let cli = CursorCliAuth { authenticated: true, auth_source: Some("cli-login".into()), email: Some("a@b".into()), bin_path: Some("/x/cursor-agent".into()) };
        let ok = compute_cursor_status(&env, false, cli);
        assert!(ok.available && ok.installed && ok.cli_login_ok);
        assert_eq!(ok.auth_source.as_deref(), Some("cli-login"));
        assert_eq!(ok.version.as_deref(), Some("Cursor Agent CLI"));
        let installed_only = compute_cursor_status(&env, false, CursorCliAuth { bin_path: Some("/x".into()), ..Default::default() });
        assert!(installed_only.installed && !installed_only.available);
    }

    #[cfg(unix)]
    fn fake_bin(dir: &std::path::Path, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[cfg(unix)]
    fn path_env(dir: &std::path::Path, home: &std::path::Path) -> EnvMap {
        [
            ("PATH".to_string(), format!("{}:/usr/bin:/bin", dir.display())),
            ("HOME".to_string(), home.to_string_lossy().into_owned()),
        ]
        .into_iter()
        .collect()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn discovery_finds_fake_clis_and_skips_bad_versions() {
        let bin = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        fake_bin(bin.path(), "claude", "echo '2.1.0 (Claude Code)'");
        fake_bin(bin.path(), "codex", "echo 'codex-cli 0.44.0'");
        fake_bin(bin.path(), "grok", "echo 'TypeError: boom 1.0'");
        fake_bin(bin.path(), "opencode", "exit 1");
        let mut env = path_env(bin.path(), home.path());
        env.insert("ANTHROPIC_API_KEY".into(), "k".into());
        let agents = discover_agents(&env, false).await;
        let commands: Vec<&str> = agents.iter().map(|a| a["command"].as_str().unwrap()).collect();
        assert_eq!(commands, vec!["claude", "codex"]);
        assert_eq!(agents[0]["authenticated"], true);
        assert_eq!(agents[0]["authSource"], "env");
        assert_eq!(agents[0]["sdkBackend"], "claude");
        assert_eq!(agents[1]["version"], "codex-cli 0.44.0");
        assert_eq!(agents[1]["authenticated"], false);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn resolve_cli_variants() {
        let bin = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let ok = fake_bin(bin.path(), "codex", "echo '0.44.0'");
        let broken = fake_bin(bin.path(), "broken", "exit 2");
        let env = path_env(bin.path(), home.path());
        let r = resolve_cli("codex", None, &env, false).await;
        assert_eq!(r["available"], true);
        assert_eq!(r["path"], ok);
        let r = resolve_cli("codex", Some(&broken), &env, false).await;
        assert_eq!((r["available"].clone(), r["installed"].clone()), (json!(false), json!(true)));
        let r = resolve_cli("codex", Some("/nonexistent/codex"), &env, false).await;
        assert_eq!(r["installed"], false);
        let r = resolve_cli("cursor", None, &env, false).await;
        assert_eq!(r["available"], false);
        assert_eq!(r["sdkInstalled"], false);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn codex_integration_and_logout() {
        let bin = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let state = bin.path().join("state");
        std::fs::write(&state, "Logged in using an API key").unwrap();
        fake_bin(bin.path(), "codex", &format!("case \"$1\" in login) cat '{0}';; logout) echo 'Successfully logged out'; echo 'Not logged in' > '{0}';; esac", state.display()));
        let env = path_env(bin.path(), home.path());
        let cache = CodexValidationCache::default();
        let info = codex_get_integration(&cache, None, &env, false).await;
        assert_eq!(info["state"], "connected_api_key");
        assert_eq!(info["isConnected"], true);
        assert_eq!(info["exitCode"], 0);
        let out = codex_logout(&cache, None, &env).await;
        assert_eq!(out["ok"], true);
        assert_eq!(out["state"], "not_logged_in");
        assert_eq!(out["logoutOutput"], "Successfully logged out");
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(home.path().join(".codex/config.toml"), "model_provider = \"p\"\n[model_providers.p]\nname = \"P\"\n").unwrap();
        let info = codex_get_integration(&cache, None, &env, false).await;
        assert_eq!(info["state"], "connected_custom_config");
        assert_eq!(info["customConfig"]["displayName"], "P");
        let missing = codex_get_integration(&cache, Some("/nonexistent/codex"), &env, false).await;
        assert_eq!(missing["state"], "unknown");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn codex_login_session_lifecycle() {
        let bin = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        fake_bin(bin.path(), "codex", "echo 'Open https://auth.openai.com/oauth?x=1 to log in'; sleep 30");
        let env = path_env(bin.path(), home.path());
        let cache = CodexValidationCache::default();
        let manager = CodexLoginManager::default();
        let started = manager.start(None, &env, &cache).await;
        assert_eq!(started["ok"], true);
        let id = started["session"]["sessionId"].as_str().unwrap().to_string();
        let again = manager.start(None, &env, &cache).await;
        assert_eq!(again["session"]["sessionId"], id);
        let mut url = None;
        for _ in 0..50 {
            url = manager.get(&id).and_then(|s| s.url);
            if url.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(url.as_deref(), Some("https://auth.openai.com/oauth?x=1"));
        let cancelled = manager.cancel(&id, &cache);
        assert_eq!(cancelled["found"], true);
        assert_eq!(cancelled["session"]["state"], "cancelled");
        for _ in 0..60 {
            if manager.entries.lock().iter().all(|e| !e.session.process_alive) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(manager.get(&id).unwrap().state, CodexLoginState::Cancelled);
        assert_eq!(manager.cancel("nope", &cache)["found"], false);

        fake_bin(bin.path(), "codex", "echo done; exit 0");
        let ok = manager.start(None, &env, &cache).await;
        let id2 = ok["session"]["sessionId"].as_str().unwrap().to_string();
        for _ in 0..60 {
            if manager.get(&id2).map(|s| s.state == CodexLoginState::Success).unwrap_or(false) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let done = manager.get(&id2).unwrap();
        assert_eq!(done.state, CodexLoginState::Success);
        assert_eq!(done.exit_code, Some(0));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn chatgpt_validation_via_exec_probe() {
        let bin = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let codex = fake_bin(bin.path(), "codex", "cat >/dev/null; echo '{\"type\":\"thread.started\",\"thread_id\":\"t\"}'; echo '{\"type\":\"turn.failed\",\"error\":{\"message\":\"401 Unauthorized\"}}'");
        let env = path_env(bin.path(), home.path());
        let cache = CodexValidationCache::default();
        let v = validate_codex_chatgpt_auth(&cache, Some(&codex), &env, Duration::from_secs(10)).await;
        assert!(!v.ok);
        assert!(is_codex_auth_error(v.code.as_deref(), v.error.as_deref().unwrap()));
        fake_bin(bin.path(), "codex", "cat >/dev/null; echo '{\"type\":\"turn.completed\"}'");
        let cached = validate_codex_chatgpt_auth(&cache, Some(&codex), &env, Duration::from_secs(10)).await;
        assert!(!cached.ok, "served from cache");
        cache.invalidate();
        let fresh = validate_codex_chatgpt_auth(&cache, Some(&codex), &env, Duration::from_secs(10)).await;
        assert!(fresh.ok);
    }
}
