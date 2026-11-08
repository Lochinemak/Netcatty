//! Layer-3 authentication probes (Electron: `aiBridge/agentAuthProbes.cjs`,
//! `ai/claudeAuth.cjs`). Best effort; never block discovery.

use crate::cli::{resolve_cursor_cli_spawn_spec, run_command, strip_ansi};
use crate::env::{env_home, expand_home_path};
use crate::EnvMap;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthProbe {
    pub authenticated: bool,
    pub auth_source: Option<String>,
}

impl AuthProbe {
    pub fn yes(source: &str) -> Self {
        Self { authenticated: true, auth_source: Some(source.to_string()) }
    }
    pub fn no() -> Self {
        Self::default()
    }
}

fn env_str<'a>(env: &'a EnvMap, key: &str) -> &'a str {
    env.get(key).map(|v| v.trim()).unwrap_or("")
}

/// `getClaudeConfigDir`: `CLAUDE_CONFIG_DIR` (with `~` expanded) or `~/.claude`.
pub fn claude_config_dir(env: &EnvMap, home: &Path) -> PathBuf {
    let custom = env_str(env, "CLAUDE_CONFIG_DIR");
    if custom.is_empty() {
        home.join(".claude")
    } else {
        PathBuf::from(expand_home_path(custom))
    }
}

/// `detectClaudeAuthPresence`: `env` | `credentials-file` | `none` (heuristic).
pub fn detect_claude_auth_presence(env: &EnvMap) -> &'static str {
    if !env_str(env, "ANTHROPIC_API_KEY").is_empty() || !env_str(env, "ANTHROPIC_AUTH_TOKEN").is_empty() {
        return "env";
    }
    let home = dirs::home_dir().unwrap_or_default();
    if claude_config_dir(env, &home).join(".credentials.json").exists() {
        return "credentials-file";
    }
    "none"
}

/// Probe input knobs so tests can run without a keychain / real home.
pub struct ProbeIo<'a> {
    pub home: PathBuf,
    pub platform_darwin: bool,
    /// Returns `(exit_code, stdout)` of the macOS keychain lookup.
    pub run_security: &'a dyn Fn() -> (i32, String),
}

impl Default for ProbeIo<'static> {
    fn default() -> Self {
        Self {
            home: dirs::home_dir().unwrap_or_default(),
            platform_darwin: cfg!(target_os = "macos"),
            run_security: &default_run_security,
        }
    }
}

fn default_run_security() -> (i32, String) {
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-s", "Claude Code-credentials", "-w"])
        .stdin(std::process::Stdio::null())
        .output();
    match output {
        Ok(out) => (out.status.code().unwrap_or(1), String::from_utf8_lossy(&out.stdout).into_owned()),
        Err(_) => (1, String::new()),
    }
}

/// Claude: env token, macOS keychain entry, or `.credentials.json`.
pub fn probe_claude_auth(env: &EnvMap, io: &ProbeIo<'_>) -> AuthProbe {
    if !env_str(env, "ANTHROPIC_API_KEY").is_empty()
        || !env_str(env, "CLAUDE_CODE_OAUTH_TOKEN").is_empty()
        || !env_str(env, "ANTHROPIC_AUTH_TOKEN").is_empty()
    {
        return AuthProbe::yes("env");
    }
    if io.platform_darwin {
        let (code, stdout) = (io.run_security)();
        if code == 0 && !stdout.trim().is_empty() {
            return AuthProbe::yes("keychain");
        }
    }
    let config_dir = {
        let custom = env_str(env, "CLAUDE_CONFIG_DIR");
        if custom.is_empty() { io.home.join(".claude") } else { PathBuf::from(custom) }
    };
    if config_dir.join(".credentials.json").exists() {
        return AuthProbe::yes("credentials-file");
    }
    AuthProbe::no()
}

/// Copilot: `gh auth status` exit 0.
pub async fn probe_copilot_auth(env: &EnvMap) -> AuthProbe {
    match run_command("gh", &["auth".into(), "status".into()], env, None, Some(Duration::from_secs(5))).await {
        Ok(result) if result.exit_code == Some(0) => AuthProbe::yes("gh"),
        _ => AuthProbe::no(),
    }
}

/// Codex: `codex login status` output, else `~/.codex/auth.json`.
pub fn probe_codex_auth(login_status_output: Option<&str>, home: &Path) -> AuthProbe {
    let out = login_status_output.unwrap_or("").to_ascii_lowercase();
    if out.contains("logged in using chatgpt") {
        return AuthProbe::yes("chatgpt");
    }
    if out.contains("logged in using an api key") || out.contains("logged in using api key") {
        return AuthProbe::yes("api-key");
    }
    if home.join(".codex").join("auth.json").exists() {
        return AuthProbe::yes("auth-file");
    }
    AuthProbe::no()
}

/// CodeBuddy: `CODEBUDDY_API_KEY` / `CODEBUDDY_AUTH_TOKEN` or `~/.codebuddy/settings.json`.
pub fn probe_codebuddy_auth(env: &EnvMap, home: &Path) -> AuthProbe {
    if !env_str(env, "CODEBUDDY_API_KEY").is_empty() {
        return AuthProbe::yes("api-key");
    }
    if !env_str(env, "CODEBUDDY_AUTH_TOKEN").is_empty() {
        return AuthProbe::yes("auth-token");
    }
    let settings = home.join(".codebuddy").join("settings.json");
    if let Ok(content) = std::fs::read_to_string(settings) {
        if let Ok(serde_json::Value::Object(parsed)) = serde_json::from_str::<serde_json::Value>(&content) {
            for key in ["authToken", "apiKeyHelper"] {
                if parsed.get(key).and_then(|v| v.as_str()).map(|s| !s.trim().is_empty()).unwrap_or(false) {
                    return AuthProbe::yes("settings-file");
                }
            }
        }
    }
    AuthProbe::no()
}

/// Grok: `XAI_API_KEY` or `$GROK_CONFIG_DIR/auth.json` (default `~/.grok`).
pub fn probe_grok_auth(env: &EnvMap, home: &Path) -> AuthProbe {
    if !env_str(env, "XAI_API_KEY").is_empty() {
        return AuthProbe::yes("env");
    }
    let config_dir = env_str(env, "GROK_CONFIG_DIR");
    let dir = if config_dir.is_empty() { home.join(".grok") } else { PathBuf::from(config_dir) };
    if dir.join("auth.json").exists() {
        return AuthProbe::yes("auth-file");
    }
    AuthProbe::no()
}

// ── Cursor CLI login (cursor-agent only) ──

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CursorCliAuth {
    pub authenticated: bool,
    pub auth_source: Option<String>,
    pub email: Option<String>,
    pub bin_path: Option<String>,
}

pub const CURSOR_CLI_BINARY_CANDIDATES: &[&str] = &["cursor-agent"];

pub fn strip_cursor_api_key_from_env(env: &EnvMap) -> EnvMap {
    let mut out = env.clone();
    out.remove("CURSOR_API_KEY");
    out
}

/// First JSON object in `text` (whole text, else the outermost `{...}` slice).
pub fn extract_first_json_object(text: &str) -> Option<serde_json::Value> {
    let raw = text.trim_start_matches('\u{feff}').trim();
    if raw.is_empty() {
        return None;
    }
    let mut candidates = vec![raw.to_string()];
    if let (Some(start), Some(end)) = (raw.find('{'), raw.rfind('}')) {
        if end > start {
            let sliced = &raw[start..=end];
            if sliced != raw {
                candidates.push(sliced.to_string());
            }
        }
    }
    candidates
        .iter()
        .filter_map(|c| serde_json::from_str::<serde_json::Value>(c).ok())
        .find(|v| v.is_object())
}

/// `parseCursorStatusJson`: reject unrelated CLIs that happen to emit JSON.
pub fn parse_cursor_status_json(stdout: &str) -> Option<serde_json::Value> {
    let parsed = extract_first_json_object(stdout)?;
    let has_auth = parsed.get("isAuthenticated").map(|v| v.is_boolean()).unwrap_or(false);
    let has_status = parsed.get("status").map(|v| v.is_string()).unwrap_or(false);
    (has_auth || has_status).then_some(parsed)
}

/// Interpret a `cursor-agent status --format json` result.
pub fn cursor_auth_from_status(bin_path: &str, status: Option<&str>) -> CursorCliAuth {
    let unauthenticated = CursorCliAuth { bin_path: Some(bin_path.to_string()), ..Default::default() };
    let Some(parsed) = status.and_then(parse_cursor_status_json) else {
        return unauthenticated;
    };
    let authenticated = parsed.get("isAuthenticated") == Some(&serde_json::Value::Bool(true))
        || parsed.get("status").and_then(|s| s.as_str()) == Some("authenticated");
    if !authenticated {
        return unauthenticated;
    }
    let email = parsed
        .get("userInfo")
        .and_then(|u| u.get("email"))
        .and_then(|e| e.as_str())
        .map(str::to_string);
    CursorCliAuth {
        authenticated: true,
        auth_source: Some("cli-login".into()),
        email,
        bin_path: Some(bin_path.to_string()),
    }
}

/// `probeCursorCliAuth`: resolve `cursor-agent` on PATH and run `status --format json`
/// without `CURSOR_API_KEY` (so a metered key cannot prove a CLI login).
pub async fn probe_cursor_cli_auth(shell_env: &EnvMap) -> CursorCliAuth {
    let env = strip_cursor_api_key_from_env(shell_env);
    let mut resolved_bin: Option<String> = None;
    for name in CURSOR_CLI_BINARY_CANDIDATES {
        let Some(bin) = crate::cli::resolve_cli_from_path(name, &env).await else { continue };
        if resolved_bin.is_none() {
            resolved_bin = Some(bin.clone());
        }
        let spec = resolve_cursor_cli_spawn_spec(&bin, &["status".into(), "--format".into(), "json".into()]);
        let mut cmd = crate::cli::command_for_spec(&spec);
        cmd.env_clear().envs(env.iter()).stdin(std::process::Stdio::null()).kill_on_drop(true);
        let output = match tokio::time::timeout(Duration::from_secs(8), cmd.output()).await {
            Ok(Ok(out)) => out,
            _ => continue,
        };
        let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
        let auth = cursor_auth_from_status(&bin, Some(&stdout));
        if auth.authenticated {
            return auth;
        }
    }
    CursorCliAuth { bin_path: resolved_bin, ..Default::default() }
}

/// Home dir used by the probes: the agent env's `HOME` when present.
pub fn probe_home(env: &EnvMap) -> PathBuf {
    env_home(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> EnvMap {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn claude_env_tokens_win() {
        let io = ProbeIo { home: PathBuf::from("/nonexistent"), platform_darwin: false, run_security: &|| (1, String::new()) };
        assert_eq!(probe_claude_auth(&env(&[("ANTHROPIC_API_KEY", " k ")]), &io), AuthProbe::yes("env"));
        assert_eq!(probe_claude_auth(&env(&[("CLAUDE_CODE_OAUTH_TOKEN", "t")]), &io), AuthProbe::yes("env"));
        assert_eq!(probe_claude_auth(&env(&[("ANTHROPIC_AUTH_TOKEN", "t")]), &io), AuthProbe::yes("env"));
        assert_eq!(probe_claude_auth(&env(&[("ANTHROPIC_API_KEY", "  ")]), &io), AuthProbe::no());
    }

    #[test]
    fn claude_keychain_then_credentials_file() {
        let dir = tempfile::tempdir().unwrap();
        let darwin = ProbeIo { home: dir.path().to_path_buf(), platform_darwin: true, run_security: &|| (0, "secret\n".into()) };
        assert_eq!(probe_claude_auth(&env(&[]), &darwin), AuthProbe::yes("keychain"));
        let empty_keychain = ProbeIo { home: dir.path().to_path_buf(), platform_darwin: true, run_security: &|| (0, "  ".into()) };
        assert_eq!(probe_claude_auth(&env(&[]), &empty_keychain), AuthProbe::no());
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(dir.path().join(".claude/.credentials.json"), "{}").unwrap();
        let linux = ProbeIo { home: dir.path().to_path_buf(), platform_darwin: false, run_security: &|| (0, "x".into()) };
        assert_eq!(probe_claude_auth(&env(&[]), &linux), AuthProbe::yes("credentials-file"));
        let custom = tempfile::tempdir().unwrap();
        std::fs::write(custom.path().join(".credentials.json"), "{}").unwrap();
        let other = ProbeIo { home: PathBuf::from("/nonexistent"), platform_darwin: false, run_security: &|| (1, String::new()) };
        assert_eq!(
            probe_claude_auth(&env(&[("CLAUDE_CONFIG_DIR", custom.path().to_str().unwrap())]), &other),
            AuthProbe::yes("credentials-file")
        );
    }

    #[test]
    fn codex_probe_reads_status_then_auth_file() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(probe_codex_auth(Some("Logged in using ChatGPT"), dir.path()), AuthProbe::yes("chatgpt"));
        assert_eq!(probe_codex_auth(Some("logged in using an API key"), dir.path()), AuthProbe::yes("api-key"));
        assert_eq!(probe_codex_auth(Some("Not logged in"), dir.path()), AuthProbe::no());
        std::fs::create_dir_all(dir.path().join(".codex")).unwrap();
        std::fs::write(dir.path().join(".codex/auth.json"), "{}").unwrap();
        assert_eq!(probe_codex_auth(None, dir.path()), AuthProbe::yes("auth-file"));
    }

    #[test]
    fn codebuddy_probe() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(probe_codebuddy_auth(&env(&[("CODEBUDDY_API_KEY", "k")]), dir.path()), AuthProbe::yes("api-key"));
        assert_eq!(probe_codebuddy_auth(&env(&[("CODEBUDDY_AUTH_TOKEN", "t")]), dir.path()), AuthProbe::yes("auth-token"));
        assert_eq!(probe_codebuddy_auth(&env(&[]), dir.path()), AuthProbe::no());
        std::fs::create_dir_all(dir.path().join(".codebuddy")).unwrap();
        std::fs::write(dir.path().join(".codebuddy/settings.json"), "{\"apiKeyHelper\":\"x\"}").unwrap();
        assert_eq!(probe_codebuddy_auth(&env(&[]), dir.path()), AuthProbe::yes("settings-file"));
        std::fs::write(dir.path().join(".codebuddy/settings.json"), "{not json").unwrap();
        assert_eq!(probe_codebuddy_auth(&env(&[]), dir.path()), AuthProbe::no());
    }

    #[test]
    fn grok_probe() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(probe_grok_auth(&env(&[("XAI_API_KEY", "k")]), dir.path()), AuthProbe::yes("env"));
        assert_eq!(probe_grok_auth(&env(&[]), dir.path()), AuthProbe::no());
        let custom = tempfile::tempdir().unwrap();
        std::fs::write(custom.path().join("auth.json"), "{}").unwrap();
        assert_eq!(probe_grok_auth(&env(&[("GROK_CONFIG_DIR", custom.path().to_str().unwrap())]), dir.path()), AuthProbe::yes("auth-file"));
    }

    #[test]
    fn cursor_status_parsing() {
        assert!(parse_cursor_status_json("{\"ok\":true}").is_none());
        let auth = cursor_auth_from_status("/x/cursor-agent", Some("noise\n{\"isAuthenticated\":true,\"userInfo\":{\"email\":\"a@b\"}}\n"));
        assert!(auth.authenticated);
        assert_eq!(auth.email.as_deref(), Some("a@b"));
        assert_eq!(auth.auth_source.as_deref(), Some("cli-login"));
        let no = cursor_auth_from_status("/x/cursor-agent", Some("{\"status\":\"unauthenticated\"}"));
        assert!(!no.authenticated);
        assert_eq!(no.bin_path.as_deref(), Some("/x/cursor-agent"));
        let status_only = cursor_auth_from_status("/x", Some("{\"status\":\"authenticated\"}"));
        assert!(status_only.authenticated);
        assert!(extract_first_json_object("\u{feff}{\"a\":1}").is_some());
    }
}
