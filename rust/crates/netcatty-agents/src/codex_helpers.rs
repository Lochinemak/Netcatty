//! Codex login sessions, integration state, `config.toml` probing and error
//! helpers (Electron: `ai/codexHelpers.cjs`).

use crate::cli::{extract_first_non_localhost_url, strip_ansi};
use crate::env::env_home;
use crate::EnvMap;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const MAX_CODEX_LOGIN_OUTPUT_BYTES: usize = 64 * 1024;
pub const MAX_CODEX_LOGIN_TERMINAL_SESSIONS: usize = 8;
pub const CODEX_LOGIN_KILL_GRACE_MS: u64 = 750;

const CODEX_AUTH_HINTS: &[&str] = &[
    "not logged in",
    "authentication required",
    "auth required",
    "login required",
    "missing credentials",
    "no credentials",
    "unauthorized",
    "forbidden",
    "codex login",
    "401",
    "403",
    "invalid_grant",
    "invalid_token",
    "credentials",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CodexLoginState {
    Running,
    Success,
    Error,
    Cancelled,
}

/// One `codex login` run (the renderer polls it by id).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexLoginSessionResponse {
    pub session_id: String,
    pub state: CodexLoginState,
    pub url: Option<String>,
    pub output: String,
    pub error: Option<String>,
    pub exit_code: Option<i32>,
    pub codex_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CodexLoginSession {
    pub id: String,
    pub state: CodexLoginState,
    pub output: String,
    pub url: Option<String>,
    pub error: Option<String>,
    pub exit_code: Option<i32>,
    pub codex_path: Option<String>,
    pub credential_home_key: String,
    /// `true` while the child process is alive.
    pub process_alive: bool,
}

impl CodexLoginSession {
    pub fn response(&self) -> CodexLoginSessionResponse {
        CodexLoginSessionResponse {
            session_id: self.id.clone(),
            state: self.state,
            url: self.url.clone(),
            output: self.output.clone(),
            error: self.error.clone(),
            exit_code: self.exit_code,
            codex_path: self.codex_path.clone(),
        }
    }
}

/// Keep the UTF-8 tail of `value` that fits in `max_bytes`.
pub fn retain_utf8_tail(value: &str, max_bytes: usize) -> String {
    let bytes = value.as_bytes();
    if bytes.len() <= max_bytes {
        return value.to_string();
    }
    let mut start = bytes.len() - max_bytes;
    while start < bytes.len() && (bytes[start] & 0xC0) == 0x80 {
        start += 1;
    }
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

/// `appendCodexLoginOutput`: strip ANSI, remember the first non-localhost URL,
/// cap the retained output.
pub fn append_codex_login_output(session: &mut CodexLoginSession, chunk: &str) {
    let clean = strip_ansi(chunk);
    if clean.is_empty() {
        return;
    }
    let combined = format!("{}{}", session.output, clean);
    if session.url.is_none() {
        session.url = extract_first_non_localhost_url(&combined);
    }
    session.output = retain_utf8_tail(&combined, MAX_CODEX_LOGIN_OUTPUT_BYTES);
}

/// Drop the oldest finished sessions beyond [`MAX_CODEX_LOGIN_TERMINAL_SESSIONS`].
pub fn prune_codex_login_sessions(sessions: &mut Vec<CodexLoginSession>) {
    let terminal: Vec<String> = sessions
        .iter()
        .filter(|s| s.state != CodexLoginState::Running && !s.process_alive)
        .map(|s| s.id.clone())
        .collect();
    let excess = terminal.len().saturating_sub(MAX_CODEX_LOGIN_TERMINAL_SESSIONS);
    for id in terminal.iter().take(excess) {
        sessions.retain(|s| &s.id != id);
    }
}

/// `normalizeCodexIntegrationState`.
pub fn normalize_codex_integration_state(raw_output: &str) -> &'static str {
    let normalized = raw_output.to_ascii_lowercase();
    if normalized.contains("logged in using chatgpt") {
        return "connected_chatgpt";
    }
    if normalized.contains("logged in using an api key") || normalized.contains("logged in using api key") {
        return "connected_api_key";
    }
    if normalized.contains("not logged in") {
        return "not_logged_in";
    }
    "unknown"
}

pub fn append_codex_chatgpt_validation_failure(raw_output: &str, validation_error: &str) -> String {
    let error = if validation_error.is_empty() { "Unknown validation error" } else { validation_error };
    [raw_output.trim(), "", "ChatGPT auth validation failed:", error].join("\n").trim().to_string()
}

/// Find `#` outside quoted regions (escapes honoured inside basic strings only).
fn find_unquoted_hash(value: &str) -> Option<usize> {
    let mut in_str = false;
    let mut quote = '\0';
    let mut escaped = false;
    for (i, ch) in value.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
                continue;
            }
            if quote == '"' && ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == quote {
                in_str = false;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            in_str = true;
            quote = ch;
            continue;
        }
        if ch == '#' {
            return Some(i);
        }
    }
    None
}

/// Narrow TOML subset: top-level string keys and `[model_providers.<name>]` tables.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CodexConfigToml {
    pub top_level: std::collections::BTreeMap<String, String>,
    pub model_providers: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
}

pub fn parse_codex_config_toml(text: &str) -> CodexConfigToml {
    let mut result = CodexConfigToml::default();
    let mut current_provider: Option<String> = None;
    let mut at_top_level = true;
    let kv_re = regex::Regex::new(r"^([A-Za-z_][\w.-]*)\s*=\s*(.+)$").unwrap();
    for raw_line in text.trim_start_matches('\u{feff}').lines() {
        let mut line = raw_line.to_string();
        if let Some(idx) = find_unquoted_hash(&line) {
            line.truncate(idx);
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') && line.len() >= 2 {
            let section = line[1..line.len() - 1].trim();
            if let Some(name) = section.strip_prefix("model_providers.") {
                current_provider = Some(name.to_string());
                result.model_providers.entry(name.to_string()).or_default();
            } else {
                current_provider = None;
            }
            at_top_level = false;
            continue;
        }
        let Some(cap) = kv_re.captures(line) else { continue };
        let key = cap[1].to_string();
        let raw = cap[2].trim();
        let value = if (raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2)
            || (raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2)
        {
            raw[1..raw.len() - 1].to_string()
        } else {
            raw.to_string()
        };
        if at_top_level {
            result.top_level.insert(key, value);
        } else if let Some(provider) = &current_provider {
            result.model_providers.entry(provider.clone()).or_default().insert(key, value);
        }
    }
    result
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CodexCustomProviderConfig {
    pub provider_name: String,
    pub display_name: String,
    pub base_url: Option<String>,
    pub env_key: Option<String>,
    pub env_key_present: bool,
    pub has_hardcoded_api_key: bool,
    pub model: Option<String>,
    pub auth_hash: Option<String>,
}

/// `readCodexCustomProviderConfig`: `$CODEX_HOME/config.toml` or `~/.codex/config.toml`.
pub fn read_codex_custom_provider_config(shell_env: &EnvMap) -> Option<CodexCustomProviderConfig> {
    let codex_home = shell_env.get("CODEX_HOME").map(|v| v.trim()).unwrap_or("");
    let path = if codex_home.is_empty() {
        env_home(shell_env).join(".codex").join("config.toml")
    } else {
        PathBuf::from(codex_home).join("config.toml")
    };
    read_codex_custom_provider_config_from(&path, shell_env)
}

pub fn read_codex_custom_provider_config_from(config_path: &Path, shell_env: &EnvMap) -> Option<CodexCustomProviderConfig> {
    let text = std::fs::read_to_string(config_path).ok()?;
    let parsed = parse_codex_config_toml(&text);
    let active = parsed.top_level.get("model_provider").map(|v| v.trim()).unwrap_or("");
    if active.is_empty() || active == "openai" {
        return None;
    }
    let entry = parsed.model_providers.get(active)?;
    let env_key_name = entry.get("env_key").map(|v| v.trim().to_string()).unwrap_or_default();
    let env_key_value = if env_key_name.is_empty() {
        String::new()
    } else {
        shell_env.get(&env_key_name).map(|v| v.trim().to_string()).unwrap_or_default()
    };
    let hardcoded = entry.get("api_key").map(|v| v.trim().to_string()).unwrap_or_default();
    let model = parsed.top_level.get("model").map(|v| v.trim().to_string()).unwrap_or_default();
    let auth_material = if !hardcoded.is_empty() { hardcoded.clone() } else { env_key_value.clone() };
    let auth_hash = (!auth_material.is_empty()).then(|| hex::encode(Sha256::digest(auth_material.as_bytes())));
    Some(CodexCustomProviderConfig {
        provider_name: active.to_string(),
        display_name: entry.get("name").cloned().unwrap_or_else(|| active.to_string()),
        base_url: entry.get("base_url").cloned(),
        env_key: (!env_key_name.is_empty()).then_some(env_key_name),
        env_key_present: !env_key_value.is_empty(),
        has_hardcoded_api_key: !hardcoded.is_empty(),
        model: (!model.is_empty()).then_some(model),
        auth_hash,
    })
}

pub fn get_codex_custom_config_preflight_error(config: Option<&CodexCustomProviderConfig>) -> Option<String> {
    let config = config?;
    let env_key = config.env_key.as_deref()?;
    if config.env_key_present || config.has_hardcoded_api_key {
        return None;
    }
    Some(format!(
        "Codex is configured to use the \"{}\" provider from ~/.codex/config.toml, but the environment variable {} is not set. Export it in your shell (e.g. add to ~/.zshrc) and click \"Refresh Status\" in Settings.",
        config.display_name, env_key
    ))
}

/// `isCodexAuthError` over `code message error`.
pub fn is_codex_auth_error(code: Option<&str>, message: &str) -> bool {
    let searchable = format!("{} {}", code.unwrap_or(""), message).to_ascii_lowercase();
    CODEX_AUTH_HINTS.iter().any(|hint| searchable.contains(hint))
}

pub fn get_codex_auth_fingerprint(api_key: &str) -> Option<String> {
    let normalized = api_key.trim();
    (!normalized.is_empty()).then(|| hex::encode(Sha256::digest(normalized.as_bytes())))
}

pub fn get_codex_mcp_fingerprint(mcp_servers: &serde_json::Value) -> String {
    hex::encode(Sha256::digest(mcp_servers.to_string().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> CodexLoginSession {
        CodexLoginSession {
            id: "codex_login_1".into(),
            state: CodexLoginState::Running,
            output: String::new(),
            url: None,
            error: None,
            exit_code: None,
            codex_path: Some("/x/codex".into()),
            credential_home_key: "/home/.codex".into(),
            process_alive: true,
        }
    }

    #[test]
    fn login_output_tracks_url_and_tail() {
        let mut s = session();
        append_codex_login_output(&mut s, "\u{1b}[1mOpen http://localhost:1455/auth\u{1b}[0m or https://auth.openai.com/x\n");
        assert_eq!(s.url.as_deref(), Some("https://auth.openai.com/x"));
        assert!(!s.output.contains('\u{1b}'));
        let big = "é".repeat(MAX_CODEX_LOGIN_OUTPUT_BYTES);
        append_codex_login_output(&mut s, &big);
        assert!(s.output.len() <= MAX_CODEX_LOGIN_OUTPUT_BYTES);
        assert!(s.output.chars().all(|c| c == 'é'));
    }

    #[test]
    fn prune_keeps_running_and_latest_terminal() {
        let mut sessions: Vec<CodexLoginSession> = (0..12)
            .map(|i| {
                let mut s = session();
                s.id = format!("s{i}");
                s.state = CodexLoginState::Success;
                s.process_alive = false;
                s
            })
            .collect();
        sessions.push(session());
        prune_codex_login_sessions(&mut sessions);
        assert_eq!(sessions.len(), MAX_CODEX_LOGIN_TERMINAL_SESSIONS + 1);
        assert!(sessions.iter().any(|s| s.id == "codex_login_1"));
        assert!(!sessions.iter().any(|s| s.id == "s0"));
        assert!(sessions.iter().any(|s| s.id == "s11"));
    }

    #[test]
    fn integration_state() {
        assert_eq!(normalize_codex_integration_state("Logged in using ChatGPT"), "connected_chatgpt");
        assert_eq!(normalize_codex_integration_state("Logged in using an API key"), "connected_api_key");
        assert_eq!(normalize_codex_integration_state("Not logged in"), "not_logged_in");
        assert_eq!(normalize_codex_integration_state("???"), "unknown");
        assert_eq!(append_codex_chatgpt_validation_failure("x", ""), "x\n\nChatGPT auth validation failed:\nUnknown validation error");
    }

    #[test]
    fn toml_subset_parsing() {
        let text = "\u{feff}model_provider = \"my\" # comment\nmodel = 'gpt-x'\n[model_providers.my]\nname = \"My \\\"Prov\\\"\" # trailing\nbase_url = \"https://api#host\"\nenv_key = \"MY_KEY\"\n[other]\nignored = 1\n";
        let parsed = parse_codex_config_toml(text);
        assert_eq!(parsed.top_level["model_provider"], "my");
        assert_eq!(parsed.top_level["model"], "gpt-x");
        assert_eq!(parsed.model_providers["my"]["base_url"], "https://api#host");
        assert_eq!(parsed.model_providers["my"]["env_key"], "MY_KEY");
        assert!(!parsed.top_level.contains_key("ignored"));
    }

    #[test]
    fn custom_provider_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "model_provider = \"openai\"\n").unwrap();
        assert!(read_codex_custom_provider_config_from(&path, &EnvMap::new()).is_none());
        std::fs::write(&path, "model_provider = \"glm\"\nmodel = \"glm-4\"\n[model_providers.glm]\nname = \"GLM\"\nbase_url = \"https://x\"\nenv_key = \"GLM_KEY\"\n").unwrap();
        let cfg = read_codex_custom_provider_config_from(&path, &EnvMap::new()).unwrap();
        assert_eq!(cfg.display_name, "GLM");
        assert!(!cfg.env_key_present);
        assert!(cfg.auth_hash.is_none());
        assert!(get_codex_custom_config_preflight_error(Some(&cfg)).unwrap().contains("GLM_KEY"));
        let env: EnvMap = [("GLM_KEY".to_string(), "secret".to_string())].into_iter().collect();
        let cfg = read_codex_custom_provider_config_from(&path, &env).unwrap();
        assert!(cfg.env_key_present);
        assert!(cfg.auth_hash.is_some());
        assert!(!cfg.auth_hash.as_deref().unwrap().contains("secret"));
        assert!(get_codex_custom_config_preflight_error(Some(&cfg)).is_none());
        std::fs::write(&path, "model_provider = \"missing\"\n").unwrap();
        assert!(read_codex_custom_provider_config_from(&path, &env).is_none());
        let via_home: EnvMap = [("CODEX_HOME".to_string(), dir.path().to_string_lossy().into_owned())].into_iter().collect();
        std::fs::write(&path, "model_provider = \"p\"\n[model_providers.p]\napi_key = \"k\"\n").unwrap();
        assert!(read_codex_custom_provider_config(&via_home).unwrap().has_hardcoded_api_key);
    }

    #[test]
    fn auth_error_detection_and_fingerprints() {
        assert!(is_codex_auth_error(Some("401"), "x"));
        assert!(is_codex_auth_error(None, "Please run codex login"));
        assert!(!is_codex_auth_error(None, "network timeout"));
        assert!(get_codex_auth_fingerprint("  ").is_none());
        assert_eq!(get_codex_auth_fingerprint("a"), get_codex_auth_fingerprint(" a "));
        assert_eq!(get_codex_mcp_fingerprint(&serde_json::json!([])).len(), 64);
    }
}
