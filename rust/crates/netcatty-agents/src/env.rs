//! Env construction for SDK agent subprocesses (Electron: `sdk/env.cjs`,
//! `aiBridge.cjs normalizeAgentEnv`, `cli/cliChatSession.cjs
//! injectCliTransportEnv`, `ai/claudeAuth.cjs expandHomePath`).

use crate::EnvMap;
use std::path::PathBuf;

/// Env var names that can be used for code injection into a child process.
pub const DANGEROUS_ENV_KEYS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "NODE_OPTIONS",
    "ELECTRON_RUN_AS_NODE",
    "PYTHONPATH",
    "RUBYLIB",
    "PERL5LIB",
    "BASH_ENV",
    "ENV",
    "CDPATH",
    "PROMPT_COMMAND",
];

pub const TOOL_CLI_DISCOVERY_ENV_VAR: &str = "NETCATTY_TOOL_CLI_DISCOVERY_FILE";
pub const TOOL_CLI_CHAT_SESSION_ENV_VAR: &str = "NETCATTY_CLI_CHAT_SESSION_ID";

pub fn is_dangerous_env_key(key: &str) -> bool {
    let normalized = key.to_ascii_uppercase();
    DANGEROUS_ENV_KEYS.contains(&normalized.as_str()) || normalized.starts_with("BASH_FUNC_")
}

/// Build the env handed to an SDK agent subprocess: filtered shell env, then
/// the per-agent env from the UI (filtered), then the CLI discovery env.
pub fn build_sdk_agent_env(
    shell_env: &EnvMap,
    requested_agent_env: Option<&EnvMap>,
    discovery: Option<(&Option<String>, Option<&str>)>,
) -> EnvMap {
    let mut env = EnvMap::new();
    for (k, v) in shell_env {
        if !is_dangerous_env_key(k) {
            env.insert(k.clone(), v.clone());
        }
    }
    if let Some(requested) = requested_agent_env {
        for (k, v) in requested {
            if !is_dangerous_env_key(k) {
                env.insert(k.clone(), v.clone());
            }
        }
    }
    if let Some((discovery_file, chat_session_id)) = discovery {
        env = inject_cli_transport_env(env, discovery_file.as_deref(), chat_session_id);
    }
    env
}

/// `injectCliTransportEnv`: bind the netcatty tool CLI discovery file and the
/// chat session id for the child.
pub fn inject_cli_transport_env(
    mut env: EnvMap,
    discovery_file_path: Option<&str>,
    chat_session_id: Option<&str>,
) -> EnvMap {
    env.remove(TOOL_CLI_CHAT_SESSION_ENV_VAR);
    if let Some(path) = discovery_file_path.filter(|p| !p.is_empty()) {
        env.insert(TOOL_CLI_DISCOVERY_ENV_VAR.to_string(), path.to_string());
    }
    if let Some(id) = chat_session_id.map(str::trim).filter(|id| !id.is_empty()) {
        env.insert(TOOL_CLI_CHAT_SESSION_ENV_VAR.to_string(), id.to_string());
    }
    env
}

/// `normalizeAgentEnv`: stringify values, drop empty keys, expand `~` in
/// `CLAUDE_CONFIG_DIR`.
pub fn normalize_agent_env(env: Option<&serde_json::Value>) -> EnvMap {
    let mut result = EnvMap::new();
    let Some(serde_json::Value::Object(map)) = env else {
        return result;
    };
    for (key, value) in map {
        if key.is_empty() || value.is_null() {
            continue;
        }
        let text = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        result.insert(key.clone(), text);
    }
    if let Some(dir) = result.get("CLAUDE_CONFIG_DIR").cloned() {
        if !dir.is_empty() {
            result.insert("CLAUDE_CONFIG_DIR".into(), expand_home_path(&dir));
        }
    }
    result
}

/// Expand a leading `~` / `~/` / `~\` to the home directory (not `~user`).
pub fn expand_home_path(p: &str) -> String {
    let trimmed = p.trim();
    let Some(home) = dirs::home_dir() else {
        return p.to_string();
    };
    if trimmed == "~" {
        return home.to_string_lossy().into_owned();
    }
    if let Some(rest) = trimmed.strip_prefix("~/").or_else(|| trimmed.strip_prefix("~\\")) {
        return home.join(rest).to_string_lossy().into_owned();
    }
    p.to_string()
}

/// Home directory as the agent env sees it (`HOME` / `USERPROFILE`), else the OS home.
pub fn env_home(env: &EnvMap) -> PathBuf {
    env.get("HOME")
        .or_else(|| env.get("USERPROFILE"))
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `envPairsToObject`: `[{name, value}]` → map.
pub fn env_pairs_to_map(pairs: &serde_json::Value) -> EnvMap {
    let mut out = EnvMap::new();
    if let serde_json::Value::Array(items) = pairs {
        for entry in items {
            let Some(name) = entry.get("name").and_then(|v| v.as_str()) else { continue };
            let value = match entry.get("value") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Null) | None => String::new(),
                Some(other) => other.to_string(),
            };
            out.insert(name.to_string(), value);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> EnvMap {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn filters_dangerous_keys_from_both_layers() {
        let shell = env(&[("PATH", "/bin"), ("LD_PRELOAD", "x"), ("BASH_FUNC_foo%%", "y")]);
        let requested = env(&[("NODE_OPTIONS", "--inspect"), ("FOO", "bar"), ("dyld_insert_libraries", "z")]);
        let merged = build_sdk_agent_env(&shell, Some(&requested), None);
        assert_eq!(merged.get("PATH").map(String::as_str), Some("/bin"));
        assert_eq!(merged.get("FOO").map(String::as_str), Some("bar"));
        assert!(!merged.contains_key("LD_PRELOAD"));
        assert!(!merged.contains_key("NODE_OPTIONS"));
        assert!(!merged.contains_key("dyld_insert_libraries"));
        assert!(!merged.keys().any(|k| k.starts_with("BASH_FUNC_")));
    }

    #[test]
    fn requested_env_overrides_shell_env() {
        let shell = env(&[("A", "1")]);
        let requested = env(&[("A", "2")]);
        assert_eq!(build_sdk_agent_env(&shell, Some(&requested), None)["A"], "2");
    }

    #[test]
    fn injects_discovery_and_chat_session() {
        let shell = env(&[("NETCATTY_CLI_CHAT_SESSION_ID", "stale")]);
        let path = Some("/tmp/discovery.json".to_string());
        let merged = build_sdk_agent_env(&shell, None, Some((&path, Some(" chat-1 "))));
        assert_eq!(merged[TOOL_CLI_DISCOVERY_ENV_VAR], "/tmp/discovery.json");
        assert_eq!(merged[TOOL_CLI_CHAT_SESSION_ENV_VAR], "chat-1");
        let merged = build_sdk_agent_env(&shell, None, Some((&None, None)));
        assert!(!merged.contains_key(TOOL_CLI_CHAT_SESSION_ENV_VAR));
    }

    #[test]
    fn normalize_agent_env_expands_claude_config_dir() {
        let value = serde_json::json!({ "CLAUDE_CONFIG_DIR": "~/.claude", "N": 1, "EMPTY": null });
        let normalized = normalize_agent_env(Some(&value));
        assert!(!normalized["CLAUDE_CONFIG_DIR"].starts_with('~'));
        assert!(normalized["CLAUDE_CONFIG_DIR"].ends_with(".claude"));
        assert_eq!(normalized["N"], "1");
        assert!(!normalized.contains_key("EMPTY"));
        assert!(normalize_agent_env(Some(&serde_json::json!([1]))).is_empty());
    }

    #[test]
    fn expand_home_only_leading_tilde() {
        assert_eq!(expand_home_path("~user/x"), "~user/x");
        assert_eq!(expand_home_path("/abs"), "/abs");
        assert!(expand_home_path("~").len() > 1);
    }
}
