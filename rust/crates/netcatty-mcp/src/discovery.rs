//! Discovery files and helper-mode environment (Electron
//! `cli/discoveryPath.cjs`, `cli/externalMcpDiscoveryPath.cjs`,
//! `cli/externalMcpDiscovery.cjs`).
//!
//! Paths are rooted at the application data directory the desktop app
//! passes in (`AppPaths::data_dir`), mirroring Electron's `userData`:
//! `<data>/netcatty-tool-cli/discovery.json` and
//! `<data>/external-mcp/discovery.json`. Both honour env overrides.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const TOOL_CLI_DISCOVERY_ENV_VAR: &str = "NETCATTY_TOOL_CLI_DISCOVERY_FILE";
pub const TOOL_CLI_CHAT_SESSION_ENV_VAR: &str = "NETCATTY_CLI_CHAT_SESSION_ID";
pub const EXTERNAL_MCP_DISCOVERY_ENV_VAR: &str = "NETCATTY_EXTERNAL_MCP_DISCOVERY_FILE";
/// Selects a helper mode when the Netcatty executable is launched by an
/// MCP client without arguments (`external` → External MCP stdio server).
pub const HELPER_MODE_ENV_VAR: &str = "NETCATTY_MCP_HELPER";
/// Comma-separated toolsets (or `all`) a stdio MCP server loads at start.
pub const TOOLSETS_ENV_VAR: &str = "NETCATTY_MCP_TOOLSETS";
pub const HELPER_MODE_EXTERNAL: &str = "external";
pub const CLI_STATE_DIR_NAME: &str = "netcatty-tool-cli";
pub const EXTERNAL_MCP_STATE_DIR_NAME: &str = "external-mcp";

/// Command-line flags of the helper modes.
pub const MCP_SERVER_FLAG: &str = "--mcp-server";
pub const EXTERNAL_MCP_SERVER_FLAG: &str = "--external-mcp-server";
pub const TOOL_CLI_FLAG: &str = "--tool-cli";

pub fn tool_cli_discovery_path(data_dir: &Path) -> PathBuf {
    std::env::var_os(TOOL_CLI_DISCOVERY_ENV_VAR)
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join(CLI_STATE_DIR_NAME).join("discovery.json"))
}

pub fn external_mcp_discovery_path(data_dir: &Path) -> PathBuf {
    std::env::var_os(EXTERNAL_MCP_DISCOVERY_ENV_VAR)
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join(EXTERNAL_MCP_STATE_DIR_NAME).join("discovery.json"))
}

/// Env an MCP client must pass to the launcher (`buildDiscoveryEnv`).
pub fn build_discovery_env(discovery_path: Option<&Path>) -> Vec<(String, String)> {
    let Some(path) = discovery_path else {
        return Vec::new();
    };
    vec![
        (EXTERNAL_MCP_DISCOVERY_ENV_VAR.to_string(), path.to_string_lossy().into_owned()),
        (HELPER_MODE_ENV_VAR.to_string(), HELPER_MODE_EXTERNAL.to_string()),
    ]
}

/// `--env K=V` (codex) or `-e K=V` (claude / grok).
pub fn format_discovery_env_cli_flags(env: &[(String, String)], style: &str) -> Vec<String> {
    let flag = if style == "claude" || style == "grok" { "-e" } else { "--env" };
    env.iter()
        .filter(|(_, v)| !v.is_empty())
        .flat_map(|(k, v)| [flag.to_string(), format!("{k}={v}")])
        .collect()
}

pub fn iso_now() -> String {
    chrono_like_iso(std::time::SystemTime::now())
}

/// RFC 3339 UTC with milliseconds (`new Date().toISOString()`).
pub fn chrono_like_iso(t: std::time::SystemTime) -> String {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let ms = d.subsec_millis();
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

/// External discovery payload (`buildExternalDiscoveryPayload`).
pub fn external_discovery_payload(port: u16, token: &str, permission_mode: &str, chat_session_id: &str, redaction: Option<&Value>) -> Value {
    let mut v = json!({
        "version": 1,
        "host": "127.0.0.1",
        "port": port,
        "token": token,
        "pid": std::process::id(),
        "permissionMode": if permission_mode.is_empty() { "confirm" } else { permission_mode },
        "chatSessionId": if chat_session_id.is_empty() { crate::host::EXTERNAL_MCP_CHAT_SESSION_ID } else { chat_session_id },
        "updatedAt": iso_now(),
    });
    if let Some(r) = redaction {
        v["redaction"] = r.clone();
    }
    v
}

/// Parsed external discovery file (`readExternalDiscovery`).
#[derive(Debug, Clone)]
pub struct ExternalDiscovery {
    pub port: u16,
    pub token: String,
    pub permission_mode: String,
    pub chat_session_id: String,
    pub redaction: Option<Value>,
}

pub fn read_external_discovery(path: &Path) -> Result<ExternalDiscovery, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let parsed: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if !parsed.is_object() {
        return Err("External MCP discovery file is invalid.".into());
    }
    let port = parsed["port"].as_f64().filter(|p| *p > 0.0 && *p < 65536.0).map(|p| p as u16);
    let token = parsed["token"].as_str().map(str::trim).unwrap_or("").to_string();
    let (Some(port), false) = (port, token.is_empty()) else {
        return Err("External MCP discovery file is missing port or token.".into());
    };
    Ok(ExternalDiscovery {
        port,
        token,
        permission_mode: parsed["permissionMode"].as_str().unwrap_or("confirm").to_string(),
        chat_session_id: parsed["chatSessionId"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(crate::host::EXTERNAL_MCP_CHAT_SESSION_ID)
            .to_string(),
        redaction: parsed.get("redaction").cloned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_format_and_env_flags() {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_700_000_000_123);
        assert_eq!(chrono_like_iso(t), "2023-11-14T22:13:20.123Z");
        let env = build_discovery_env(Some(Path::new("/tmp/d.json")));
        assert_eq!(
            format_discovery_env_cli_flags(&env, "claude"),
            vec!["-e", "NETCATTY_EXTERNAL_MCP_DISCOVERY_FILE=/tmp/d.json", "-e", "NETCATTY_MCP_HELPER=external"]
        );
        assert_eq!(format_discovery_env_cli_flags(&env, "codex")[0], "--env");
        assert!(build_discovery_env(None).is_empty());
    }

    #[test]
    fn external_discovery_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.json");
        let payload = external_discovery_payload(4321, "tok", "auto", "", None);
        std::fs::write(&path, payload.to_string()).unwrap();
        let d = read_external_discovery(&path).unwrap();
        assert_eq!(d.port, 4321);
        assert_eq!(d.chat_session_id, "__external_mcp__");
        std::fs::write(&path, "{\"port\":1}").unwrap();
        assert!(read_external_discovery(&path).is_err());
    }
}
