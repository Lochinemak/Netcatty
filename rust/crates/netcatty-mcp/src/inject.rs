//! Launch spec of the Netcatty MCP server injected into SDK agents
//! (Electron `aiBridge/sdk/injectMcp.cjs` + `buildMcpServerConfig`).
//!
//! The neutral shape `{ name, type: "stdio", command, args, env: [{name,value}] }`
//! is converted by each SDK driver into its own MCP config format.

use crate::discovery::MCP_SERVER_FLAG;
use crate::host::McpHost;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const INJECTED_MCP_SERVER_NAME: &str = "netcatty-remote-hosts";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvPair {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InjectedMcpServer {
    pub name: String,
    #[serde(rename = "type")]
    pub server_type: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<EnvPair>,
}

impl InjectedMcpServer {
    /// `{ KEY: VALUE }` view for SDKs that take an env object.
    pub fn env_object(&self) -> serde_json::Map<String, serde_json::Value> {
        self.env.iter().map(|p| (p.name.clone(), serde_json::Value::String(p.value.clone()))).collect()
    }
}

/// Path of the running Netcatty executable (`std::env::current_exe`).
pub fn current_executable() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("netcatty"))
}

/// The stdio MCP server launch spec for one chat (`buildMcpServerConfig`).
pub fn build_mcp_server_config(
    executable: &Path,
    port: u16,
    token: Option<&str>,
    scoped_session_ids: &[String],
    chat_session_id: Option<&str>,
    permission_mode: &str,
) -> InjectedMcpServer {
    let mut env = vec![EnvPair { name: "NETCATTY_MCP_PORT".into(), value: port.to_string() }];
    if let Some(t) = token {
        env.push(EnvPair { name: "NETCATTY_MCP_TOKEN".into(), value: t.into() });
    }
    if std::env::var("NETCATTY_MCP_DEBUG").ok().as_deref() == Some("1") {
        env.push(EnvPair { name: "NETCATTY_MCP_DEBUG".into(), value: "1".into() });
    }
    let chat = chat_session_id.filter(|c| !c.is_empty());
    if chat.is_none() && !scoped_session_ids.is_empty() {
        env.push(EnvPair { name: "NETCATTY_MCP_SESSION_IDS".into(), value: scoped_session_ids.join(",") });
    }
    if let Some(c) = chat {
        env.push(EnvPair { name: "NETCATTY_MCP_CHAT_SESSION_ID".into(), value: c.into() });
    }
    env.push(EnvPair { name: "NETCATTY_MCP_PERMISSION_MODE".into(), value: permission_mode.into() });
    InjectedMcpServer {
        name: INJECTED_MCP_SERVER_NAME.into(),
        server_type: "stdio".into(),
        command: executable.to_string_lossy().into_owned(),
        args: vec![MCP_SERVER_FLAG.into()],
        env,
    }
}

/// MCP servers to inject into an SDK agent (`buildInjectedMcpServers`).
///
/// Starts the control host for both modes (the tool CLI reaches it via the
/// discovery file in `skills` mode); returns `[]` unless
/// `tool_integration_mode == "mcp"` or when the host cannot start.
pub async fn build_injected_mcp_servers(host: &McpHost, chat_session_id: &str, tool_integration_mode: &str) -> Vec<InjectedMcpServer> {
    let port = match host.get_or_create_host().await {
        Ok(port) => port,
        Err(err) => {
            tracing::error!(%err, "failed to start netcatty MCP host");
            return Vec::new();
        }
    };
    if tool_integration_mode != "mcp" {
        return Vec::new();
    }
    let scoped = host.scoped_session_ids(Some(chat_session_id));
    vec![build_mcp_server_config(
        &current_executable(),
        port,
        host.tcp.token().as_deref(),
        &scoped,
        Some(chat_session_id),
        &host.permission_mode(),
    )]
}

/// Command prefix for the tool CLI helper mode (`[exe, "--tool-cli"]`).
pub fn tool_cli_invocation() -> Vec<String> {
    vec![current_executable().to_string_lossy().into_owned(), crate::discovery::TOOL_CLI_FLAG.into()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_shape_matches_electron() {
        let c = build_mcp_server_config(Path::new("/Applications/Netcatty.app/Contents/MacOS/Netcatty"), 5555, Some("tok"), &["s1".into()], Some("chat-1"), "confirm");
        assert_eq!(c.server_type, "stdio");
        assert_eq!(c.args, vec!["--mcp-server"]);
        let names: Vec<&str> = c.env.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["NETCATTY_MCP_PORT", "NETCATTY_MCP_TOKEN", "NETCATTY_MCP_CHAT_SESSION_ID", "NETCATTY_MCP_PERMISSION_MODE"]);
        let c = build_mcp_server_config(Path::new("/x"), 1, None, &["a".into(), "b".into()], None, "auto");
        assert!(c.env.iter().any(|e| e.name == "NETCATTY_MCP_SESSION_IDS" && e.value == "a,b"));
        assert_eq!(c.env_object()["NETCATTY_MCP_PORT"], "1");
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["type"], "stdio");
    }
}
