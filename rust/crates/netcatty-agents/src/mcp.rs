//! Neutral MCP server shape injected into every managed agent (Electron:
//! `sdk/injectMcp.cjs`). Each driver converts it into its SDK's config format.
//!
//! The real provider lives in the `netcatty_mcp` crate
//! (`netcatty_mcp::build_injected_mcp_servers`); until it is merged the
//! runtime is wired with [`NoopMcpInjectionProvider`]. See
//! `TODO(mcp-injection)` in `runtime.rs`.

use crate::EnvMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvPair {
    pub name: String,
    pub value: String,
}

/// `{ name, type: "stdio", command, args, env: [{name, value}] }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerConfig {
    pub name: String,
    #[serde(rename = "type", default = "stdio")]
    pub kind: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<EnvPair>,
}

fn stdio() -> String {
    "stdio".to_string()
}

impl McpServerConfig {
    pub fn stdio(name: &str, command: &str, args: Vec<String>, env: Vec<EnvPair>) -> Self {
        Self { name: name.to_string(), kind: stdio(), command: command.to_string(), args, env }
    }

    /// `mcpEnvPairsToObject`.
    pub fn env_map(&self) -> EnvMap {
        self.env.iter().map(|p| (p.name.clone(), p.value.clone())).collect()
    }

    /// `env` as a JSON object (what the claude / codex / copilot configs expect).
    pub fn env_object(&self) -> serde_json::Value {
        serde_json::Value::Object(self.env.iter().map(|p| (p.name.clone(), serde_json::Value::String(p.value.clone()))).collect())
    }
}

/// `mcpEnvPairsToObject` on a JSON pair array.
pub fn mcp_env_pairs_to_object(pairs: &serde_json::Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let serde_json::Value::Array(items) = pairs {
        for pair in items {
            if let (Some(name), Some(value)) = (pair.get("name").and_then(|v| v.as_str()), pair.get("value").and_then(|v| v.as_str())) {
                out.insert(name.to_string(), value.to_string());
            }
        }
    }
    out
}

/// Hook into the netcatty MCP control host. `build_injected_mcp_servers` must
/// also start the host in skills mode (the CLI discovers it through the
/// discovery file) and return no servers in that mode.
#[async_trait::async_trait]
pub trait McpInjectionProvider: Send + Sync {
    /// Servers to inject for a chat session (`[]` in skills mode).
    async fn build_injected_mcp_servers(
        &self,
        chat_session_id: &str,
        tool_integration_mode: &str,
    ) -> Result<Vec<McpServerConfig>, String>;

    /// Path of the netcatty tool CLI discovery file written by the host.
    fn discovery_file_path(&self) -> Option<String> {
        None
    }

    /// Attachments staged for this turn (`updateAttachmentMetadata`).
    fn update_attachment_metadata(&self, _attachments: &[crate::session::StagedAttachment], _chat_session_id: &str) {}

    /// `setChatSessionCancelled` / `cancelPtyExecsForSession` / `clearPendingApprovals`.
    fn set_chat_session_cancelled(&self, _chat_session_id: &str, _cancelled: bool) {}

    /// `cleanupScopedMetadata`.
    async fn cleanup_scoped_metadata(&self, _chat_session_id: &str) {}
}

/// Placeholder provider: no MCP server is injected.
#[derive(Debug, Default)]
pub struct NoopMcpInjectionProvider;

#[async_trait::async_trait]
impl McpInjectionProvider for NoopMcpInjectionProvider {
    async fn build_injected_mcp_servers(&self, _chat_session_id: &str, _mode: &str) -> Result<Vec<McpServerConfig>, String> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_pairs_to_object_ignores_bad_entries() {
        let pairs = serde_json::json!([
            { "name": "A", "value": "1" },
            { "name": "B", "value": 2 },
            { "value": "x" },
            "junk"
        ]);
        let out = mcp_env_pairs_to_object(&pairs);
        assert_eq!(out.len(), 1);
        assert_eq!(out["A"], "1");
        assert!(mcp_env_pairs_to_object(&serde_json::json!(null)).is_empty());
    }

    #[test]
    fn config_round_trips_with_neutral_json() {
        let cfg: McpServerConfig = serde_json::from_value(serde_json::json!({
            "name": "netcatty-remote-hosts", "type": "stdio", "command": "/app/netcatty", "args": ["--mcp-server"],
            "env": [{ "name": "NETCATTY_MCP_PORT", "value": "1234" }]
        }))
        .unwrap();
        assert_eq!(cfg.env_map()["NETCATTY_MCP_PORT"], "1234");
        assert_eq!(cfg.env_object()["NETCATTY_MCP_PORT"], "1234");
        let back = serde_json::to_value(&cfg).unwrap();
        assert_eq!(back["type"], "stdio");
    }

    #[tokio::test]
    async fn noop_provider_injects_nothing() {
        let provider = NoopMcpInjectionProvider;
        assert!(provider.build_injected_mcp_servers("chat", "mcp").await.unwrap().is_empty());
        assert!(provider.discovery_file_path().is_none());
    }
}
