//! Managed SDK agents, agent discovery, CLI resolution, Codex integration /
//! login and the Codex App Server interactions (Electron:
//! `aiBridge/sdk/sdkStreamHandlers.cjs`, `aiBridge/agentDiscoveryHandlers.cjs`).
//! The logic lives in the `netcatty-agents` crate; these commands only adapt
//! the renderer payloads. See `rust/docs/ipc-agents.md`.

use super::CmdResult;
use netcatty_agents::emit::EventSink;
use netcatty_agents::{AgentsRuntime, RuntimeConfig};
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::{AppHandle, Runtime, State};

/// Forwards agent events to every window (`safeSend`).
struct TauriSink<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> EventSink for TauriSink<R> {
    fn send(&self, channel: &str, payload: Value) {
        crate::events::emit(&self.app, channel, payload);
    }
}

/// Managed state: the agents runtime shared by every window.
pub struct AgentsState {
    pub runtime: Arc<AgentsRuntime>,
}

impl AgentsState {
    pub fn new<R: Runtime>(app: AppHandle<R>) -> Self {
        let paths = netcatty_store::AppPaths::resolve();
        let temp_app = app.clone();
        let mut config = RuntimeConfig::new(&app.package_info().version.to_string(), paths.data_dir.clone(), paths.temp_dir());
        config.temp_dir = Arc::new(move || super::tempdir::current(&temp_app));
        let runtime = Arc::new(AgentsRuntime::new(config, Arc::new(TauriSink { app })));
        Self { runtime }
    }
}

/// Plug the netcatty MCP host into the agents runtime: MCP server injection,
/// chat cancellation / attachment / cleanup hooks and the renderer approval
/// channel. Called from `lib.rs` setup once both states are managed.
pub fn wire_mcp<R: Runtime>(app: &AppHandle<R>) {
    use tauri::Manager;
    let (Some(agents), Some(mcp)) = (app.try_state::<AgentsState>(), app.try_state::<super::mcp::McpState>()) else {
        return;
    };
    let paths = netcatty_store::AppPaths::resolve();
    let discovery = netcatty_mcp::discovery::tool_cli_discovery_path(&paths.data_dir).to_string_lossy().into_owned();
    let bridge = Arc::new(McpBridge { host: mcp.host.clone(), discovery });
    agents.runtime.set_mcp_provider(bridge.clone());
    agents.runtime.set_approval_provider(bridge);
}

/// Adapter from `netcatty_mcp::McpHost` to the agents runtime hooks
/// (Electron: `injectMcp.cjs` + `mcpServerBridge` calls in `sdkStreamHandlers`).
struct McpBridge {
    host: Arc<netcatty_mcp::host::McpHost>,
    discovery: String,
}

#[async_trait::async_trait]
impl netcatty_agents::McpInjectionProvider for McpBridge {
    async fn build_injected_mcp_servers(
        &self,
        chat_session_id: &str,
        tool_integration_mode: &str,
    ) -> Result<Vec<netcatty_agents::McpServerConfig>, String> {
        let servers = netcatty_mcp::build_injected_mcp_servers(&self.host, chat_session_id, tool_integration_mode).await;
        Ok(servers
            .into_iter()
            .map(|s| netcatty_agents::McpServerConfig {
                name: s.name,
                kind: s.server_type,
                command: s.command,
                args: s.args,
                env: s.env.into_iter().map(|p| netcatty_agents::mcp::EnvPair { name: p.name, value: p.value }).collect(),
            })
            .collect())
    }

    fn discovery_file_path(&self) -> Option<String> {
        Some(self.discovery.clone())
    }

    fn update_attachment_metadata(&self, attachments: &[netcatty_agents::session::StagedAttachment], chat_session_id: &str) {
        let values: Vec<Value> = attachments.iter().filter_map(|a| serde_json::to_value(a).ok()).collect();
        self.host.update_attachment_metadata(&values, chat_session_id);
    }

    fn set_chat_session_cancelled(&self, chat_session_id: &str, cancelled: bool) {
        self.host.set_chat_session_cancelled(chat_session_id, cancelled);
        if cancelled {
            self.host.cancel_pty_execs_for_session(chat_session_id);
            self.host.clear_pending_approvals(Some(chat_session_id));
        }
    }

    async fn cleanup_scoped_metadata(&self, chat_session_id: &str) {
        self.host.cleanup_scoped_metadata(chat_session_id).await;
    }
}

#[async_trait::async_trait]
impl netcatty_agents::ApprovalProvider for McpBridge {
    async fn request_approval(&self, tool_name: &str, args: Value, chat_session_id: &str) -> bool {
        self.host.request_approval(tool_name, args, Some(chat_session_id.to_string()), None, None).await
    }

    fn clear_pending_approvals(&self, chat_session_id: &str) {
        self.host.clear_pending_approvals(Some(chat_session_id));
    }
}

impl Drop for AgentsState {
    fn drop(&mut self) {
        self.runtime.shutdown();
    }
}

fn opt(v: Option<Value>) -> Value {
    v.unwrap_or_else(|| json!({}))
}

#[tauri::command]
pub async fn ai_agents_discover(state: State<'_, AgentsState>, options: Option<Value>) -> CmdResult<Value> {
    Ok(state.runtime.discover_agents(&opt(options)).await)
}

#[tauri::command]
pub async fn ai_resolve_cli(state: State<'_, AgentsState>, payload: Value) -> CmdResult<Value> {
    Ok(state.runtime.resolve_cli(&payload).await)
}

#[tauri::command]
pub async fn ai_shell_env_prewarm(state: State<'_, AgentsState>) -> CmdResult<Value> {
    Ok(state.runtime.prewarm_shell_env().await)
}

#[tauri::command]
pub async fn ai_codex_get_integration(state: State<'_, AgentsState>, options: Option<Value>) -> CmdResult<Value> {
    Ok(state.runtime.codex_get_integration(&opt(options)).await)
}

#[tauri::command]
pub async fn ai_codex_start_login(state: State<'_, AgentsState>, options: Option<Value>) -> CmdResult<Value> {
    Ok(state.runtime.codex_start_login(&opt(options)).await)
}

#[tauri::command]
pub fn ai_codex_get_login_session(state: State<'_, AgentsState>, session_id: String) -> CmdResult<Value> {
    Ok(state.runtime.codex_get_login_session(&session_id))
}

#[tauri::command]
pub fn ai_codex_cancel_login(state: State<'_, AgentsState>, session_id: String) -> CmdResult<Value> {
    Ok(state.runtime.codex_cancel_login(&session_id))
}

#[tauri::command]
pub async fn ai_codex_logout(state: State<'_, AgentsState>, options: Option<Value>) -> CmdResult<Value> {
    Ok(state.runtime.codex_logout(&opt(options)).await)
}

/// Runs a whole turn; events stream on `netcatty:ai:sdk-agent:*`.
#[tauri::command]
pub async fn ai_sdk_agent_stream(state: State<'_, AgentsState>, payload: Value) -> CmdResult<Value> {
    let runtime = state.runtime.clone();
    Ok(runtime.stream(payload).await)
}

#[tauri::command]
pub async fn ai_sdk_agent_steer(state: State<'_, AgentsState>, payload: Value) -> CmdResult<Value> {
    Ok(state.runtime.steer(&payload).await)
}

#[tauri::command]
pub async fn ai_sdk_agent_list_models(state: State<'_, AgentsState>, payload: Value) -> CmdResult<Value> {
    Ok(state.runtime.list_models(&payload).await)
}

#[tauri::command]
pub async fn ai_sdk_agent_cancel(state: State<'_, AgentsState>, request_id: String, chat_session_id: Option<String>) -> CmdResult<Value> {
    Ok(state.runtime.cancel(&request_id, chat_session_id.as_deref()).await)
}

#[tauri::command]
pub async fn ai_sdk_agent_cleanup(state: State<'_, AgentsState>, chat_session_id: String) -> CmdResult<Value> {
    Ok(state.runtime.cleanup(&chat_session_id).await)
}

#[tauri::command]
pub fn ai_sdk_agent_elicitation_response(state: State<'_, AgentsState>, payload: Value) -> CmdResult<Value> {
    Ok(state.runtime.elicitation_response(&payload))
}

#[tauri::command]
pub async fn ai_sdk_agent_mcp_status(state: State<'_, AgentsState>, payload: Option<Value>) -> CmdResult<Value> {
    Ok(state.runtime.mcp_status(&opt(payload)).await)
}

#[tauri::command]
pub async fn ai_sdk_agent_account_info(state: State<'_, AgentsState>, payload: Option<Value>) -> CmdResult<Value> {
    Ok(state.runtime.account_info(&opt(payload)).await)
}

#[tauri::command]
pub fn ai_sdk_agent_plugin_install(state: State<'_, AgentsState>, payload: Value) -> CmdResult<Value> {
    Ok(state.runtime.plugin_action("plugin-install", &payload))
}

#[tauri::command]
pub fn ai_sdk_agent_plugin_enable(state: State<'_, AgentsState>, payload: Value) -> CmdResult<Value> {
    Ok(state.runtime.plugin_action("plugin-enable", &payload))
}

#[tauri::command]
pub fn ai_sdk_agent_plugin_disable(state: State<'_, AgentsState>, payload: Value) -> CmdResult<Value> {
    Ok(state.runtime.plugin_action("plugin-disable", &payload))
}

#[tauri::command]
pub fn ai_sdk_agent_marketplace_install(state: State<'_, AgentsState>, payload: Value) -> CmdResult<Value> {
    Ok(state.runtime.plugin_action("marketplace-install", &payload))
}

#[tauri::command]
pub fn ai_sdk_agent_marketplace_remove(state: State<'_, AgentsState>, payload: Value) -> CmdResult<Value> {
    Ok(state.runtime.plugin_action("marketplace-remove", &payload))
}

#[tauri::command]
pub async fn codex_app_server_status(state: State<'_, AgentsState>, payload: Option<Value>) -> CmdResult<Value> {
    Ok(state.runtime.codex_app_server_status(&opt(payload)).await)
}

#[tauri::command]
pub fn codex_app_server_respond(state: State<'_, AgentsState>, payload: Value) -> CmdResult<Value> {
    Ok(state.runtime.respond_codex_interaction(&payload))
}

#[tauri::command]
pub fn codex_app_server_cancel_timeout(state: State<'_, AgentsState>, interaction_id: String) -> CmdResult<Value> {
    Ok(state.runtime.cancel_codex_interaction_timeout(&interaction_id))
}
