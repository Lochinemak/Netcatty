//! AI control plane commands: capability RPC for the renderer harness, the
//! vault-agent request bridge, MCP host settings / scopes / approvals, the
//! tool-output temp store and the External MCP controller. Logic lives in
//! `netcatty-mcp`; this module adapts it to the session registry, SFTP and
//! the event bus. See `rust/docs/ipc-mcp.md`.

use super::system::exec::{bounded_exec, BoundedError};
use super::CmdResult;
use crate::events;
use crate::sessions::{SessionRegistry, SessionFlags};
use crate::state::Ctx;
use netcatty_core::ipc::EndpointType;
use netcatty_core::models::SftpFilenameEncoding;
use netcatty_mcp::host::backend::{ChannelError, ChannelOutput, HostBackend, SftpOp, TerminalSession};
use netcatty_mcp::host::McpHost;
use netcatty_ptyexec::job::{OutputRx, PtyInput};
use netcatty_ptyexec::shell_kind::{ExecProbe, ShellKindState};
use netcatty_ptyexec::shell_utils::PromptTracker;
use netcatty_ssh::SshConnection;
use serde_json::{json, Map, Value};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Manager, Runtime};

/// Managed state of the AI control plane.
pub struct McpState {
    pub host: Arc<McpHost>,
    pub external: Arc<netcatty_mcp::external::ExternalMcpController>,
    pub tool_outputs: Arc<netcatty_mcp::tool_output::ToolOutputStore>,
    pub approval_alert_mode: parking_lot::Mutex<String>,
}

impl McpState {
    pub fn new<R: Runtime>(app: &AppHandle<R>) -> Self {
        let paths = netcatty_store::AppPaths::resolve();
        let backend = Arc::new(DesktopBackend { app: app.clone() });
        let host = McpHost::new(backend, Some(netcatty_mcp::discovery::tool_cli_discovery_path(&paths.data_dir)));
        let external = netcatty_mcp::external::ExternalMcpController::new(
            host.clone(),
            netcatty_mcp::discovery::external_mcp_discovery_path(&paths.data_dir),
            netcatty_mcp::inject::current_executable(),
            netcatty_mcp::external::skill::bundled_skill_path(app.path().resource_dir().ok().as_deref()),
        );
        let app2 = app.clone();
        let tool_outputs = Arc::new(netcatty_mcp::tool_output::ToolOutputStore::new(
            Arc::new(move || super::tempdir::current(&app2)),
            paths.data_dir.join("tool-output-signing.key"),
        ));
        Self { host, external, tool_outputs, approval_alert_mode: parking_lot::Mutex::new("unfocused".into()) }
    }
}

/// The MCP host's view of the application.
pub(crate) struct DesktopBackend<R: Runtime> {
    pub app: AppHandle<R>,
}

impl<R: Runtime> DesktopBackend<R> {
    fn registry(&self) -> Option<SessionRegistry<R>> {
        self.app.try_state::<crate::state::AppState<R>>().map(|s| s.sessions.clone())
    }
}

#[async_trait::async_trait]
impl<R: Runtime> HostBackend for DesktopBackend<R> {
    fn session(&self, session_id: &str) -> Option<Arc<dyn TerminalSession>> {
        let registry = self.registry()?;
        let flags = registry.flags_of(session_id)?;
        let state = self.app.state::<crate::state::AppState<R>>();
        let connection = registry.connection_of(session_id);
        let single_channel = state.system.is_single_channel(session_id);
        Some(Arc::new(DesktopTerminal {
            app: self.app.clone(),
            registry,
            session_id: session_id.to_string(),
            flags,
            connection,
            single_channel,
        }))
    }

    fn session_ids(&self) -> Vec<String> {
        let mut ids = self.registry().map(|r| r.session_ids()).unwrap_or_default();
        ids.sort();
        ids
    }

    async fn sftp(&self, session_id: &str, op: SftpOp, cancel: tokio_util::sync::CancellationToken) -> Result<Value, String> {
        let registry = self.registry().ok_or("Session not found")?;
        let conn = registry
            .connection_of(session_id)
            .ok_or_else(|| format!("Session \"{session_id}\" has no SSH connection for SFTP"))?;
        let client = netcatty_sftp::SftpClient::open(conn, SftpFilenameEncoding::default()).await.map_err(|e| e.to_string())?;
        let client = Arc::new(client);
        let result = tokio::select! {
            _ = cancel.cancelled() => Err("Cancelled".to_string()),
            r = run_sftp_op(&self.app, &client, op, cancel.clone()) => r,
        };
        if let Ok(c) = Arc::try_unwrap(client) {
            let _ = c.close().await;
        }
        result
    }

    fn emit(&self, event: &str, payload: Value) {
        events::emit(&self.app, event, payload);
    }

    fn has_approval_window(&self) -> bool {
        !self.app.webview_windows().is_empty()
    }

    async fn list_port_forwards(&self) -> Vec<Value> {
        self.app
            .try_state::<crate::state::AppState<R>>()
            .map(|s| s.tunnels.list().into_iter().filter_map(|t| serde_json::to_value(t).ok()).collect())
            .unwrap_or_default()
    }

    fn sync_external_approval_attention(&self, pending: usize) {
        if pending == 0 {
            return;
        }
        let mode = self.app.try_state::<McpState>().map(|s| s.approval_alert_mode.lock().clone()).unwrap_or_default();
        if mode == "off" {
            return;
        }
        let focused = self.app.webview_windows().values().any(|w| w.is_focused().unwrap_or(false));
        if mode == "unfocused" && focused {
            return;
        }
        if let Some(w) = self.app.get_webview_window("main") {
            let _ = w.request_user_attention(Some(tauri::UserAttentionType::Informational));
        }
    }
}

async fn run_sftp_op<R: Runtime>(
    app: &AppHandle<R>,
    client: &Arc<netcatty_sftp::SftpClient>,
    op: SftpOp,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<Value, String> {
    let e = |err: netcatty_sftp::SftpError| err.to_string();
    Ok(match op {
        SftpOp::List { path } => serde_json::to_value(client.list(&path, None).await.map_err(e)?).unwrap_or(Value::Null),
        SftpOp::Read { path } => json!(String::from_utf8_lossy(&client.read(&path, None, None).await.map_err(e)?)),
        SftpOp::Write { path, content } => {
            client.write(&path, content.as_bytes(), None).await.map_err(e)?;
            Value::Null
        }
        SftpOp::Mkdir { path } => {
            client.mkdir(&path, None).await.map_err(e)?;
            Value::Null
        }
        SftpOp::Delete { path } => {
            client.delete(&path, None, None).await.map_err(e)?;
            Value::Null
        }
        SftpOp::Rename { old_path, new_path } => {
            client.rename(&old_path, &new_path, None).await.map_err(e)?;
            Value::Null
        }
        SftpOp::Stat { path } => serde_json::to_value(client.stat(&path, None).await.map_err(e)?).unwrap_or(Value::Null),
        SftpOp::Chmod { path, mode } => {
            client.chmod(&path, &mode, None).await.map_err(e)?;
            Value::Null
        }
        SftpOp::Home => json!(client.home_dir.clone().unwrap_or_default()),
        SftpOp::Download { remote_path, local_path, transfer_id, .. } => {
            transfer(app, client, EndpointType::Sftp, EndpointType::Local, remote_path, local_path, transfer_id, cancel).await?
        }
        SftpOp::Upload { local_path, remote_path, transfer_id, .. } => {
            transfer(app, client, EndpointType::Local, EndpointType::Sftp, local_path, remote_path, transfer_id, cancel).await?
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn transfer<R: Runtime>(
    app: &AppHandle<R>,
    client: &Arc<netcatty_sftp::SftpClient>,
    source_type: EndpointType,
    target_type: EndpointType,
    source_path: String,
    target_path: String,
    transfer_id: String,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<Value, String> {
    use netcatty_sftp::transfer::{start_transfer, TransferEndpoints, TransferOutcome, TransferRequest};
    let download = source_type == EndpointType::Sftp;
    let request = TransferRequest {
        transfer_id: transfer_id.clone(),
        source_type,
        target_type,
        source_path,
        target_path,
        total_bytes: None,
        checkpoint_bytes: 0,
        stage_target: true,
    };
    let endpoints = TransferEndpoints {
        source: download.then(|| client.clone()),
        target: (!download).then(|| client.clone()),
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut handle = start_transfer(request, endpoints, Some(tx)).map_err(|e| e.to_string())?;
    let app2 = app.clone();
    let id2 = transfer_id.clone();
    let progress = tokio::spawn(async move {
        while let Some((_, p)) = rx.recv().await {
            events::emit(
                &app2,
                netcatty_mcp::host::sftp::GLOBAL_TRANSFER_EVENT,
                json!({ "type": "progress", "transferId": id2, "transferred": p.transferred, "totalBytes": p.total, "speed": p.speed }),
            );
        }
    });
    let outcome = tokio::select! {
        _ = cancel.cancelled() => {
            handle.cancel();
            (&mut handle.done).await.ok()
        }
        o = &mut handle.done => o.ok(),
    };
    progress.abort();
    match outcome {
        Some(TransferOutcome::Completed { total }) => Ok(json!({ "totalBytes": total })),
        Some(TransferOutcome::Cancelled { .. }) | Some(TransferOutcome::Paused { .. }) => Ok(json!({ "cancelled": true, "error": "Transfer cancelled" })),
        Some(TransferOutcome::Failed { error, .. }) => Ok(json!({ "error": error })),
        None => Err("Transfer ended without a result".into()),
    }
}

/// A live terminal session as seen by the MCP host.
struct DesktopTerminal<R: Runtime> {
    app: AppHandle<R>,
    registry: SessionRegistry<R>,
    session_id: String,
    flags: Arc<SessionFlags>,
    connection: Option<Arc<SshConnection>>,
    single_channel: bool,
}

struct RegistryWriter<R: Runtime> {
    registry: SessionRegistry<R>,
    session_id: String,
}

#[async_trait::async_trait]
impl<R: Runtime> PtyInput for RegistryWriter<R> {
    async fn write(&self, data: &str) -> Result<(), String> {
        self.registry.write_text(&self.session_id, data).await.map_err(|e| e.message)
    }
}

struct ConnProbe(Arc<SshConnection>);

#[async_trait::async_trait]
impl ExecProbe for ConnProbe {
    async fn exec_probe(&self, command: &str, timeout_ms: u64) -> Option<String> {
        let t = Duration::from_millis(timeout_ms.max(1));
        let out = bounded_exec(&self.0, command, None, t, t, 64 * 1024).await.ok()?;
        Some(format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
    }
}

#[async_trait::async_trait]
impl<R: Runtime> TerminalSession for DesktopTerminal<R> {
    fn session_id(&self) -> &str {
        &self.session_id
    }
    fn protocol(&self) -> &str {
        self.flags.ai.info.lock().0
    }
    fn label(&self) -> String {
        self.flags.ai.info.lock().1.clone()
    }
    fn hostname(&self) -> String {
        self.connection.as_ref().map(|c| c.options.target.hostname.clone()).unwrap_or_default()
    }
    fn username(&self) -> String {
        self.connection.as_ref().map(|c| c.options.target.username.clone()).unwrap_or_default()
    }
    fn host_id(&self) -> String {
        self.flags.ai.info.lock().2.clone().unwrap_or_default()
    }
    fn writer(&self) -> Option<Arc<dyn PtyInput>> {
        Some(Arc::new(RegistryWriter { registry: self.registry.clone(), session_id: self.session_id.clone() }))
    }
    fn subscribe(&self) -> OutputRx {
        self.flags.ai.subscribe()
    }
    fn prompt(&self) -> PromptTracker {
        self.flags.ai.prompt.lock().clone()
    }
    fn shell_kind(&self) -> Arc<ShellKindState> {
        self.flags.ai.shell_kind.clone()
    }
    fn remote_ssh_version(&self) -> String {
        self.connection
            .as_ref()
            .and_then(|c| c.server_banner.clone())
            .map(|b| super::session::software_from_banner(&b))
            .unwrap_or_default()
    }
    fn single_channel(&self) -> bool {
        self.single_channel
    }
    fn exec_probe(&self) -> Option<Arc<dyn ExecProbe>> {
        self.connection.clone().map(|c| Arc::new(ConnProbe(c)) as Arc<dyn ExecProbe>)
    }
    async fn channel_exec(&self, command: &str, timeout_ms: u64, max: usize) -> Option<Result<ChannelOutput, ChannelError>> {
        let conn = self.connection.clone()?;
        let t = Duration::from_millis(timeout_ms.max(1));
        Some(match bounded_exec(&conn, command, None, t, t, max).await {
            Ok(out) => Ok(ChannelOutput {
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                exit_code: out.code,
            }),
            Err(BoundedError::OpenTimeout(_)) => Err(ChannelError::OpenTimeout),
            Err(BoundedError::RunTimeout(_)) => Err(ChannelError::RunTimeout),
            Err(BoundedError::OutputLimit(n)) => Err(ChannelError::OutputLimit(n)),
            Err(BoundedError::Failed(m)) => Err(ChannelError::Failed(m)),
        })
    }
    fn prompt_recovery_pending(&self) -> Arc<AtomicBool> {
        self.flags.ai.prompt_recovery_pending.clone()
    }
    fn clear_flow(&self) {
        let _ = self.registry.set_flow_paused(&self.session_id, false);
    }
    fn emit_display(&self, data: &str, synthetic: bool) {
        let mut payload = json!({ "sessionId": self.session_id, "data": data });
        if synthetic {
            payload["syntheticEcho"] = json!(true);
        }
        events::emit(&self.app, netcatty_core::ipc::events::SESSION_DATA, payload);
    }
}

pub(crate) fn mcp<'a, R: Runtime>(state: &'a Ctx<'_, R>) -> CmdResult<tauri::State<'a, McpState>> {
    state
        .app
        .try_state::<McpState>()
        .ok_or_else(|| netcatty_core::CoreError::unsupported("AI control plane is not initialised"))
}

fn arr(v: Option<Value>) -> Vec<Value> {
    v.and_then(|v| v.as_array().cloned()).unwrap_or_default()
}

// ── renderer harness ────────────────────────────────────────────────────

/// `aiCapability(rpcMethod, params, chatSessionId)`.
#[tauri::command]
pub async fn ai_capability<R: Runtime>(state: Ctx<'_, R>, rpc_method: String, params: Option<Map<String, Value>>, chat_session_id: Option<String>) -> CmdResult<Value> {
    let host = mcp(&state)?.host.clone();
    Ok(host.renderer_capability(&rpc_method, params, chat_session_id.as_deref()).await)
}

/// `respondVaultAgent(requestId, result)`.
#[tauri::command]
pub fn ai_vault_agent_respond<R: Runtime>(state: Ctx<'_, R>, request_id: String, result: Option<Value>) -> CmdResult<Value> {
    Ok(mcp(&state)?.host.vault_agent.respond(&request_id, result.unwrap_or(Value::Null)))
}

// ── scopes / settings ───────────────────────────────────────────────────

#[tauri::command]
pub fn ai_mcp_update_sessions<R: Runtime>(state: Ctx<'_, R>, sessions: Option<Value>, chat_session_id: Option<String>) -> CmdResult<Value> {
    let st = mcp(&state)?;
    let list = arr(sessions);
    if chat_session_id.as_deref() == Some(netcatty_mcp::EXTERNAL_MCP_CHAT_SESSION_ID) && !st.external.is_enabled() {
        return Ok(json!({ "ok": false, "error": "External MCP is disabled" }));
    }
    st.host.update_session_metadata(&list, chat_session_id.as_deref());
    Ok(json!({ "ok": true, "count": list.len() }))
}

#[tauri::command]
pub fn ai_mcp_update_live_sessions<R: Runtime>(state: Ctx<'_, R>, sessions: Option<Value>) -> CmdResult<Value> {
    Ok(mcp(&state)?.host.update_live_session_metadata(&arr(sessions)))
}

#[tauri::command]
pub fn ai_mcp_merge_sessions<R: Runtime>(state: Ctx<'_, R>, sessions: Option<Value>, chat_session_id: Option<String>) -> CmdResult<Value> {
    let st = mcp(&state)?;
    let Some(chat) = chat_session_id.filter(|c| !c.is_empty()) else {
        return Ok(json!({ "ok": false, "error": "chatSessionId is required" }));
    };
    if chat == netcatty_mcp::EXTERNAL_MCP_CHAT_SESSION_ID && !st.external.is_enabled() {
        return Ok(json!({ "ok": false, "error": "External MCP is disabled" }));
    }
    Ok(st.host.merge_session_metadata(&arr(sessions), &chat))
}

#[tauri::command]
pub fn ai_mcp_update_attachments<R: Runtime>(state: Ctx<'_, R>, attachments: Option<Value>, chat_session_id: Option<String>) -> CmdResult<Value> {
    mcp(&state)?.host.update_attachment_metadata(&arr(attachments), chat_session_id.as_deref().unwrap_or(""));
    Ok(json!({ "ok": true }))
}

#[tauri::command]
pub fn ai_mcp_set_command_blocklist<R: Runtime>(state: Ctx<'_, R>, blocklist: Option<Value>) -> CmdResult<Value> {
    let Some(list) = blocklist.and_then(|v| v.as_array().cloned()) else {
        return Ok(json!({ "ok": false, "error": "blocklist must be an array" }));
    };
    let valid: Vec<String> = list
        .iter()
        .filter_map(Value::as_str)
        .filter(|p| netcatty_ptyexec::safety::is_valid_pattern(p))
        .map(str::to_string)
        .collect();
    mcp(&state)?.host.set_command_blocklist(valid);
    Ok(json!({ "ok": true }))
}

#[tauri::command]
pub fn ai_mcp_set_command_timeout<R: Runtime>(state: Ctx<'_, R>, timeout: Option<Value>) -> CmdResult<Value> {
    let max = netcatty_mcp::host::MAX_COMMAND_TIMEOUT_SECONDS as f64;
    match number(timeout).filter(|v| (1.0..=max).contains(v)) {
        Some(v) => {
            mcp(&state)?.host.set_command_timeout(v);
            Ok(json!({ "ok": true }))
        }
        None => Ok(json!({ "ok": false, "error": format!("timeout must be a number between 1 and {}", netcatty_mcp::host::MAX_COMMAND_TIMEOUT_SECONDS) })),
    }
}

fn number(v: Option<Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
    .filter(|f: &f64| f.is_finite())
}

#[tauri::command]
pub fn ai_mcp_set_max_iterations<R: Runtime>(state: Ctx<'_, R>, max_iterations: Option<Value>) -> CmdResult<Value> {
    match number(max_iterations).filter(|v| (1.0..=100.0).contains(v)) {
        Some(v) => {
            mcp(&state)?.host.set_max_iterations(v);
            Ok(json!({ "ok": true }))
        }
        None => Ok(json!({ "ok": false, "error": "maxIterations must be a number between 1 and 100" })),
    }
}

#[tauri::command]
pub fn ai_mcp_set_permission_mode<R: Runtime>(state: Ctx<'_, R>, mode: Option<String>) -> CmdResult<Value> {
    let mode = mode.unwrap_or_default();
    if !matches!(mode.as_str(), "observer" | "confirm" | "auto") {
        return Ok(json!({ "ok": false, "error": "mode must be one of: observer, confirm, auto" }));
    }
    mcp(&state)?.host.set_permission_mode(&mode);
    Ok(json!({ "ok": true }))
}

#[tauri::command]
pub fn ai_mcp_set_tool_integration_mode<R: Runtime>(state: Ctx<'_, R>, mode: Option<String>) -> CmdResult<Value> {
    let mode = mode.unwrap_or_default();
    if !matches!(mode.as_str(), "mcp" | "skills") {
        return Ok(json!({ "ok": false, "error": "mode must be one of: mcp, skills" }));
    }
    mcp(&state)?.host.set_tool_integration_mode(&mode);
    Ok(json!({ "ok": true }))
}

#[tauri::command]
pub fn ai_mcp_sync_permission_grants<R: Runtime>(state: Ctx<'_, R>, grants: Option<Value>) -> CmdResult<Value> {
    let count = mcp(&state)?.host.set_permission_grants(&grants.unwrap_or(Value::Null));
    Ok(json!({ "ok": true, "count": count }))
}

// ── approvals ───────────────────────────────────────────────────────────

#[tauri::command]
pub fn ai_mcp_approval_respond<R: Runtime>(state: Ctx<'_, R>, approval_id: String, approved: Option<bool>, scope: Option<String>) -> CmdResult<Value> {
    let accepted = mcp(&state)?.host.resolve_approval(&approval_id, approved == Some(true), scope.as_deref().unwrap_or("once"));
    Ok(json!({ "ok": true, "accepted": accepted }))
}

#[tauri::command]
pub fn ai_mcp_approval_cancel_timeout<R: Runtime>(state: Ctx<'_, R>, approval_id: String) -> CmdResult<Value> {
    let cancelled = mcp(&state)?.host.cancel_approval_timeout(&approval_id);
    Ok(json!({ "ok": true, "cancelled": cancelled }))
}

/// `setExternalMcpApprovalAlertMode({ mode })` → `{ mode }`.
#[tauri::command]
pub fn mcp_set_approval_alert_mode<R: Runtime>(state: Ctx<'_, R>, payload: Option<Value>) -> CmdResult<Value> {
    let mode = payload.as_ref().and_then(|p| p["mode"].as_str()).unwrap_or("");
    let mode = if matches!(mode, "off" | "unfocused" | "always") { mode } else { "unfocused" };
    *mcp(&state)?.approval_alert_mode.lock() = mode.to_string();
    Ok(json!({ "mode": mode }))
}

/// Kill running commands, jobs, SFTP and approvals of a cancelled chat.
/// The AI core's `aiSetChatSessionCancelled` calls this after setting its flag.
pub async fn apply_chat_session_cancelled<R: Runtime>(app: &AppHandle<R>, chat_session_id: &str, cancelled: bool) -> Value {
    match app.try_state::<McpState>() {
        Some(st) => st.host.apply_chat_session_cancelled(chat_session_id, cancelled).await,
        None => json!({ "ok": false, "error": "AI control plane is not initialised" }),
    }
}

/// Launch spec of the stdio MCP server for an SDK agent chat
/// (`netcatty_mcp::build_injected_mcp_servers` on the managed host).
pub async fn injected_mcp_servers<R: Runtime>(app: &AppHandle<R>, chat_session_id: &str, tool_integration_mode: &str) -> Vec<netcatty_mcp::InjectedMcpServer> {
    match app.try_state::<McpState>() {
        Some(st) => netcatty_mcp::build_injected_mcp_servers(&st.host, chat_session_id, tool_integration_mode).await,
        None => Vec::new(),
    }
}

// ── tool output temp store ──────────────────────────────────────────────

#[tauri::command]
pub async fn tool_output_persistence_status<R: Runtime>(state: Ctx<'_, R>) -> CmdResult<Value> {
    Ok(mcp(&state)?.tool_outputs.persistence_status())
}

#[tauri::command]
pub async fn tool_output_write<R: Runtime>(state: Ctx<'_, R>, record: Option<Value>, content: Option<String>) -> CmdResult<Value> {
    let store = mcp(&state)?.tool_outputs.clone();
    Ok(store.write(record.unwrap_or(Value::Null), content.unwrap_or_default()).await)
}

#[tauri::command]
pub async fn tool_output_restore<R: Runtime>(state: Ctx<'_, R>, handle_id: Option<String>, chat_session_id: Option<String>) -> CmdResult<Value> {
    let store = mcp(&state)?.tool_outputs.clone();
    Ok(store.restore(&handle_id.unwrap_or_default(), &chat_session_id.unwrap_or_default()).await)
}

#[tauri::command]
pub async fn tool_output_read<R: Runtime>(state: Ctx<'_, R>, path: Option<String>, request: Option<Value>) -> CmdResult<Value> {
    let store = mcp(&state)?.tool_outputs.clone();
    Ok(store.read(&path.unwrap_or_default(), request).await)
}

#[tauri::command]
pub async fn tool_output_delete<R: Runtime>(state: Ctx<'_, R>, path: Option<String>) -> CmdResult<Value> {
    let store = mcp(&state)?.tool_outputs.clone();
    Ok(json!({ "ok": store.delete(&path.unwrap_or_default()).await }))
}

#[tauri::command]
pub async fn tool_output_delete_chat<R: Runtime>(state: Ctx<'_, R>, chat_session_id: Option<String>) -> CmdResult<Value> {
    let store = mcp(&state)?.tool_outputs.clone();
    Ok(json!({ "deletedCount": store.delete_chat(&chat_session_id.unwrap_or_default()).await }))
}

#[tauri::command]
pub async fn tool_output_delete_terminal_session<R: Runtime>(state: Ctx<'_, R>, chat_session_id: Option<String>, terminal_session_id: Option<String>) -> CmdResult<Value> {
    let store = mcp(&state)?.tool_outputs.clone();
    Ok(json!({ "deletedCount": store.delete_terminal_session(&chat_session_id.unwrap_or_default(), &terminal_session_id.unwrap_or_default()).await }))
}

#[tauri::command]
pub async fn tool_output_delete_terminal<R: Runtime>(state: Ctx<'_, R>, terminal_session_id: Option<String>) -> CmdResult<Value> {
    let store = mcp(&state)?.tool_outputs.clone();
    Ok(json!({ "deletedCount": store.delete_terminal(&terminal_session_id.unwrap_or_default()).await }))
}

// ── External MCP ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn external_mcp_get_status<R: Runtime>(state: Ctx<'_, R>) -> CmdResult<Value> {
    Ok(mcp(&state)?.external.status())
}

#[tauri::command]
pub async fn external_mcp_set_enabled<R: Runtime>(state: Ctx<'_, R>, enabled: Option<bool>) -> CmdResult<Value> {
    let ext = mcp(&state)?.external.clone();
    Ok(ext.set_enabled(enabled == Some(true)).await)
}

#[tauri::command]
pub async fn external_mcp_set_config<R: Runtime>(state: Ctx<'_, R>, config: Option<Value>) -> CmdResult<Value> {
    let ext = mcp(&state)?.external.clone();
    let config = config.unwrap_or(json!({}));
    let status = ext.set_config(&config).await;
    // TODO(ai-privacy): apply the normalized redaction policy to the AI core
    // privacy service: `commands::ai::configure_privacy(&AiState, Some(&redaction))`
    // when `config.redaction` is a valid policy, `None` when it is invalid /
    // null. The AI core module is merged separately.
    let _privacy_policy: Option<&Value> = config.get("redaction").filter(|_| status["ok"] != json!(false));
    Ok(status)
}

#[tauri::command]
pub async fn external_mcp_get_universal_setup_prompt<R: Runtime>(state: Ctx<'_, R>) -> CmdResult<Value> {
    Ok(mcp(&state)?.external.universal_setup_prompt().await)
}

#[tauri::command]
pub async fn external_mcp_client_status<R: Runtime>(state: Ctx<'_, R>, client: String) -> CmdResult<Value> {
    let ext = mcp(&state)?.external.clone();
    Ok(ext.client_status(&client).await)
}

#[tauri::command]
pub async fn external_mcp_client_add<R: Runtime>(state: Ctx<'_, R>, client: String) -> CmdResult<Value> {
    let ext = mcp(&state)?.external.clone();
    Ok(ext.client_add(&client).await)
}
