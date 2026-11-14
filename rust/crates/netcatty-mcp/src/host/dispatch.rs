//! RPC dispatch of the host (Electron `dispatchCore`, `handleGetContext`,
//! `handleGetStatus`, attachments, `handleReadContext`).

use super::backend::HostBackend;
use super::target::SessionTarget;
use super::{find_meta_across_scopes, McpHost, EXTERNAL_MCP_CHAT_SESSION_ID, MCP_APPROVAL_TIMEOUT_MS};
use netcatty_capabilities::catalog::SURFACE_BUILTIN;
use netcatty_capabilities::grants::PermissionGrant;
use netcatty_capabilities::policy::{evaluate_permission_with_grants, PermissionRequest, USER_DENIED_MESSAGE};
use netcatty_capabilities::registry::capability_by_rpc_method;
use netcatty_capabilities::services::{run_guard, ExecGuard};
use netcatty_capabilities::surfaces::list_mcp_tools;
use netcatty_capabilities::{CapabilityHost, DispatchContext, PortForwardRuntime, SessionHooks};
use serde_json::{json, Map, Value};
use std::sync::{Arc, Weak};

pub const VAULT_HOSTS_VS_NOTES_GUIDANCE: &str = "Vault → Hosts vs Vault → Notes: When the user asks to add/create/import a host (创建主机、添加主机、保存 SSH 连接凭据), use vault_hosts_create with dryRun=true first, or vault_hosts_import for known export formats (PuTTY, MobaXterm, CSV, SecureCRT, FinalShell, ssh_config) — NOT vault_notes_create. For attached host files, use vault_hosts_import only when the attachment is a known export format; for unknown attached host/server text, read the attachment content, extract hostname, username, password, port, group, tags, and label yourself, then call vault_hosts_create with dryRun=true first. Extract hostname, username, password or local keyPath, port, group, tags, and label from the user's text; put long admin tables or remarks in the host notes field (host_notes_set / Host Details metadata), not Vault sidebar Notes. Use vault_notes_create or vault_notes_update ONLY when the user explicitly wants markdown documentation in Vault → Notes (保险箱笔记 sidebar). Use vault_notes_import to import generated or attached markdown as one or more sidebar notes. Use vault_hosts_list to resolve hostId before vault_hosts_update or vault_hosts_delete. If vault_hosts_create or vault_hosts_import fails, report the error — do not silently create a Vault note instead.";

pub const VAULT_SCRIPTS_GUIDANCE: &str = "Snippets vs automation scripts: snippets_* for shell command text (optional named placeholders written with two curly braces on each side). scripts_* for nct JavaScript automation (await nct.screen.sendLine, waitForText/waitForRegex, dialogs). Call scripts_reference before authoring scripts. scripts_run with wait=true blocks until completion; use scripts_runs_list / scripts_run_stop / scripts_run_pause / scripts_run_resume for lifecycle. Triggers: manual, onConnect (runs after connect), onOutput (regex triggerPattern). Host/group linking: scripts_targets_set supports targets and dynamic targetGroups; per-host connect order: host_connect_scripts_list / host_connect_scripts_set.";

pub fn append_vault_agent_guidance(description: &str) -> String {
    let mut result = description.trim().to_string();
    if !result.contains("Vault → Hosts vs Vault → Notes") {
        result = if result.is_empty() { VAULT_HOSTS_VS_NOTES_GUIDANCE.into() } else { format!("{result} {VAULT_HOSTS_VS_NOTES_GUIDANCE}") };
    }
    if !result.contains("Snippets vs automation scripts") {
        result = if result.is_empty() { VAULT_SCRIPTS_GUIDANCE.into() } else { format!("{result} {VAULT_SCRIPTS_GUIDANCE}") };
    }
    result
}

fn str_param<'a>(p: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    p.get(k).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn scoped_ids(p: &Map<String, Value>) -> Option<Vec<String>> {
    p.get("scopedSessionIds").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
}

fn build_mcp_tool_hints() -> Value {
    let tools = list_mcp_tools();
    let get = |id: &str| tools.iter().find(|t| t.capability_id == id).map(|t| t.mcp_tool.clone());
    let pick = |pairs: &[(&str, &str)]| {
        let mut m = Map::new();
        for (k, id) in pairs {
            if let Some(t) = get(id) {
                m.insert((*k).into(), json!(t));
            }
        }
        Value::Object(m)
    };
    json!({
        "environment": get("session.environment"),
        "terminal": pick(&[("execute", "terminal.execute"), ("start", "terminal.start"), ("poll", "terminal.poll"), ("stop", "terminal.stop")]),
        "attachments": pick(&[("list", "attachment.list"), ("read", "attachment.read")]),
        "sftp": pick(&[("list", "sftp.list"), ("find", "sftp.find"), ("read", "sftp.read"), ("write", "sftp.write"), ("download", "sftp.download"), ("upload", "sftp.upload")]),
    })
}

fn terminal_tool_guidance(hints: &Value) -> String {
    let t = &hints["terminal"];
    let (e, s, p, x) = (t["execute"].as_str(), t["start"].as_str(), t["poll"].as_str(), t["stop"].as_str());
    if let (Some(e), Some(s), Some(p), Some(x)) = (e, s, p, x) {
        return format!("For terminal commands, use `{e}` for short commands and `{s}`, `{p}`, and `{x}` for long-running commands. ");
    }
    if t.as_object().is_some_and(|m| !m.is_empty()) {
        return "For terminal commands, use the terminal tools listed in tools.terminal. ".into();
    }
    String::new()
}

const TEXT_ATTACHMENT_EXTENSIONS: [&str; 39] = [
    ".txt", ".md", ".markdown", ".json", ".jsonc", ".jsonl", ".yaml", ".yml", ".toml", ".ini", ".csv", ".tsv", ".xml", ".html", ".css", ".js", ".jsx", ".ts",
    ".tsx", ".mjs", ".cjs", ".py", ".sh", ".bash", ".zsh", ".fish", ".rs", ".go", ".java", ".kt", ".rb", ".php", ".sql", ".log", ".conf", ".cfg", ".env",
    ".gitignore", ".htm",
];

fn is_likely_text_attachment(media_type: &str, filename: &str) -> bool {
    let mt = media_type.to_lowercase();
    if mt.starts_with("text/") || mt.ends_with("+json") || mt.ends_with("+xml") {
        return true;
    }
    if let Some(sub) = mt.strip_prefix("application/") {
        if matches!(sub, "json" | "xml" | "javascript" | "x-javascript" | "typescript" | "yaml" | "x-yaml" | "toml" | "csv" | "x-ndjson" | "ndjson") {
            return true;
        }
    }
    let lower = filename.to_lowercase();
    let ext = std::path::Path::new(&lower)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_else(|| if lower.starts_with('.') { lower.clone() } else { String::new() });
    TEXT_ATTACHMENT_EXTENSIONS.contains(&ext.as_str()) && ext != ".htm"
}

impl McpHost {
    /// Top-level dispatch of one RPC (`dispatch` / `dispatchCore`). `Err`
    /// becomes a JSON-RPC error response.
    pub async fn dispatch(&self, method: &str, mut params: Map<String, Value>, ctx: DispatchContext) -> Result<Value, String> {
        // A session named by label / hostname becomes its id before anything
        // (permissions, approvals, scope checks) looks at the target.
        if method != "netcatty/getContext" {
            match self.resolve_session_target(&params) {
                SessionTarget::Resolved(id) => {
                    params.insert("sessionId".into(), json!(id));
                }
                SessionTarget::Ambiguous(error) => return Ok(error),
                SessionTarget::Unchanged => {}
            }
        }
        if !method.starts_with("netcatty/") {
            if let Some(result) = self.capabilities.dispatch(method, &params, &ctx).await? {
                return Ok(result);
            }
        }
        let capability = capability_by_rpc_method(method, SURFACE_BUILTIN);
        let cap_id = capability.map(|c| c.id.as_str()).unwrap_or("");
        let is_exec = cap_id == "terminal.execute" || cap_id == "terminal.start";
        let chat = str_param(&params, "chatSessionId").map(str::to_string);
        let session_id = str_param(&params, "sessionId").map(str::to_string);
        self.prune_completed_background_jobs();

        let target = self.approval_target(&params);
        let host_id = target.as_ref().and_then(|t| t["hostId"].as_str()).filter(|s| !s.is_empty()).map(str::to_string);
        let mode = self.permission_mode();
        let grants: Vec<PermissionGrant> = self.permission_grants();
        let decision = evaluate_permission_with_grants(
            &PermissionRequest {
                rpc_method: method,
                surface: SURFACE_BUILTIN,
                permission_mode: &mode,
                params: &params,
                chat_session_cancelled: self.is_chat_session_cancelled(chat.as_deref()),
                host_id: host_id.as_deref(),
            },
            &grants,
        );
        if !decision.allowed {
            return Ok(json!({ "ok": false, "error": decision.error }));
        }
        let explicit = scoped_ids(&params);
        if method != "netcatty/getContext" {
            if let Some(sid) = &session_id {
                if let Some(err) = self.validate_session_scope(sid, chat.as_deref(), explicit.as_deref()) {
                    return Ok(self.scope_error(err, &params));
                }
            }
        }
        let mut _write_guard = None;
        if is_exec {
            if let Some(sid) = &session_id {
                if self.jobs.is_closing(sid) {
                    return Ok(json!({ "ok": false, "error": format!("Session \"{sid}\" is closing.") }));
                }
                if let Some(busy) = self.session_busy_error(sid) {
                    return Ok(busy);
                }
                match self.try_reserve_pending_write(sid, method) {
                    Some(g) => _write_guard = Some(g),
                    None => {
                        return Ok(json!({ "ok": false, "error": "Session already has another command request awaiting approval or startup. Wait for it to finish before starting a new command." }))
                    }
                }
            }
        }
        let tracks_activity = session_id.is_some() && (is_exec || cap_id.starts_with("sftp."));
        let activity = tracks_activity && self.idle.begin_activity(session_id.as_deref().unwrap_or(""));
        let result = self.dispatch_approved(method, &params, &ctx, decision.requires_approval, target, is_exec).await;
        if activity {
            self.idle.end_activity(session_id.as_deref().unwrap_or(""));
        }
        result
    }

    async fn dispatch_approved(
        &self,
        method: &str,
        params: &Map<String, Value>,
        ctx: &DispatchContext,
        requires_approval: bool,
        target: Option<Value>,
        is_exec: bool,
    ) -> Result<Value, String> {
        let chat = str_param(params, "chatSessionId").map(str::to_string);
        if requires_approval && !self.has_session_approval(ctx.external_client) {
            let mut args = params.clone();
            args.remove("chatSessionId");
            let approved = self.request_approval(method, Value::Object(args), chat.clone(), target, ctx.external_client).await;
            if !approved {
                return Ok(json!({ "ok": false, "error": USER_DENIED_MESSAGE }));
            }
        }
        if is_exec {
            if let Some(sid) = str_param(params, "sessionId") {
                if let Some(err) = self.validate_session_scope(sid, chat.as_deref(), scoped_ids(params).as_deref()) {
                    return Ok(json!({ "ok": false, "error": err }));
                }
                if self.jobs.is_closing(sid) {
                    return Ok(json!({ "ok": false, "error": format!("Session \"{sid}\" is closing.") }));
                }
            }
        }
        run_guard(ctx.before_execute.as_ref())?;
        let guard = ctx.before_execute.clone();
        match method {
            "netcatty/getContext" => self.handle_get_context(params).await,
            "netcatty/getStatus" => Ok(self.handle_get_status()),
            "netcatty/listAttachments" => Ok(self.handle_list_attachments(params)),
            "netcatty/readAttachment" => Ok(self.handle_read_attachment(params)),
            "netcatty/readContext" => Ok(self.handle_read_context(params).await),
            "netcatty/exec" => self.handle_exec(params, guard).await,
            "netcatty/jobStart" => self.handle_job_start(params, guard).await,
            "netcatty/jobPoll" => self.handle_job_poll(params),
            "netcatty/jobStop" => self.handle_job_stop(params),
            "netcatty/setCancelled" => {
                let chat = chat.unwrap_or_default();
                if chat.is_empty() {
                    return Err("chatSessionId is required".into());
                }
                let cancelled = params.get("cancelled").and_then(Value::as_bool) != Some(false);
                Ok(self.apply_chat_session_cancelled(&chat, cancelled).await)
            }
            m if m.starts_with("netcatty/sftp/") => self.handle_sftp(m, params, guard.as_ref()).await,
            other => Err(format!("Unknown method: {other}")),
        }
    }

    pub async fn handle_get_context(&self, params: &Map<String, Value>) -> Result<Value, String> {
        let hints = build_mcp_tool_hints();
        let chat = str_param(params, "chatSessionId");
        if chat == Some(EXTERNAL_MCP_CHAT_SESSION_ID) {
            if !self.external_enabled() {
                return Ok(json!({ "environment": "netcatty-terminal", "description": "External MCP is disabled.", "hosts": [], "hostCount": 0, "tools": hints }));
            }
            self.sync_live_sessions_to_external_scope();
        }
        let explicit = scoped_ids(params);
        let Some(resolved) = self.resolve_scoped_session_ids(chat, explicit.as_deref()) else {
            return Err("chatSessionId or scopedSessionIds is required.".into());
        };
        if resolved.is_empty() {
            return Ok(json!({ "environment": "netcatty-terminal", "description": "No hosts are available in the current scope.", "hosts": [], "hostCount": 0, "tools": hints }));
        }
        let mut hosts = Vec::new();
        let mut added = std::collections::HashSet::new();
        for id in self.backend.session_ids() {
            if !resolved.contains(&id) {
                continue;
            }
            let Some(session) = self.backend.session(&id) else {
                continue;
            };
            let has_transport = session.writer().is_some();
            let scope_meta = self.session_meta(&id, chat);
            if !has_transport && scope_meta.is_none() {
                continue;
            }
            let meta = scope_meta.clone().unwrap_or_default();
            let or = |a: &str, b: String| if a.is_empty() { b } else { a.to_string() };
            hosts.push(json!({
                "sessionId": id,
                "hostname": or(&meta.hostname, session.hostname()),
                "label": or(&meta.label, session.label()),
                "os": meta.os,
                "username": or(&meta.username, session.username()),
                "protocol": or(&meta.protocol, session.protocol().to_string()),
                "shellType": or(&meta.shell_type, session.shell_kind().shell_kind()),
                "deviceType": meta.device_type,
                "connected": if scope_meta.is_some() { meta.connected } else { has_transport },
                "hostId": meta.host_id,
                "hostChain": meta.host_chain.clone().unwrap_or_default(),
                "activePortForwards": meta.active_port_forwards.clone().unwrap_or_default(),
            }));
            added.insert(id);
        }
        for id in &resolved {
            if added.contains(id) {
                continue;
            }
            if let Some(meta) = self.session_meta(id, chat) {
                hosts.push(meta.to_host(id));
                added.insert(id.clone());
            }
        }
        let tunnels = self.backend.list_port_forwards().await;
        let description = append_vault_agent_guidance(&format!(
            "You are operating inside Netcatty, a multi-session terminal manager. The available sessions may be remote hosts, local terminals, Mosh-backed shells, or serial port connections (network devices, embedded systems). Use the provided tools to execute commands through the sessions exposed by Netcatty. {}Serial sessions (protocol: serial, shellType: raw) do not run a standard shell — commands are sent as-is. A session listed with connected false is still in the scope. SSH auto-reconnect keeps the same sessionId: wait and retry that session while it reconnects. Inactive disconnected or restored tabs may require user action; host_open reuses connected or connecting sessions by default and opens a connection when none is usable. Network device sessions (deviceType: network) use vendor CLIs (Huawei VRP, Cisco IOS, etc.) — commands are sent as-is without shell wrapping, and exit codes are unavailable. Vault snippets, port forwarding rules/tunnels, and SFTP read/write tools are available when exposed in the tool list. Always prefer these tools over suggesting the user to do things manually.",
            terminal_tool_guidance(&hints)
        ));
        let count = hosts.len();
        Ok(json!({
            "environment": "netcatty-terminal",
            "description": description,
            "hosts": hosts,
            "hostCount": count,
            "activePortForwardTunnels": tunnels,
            "tools": hints,
        }))
    }

    pub fn handle_get_status(&self) -> Value {
        self.ensure_cli_discovery_file();
        let path = self.tcp.discovery_path();
        let st = self.st.lock();
        json!({
            "ok": true,
            "environment": "netcatty-terminal",
            "permissionMode": st.permission_mode,
            "approvalTimeoutMs": MCP_APPROVAL_TIMEOUT_MS,
            "commandTimeoutMs": st.command_timeout_ms,
            "maxIterations": st.max_iterations,
            "tcpPort": self.tcp.port(),
            "sessionCount": self.backend.session_ids().len(),
            "scopedContextCount": st.scoped.len(),
            "activeExecutionCount": self.active_execs.len(),
            "activeSftpOperationCount": self.active_sftp_op_count(),
            "activeChatExecutionCount": st.active_chat_execs.len(),
            "pendingApprovalCount": self.pending_approval_count(),
            "discoveryFilePath": path.as_ref().map(|p| p.to_string_lossy().into_owned()),
            "discoveryFilePresent": path.as_ref().is_some_and(|p| p.exists()),
        })
    }

    pub fn handle_list_attachments(&self, params: &Map<String, Value>) -> Value {
        let Some(chat) = str_param(params, "chatSessionId") else {
            return json!({ "ok": false, "error": "chatSessionId is required." });
        };
        let list: Vec<Value> = self
            .scoped_attachments(chat)
            .into_iter()
            .map(|a| {
                let mut v = json!({ "filename": a.filename, "mediaType": a.media_type });
                if !a.file_path.is_empty() {
                    v["filePath"] = json!(a.file_path);
                }
                if let Some(n) = a.size_bytes {
                    v["sizeBytes"] = json!(n);
                }
                v
            })
            .collect();
        json!({ "ok": true, "attachments": list })
    }

    pub fn handle_read_attachment(&self, params: &Map<String, Value>) -> Value {
        use base64::Engine;
        let Some(chat) = str_param(params, "chatSessionId") else {
            return json!({ "ok": false, "error": "chatSessionId is required." });
        };
        let requested_path = params.get("filePath").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(super::absolutize);
        let requested_name = params.get("filename").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        if requested_path.is_none() && requested_name.is_none() {
            return json!({ "ok": false, "error": "filePath or filename is required." });
        }
        let found = self.scoped_attachments(chat).into_iter().find(|a| {
            requested_path.as_deref().is_some_and(|p| a.file_path == p) || requested_name.as_deref().is_some_and(|n| a.filename == n)
        });
        let Some(a) = found else {
            return json!({ "ok": false, "error": "Attachment is not registered for this chat session." });
        };
        let max_bytes = params.get("maxBytes").and_then(Value::as_u64).map(|v| v as usize);
        let too_big = json!({ "ok": false, "error": "Attachment exceeds the requested size limit." });
        let bytes: Vec<u8> = if !a.base64_data.is_empty() {
            let decoded = base64::engine::general_purpose::STANDARD.decode(a.base64_data.trim()).unwrap_or_default();
            if max_bytes.is_some_and(|m| decoded.len() > m) {
                return too_big;
            }
            decoded
        } else {
            match std::fs::File::open(&a.file_path) {
                Err(e) => return json!({ "ok": false, "error": e.to_string() }),
                Ok(f) => {
                    use std::io::Read;
                    let mut buf = Vec::new();
                    let limit = max_bytes.map(|m| m as u64 + 1).unwrap_or(u64::MAX);
                    if let Err(e) = f.take(limit).read_to_end(&mut buf) {
                        return json!({ "ok": false, "error": e.to_string() });
                    }
                    if max_bytes.is_some_and(|m| buf.len() > m) {
                        return too_big;
                    }
                    buf
                }
            }
        };
        let mut out = json!({
            "ok": true,
            "filename": a.filename,
            "mediaType": a.media_type,
            "sizeBytes": bytes.len(),
            "base64Data": base64::engine::general_purpose::STANDARD.encode(&bytes),
        });
        if !a.file_path.is_empty() {
            out["filePath"] = json!(a.file_path);
        }
        if is_likely_text_attachment(&a.media_type, &a.filename) {
            out["text"] = json!(String::from_utf8_lossy(&bytes));
        }
        out
    }

    pub async fn handle_read_context(&self, params: &Map<String, Value>) -> Value {
        use netcatty_capabilities::VaultAgent;
        let chat = str_param(params, "chatSessionId");
        let explicit = scoped_ids(params);
        let scoped = self.resolve_scoped_session_ids(chat, explicit.as_deref());
        let session_id = params
            .get("sessionId")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| scoped.as_ref().filter(|s| s.len() == 1).map(|s| s[0].clone()));
        let Some(session_id) = session_id else {
            return json!({ "ok": false, "error": "sessionId is required when the scope does not contain exactly one terminal." });
        };
        if let Some(err) = self.validate_session_scope(&session_id, chat, explicit.as_deref()) {
            return json!({ "ok": false, "error": err });
        }
        let result = self
            .vault_agent
            .invoke(
                "terminal.readContext",
                json!({ "sessionId": session_id, "range": params.get("range"), "startLine": params.get("startLine"), "maxLines": params.get("maxLines") }),
                None,
            )
            .await;
        match self.validate_session_scope(&session_id, chat, explicit.as_deref()) {
            Some(err) => json!({ "ok": false, "error": err }),
            None => result,
        }
    }

    /// `aiCapability` from the renderer harness (`netcatty:ai:capability`).
    pub async fn renderer_capability(&self, rpc_method: &str, params: Option<Map<String, Value>>, chat: Option<&str>) -> Value {
        if rpc_method.is_empty() {
            return json!({ "ok": false, "error": "rpcMethod is required" });
        }
        let mut p = params.unwrap_or_default();
        match chat {
            Some(c) => {
                p.insert("chatSessionId".into(), json!(c));
            }
            None => {
                p.remove("chatSessionId");
            }
        }
        match self.dispatch(rpc_method, p, DispatchContext::default()).await {
            Ok(v) => v,
            Err(e) => json!({ "ok": false, "error": e }),
        }
    }

    pub(crate) async fn on_host_opened_impl(&self, chat: Option<&str>, session_id: &str, generation: Value, result: &Value) -> Option<bool> {
        let chat = chat.filter(|c| !c.is_empty())?;
        let close_rev = generation["closeRevision"].as_u64().unwrap_or(0);
        if self.closed_revision_of(session_id) > close_rev {
            return Some(false);
        }
        let gen = self.st.lock().ownership.capture_generation(chat);
        let gen_ok = generation["generationAlive"].as_bool() == Some(true)
            && gen.as_ref().is_some_and(|g| !g.revoked.load(std::sync::atomic::Ordering::SeqCst))
            && generation["generationId"].as_u64() == gen.as_ref().map(|g| g.id);
        if result.get("reused").and_then(Value::as_bool) == Some(true) {
            if !gen_ok {
                self.st.lock().scoped.remove(chat);
                return Some(false);
            }
            self.ensure_opened_session_metadata(chat, session_id, result);
            return Some(true);
        }
        let registered = gen_ok && {
            let mut st = self.st.lock();
            let g = st.ownership.capture_generation(chat);
            st.ownership.register(chat, session_id, g.as_ref())
        };
        if !registered {
            self.idle.track(chat, session_id);
            let params = json!({ "chatSessionId": chat, "sessionId": session_id });
            let _ = self.sessions_svc.close(params.as_object().unwrap(), None, true).await;
            let mut st = self.st.lock();
            super::McpHost::forget_meta_locked(&mut st, session_id);
            return Some(false);
        }
        self.st.lock().closed_revisions.retain(|(id, _)| id != session_id);
        self.ensure_opened_session_metadata(chat, session_id, result);
        self.idle.track(chat, session_id);
        Some(true)
    }

    fn ensure_opened_session_metadata(&self, chat: &str, session_id: &str, result: &Value) {
        if self.st.lock().scoped.get(chat).is_some_and(|s| s.metadata.contains_key(session_id)) {
            return;
        }
        let latest = find_meta_across_scopes(&self.st.lock(), session_id, Some(chat));
        let entry = match latest {
            Some(meta) => {
                let mut v = meta.to_public();
                v["sessionId"] = json!(session_id);
                v
            }
            None => {
                let host = result.get("host").cloned().unwrap_or(json!({}));
                let host_id = result.get("hostId").and_then(Value::as_str).or_else(|| host["id"].as_str()).unwrap_or("");
                let saved = result.get("savedHostId").and_then(Value::as_str).filter(|s| *s == host_id).unwrap_or("");
                json!({
                    "sessionId": session_id,
                    "hostname": host["hostname"].as_str().unwrap_or(""),
                    "label": host["label"].as_str().or(host["hostname"].as_str()).unwrap_or(session_id),
                    "os": host["os"].as_str().unwrap_or(""),
                    "username": host["username"].as_str().unwrap_or(""),
                    "protocol": result.get("protocol").and_then(Value::as_str).or(host["protocol"].as_str()).unwrap_or(""),
                    "shellType": "",
                    "deviceType": host["deviceType"].as_str().unwrap_or(""),
                    "connected": result.get("status").and_then(Value::as_str) == Some("connected"),
                    "hostId": host_id,
                    "savedHostId": saved,
                    "hostChain": [],
                    "activePortForwards": [],
                })
            }
        };
        self.merge_session_metadata(&[entry], chat);
    }
}

/// [`CapabilityHost`] over a weak host reference.
pub(crate) struct HostCapabilityHooks(pub Weak<McpHost>);

#[async_trait::async_trait]
impl CapabilityHost for HostCapabilityHooks {
    fn permission_mode(&self) -> String {
        self.0.upgrade().map(|h| h.permission_mode()).unwrap_or_else(|| "confirm".into())
    }
    fn permission_grants(&self) -> Vec<PermissionGrant> {
        self.0.upgrade().map(|h| h.permission_grants()).unwrap_or_default()
    }
    fn is_chat_session_cancelled(&self, chat: Option<&str>) -> bool {
        self.0.upgrade().is_some_and(|h| h.is_chat_session_cancelled(chat))
    }
    fn approval_target(&self, params: &Map<String, Value>) -> Option<Value> {
        self.0.upgrade()?.approval_target(params)
    }
    fn has_session_approval(&self, ctx: &DispatchContext) -> bool {
        self.0.upgrade().is_some_and(|h| h.has_session_approval(ctx.external_client))
    }
    async fn request_approval(&self, tool: &str, args: Value, chat: Option<String>, target: Option<Value>, ctx: &DispatchContext) -> bool {
        match self.0.upgrade() {
            Some(h) => h.request_approval(tool, args, chat, target, ctx.external_client).await,
            None => false,
        }
    }
    fn capture_host_open_scope(&self, chat: Option<&str>) -> Value {
        let Some(h) = self.0.upgrade() else {
            return Value::Null;
        };
        let mut st = h.st.lock();
        let gen = chat.and_then(|c| st.ownership.capture_generation(c));
        json!({
            "closeRevision": st.close_revision,
            "generationAlive": gen.is_some(),
            "generationId": gen.as_ref().map(|g| g.id),
        })
    }
    async fn on_host_opened(&self, chat: Option<&str>, session_id: &str, generation: Value, result: &Value) -> Option<bool> {
        self.0.upgrade()?.on_host_opened_impl(chat, session_id, generation, result).await
    }
}

/// [`SessionHooks`] over a weak host reference.
pub(crate) struct HostSessionHooks(pub Weak<McpHost>);

#[async_trait::async_trait]
impl SessionHooks for HostSessionHooks {
    fn validate_reconnect(&self, params: &Map<String, Value>) -> Value {
        let Some(h) = self.0.upgrade() else {
            return json!({ "ok": false, "error": "Session recovery bridge is unavailable." });
        };
        let sid = str_param(params, "sessionId").unwrap_or("");
        let chat = str_param(params, "chatSessionId");
        if let Some(err) = h.validate_session_scope(sid, chat, scoped_ids(params).as_deref()) {
            return json!({ "ok": false, "error": err });
        }
        if h.is_chat_session_cancelled(chat) {
            return json!({ "ok": false, "error": "Chat session is cancelled." });
        }
        if h.permission_mode() == "observer" {
            return json!({ "ok": false, "error": "Recovery is unavailable in observer mode." });
        }
        if h.idle.is_closing(sid) {
            return json!({ "ok": false, "error": "Session is closing." });
        }
        json!({ "ok": true })
    }

    async fn inspect_recovery(&self, params: &Map<String, Value>, timeout_ms: u64) -> Value {
        use netcatty_capabilities::VaultAgent;
        let Some(h) = self.0.upgrade() else {
            return json!({ "ok": false, "error": "Session recovery bridge is unavailable." });
        };
        let sid = str_param(params, "sessionId").unwrap_or("").to_string();
        h.idle.touch(&sid);
        let mut state = h.vault_agent.invoke("session.inspectRecovery", json!({ "sessionId": sid }), Some(timeout_ms)).await;
        if state.get("ok").and_then(Value::as_bool) != Some(true) {
            return state;
        }
        let meta = h.session_meta(&sid, str_param(params, "chatSessionId"));
        let probe = h.backend.session(&sid).map(|s| {
            let p = s.prompt();
            (p.tracked, !p.ready_prompt().is_empty())
        });
        let tracked = probe.is_some_and(|(t, _)| t) && !meta.is_some_and(|m| m.is_network_device_like());
        let connected = state.get("status").and_then(Value::as_str) == Some("connected");
        state["shellReady"] = if !connected {
            json!(false)
        } else if probe.is_none() || !tracked {
            Value::Null
        } else {
            json!(probe.unwrap().1)
        };
        state["busy"] = json!(h.session_busy_error(&sid).is_some());
        state
    }

    fn validate_close(&self, params: &Map<String, Value>) -> Value {
        let Some(h) = self.0.upgrade() else {
            return json!({ "ok": false, "error": "Session close bridge is unavailable." });
        };
        let sid = str_param(params, "sessionId").unwrap_or("");
        let chat = str_param(params, "chatSessionId");
        if let Some(err) = h.validate_session_scope(sid, chat, scoped_ids(params).as_deref()) {
            return json!({ "ok": false, "error": err });
        }
        if h.idle.is_closing(sid) {
            return json!({ "ok": false, "error": format!("Session \"{sid}\" is closing.") });
        }
        let result = h.st.lock().ownership.validate(chat, sid);
        result
    }

    async fn before_close(&self, params: &Map<String, Value>) {
        let Some(h) = self.0.upgrade() else {
            return;
        };
        let sid = str_param(params, "sessionId").unwrap_or("");
        h.idle.begin_close(sid);
        h.begin_terminal_session_close(sid);
        h.cancel_background_jobs_for_terminal(sid);
        h.cancel_sftp_ops_for_terminal(sid);
    }

    async fn after_close(&self, params: &Map<String, Value>, closed: bool, not_found: bool) {
        let Some(h) = self.0.upgrade() else {
            return;
        };
        let sid = str_param(params, "sessionId").unwrap_or("");
        h.end_terminal_session_close(sid);
        if closed {
            return;
        }
        if not_found {
            h.forget_closed_terminal_session(sid);
            return;
        }
        h.idle.resume(sid);
    }

    async fn on_closed(&self, session_id: &str) {
        if let Some(h) = self.0.upgrade() {
            h.settle_background_jobs_for_terminal(session_id).await;
            h.forget_closed_terminal_session(session_id);
        }
    }
}

pub(crate) struct HostPortForwards(pub Arc<dyn HostBackend>);

#[async_trait::async_trait]
impl PortForwardRuntime for HostPortForwards {
    async fn list_tunnels(&self) -> Vec<Value> {
        self.0.list_port_forwards().await
    }
}

/// Keep `ExecGuard` re-exported for callers building contexts.
pub type Guard = ExecGuard;
