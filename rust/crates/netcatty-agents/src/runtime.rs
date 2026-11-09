//! Request dispatcher for the managed agents (Electron:
//! `aiBridge/sdk/sdkStreamHandlers.cjs` plus the discovery / Codex handlers).
//! Every public method takes the renderer payload as JSON and returns the
//! Electron response shape.

use crate::catalog::{self, CacheEntry, ModelCache, ModelCatalog};
use crate::context::{build_external_agent_contextual_prompt, build_external_agent_system_context, ContextInput, DefaultTargetSession, SkillsCliInvocation};
use crate::discovery::{self, CodexLoginManager, CodexValidationCache};
use crate::drivers::{self, codex_app_server::CodexAppServerRuntime, AdvancedOptions, ElicitationRegistry, ListContext, TurnContext};
pub use crate::drivers::{ApprovalProvider, NoopApprovalProvider};
use crate::emit::{Emitter, EventSink};
use crate::env::{build_sdk_agent_env, normalize_agent_env};
use crate::mcp::{McpInjectionProvider, NoopMcpInjectionProvider};
use crate::session::{self, AttachmentInput, ResumeInput, SessionIdMap};
use crate::shell_env::ShellEnvCache;
use crate::EnvMap;
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Renderer event sink (`safeSend`).
pub use crate::emit::EventSink as AgentEventSink;

pub const VALID_BACKENDS: &[&str] = &["claude", "codex", "copilot", "cursor", "codebuddy", "opencode", "grok", "mimo"];

/// Static configuration supplied by the host app.
#[derive(Clone)]
pub struct RuntimeConfig {
    pub app_version: String,
    /// User data dir (last-known-good model catalogs live here).
    pub data_dir: PathBuf,
    /// Current managed temp dir (attachments, Cursor CLI workspaces).
    pub temp_dir: Arc<dyn Fn() -> PathBuf + Send + Sync>,
    /// Netcatty tool CLI invocation for skills mode.
    pub skills_cli: SkillsCliInvocation,
    /// Extra files the OpenCode / MiMo skills allowlist must cover.
    pub skills_allowlist_files: Vec<String>,
    /// Netcatty tool CLI state dir (discovery file parent).
    pub cli_state_dir: Option<String>,
}

impl RuntimeConfig {
    pub fn new(app_version: &str, data_dir: PathBuf, temp_dir: PathBuf) -> Self {
        Self {
            app_version: app_version.to_string(),
            data_dir,
            temp_dir: Arc::new(move || temp_dir.clone()),
            skills_cli: SkillsCliInvocation::default(),
            skills_allowlist_files: Vec::new(),
            cli_state_dir: None,
        }
    }
}

#[derive(Clone)]
struct RequestRuntime {
    backend: String,
    codex_runtime: String,
    tool_mode: String,
}

pub struct AgentsRuntime {
    config: RuntimeConfig,
    sink: Arc<dyn EventSink>,
    pub shell_env: ShellEnvCache,
    mcp: RwLock<Arc<dyn McpInjectionProvider>>,
    approvals: RwLock<Arc<dyn ApprovalProvider>>,
    active: DashMap<String, CancellationToken>,
    request_sessions: DashMap<String, String>,
    request_runtimes: DashMap<String, RequestRuntime>,
    session_ids: Arc<Mutex<SessionIdMap>>,
    model_cache: Mutex<ModelCache>,
    model_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    pub codex_login: CodexLoginManager,
    pub codex_validation: CodexValidationCache,
    pub app_server: CodexAppServerRuntime,
    pub elicitations: Arc<ElicitationRegistry>,
}

fn s(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(str::to_string)
}

impl AgentsRuntime {
    /// Build the runtime. `TODO(mcp-injection)`: the host replaces the
    /// [`NoopMcpInjectionProvider`] with the netcatty MCP provider via
    /// [`AgentsRuntime::set_mcp_provider`] once `netcatty_mcp` is merged.
    pub fn new(config: RuntimeConfig, sink: Arc<dyn EventSink>) -> Self {
        let app_server = CodexAppServerRuntime::new(&config.app_version, sink.clone());
        Self {
            config,
            sink,
            shell_env: ShellEnvCache::new(),
            mcp: RwLock::new(Arc::new(NoopMcpInjectionProvider)),
            approvals: RwLock::new(Arc::new(NoopApprovalProvider)),
            active: DashMap::new(),
            request_sessions: DashMap::new(),
            request_runtimes: DashMap::new(),
            session_ids: Arc::new(Mutex::new(SessionIdMap::new())),
            model_cache: Mutex::new(ModelCache::default()),
            model_locks: Mutex::new(HashMap::new()),
            codex_login: CodexLoginManager::default(),
            codex_validation: CodexValidationCache::default(),
            app_server,
            elicitations: Arc::new(ElicitationRegistry::default()),
        }
    }

    pub fn set_mcp_provider(&self, provider: Arc<dyn McpInjectionProvider>) {
        *self.mcp.write() = provider;
    }

    pub fn set_approval_provider(&self, provider: Arc<dyn ApprovalProvider>) {
        *self.approvals.write() = provider;
    }

    fn mcp(&self) -> Arc<dyn McpInjectionProvider> {
        self.mcp.read().clone()
    }

    async fn agent_env(&self, requested: &EnvMap, chat: Option<&str>) -> (Arc<EnvMap>, EnvMap) {
        let shell = self.shell_env.get().await;
        let discovery = self.mcp().discovery_file_path();
        let env = build_sdk_agent_env(&shell, Some(requested), Some((&discovery, chat)));
        (shell, crate::cli::normalize_claude_code_executable_env_for_sdk(env))
    }

    // ── Discovery / CLI resolution ──

    pub async fn discover_agents(&self, options: &Value) -> Value {
        if options["refreshShellEnv"] == true {
            self.shell_env.invalidate();
        }
        let shell = self.shell_env.get().await;
        Value::Array(discovery::discover_agents(&shell, options["apiKeyPresent"] == true).await)
    }

    pub async fn resolve_cli(&self, params: &Value) -> Value {
        if params["refreshShellEnv"] == true {
            self.shell_env.invalidate();
        }
        let shell = self.shell_env.get().await;
        discovery::resolve_cli(params["command"].as_str().unwrap_or(""), params["customPath"].as_str(), &shell, params["apiKeyPresent"] == true).await
    }

    pub async fn prewarm_shell_env(&self) -> Value {
        self.shell_env.get().await;
        json!({ "ok": true })
    }

    async fn codex_env(&self, options: &Value) -> EnvMap {
        let shell = self.shell_env.get().await;
        let discovery = self.mcp().discovery_file_path();
        build_sdk_agent_env(&shell, Some(&normalize_agent_env(options.get("agentEnv"))), Some((&discovery, None)))
    }

    pub async fn codex_get_integration(&self, options: &Value) -> Value {
        if options["refreshShellEnv"] == true {
            self.shell_env.invalidate();
        }
        let env = self.codex_env(options).await;
        discovery::codex_get_integration(&self.codex_validation, options["codexPath"].as_str(), &env, options["validateChatGptAuth"] == true).await
    }

    pub async fn codex_start_login(&self, options: &Value) -> Value {
        let env = self.codex_env(options).await;
        self.codex_login.start(options["codexPath"].as_str(), &env, &self.codex_validation).await
    }

    pub fn codex_get_login_session(&self, session_id: &str) -> Value {
        match self.codex_login.get(session_id) {
            Some(session) => json!({ "ok": true, "session": session }),
            None => json!({ "ok": false, "error": "Codex login session not found" }),
        }
    }

    pub fn codex_cancel_login(&self, session_id: &str) -> Value {
        self.codex_login.cancel(session_id, &self.codex_validation)
    }

    pub async fn codex_logout(&self, options: &Value) -> Value {
        let env = self.codex_env(options).await;
        discovery::codex_logout(&self.codex_validation, options["codexPath"].as_str(), &env).await
    }

    /// `resolveSdkBackendBinPath`.
    pub async fn resolve_backend_bin_path(&self, backend: &str, configured: Option<&str>, shell: &EnvMap, env: &EnvMap) -> Result<Option<String>, String> {
        let raw = configured.unwrap_or("").trim();
        if !raw.is_empty() && crate::cli::is_path_like_command(raw) {
            let normalized = crate::cli::normalize_cli_path_for_platform(raw).ok_or_else(|| format!("Agent CLI path not found: {raw}"))?;
            let real = crate::cli::resolve_real_cli_path(&normalized);
            return Ok(match backend {
                "claude" => crate::cli::resolve_claude_code_executable_for_sdk(&real),
                "codex" => crate::cli::resolve_codex_executable_for_sdk(&real),
                "codebuddy" => crate::cli::resolve_codebuddy_executable_for_sdk(&real),
                _ => Some(real),
            });
        }
        let from_env = |keys: &[&str]| keys.iter().find_map(|k| env.get(*k).and_then(|v| crate::cli::normalize_cli_path_for_platform(v)));
        match backend {
            "codebuddy" | "opencode" | "mimo" => {
                let keys: &[&str] = match backend {
                    "codebuddy" => &["CODEBUDDY_CODE_PATH"],
                    "opencode" => &["OPENCODE_BIN"],
                    _ => &["MIMOCODE_BIN", "MIMOCODE_BIN_PATH"],
                };
                let raw = match from_env(keys) {
                    Some(p) => Some(p),
                    None => crate::cli::resolve_cli_from_path(backend, shell).await,
                };
                Ok(raw.map(|r| crate::cli::resolve_real_cli_path(&r)).and_then(|r| if backend == "codebuddy" { crate::cli::resolve_codebuddy_executable_for_sdk(&r) } else { Some(r) }))
            }
            _ => Ok(crate::cli::resolve_sdk_bin_path(backend, shell).await),
        }
    }

    async fn resolve_cursor_cli_bin(&self, configured: Option<String>, shell: &EnvMap) -> Option<String> {
        let mut bin = configured;
        let sentinel = bin.as_deref().map(|b| b == "cursor" || regex::Regex::new(r"(?i)(?:^|[/\\])cursor$").unwrap().is_match(b)).unwrap_or(true);
        if sentinel {
            if let Some(p) = crate::auth::probe_cursor_cli_auth(shell).await.bin_path {
                bin = Some(p);
            }
        }
        if bin.is_none() {
            bin = crate::cli::resolve_cli_from_path("cursor-agent", shell).await;
        }
        bin
    }

    // ── Stream ──

    /// `netcatty:ai:sdk-agent:stream`. Resolves when the turn ends.
    pub async fn stream(&self, payload: Value) -> Value {
        let request_id = s(&payload, "requestId").unwrap_or_default();
        let chat = s(&payload, "chatSessionId").unwrap_or_default();
        let backend_raw = s(&payload, "sdkBackend").unwrap_or_default();
        let backend = backend_raw.trim().to_string();
        let emitter = Emitter::new(self.sink.clone(), &request_id);
        if !VALID_BACKENDS.contains(&backend.as_str()) {
            emitter.emit_error(format!("Unknown SDK backend: {backend_raw}"));
            return json!({ "ok": false, "error": "Unknown SDK backend" });
        }
        let cancel = CancellationToken::new();
        self.active.insert(request_id.clone(), cancel.clone());
        self.request_sessions.insert(request_id.clone(), chat.clone());
        let mcp = self.mcp();
        mcp.set_chat_session_cancelled(&chat, false);
        let result = self.run_stream(&payload, &request_id, &chat, &backend, emitter.clone(), cancel).await;
        self.active.remove(&request_id);
        self.request_sessions.remove(&request_id);
        self.request_runtimes.remove(&request_id);
        match result {
            Ok(()) => json!({ "ok": true }),
            Err(error) => {
                emitter.emit_error(error.clone());
                json!({ "ok": false, "error": error })
            }
        }
    }

    async fn run_stream(&self, payload: &Value, request_id: &str, chat: &str, backend: &str, emitter: Emitter, cancel: CancellationToken) -> Result<(), String> {
        let mode = if payload["toolIntegrationMode"] == "skills" { "skills" } else { "mcp" };
        let mcp = self.mcp();
        let injected = match mcp.build_injected_mcp_servers(chat, mode).await {
            Ok(servers) => servers,
            Err(error) => {
                tracing::error!(%error, "failed to inject the netcatty MCP server");
                Vec::new()
            }
        };
        let mut requested = normalize_agent_env(payload.get("agentEnv"));
        let claude_settings = requested.remove("NETCATTY_CLAUDE_SETTINGS");
        let cursor_auth = if requested.remove("NETCATTY_CURSOR_AUTH_MODE").as_deref() == Some("cli-login") { "cli-login" } else { "api-key" };
        let cursor_cli_bin = requested.remove("NETCATTY_CURSOR_CLI_BIN").map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        if cursor_auth == "cli-login" {
            requested.remove("CURSOR_API_KEY");
        }
        let (shell, mut env) = self.agent_env(&requested, Some(chat)).await;
        if cursor_auth == "cli-login" {
            env.remove("CURSOR_API_KEY");
        }
        let agent_command = s(payload, "agentCommand");
        let bin_path = self.resolve_backend_bin_path(backend, agent_command.as_deref(), &shell, &env).await?;
        if backend == "codex" {
            env = crate::cli::add_codex_executable_env_for_sdk(env, bin_path.as_deref());
        }
        let cursor_cli_bin = if backend == "cursor" && cursor_auth == "cli-login" { self.resolve_cursor_cli_bin(cursor_cli_bin, &shell).await } else { cursor_cli_bin };
        let codex_runtime = if backend == "codex" && payload["codexRuntime"] == "app-server" { "app-server" } else { "sdk" };
        let grok_runtime = if backend == "grok" {
            session::normalize_sdk_runtime(Some(env.get("NETCATTY_GROK_RUNTIME").map(String::as_str).or(std::env::var("NETCATTY_GROK_RUNTIME").ok().as_deref()).unwrap_or("acp"))).to_string()
        } else {
            "sdk".to_string()
        };
        let session_runtime = if backend == "grok" { grok_runtime.clone() } else { codex_runtime.to_string() };
        self.request_runtimes.insert(request_id.to_string(), RequestRuntime { backend: backend.to_string(), codex_runtime: codex_runtime.to_string(), tool_mode: mode.to_string() });
        let has_configured_command = agent_command.as_deref().map(crate::cli::is_path_like_command).unwrap_or(false);
        let session_bin = if backend == "cursor" && cursor_auth == "cli-login" { cursor_cli_bin.clone().or(bin_path.clone()) } else { bin_path.clone() }.unwrap_or_default();
        let auth_mode = if backend == "cursor" { cursor_auth } else { "" };
        let permission_mode = s(payload, "permissionMode").filter(|m| !m.is_empty()).unwrap_or_else(|| "confirm".into());
        let cli_mode = if backend == "cursor" && cursor_auth == "cli-login" { if permission_mode.eq_ignore_ascii_case("observer") { "ask" } else { "agent" } } else { "" };
        let session_key = session::build_sdk_session_key(chat, backend, &session_bin, &session_runtime, auth_mode, cli_mode);
        let (resume, has_in_memory) = {
            let mut map = self.session_ids.lock();
            if !cli_mode.is_empty() {
                session::expire_sibling_cursor_cli_mode_sessions(&mut map, chat, backend, &session_bin, &session_runtime, auth_mode, cli_mode);
            }
            session::expire_sibling_grok_runtime_sessions(&mut map, chat, backend, &session_bin, &session_runtime);
            let has = map.contains_key(&session_key);
            let resume = session::resolve_sdk_resume_session_id(
                &map,
                &session_key,
                &ResumeInput { existing_session_id: payload["existingSessionId"].as_str(), backend, bin_path: &session_bin, runtime: &session_runtime, auth_mode, cli_mode, has_configured_command },
            );
            (resume, has)
        };
        let replay = session::should_replay_sdk_history(backend, codex_runtime, resume.as_deref(), has_in_memory);
        let attachments: Vec<AttachmentInput> = serde_json::from_value(payload.get("images").cloned().unwrap_or(Value::Null)).unwrap_or_default();
        let temp_dir = (self.config.temp_dir)();
        let (turn_prompt, staged) = session::build_sdk_turn_prompt(&session::TurnPromptInput {
            prompt: payload["prompt"].as_str().unwrap_or(""),
            history_messages: payload.get("historyMessages"),
            replay_history: replay,
            attachments: &attachments,
            tool_integration_mode: mode,
            temp_dir: &temp_dir,
        });
        let history_seed = (backend == "grok" && resume.is_some() && !replay).then(|| session::format_sdk_history_replay_section(payload.get("historyMessages")));
        mcp.update_attachment_metadata(&staged, chat);
        let target: Option<DefaultTargetSession> = payload.get("defaultTargetSession").and_then(|v| serde_json::from_value(v.clone()).ok());
        let ctx_input = ContextInput { mode, chat_session_id: chat, default_target_session: target.as_ref(), user_skills_context: payload["userSkillsContext"].as_str(), skills_cli: &self.config.skills_cli };
        let system_context = build_external_agent_system_context(&ctx_input);
        let contextual = build_external_agent_contextual_prompt(&ctx_input, &turn_prompt);
        let (prompt, system_prompt) = session::resolve_sdk_prompt_placement(backend, &turn_prompt, &contextual, &system_context);
        let skills_allowlist = if mode == "skills" && (backend == "opencode" || backend == "mimo") {
            let mut files = self.config.skills_allowlist_files.clone();
            if let Some(d) = mcp.discovery_file_path() {
                files.push(d);
            }
            if let Ok(exe) = std::env::current_exe() {
                files.push(exe.to_string_lossy().into_owned());
            }
            files.extend(staged.iter().map(|a| a.file_path.clone()));
            let temp = temp_dir.to_string_lossy().into_owned();
            drivers::opencode::skills_path_allowlist(&files, self.config.cli_state_dir.as_deref(), Some(&temp))
        } else {
            Vec::new()
        };
        // Record native session ids as soon as they appear (Stop must not lose them).
        let mut extra = json!({ "sdkBackend": backend, "binPath": session_bin, "runtime": session_runtime });
        if !auth_mode.is_empty() {
            extra["authMode"] = json!(auth_mode);
        }
        if !cli_mode.is_empty() {
            extra["cliMode"] = json!(cli_mode);
        }
        emitter.set_session_id_extra(extra);
        let ids = self.session_ids.clone();
        let key = session_key.clone();
        emitter.set_on_session_id(Arc::new(move |id| {
            ids.lock().insert(key.clone(), id.to_string());
        }));
        let advanced = AdvancedOptions {
            effort: s(payload, "effort").filter(|e| !e.is_empty()),
            max_turns: payload["maxTurns"].as_u64().filter(|t| *t > 0),
            max_budget_usd: payload["maxBudgetUsd"].as_f64().filter(|b| *b > 0.0),
            fallback_model: s(payload, "fallbackModel").filter(|f| !f.is_empty()),
            sandbox: payload.get("sandbox").cloned().filter(|v| !v.is_null()),
            enable_file_checkpointing: payload["enableFileCheckpointing"].as_bool(),
            persist_session: payload["persistSession"].as_bool(),
        };
        let cwd = payload["cwd"].as_str().filter(|c| !c.is_empty()).map(PathBuf::from).unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| temp_dir.clone()));
        let ctx = TurnContext {
            request_id: request_id.to_string(),
            chat_session_id: chat.to_string(),
            prompt,
            system_prompt,
            cwd,
            model: s(payload, "model").filter(|m| !m.is_empty()),
            permission_mode,
            env,
            bin_path,
            injected_mcp_servers: injected,
            claude_settings,
            tool_integration_mode: mode.to_string(),
            skills_cli_prefix: (mode == "skills").then(|| self.config.skills_cli.command_prefix.clone()),
            skills_path_allowlist: skills_allowlist,
            emitter: emitter.clone(),
            cancel,
            resume_session_id: resume,
            attachments: staged,
            history_seed,
            grok_runtime,
            cursor_auth_mode: cursor_auth.to_string(),
            cursor_cli_bin_path: cursor_cli_bin,
            temp_dir,
            approvals: self.approvals.read().clone(),
            elicitations: self.elicitations.clone(),
            advanced,
        };
        let result = match backend {
            "claude" => drivers::claude::run_turn(&ctx).await,
            "codex" if codex_runtime == "app-server" => self.app_server.run_turn(&ctx).await?,
            "codex" => drivers::codex_exec::run_turn(&ctx, None, None).await,
            "copilot" => drivers::copilot::run_turn(&ctx).await,
            "cursor" if ctx.cursor_auth_mode == "cli-login" => drivers::cursor_cli::run_turn(&ctx).await,
            "cursor" => return Err("Cursor API-key mode needs the Cursor SDK, which is not available in this build. Switch Cursor to CLI login (`cursor-agent login`) in Settings → AI.".into()),
            "codebuddy" => drivers::codebuddy::run_turn(&ctx).await,
            "opencode" => drivers::opencode::run_turn(&ctx).await,
            "grok" if ctx.grok_runtime == "streaming-json" => drivers::grok::run_turn(&ctx).await,
            "grok" => drivers::grok_acp::run_turn(&ctx).await,
            "mimo" => drivers::mimo::run_turn(&ctx).await,
            _ => return Err("Unknown SDK backend".into()),
        };
        if let Some(id) = result.session_id {
            self.session_ids.lock().insert(session_key, id);
        }
        Ok(())
    }

    /// `netcatty:ai:sdk-agent:cancel`.
    pub async fn cancel(&self, request_id: &str, chat_session_id: Option<&str>) -> Value {
        let owned = self.request_sessions.get(request_id).map(|v| v.clone());
        if let (Some(o), Some(c)) = (&owned, chat_session_id) {
            if !c.is_empty() && o != c {
                return json!({ "ok": false, "error": "Agent request ownership mismatch" });
            }
        }
        let chat = owned.or(chat_session_id.map(str::to_string)).unwrap_or_default();
        let mcp = self.mcp();
        mcp.set_chat_session_cancelled(&chat, true);
        self.approvals.read().clear_pending_approvals(&chat);
        self.app_server.cancel_turn(request_id).await;
        match self.active.get(request_id) {
            Some(token) => {
                token.cancel();
                json!({ "ok": true })
            }
            None => json!({ "ok": false, "error": "Stream not found" }),
        }
    }

    /// `netcatty:ai:sdk-agent:cleanup`.
    pub async fn cleanup(&self, chat_session_id: &str) -> Value {
        let mcp = self.mcp();
        mcp.set_chat_session_cancelled(chat_session_id, true);
        let ids: Vec<String> = self.request_sessions.iter().filter(|e| e.value() == chat_session_id).map(|e| e.key().clone()).collect();
        for id in ids {
            if let Some((_, token)) = self.active.remove(&id) {
                token.cancel();
            }
            self.request_sessions.remove(&id);
            self.request_runtimes.remove(&id);
        }
        session::delete_sdk_session_keys_for_chat(&mut self.session_ids.lock(), chat_session_id);
        self.elicitations.cancel_for_chat(chat_session_id);
        self.app_server.cleanup_chat_session(chat_session_id).await;
        mcp.cleanup_scoped_metadata(chat_session_id).await;
        json!({ "ok": true })
    }

    /// `netcatty:ai:sdk-agent:steer` (Codex App Server only).
    pub async fn steer(&self, payload: &Value) -> Value {
        let request_id = s(payload, "requestId").unwrap_or_default();
        let chat = s(payload, "chatSessionId").unwrap_or_default();
        let client_id = s(payload, "clientUserMessageId").unwrap_or_default();
        if request_id.is_empty() || chat.is_empty() || client_id.is_empty() {
            return json!({ "status": "failed", "message": "Invalid Codex steer request" });
        }
        if self.request_sessions.get(&request_id).map(|c| c.clone()) != Some(chat.clone()) {
            return json!({ "status": "inactive" });
        }
        let Some(rt) = self.request_runtimes.get(&request_id).map(|r| r.clone()) else { return json!({ "status": "busy" }) };
        if rt.backend != "codex" || rt.codex_runtime != "app-server" {
            return json!({ "status": "unsupported" });
        }
        let attachments: Vec<AttachmentInput> = serde_json::from_value(payload.get("images").cloned().unwrap_or(Value::Null)).unwrap_or_default();
        let temp = (self.config.temp_dir)();
        let (prompt, staged) = session::build_sdk_turn_prompt(&session::TurnPromptInput { prompt: payload["prompt"].as_str().unwrap_or(""), history_messages: None, replay_history: false, attachments: &attachments, tool_integration_mode: &rt.tool_mode, temp_dir: &temp });
        self.mcp().update_attachment_metadata(&staged, &chat);
        let result = self.app_server.steer_turn(&request_id, &chat, &prompt, &staged, &client_id).await;
        if result["status"] == "inactive" && self.active.contains_key(&request_id) {
            return json!({ "status": "busy" });
        }
        result
    }

    // ── Model catalogs ──

    /// `netcatty:ai:sdk-agent:list-models`: TTL cache → last-known-good → live.
    pub async fn list_models(&self, payload: &Value) -> Value {
        let backend_raw = s(payload, "sdkBackend").unwrap_or_default();
        let backend = backend_raw.trim().to_string();
        if !VALID_BACKENDS.contains(&backend.as_str()) {
            return json!({ "ok": false, "error": format!("Unknown SDK backend: {backend_raw}") });
        }
        let force = payload["force"] == true;
        let mut requested = normalize_agent_env(payload.get("agentEnv"));
        let cursor_auth = if requested.remove("NETCATTY_CURSOR_AUTH_MODE").as_deref() == Some("cli-login") { "cli-login" } else { "api-key" };
        let cursor_cli = requested.remove("NETCATTY_CURSOR_CLI_BIN").map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        if cursor_auth == "cli-login" {
            requested.remove("CURSOR_API_KEY");
        }
        let (shell, mut env) = self.agent_env(&requested, None).await;
        if cursor_auth == "cli-login" {
            env.remove("CURSOR_API_KEY");
        }
        let bin_path = match self.resolve_backend_bin_path(&backend, payload["agentCommand"].as_str(), &shell, &env).await {
            Ok(b) => b,
            Err(e) => return json!({ "ok": true, "currentModelId": null, "models": [], "warning": e }),
        };
        let cursor_cli = if backend == "cursor" && cursor_auth == "cli-login" { self.resolve_cursor_cli_bin(cursor_cli, &shell).await } else { cursor_cli };
        let codex_runtime = if backend == "codex" && payload["codexRuntime"] == "app-server" { "app-server" } else { "sdk" };
        let key_bin = if cursor_auth == "cli-login" && backend == "cursor" { cursor_cli.clone().or(bin_path.clone()) } else { bin_path.clone() }.unwrap_or_default();
        let cache_key = catalog::build_sdk_model_cache_key(&backend, &key_bin, &env, &format!("{codex_runtime}:{cursor_auth}"));
        if !force {
            if let Some(hit) = self.model_cache.lock().get(&cache_key) {
                return json!({ "ok": true, "currentModelId": hit.catalog.current_model_id, "models": hit.catalog.models, "source": "live", "fetchedAt": hit.fetched_at });
            }
        }
        let lock = self.model_locks.lock().entry(cache_key.clone()).or_default().clone();
        let _guard = lock.lock().await;
        if !force {
            if let Some(hit) = self.model_cache.lock().get(&cache_key) {
                return json!({ "ok": true, "currentModelId": hit.catalog.current_model_id, "models": hit.catalog.models, "source": "live", "fetchedAt": hit.fetched_at });
            }
        }
        let lkg_path = catalog::last_known_catalog_path(&self.config.data_dir);
        if !force {
            if let Some(entry) = catalog::read_last_known_entry(&lkg_path, &cache_key) {
                return json!({ "ok": true, "currentModelId": catalog::remap_last_known_current_model_id(&entry), "models": entry.models, "source": "last-known-good", "fetchedAt": entry.fetched_at });
            }
        }
        let budget = catalog::catalog_budget(&backend);
        let cancel = CancellationToken::new();
        let ctx = ListContext {
            bin_path: bin_path.clone(),
            env: env.clone(),
            cwd: payload["cwd"].as_str().filter(|c| !c.is_empty()).map(PathBuf::from).unwrap_or_else(|| (self.config.temp_dir)()),
            cancel: cancel.clone(),
            deadline: Instant::now() + budget - catalog::MODEL_LIST_DEADLINE_HEADROOM,
            cursor_auth_mode: cursor_auth.to_string(),
            cursor_cli_bin_path: cursor_cli,
        };
        let fetched = tokio::time::timeout(budget, self.fetch_catalog(&backend, codex_runtime, &ctx)).await;
        cancel.cancel();
        let fetched = match fetched {
            Ok(r) => r,
            Err(_) => Err(format!("list-models timed out after {}ms", budget.as_millis())),
        };
        match fetched {
            Ok(catalog) => {
                let fetched_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                if !catalog.is_empty() {
                    self.model_cache.lock().set(&cache_key, CacheEntry { at: Instant::now(), catalog: catalog.clone(), fetched_at: fetched_at.clone() });
                }
                if !catalog.models.is_empty() {
                    catalog::write_last_known_entry(&lkg_path, &cache_key, &backend, &catalog.models, catalog.current_model_id.as_deref());
                } else if let Some(current) = catalog.current_model_id.as_deref() {
                    if catalog::read_last_known_entry(&lkg_path, &cache_key).is_some() {
                        catalog::refresh_last_known_current_id(&lkg_path, &cache_key, current);
                    } else {
                        catalog::write_last_known_entry(&lkg_path, &cache_key, &backend, &[json!({ "id": current, "name": current })], Some(current));
                    }
                }
                json!({ "ok": true, "currentModelId": catalog.current_model_id, "models": catalog.models, "source": "live", "fetchedAt": fetched_at })
            }
            Err(error) => match catalog::read_last_known_entry(&lkg_path, &cache_key) {
                Some(entry) => json!({
                    "ok": true,
                    "currentModelId": catalog::remap_last_known_current_model_id(&entry),
                    "models": entry.models,
                    "warning": format!("{error} — serving the last-known-good catalog fetched at {}", entry.fetched_at),
                    "source": "last-known-good",
                    "fetchedAt": entry.fetched_at,
                }),
                None => json!({ "ok": true, "currentModelId": null, "models": [], "warning": error }),
            },
        }
    }

    async fn fetch_catalog(&self, backend: &str, codex_runtime: &str, ctx: &ListContext) -> Result<ModelCatalog, String> {
        let wrap = |models: Vec<Value>| ModelCatalog { current_model_id: None, models };
        let catalog = match backend {
            "claude" => wrap(drivers::claude::list_models(ctx).await),
            "codex" => {
                let bin = ctx.bin_path.clone().ok_or("Codex binary not found. Configure Codex in Settings -> AI.")?;
                let _ = codex_runtime;
                self.app_server.list_models(&bin, &ctx.env).await?
            }
            "copilot" => wrap(drivers::copilot::list_models(ctx).await),
            "cursor" if ctx.cursor_auth_mode == "cli-login" => drivers::cursor_cli::list_models(ctx).await,
            "cursor" => ModelCatalog::default(),
            "codebuddy" => wrap(drivers::codebuddy::list_models(ctx).await),
            "opencode" => drivers::opencode::list_models(ctx).await?,
            "grok" => drivers::grok::list_models(ctx).await,
            "mimo" => drivers::mimo::list_models(ctx).await,
            _ => ModelCatalog::default(),
        }
        .normalized();
        if catalog.is_empty() {
            return Err("The live model catalog returned no models".into());
        }
        Ok(catalog)
    }

    // ── Codex App Server ──

    pub async fn codex_app_server_status(&self, payload: &Value) -> Value {
        let (shell, env) = self.agent_env(&normalize_agent_env(payload.get("agentEnv")), None).await;
        let bin = match self.resolve_backend_bin_path("codex", payload["agentCommand"].as_str(), &shell, &env).await {
            Ok(Some(b)) => b,
            Ok(None) => return json!({ "ok": true, "available": false, "error": "Codex binary not found. Configure Codex in Settings -> AI." }),
            Err(e) => return json!({ "ok": true, "available": false, "error": e }),
        };
        let env = crate::cli::add_codex_executable_env_for_sdk(env, Some(&bin));
        let mut r = drivers::codex_app_server::probe(&bin, &env).await;
        r["ok"] = json!(true);
        r
    }

    pub fn respond_codex_interaction(&self, payload: &Value) -> Value {
        if self.app_server.respond_interaction(payload) {
            json!({ "ok": true })
        } else {
            json!({ "ok": false, "error": "Interaction not found" })
        }
    }

    pub fn cancel_codex_interaction_timeout(&self, interaction_id: &str) -> Value {
        json!({ "ok": true, "cancelled": self.app_server.cancel_interaction_timeout(interaction_id) })
    }

    // ── CodeBuddy extras ──

    async fn codebuddy_bin(&self, payload: &Value) -> Result<(Option<String>, EnvMap), String> {
        let (shell, env) = self.agent_env(&normalize_agent_env(payload.get("agentEnv")), None).await;
        let bin = self.resolve_backend_bin_path("codebuddy", payload["agentCommand"].as_str(), &shell, &env).await?;
        Ok((bin, env))
    }

    pub async fn mcp_status(&self, payload: &Value) -> Value {
        match self.codebuddy_bin(payload).await {
            Ok((bin, env)) => json!({ "ok": true, "servers": drivers::codebuddy::mcp_status(bin.as_deref(), &env).await }),
            Err(e) => json!({ "ok": false, "error": e }),
        }
    }

    pub async fn account_info(&self, payload: &Value) -> Value {
        match self.codebuddy_bin(payload).await {
            Ok((bin, env)) => json!({ "ok": true, "account": drivers::codebuddy::account_info(bin.as_deref(), &env).await }),
            Err(e) => json!({ "ok": false, "error": e }),
        }
    }

    pub fn elicitation_response(&self, payload: &Value) -> Value {
        let Some(id) = payload["elicitationId"].as_str().filter(|i| !i.is_empty()) else { return json!({ "ok": false, "error": "Missing elicitationId" }) };
        let mut response = json!({ "action": payload["action"].as_str().filter(|a| !a.is_empty()).unwrap_or("cancel") });
        if let Some(content) = payload.get("content").filter(|c| !c.is_null()) {
            response["content"] = content.clone();
        }
        if self.elicitations.resolve(id, response) {
            json!({ "ok": true })
        } else {
            json!({ "ok": false, "error": "Elicitation not found or already resolved" })
        }
    }

    pub fn plugin_action(&self, action: &str, payload: &Value) -> Value {
        use drivers::codebuddy::plugins;
        let dir = plugins::codebuddy_dir();
        let opts = &payload["options"];
        let result = match action {
            "plugin-install" => plugins::set_plugin(&dir, opts["name"].as_str().unwrap_or(""), opts["marketplace"].as_str().unwrap_or(""), true),
            "plugin-enable" => plugins::set_plugin(&dir, payload["name"].as_str().unwrap_or(""), payload["marketplace"].as_str().unwrap_or(""), true),
            "plugin-disable" => plugins::set_plugin(&dir, payload["name"].as_str().unwrap_or(""), payload["marketplace"].as_str().unwrap_or(""), false),
            "marketplace-install" => plugins::install_marketplace(&dir, opts["name"].as_str().unwrap_or(""), opts["repo"].as_str().unwrap_or(""), opts["autoUpdate"].as_bool().unwrap_or(true)),
            "marketplace-remove" => plugins::remove_marketplace(&dir, opts["name"].as_str().unwrap_or(""), opts["removePlugins"].as_bool().unwrap_or(true)),
            _ => Err(format!("Unknown plugin action: {action}")),
        };
        match result {
            Ok(r) => json!({ "ok": true, "result": r }),
            Err(e) => json!({ "ok": false, "error": e }),
        }
    }

    /// App shutdown: abort turns, close App Server connections, kill logins.
    pub fn shutdown(&self) {
        for entry in self.active.iter() {
            entry.value().cancel();
        }
        self.app_server.close();
        self.codex_login.shutdown();
        self.elicitations.cancel_all();
    }

    /// Wait (bounded) until no turn is active (tests / shutdown).
    pub async fn wait_idle(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while !self.active.is_empty() {
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::RecordingSink;

    fn runtime(sink: Arc<RecordingSink>) -> (AgentsRuntime, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let rt = AgentsRuntime::new(RuntimeConfig::new("1.0.0", dir.path().to_path_buf(), dir.path().join("tmp")), sink);
        (rt, dir)
    }

    #[tokio::test]
    async fn unknown_backend_emits_error() {
        let sink = Arc::new(RecordingSink::default());
        let (rt, _d) = runtime(sink.clone());
        let r = rt.stream(json!({ "requestId": "r1", "chatSessionId": "c", "sdkBackend": "nope", "prompt": "x" })).await;
        assert_eq!(r, json!({ "ok": false, "error": "Unknown SDK backend" }));
        assert_eq!(sink.errors(), vec!["Unknown SDK backend: nope".to_string()]);
        assert_eq!(rt.list_models(&json!({ "sdkBackend": "nope" })).await["ok"], false);
    }

    #[tokio::test]
    async fn cancel_cleanup_steer_without_turns() {
        let sink = Arc::new(RecordingSink::default());
        let (rt, _d) = runtime(sink);
        assert_eq!(rt.cancel("r", Some("c")).await, json!({ "ok": false, "error": "Stream not found" }));
        assert_eq!(rt.cleanup("c").await, json!({ "ok": true }));
        assert_eq!(rt.steer(&json!({ "requestId": "r", "chatSessionId": "c", "clientUserMessageId": "u" })).await, json!({ "status": "inactive" }));
        assert_eq!(rt.steer(&json!({ "requestId": "r" })).await["status"], "failed");
        assert_eq!(rt.elicitation_response(&json!({})), json!({ "ok": false, "error": "Missing elicitationId" }));
        assert_eq!(rt.respond_codex_interaction(&json!({ "interactionId": "x" }))["ok"], false);
        assert_eq!(rt.cancel_codex_interaction_timeout("x"), json!({ "ok": true, "cancelled": false }));
        assert_eq!(rt.codex_get_login_session("x")["ok"], false);
    }

    /// Full turn through the dispatcher with a fake `claude` on PATH: session
    /// id decoration, resume of the recorded id on the next turn.
    #[cfg(unix)]
    #[tokio::test]
    async fn claude_turn_records_and_resumes_session() {
        use std::os::unix::fs::PermissionsExt;
        let sink = Arc::new(RecordingSink::default());
        let (rt, dir) = runtime(sink.clone());
        let bin = dir.path().join("claude");
        let args_log = dir.path().join("args.log");
        std::fs::write(&bin, format!(r#"#!/bin/sh
echo "$@" >> '{}'
while IFS= read -r line; do
  case "$line" in
    *'"type":"user"'*)
      printf '%s\n' '{{"type":"system","subtype":"init","session_id":"native-1"}}'
      printf '%s\n' '{{"type":"stream_event","session_id":"native-1","event":{{"type":"content_block_delta","delta":{{"type":"text_delta","text":"pong"}}}}}}'
      printf '%s\n' '{{"type":"result","subtype":"success","session_id":"native-1"}}'
      ;;
  esac
done
"#, args_log.display())).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let payload = |req: &str| json!({ "requestId": req, "chatSessionId": "chat", "sdkBackend": "claude", "prompt": "ping", "agentCommand": bin.to_string_lossy(), "toolIntegrationMode": "mcp", "historyMessages": [{ "role": "user", "content": "earlier" }] });
        let r = tokio::time::timeout(Duration::from_secs(20), rt.stream(payload("r1"))).await.unwrap();
        assert_eq!(r, json!({ "ok": true }));
        let ev = sink.stream_events();
        let sid = ev.iter().find(|e| e["type"] == "session-id").unwrap();
        assert_eq!(sid["sessionId"], "native-1");
        assert_eq!(sid["sdkBackend"], "claude");
        assert_eq!(sid["runtime"], "sdk");
        assert_eq!(sink.done_count(), 1);
        let r2 = tokio::time::timeout(Duration::from_secs(20), rt.stream(payload("r2"))).await.unwrap();
        assert_eq!(r2["ok"], true);
        let log = std::fs::read_to_string(&args_log).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert!(!lines[0].contains("--resume"));
        assert!(lines[1].contains("--resume native-1"));
        rt.cleanup("chat").await;
        assert!(rt.session_ids.lock().is_empty());
    }

    /// Catalog: live fetch is cached and persisted as last-known-good.
    #[cfg(unix)]
    #[tokio::test]
    async fn list_models_caches_and_persists() {
        use std::os::unix::fs::PermissionsExt;
        let sink = Arc::new(RecordingSink::default());
        let (rt, dir) = runtime(sink);
        let bin = dir.path().join("cursor-agent");
        std::fs::write(&bin, "#!/bin/sh\nprintf 'auto - Auto (current)\\ngpt-5 - GPT-5\\n'\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let payload = json!({ "sdkBackend": "cursor", "agentEnv": { "NETCATTY_CURSOR_AUTH_MODE": "cli-login", "NETCATTY_CURSOR_CLI_BIN": bin.to_string_lossy() } });
        let live = rt.list_models(&payload).await;
        assert_eq!(live["source"], "live");
        assert_eq!(live["currentModelId"], "auto");
        let cached = rt.list_models(&payload).await;
        assert_eq!(cached["fetchedAt"], live["fetchedAt"]);
        let rt2 = AgentsRuntime::new(RuntimeConfig::new("1.0.0", dir.path().to_path_buf(), dir.path().join("tmp")), Arc::new(RecordingSink::default()));
        let lkg = rt2.list_models(&payload).await;
        assert_eq!(lkg["source"], "last-known-good");
        assert_eq!(lkg["models"].as_array().unwrap().len(), 2);
    }
}
