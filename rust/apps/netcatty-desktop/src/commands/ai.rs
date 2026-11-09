//! AI core commands (Electron: `aiBridge/providerHandlers.cjs`,
//! `aiBridge/privacyHandlers.cjs`, the chat-session cancel flag of
//! `aiBridge/cattyExecHandlers.cjs`, `aiSessionsBackupBridge.cjs`).
//! The logic lives in the `netcatty-ai` crate; see `rust/docs/ipc-ai.md`.
//!
//! * Every command takes one `payload` object shaped like the Electron IPC
//!   argument and answers with the Electron result object (`{ ok, … }`), so
//!   the renderer adapter is a straight mapping. Failures are reported in
//!   that object, never as rejected invokes, as in Electron.
//! * Streaming chat events (`netcatty:ai:stream:data|end|error`) are emitted
//!   with `emit_to(<calling window label>)` (Electron: `event.sender`). JS
//!   listeners registered for any target still receive them, so the adapter
//!   filters by `requestId`, as the Electron preload does.
//! * Sender checks: Electron accepts the main window (`validateSender`) or
//!   the main + settings windows (`validateSenderOrSettings`); the same
//!   window labels are enforced here.
//! * API keys, decrypted headers, prompts and response bodies are never logged.

use super::window::{MAIN_LABEL, SETTINGS_LABEL};
use crate::state::AppState;
use netcatty_ai::backup::{AiSessionsBackup, FileResult, GenerationResult};
use netcatty_ai::fetch::{ai_fetch as run_fetch, FetchRequest, FetchResult};
use netcatty_ai::privacy::service::Operation;
use netcatty_ai::privacy::AiPrivacyService;
use netcatty_ai::providers::{headers_from_value, ProviderRegistry};
use netcatty_ai::skills;
use netcatty_ai::stream::{stream_request, StreamError, StreamOptions, StreamSink};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio_util::sync::CancellationToken;

pub const AI_STREAM_DATA: &str = "netcatty:ai:stream:data";
pub const AI_STREAM_END: &str = "netcatty:ai:stream:end";
pub const AI_STREAM_ERROR: &str = "netcatty:ai:stream:error";

const UNAUTHORIZED: &str = "Unauthorized IPC sender";

/// One running chat stream. `generation` tells a finished stream apart
/// from a newer request that reused its `requestId`.
pub struct StreamHandle {
    pub generation: u64,
    pub token: CancellationToken,
}

static NEXT_STREAM_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Managed AI state (`app.manage(AiState::new(&paths))`).
pub struct AiState {
    /// Synced provider configs, web-search config and the fetch allowlist.
    pub registry: Arc<Mutex<ProviderRegistry>>,
    /// Per-chat privacy maps. Starts "still loading" until the renderer
    /// pushes the persisted policy ([`configure_privacy`]).
    pub privacy: Arc<Mutex<AiPrivacyService>>,
    /// Cancellation tokens of running chat streams keyed by `requestId`.
    pub active_streams: Arc<dashmap::DashMap<String, StreamHandle>>,
    /// Chat sessions the user stopped (`aiSetChatSessionCancelled`); tool
    /// executors check this through [`is_chat_session_cancelled`].
    pub cancelled_chat_sessions: Arc<Mutex<HashSet<String>>>,
    pub backup: AiSessionsBackup,
    data_dir: PathBuf,
}

impl AiState {
    pub fn new(paths: &netcatty_store::AppPaths) -> Self {
        Self {
            registry: Arc::new(Mutex::new(ProviderRegistry::default())),
            privacy: Arc::new(Mutex::new(AiPrivacyService::default())),
            active_streams: Arc::new(dashmap::DashMap::new()),
            cancelled_chat_sessions: Arc::new(Mutex::new(HashSet::new())),
            backup: AiSessionsBackup::new(&paths.data_dir),
            data_dir: paths.data_dir.clone(),
        }
    }

    /// Abort every running stream (app shutdown).
    pub fn cancel_all_streams(&self) {
        for entry in self.active_streams.iter() {
            entry.value().token.cancel();
        }
        self.active_streams.clear();
    }
}

/// Apply the AI privacy policy (`redaction` of `externalMcpSetConfig`;
/// `None` / JSON `null` invalidates, as Electron does for a corrupt saved
/// policy). Exposed for the External MCP controller, which owns the
/// `externalMcpSetConfig` command. Returns the error message on failure.
pub fn configure_privacy(state: &AiState, redaction: Option<&Value>) -> Result<(), String> {
    let mut privacy = state.privacy.lock();
    match redaction {
        None | Some(Value::Null) => {
            privacy.invalidate_configuration();
            Err(netcatty_ai::privacy::service::CONFIG_ERROR.into())
        }
        Some(policy) => privacy.configure(Some(policy)).map(|_| ()).map_err(|e| e.message().into()),
    }
}

/// Has the user stopped this chat session?
pub fn is_chat_session_cancelled(state: &AiState, chat_session_id: &str) -> bool {
    state.cancelled_chat_sessions.lock().contains(chat_session_id)
}

fn ai_state<R: Runtime>(app: &AppHandle<R>) -> tauri::State<'_, AiState> {
    app.state::<AiState>()
}

/// `validateSender`: main window only.
fn is_main<R: Runtime>(window: &tauri::Window<R>) -> bool {
    window.label() == MAIN_LABEL
}

/// `validateSenderOrSettings`: main or settings window.
fn is_main_or_settings<R: Runtime>(window: &tauri::Window<R>) -> bool {
    is_main(window) || window.label() == SETTINGS_LABEL
}

fn str_field<'a>(payload: &'a Value, name: &str) -> Option<&'a str> {
    payload.get(name).and_then(Value::as_str)
}

fn ok_error(error: impl Into<String>) -> Value {
    json!({ "ok": false, "error": error.into() })
}

/// Decrypt a stored secret with the credential cipher. Plaintext and blobs
/// this machine cannot decrypt pass through unchanged; a failed decryption
/// gives `""` (Electron `decryptApiKeyValue`).
fn decryptor<R: Runtime>(app: &AppHandle<R>) -> impl Fn(&str) -> String + '_ {
    let state = app.state::<AppState<R>>();
    move |value: &str| {
        if !netcatty_ai::providers::is_encrypted(value) {
            return value.to_owned();
        }
        state.cipher().decrypt(value).unwrap_or_default()
    }
}

/// `new URL(url)` with an http(s) scheme, else the Electron error message.
fn check_http_url(url: &str) -> Result<(), &'static str> {
    match url::Url::parse(url) {
        Ok(parsed) if parsed.scheme() == "https" || parsed.scheme() == "http" => Ok(()),
        Ok(_) => Err("Only HTTP(S) URLs are allowed"),
        Err(_) => Err("Invalid URL"),
    }
}

// ---------------------------------------------------------------------------
// Provider / web-search sync and the allowlist
// ---------------------------------------------------------------------------

/// `aiSyncProviders(providers)`: provider configs (keys stay encrypted).
#[tauri::command]
pub fn ai_sync_providers<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>, payload: Value) -> Value {
    if !is_main_or_settings(&window) {
        return json!({ "ok": false });
    }
    if let Some(providers) = payload.get("providers").and_then(Value::as_array) {
        ai_state(&app).registry.lock().sync_providers(providers);
    }
    json!({ "ok": true })
}

/// `aiSyncWebSearch(apiHost, apiKey)`: web-search host (allowlist) and the
/// encrypted key that replaces `__WEB_SEARCH_KEY__`.
#[tauri::command]
pub fn ai_sync_web_search<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>, payload: Value) -> Value {
    if !is_main_or_settings(&window) {
        return json!({ "ok": false });
    }
    let api_host = str_field(&payload, "apiHost").map(str::to_owned);
    let api_key = str_field(&payload, "apiKey").map(str::to_owned);
    ai_state(&app).registry.lock().sync_web_search(api_host, api_key);
    json!({ "ok": true })
}

/// `aiAllowlistAddHost(baseURL)`: allow a host for 30 seconds.
#[tauri::command]
pub fn ai_allowlist_add_host<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>, payload: Value) -> Value {
    if !is_main_or_settings(&window) {
        return ok_error(UNAUTHORIZED);
    }
    let Some(base_url) = str_field(&payload, "baseURL") else {
        return ok_error("baseURL must be a string");
    };
    match ai_state(&app).registry.lock().allowlist.add_host(base_url) {
        Ok(()) => json!({ "ok": true }),
        Err(error) => ok_error(error),
    }
}

// ---------------------------------------------------------------------------
// aiFetch
// ---------------------------------------------------------------------------

/// `agent-model_<uuid>_<uuid>_fetch_…` request ids of delegated plugin agents.
fn is_delegated_fetch_id(request_id: &str) -> bool {
    let is_id = |s: &str| s.len() == 36 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-');
    let Some(rest) = request_id.strip_prefix("agent-model_") else { return false };
    rest.len() > 74
        && rest.is_char_boundary(36)
        && is_id(&rest[..36])
        && rest[36..].starts_with('_')
        && rest.is_char_boundary(73)
        && is_id(&rest[37..73])
        && rest[73..].starts_with("_fetch_")
}

/// `aiFetch(url, method, headers, body, providerId, skipHostCheck,
/// followRedirects, skipTLSVerify, requestId?)`: non-streaming request.
#[tauri::command]
pub async fn ai_fetch<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>, payload: Value) -> FetchResult {
    if !is_main_or_settings(&window) {
        return FetchResult::failure(UNAUTHORIZED);
    }
    let url = str_field(&payload, "url").unwrap_or_default().to_owned();
    let provider_id = str_field(&payload, "providerId").filter(|p| !p.is_empty()).map(str::to_owned);
    let skip_host_check = payload.get("skipHostCheck").and_then(Value::as_bool).unwrap_or(false);
    let headers = headers_from_value(payload.get("headers"));

    let (resolved_url, resolved_headers, skip_tls) = {
        let state = ai_state(&app);
        let registry = state.registry.lock();
        let decrypt = decryptor(&app);
        let (url, headers) = match registry.inject_api_key(&url, &headers, provider_id.as_deref(), &decrypt) {
            Ok(patched) => patched,
            Err(error) => return FetchResult::failure(error),
        };
        let headers = registry.inject_web_search_key(&headers, &decrypt);
        let skip_tls = payload.get("skipTLSVerify").and_then(Value::as_bool).unwrap_or(false)
            || registry.should_skip_tls_verify(provider_id.as_deref());
        (url, headers, skip_tls)
    };

    if let Err(error) = check_http_url(&resolved_url) {
        return FetchResult::failure(error);
    }
    let allowlist_ok = ai_state(&app).registry.lock().allowlist.is_allowed(&resolved_url, skip_host_check);
    if !allowlist_ok {
        return FetchResult::failure("URL host is not in the allowed list");
    }
    // Delegated (plugin agent) fetches need the plugin runtime, which the
    // Rust build does not have yet; any other request id is invalid.
    if let Some(request_id) = payload.get("requestId").filter(|v| !v.is_null()) {
        return FetchResult::failure(match request_id.as_str() {
            Some(id) if is_delegated_fetch_id(id) => "Delegated Agent unavailable",
            _ => "Delegated request identity invalid",
        });
    }

    let registry = ai_state(&app).registry.clone();
    let request = FetchRequest {
        url: resolved_url,
        method: str_field(&payload, "method").map(str::to_owned),
        headers: resolved_headers,
        body: str_field(&payload, "body").map(str::to_owned),
        skip_tls_verify: skip_tls,
        follow_redirects: payload.get("followRedirects").and_then(Value::as_bool).unwrap_or(false),
        max_response_bytes: None,
    };
    run_fetch(
        request,
        move |target| registry.lock().allowlist.is_allowed(target, skip_host_check),
        CancellationToken::new(),
    )
    .await
}

// ---------------------------------------------------------------------------
// Chat streaming
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamDataEvent {
    request_id: String,
    data: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamEndEvent {
    request_id: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamErrorEvent {
    request_id: String,
    error: String,
}

/// Emits the stream events to the requesting window.
struct WindowSink<R: Runtime> {
    app: AppHandle<R>,
    label: String,
    request_id: String,
    active_streams: Arc<dashmap::DashMap<String, StreamHandle>>,
    generation: u64,
}

impl<R: Runtime> WindowSink<R> {
    fn emit<T: Serialize + Clone>(&self, event: &str, payload: T) {
        if let Err(err) = self.app.emit_to(self.label.as_str(), event, payload) {
            tracing::debug!(event, %err, "AI stream event emit failed");
        }
    }
}

impl<R: Runtime> StreamSink for WindowSink<R> {
    fn data(&self, payload: String) {
        self.emit(AI_STREAM_DATA, StreamDataEvent { request_id: self.request_id.clone(), data: payload });
    }

    fn end(&self) {
        self.emit(AI_STREAM_END, StreamEndEvent { request_id: self.request_id.clone() });
    }

    fn error(&self, message: String) {
        self.emit(AI_STREAM_ERROR, StreamErrorEvent { request_id: self.request_id.clone(), error: message });
    }

    fn finished(&self) {
        // Only drop our own registration: a later request may reuse the id.
        self.active_streams
            .remove_if(&self.request_id, |_, current| current.generation == self.generation);
    }
}

/// Plugin-runtime model streams (`plugin-model_<runtime>_…`) are capped at
/// 15 s idle / 60 s total, as in Electron.
fn plugin_stream_timeouts(request_id: &str, idle: Option<f64>) -> Option<(f64, f64)> {
    let rest = request_id.strip_prefix("plugin-model_")?;
    let runtime = rest.split('_').next().unwrap_or("");
    if runtime.is_empty() || runtime.len() > 128 || !runtime.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    let idle = idle.filter(|v| v.is_finite() && *v > 0.0).unwrap_or(15_000.0).clamp(1.0, 15_000.0);
    Some((idle, 60_000.0))
}

/// `aiChatStream(requestId, url, headers, body, providerId, idleTimeoutMs)`.
/// Resolves once the response headers arrive; the body follows as events.
#[tauri::command]
pub async fn ai_chat_stream<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>, payload: Value) -> Value {
    if !is_main(&window) {
        return ok_error(UNAUTHORIZED);
    }
    let Some(request_id) = str_field(&payload, "requestId").filter(|id| !id.is_empty()).map(str::to_owned) else {
        return ok_error("requestId is required");
    };
    let url = str_field(&payload, "url").unwrap_or_default().to_owned();
    let provider_id = str_field(&payload, "providerId").filter(|p| !p.is_empty()).map(str::to_owned);
    let headers = headers_from_value(payload.get("headers"));

    let (resolved_url, resolved_headers, skip_tls) = {
        let state = ai_state(&app);
        let registry = state.registry.lock();
        let decrypt = decryptor(&app);
        match registry.inject_api_key(&url, &headers, provider_id.as_deref(), &decrypt) {
            Ok((url, headers)) => (url, headers, registry.should_skip_tls_verify(provider_id.as_deref())),
            Err(error) => return ok_error(error),
        }
    };
    if let Err(error) = check_http_url(&resolved_url) {
        return ok_error(error);
    }
    if !ai_state(&app).registry.lock().allowlist.is_allowed(&resolved_url, false) {
        return ok_error("URL host is not in the allowed list");
    }
    // Delegated plugin-agent streams need the plugin runtime (not ported).
    if request_id.starts_with("agent-model_") {
        return ok_error("Delegated model request identity invalid");
    }

    let idle_timeout_ms = payload.get("idleTimeoutMs").and_then(Value::as_f64);
    let (idle_timeout_ms, total_timeout_ms) = match plugin_stream_timeouts(&request_id, idle_timeout_ms) {
        Some((idle, total)) => (Some(idle), Some(total)),
        None => (idle_timeout_ms, None),
    };

    // Register cancellation before any await so Stop works immediately.
    let token = CancellationToken::new();
    let generation = NEXT_STREAM_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let active_streams = ai_state(&app).active_streams.clone();
    if let Some(previous) = active_streams.insert(request_id.clone(), StreamHandle { generation, token: token.clone() }) {
        previous.token.cancel();
    }
    let sink = Arc::new(WindowSink {
        app: app.clone(),
        label: window.label().to_owned(),
        request_id: request_id.clone(),
        active_streams: active_streams.clone(),
        generation,
    });
    let options = StreamOptions {
        method: Some("POST".into()),
        headers: resolved_headers,
        body: str_field(&payload, "body").map(str::to_owned),
        idle_timeout_ms,
        total_timeout_ms,
        max_error_body_bytes: None,
        skip_tls_verify: skip_tls,
    };
    match stream_request(resolved_url, options, sink, token).await {
        Ok(started) => json!({ "ok": true, "statusCode": started.status_code, "statusText": started.status_text }),
        Err(StreamError::Aborted) => json!({ "ok": false, "aborted": true, "error": "Aborted" }),
        Err(StreamError::Failed(message)) => ok_error(message),
    }
}

/// `aiChatCancel(requestId)` → `true` when a stream was cancelled.
#[tauri::command]
pub fn ai_chat_cancel<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>, payload: Value) -> Value {
    if !is_main(&window) {
        return ok_error(UNAUTHORIZED);
    }
    let Some(request_id) = str_field(&payload, "requestId") else { return json!(false) };
    match ai_state(&app).active_streams.remove(request_id) {
        Some((_, handle)) => {
            handle.token.cancel();
            json!(true)
        }
        None => json!(false),
    }
}

/// `aiSetChatSessionCancelled(chatSessionId, cancelled = true)`.
#[tauri::command]
pub fn ai_set_chat_session_cancelled<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>, payload: Value) -> Value {
    if !is_main(&window) {
        return ok_error(UNAUTHORIZED);
    }
    let Some(chat_session_id) = str_field(&payload, "chatSessionId").filter(|id| !id.is_empty()) else {
        return ok_error("chatSessionId is required");
    };
    let cancelled = payload.get("cancelled") != Some(&Value::Bool(false));
    let state = ai_state(&app);
    let mut set = state.cancelled_chat_sessions.lock();
    if cancelled {
        set.insert(chat_session_id.to_owned());
    } else {
        set.remove(chat_session_id);
    }
    drop(set);
    // Kill running commands, background jobs, SFTP ops and pending approvals
    // of this chat in the AI control plane (Electron: mcpServerBridge).
    let app2 = app.clone();
    let chat = chat_session_id.to_owned();
    tauri::async_runtime::spawn(async move {
        super::mcp::apply_chat_session_cancelled(&app2, &chat, cancelled).await;
    });
    json!({ "ok": true, "chatSessionId": chat_session_id, "cancelled": cancelled })
}

// ---------------------------------------------------------------------------
// Privacy
// ---------------------------------------------------------------------------

/// `aiPrivacyStatus()` → `{ ok, enabled }`.
#[tauri::command]
pub fn ai_privacy_status<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>) -> Value {
    if !is_main(&window) {
        return ok_error("Unauthorized");
    }
    match ai_state(&app).privacy.lock().is_enabled() {
        Ok(enabled) => json!({ "ok": true, "enabled": enabled }),
        Err(err) => ok_error(err.message()),
    }
}

/// `aiPrivacyTransform({ chatSessionId, operation, value })`.
#[tauri::command]
pub async fn ai_privacy_transform<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>, payload: Value) -> Value {
    if !is_main(&window) {
        return ok_error("Unauthorized");
    }
    let Some(operation) = Operation::parse(str_field(&payload, "operation")) else {
        return ok_error("Invalid AI privacy operation.");
    };
    let chat_session_id = str_field(&payload, "chatSessionId").unwrap_or_default().to_owned();
    let value = payload.get("value").cloned().unwrap_or(Value::Null);
    let privacy = ai_state(&app).privacy.clone();
    // Values can be large; keep the regex work off the async workers.
    let result = tauri::async_runtime::spawn_blocking(move || {
        privacy.lock().transform(operation, &chat_session_id, &value)
    })
    .await;
    match result {
        Ok(Ok(value)) => json!({ "ok": true, "value": value }),
        Ok(Err(err)) => ok_error(err.message()),
        Err(_) => ok_error(netcatty_ai::privacy::service::VALUE_ERROR),
    }
}

/// `aiPrivacyClearSession(chatSessionId)`.
#[tauri::command]
pub fn ai_privacy_clear<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>, chat_session_id: Value) -> Value {
    if !is_main(&window) {
        return ok_error("Unauthorized");
    }
    let id = chat_session_id.as_str().unwrap_or_default();
    match ai_state(&app).privacy.lock().clear_session(id) {
        Ok(()) => json!({ "ok": true }),
        Err(err) => ok_error(err.message()),
    }
}

/// Startup fallback used by the renderer adapter: apply the persisted policy
/// only while the service is still waiting for its first configuration, so
/// a later `externalMcpSetConfig({ redaction })` always wins. `redaction:
/// null` marks a corrupt saved policy (fails closed).
#[tauri::command]
pub fn ai_privacy_initialize<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>, payload: Value) -> Value {
    if !is_main_or_settings(&window) {
        return ok_error(UNAUTHORIZED);
    }
    let state = ai_state(&app);
    let pending = matches!(
        state.privacy.lock().is_enabled(),
        Err(netcatty_ai::privacy::AiPrivacyError::Loading)
    );
    if !pending {
        return json!({ "ok": true, "applied": false });
    }
    match configure_privacy(&state, payload.get("redaction")) {
        Ok(()) => json!({ "ok": true, "applied": true }),
        Err(error) => ok_error(error),
    }
}

// ---------------------------------------------------------------------------
// User skills and the skills CLI
// ---------------------------------------------------------------------------

async fn scan_skills(data_dir: PathBuf) -> Result<skills::SkillsScan, String> {
    tauri::async_runtime::spawn_blocking(move || skills::scan_user_skills(&data_dir).map_err(|e| e.to_string()))
        .await
        .map_err(|e| e.to_string())?
}

fn status_value(status: &skills::UserSkillsStatus) -> serde_json::Map<String, Value> {
    match serde_json::to_value(status) {
        Ok(Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    }
}

/// `aiUserSkillsGetStatus()` → `{ ok, directoryPath, readyCount, warningCount, skills, warnings }`.
#[tauri::command]
pub async fn ai_user_skills_status<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>) -> Value {
    if !is_main_or_settings(&window) {
        return ok_error(UNAUTHORIZED);
    }
    match scan_skills(ai_state(&app).data_dir.clone()).await {
        Ok(scan) => {
            let mut out = status_value(&scan.status);
            out.insert("ok".into(), json!(true));
            Value::Object(out)
        }
        Err(error) => ok_error(error),
    }
}

/// `aiUserSkillsOpenFolder()`: open the skills folder in the file manager.
#[tauri::command]
pub async fn ai_user_skills_open<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>) -> Value {
    use tauri_plugin_opener::OpenerExt;
    if !is_main_or_settings(&window) {
        return ok_error(UNAUTHORIZED);
    }
    match scan_skills(ai_state(&app).data_dir.clone()).await {
        Ok(scan) => {
            let opened = app.opener().open_path(scan.status.directory_path.clone(), None::<&str>);
            let mut out = status_value(&scan.status);
            out.insert("ok".into(), json!(opened.is_ok()));
            if let Err(err) = opened {
                out.insert("error".into(), json!(err.to_string()));
            }
            Value::Object(out)
        }
        Err(error) => ok_error(error),
    }
}

/// `aiUserSkillsBuildContext(prompt, selectedSkillSlugs)` → `{ ok, context, status }`.
#[tauri::command]
pub async fn ai_user_skills_build_context<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>, payload: Value) -> Value {
    if !is_main(&window) {
        return ok_error(UNAUTHORIZED);
    }
    let prompt = str_field(&payload, "prompt").unwrap_or_default().to_owned();
    let slugs: Vec<String> = payload
        .get("selectedSkillSlugs")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        }).collect())
        .unwrap_or_default();
    match scan_skills(ai_state(&app).data_dir.clone()).await {
        Ok(scan) => {
            let context = skills::build_user_skills_context(&scan, &prompt, &slugs);
            json!({ "ok": true, "context": context, "status": scan.status })
        }
        Err(error) => ok_error(error),
    }
}

/// Bundled `skills/netcatty-tool-cli/SKILL.md`: Tauri resources, else the
/// repository checkout in debug builds.
fn tool_skill_path<R: Runtime>(app: &AppHandle<R>) -> Option<PathBuf> {
    let relative = PathBuf::from("skills").join("netcatty-tool-cli").join("SKILL.md");
    let mut candidates = Vec::new();
    if let Ok(resources) = app.path().resource_dir() {
        candidates.push(resources.join(&relative));
    }
    if cfg!(debug_assertions) {
        candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").join(&relative));
    }
    candidates.into_iter().find(|p| p.is_file()).map(|p| p.canonicalize().unwrap_or(p))
}

/// The tool CLI is the Netcatty executable itself in `--tool-cli` mode.
pub const TOOL_CLI_FLAG: &str = "--tool-cli";

/// `aiSkillsCliGetInvocation()` → `{ ok, skillPath, commandPrefix, launcherPath, usesLauncher }`.
#[tauri::command]
pub fn ai_skills_cli_invocation<R: Runtime>(app: AppHandle<R>, window: tauri::Window<R>) -> Value {
    if !is_main_or_settings(&window) {
        return ok_error(UNAUTHORIZED);
    }
    let skill_path = tool_skill_path(&app).map(|p| p.to_string_lossy().into_owned());
    match std::env::current_exe() {
        Ok(exe) => {
            let exe = exe.to_string_lossy().into_owned();
            json!({
                "ok": true,
                "skillPath": skill_path,
                "commandPrefix": format!("\"{exe}\" {TOOL_CLI_FLAG}"),
                "launcherPath": exe,
                "usesLauncher": true,
            })
        }
        Err(err) => ok_error(err.to_string()),
    }
}

// ---------------------------------------------------------------------------
// AI sessions backup
// ---------------------------------------------------------------------------

/// `aiSessionsBackupWrite({ json })`.
#[tauri::command]
pub async fn ai_sessions_backup_write<R: Runtime>(app: AppHandle<R>, payload: Value) -> GenerationResult {
    let backup = ai_state(&app).backup.clone();
    let json = str_field(&payload, "json").map(str::to_owned);
    tauri::async_runtime::spawn_blocking(move || backup.write_generation(json.as_deref()))
        .await
        .unwrap_or_default()
}

/// `aiSessionsBackupReadLatest()` → `{ ok, json?, file? }`.
#[tauri::command]
pub async fn ai_sessions_backup_read_latest<R: Runtime>(app: AppHandle<R>) -> GenerationResult {
    let backup = ai_state(&app).backup.clone();
    tauri::async_runtime::spawn_blocking(move || backup.read_latest_generation())
        .await
        .unwrap_or_default()
}

/// `aiSessionsBackupExport({ json })`: save dialog, then write.
#[tauri::command]
pub async fn ai_sessions_backup_export<R: Runtime>(app: AppHandle<R>, payload: Value) -> FileResult {
    use tauri_plugin_dialog::DialogExt;
    let Some(json) = netcatty_ai::backup::valid_json_payload(str_field(&payload, "json")).map(str::to_owned) else {
        return FileResult::failure("invalid-json");
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_file_name(AiSessionsBackup::export_file_name())
        .add_filter("JSON", &["json"])
        .add_filter("All Files", &["*"])
        .save_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(path) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else {
        return FileResult::canceled();
    };
    tauri::async_runtime::spawn_blocking(move || AiSessionsBackup::write_export(&path, &json))
        .await
        .unwrap_or_else(|e| FileResult::failure(e.to_string()))
}

/// `aiSessionsBackupImport()`: open dialog, then read.
#[tauri::command]
pub async fn ai_sessions_backup_import<R: Runtime>(app: AppHandle<R>) -> FileResult {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .add_filter("JSON", &["json"])
        .add_filter("All Files", &["*"])
        .pick_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(path) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else {
        return FileResult::canceled();
    };
    tauri::async_runtime::spawn_blocking(move || AiSessionsBackup::read_import(&path))
        .await
        .unwrap_or_else(|e| FileResult::failure(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_checks_match_electron_messages() {
        assert_eq!(check_http_url("https://x.example/"), Ok(()));
        assert_eq!(check_http_url("file:///etc/passwd"), Err("Only HTTP(S) URLs are allowed"));
        assert_eq!(check_http_url("not a url"), Err("Invalid URL"));
    }

    #[test]
    fn delegated_ids_and_plugin_timeouts() {
        let uuid = "0123abcd-0000-0000-0000-000000000000";
        assert!(is_delegated_fetch_id(&format!("agent-model_{uuid}_{uuid}_fetch_x")));
        assert!(!is_delegated_fetch_id("agent-model_bad_fetch_x"));
        assert_eq!(plugin_stream_timeouts("plugin-model_rt-1_abc", None), Some((15_000.0, 60_000.0)));
        assert_eq!(plugin_stream_timeouts("plugin-model_rt_abc", Some(500.0)), Some((500.0, 60_000.0)));
        assert_eq!(plugin_stream_timeouts("plugin-model_rt_abc", Some(99_999.0)), Some((15_000.0, 60_000.0)));
        assert_eq!(plugin_stream_timeouts("chat-123", Some(500.0)), None);
        assert_eq!(plugin_stream_timeouts("plugin-model__x", None), None);
    }

    #[test]
    fn privacy_configuration_entry_point() {
        let dir = tempfile::tempdir().unwrap();
        let state = AiState::new(&netcatty_store::AppPaths::resolve_with(Some(dir.path().to_path_buf())));
        assert!(state.privacy.lock().is_enabled().is_err());
        configure_privacy(&state, Some(&json!({ "enabled": true }))).unwrap();
        assert_eq!(state.privacy.lock().is_enabled(), Ok(true));
        assert!(configure_privacy(&state, None).is_err());
        assert!(state.privacy.lock().is_enabled().is_err());
        assert!(configure_privacy(&state, Some(&json!({ "enabled": "x" }))).is_err());
        state.cancelled_chat_sessions.lock().insert("c".into());
        assert!(is_chat_session_cancelled(&state, "c"));
        assert!(!is_chat_session_cancelled(&state, "d"));
    }
}
