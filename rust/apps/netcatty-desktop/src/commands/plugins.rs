//! Plugin host commands (Electron: `electron/plugins/pluginBridge.cjs`).
//!
//! The host itself lives in `netcatty-plugins`; this module wires it to the
//! app: the `netcatty-plugin` URI scheme and iframe relay for browser
//! runtimes, renderer events (Electron channel names), permission /
//! interaction prompts owned by the calling window, dialogs, the clipboard
//! and the session registry.
//!
//! Every management call goes through one command, `plugin_call
//! { method, payload }`, where `method` is the Electron IPC channel suffix
//! (`netcatty:plugins:<method>`), so the contract maps 1:1 onto
//! `pluginBridge.cjs`. Browser runtimes use `plugin_runtime_attach`,
//! `plugin_runtime_messages` and `plugin_runtime_exited`.
//!
//! Contract: `rust/docs/ipc-plugins.md`.

use super::CmdResult;
use crate::state::AppState;
use netcatty_core::CoreError;
use netcatty_plugins::browser::{BrowserLauncher, BrowserResources, BrowserRuntimeHost, RendererRuntimeHost};
use netcatty_plugins::host::{channels, HostConfig, HostEvents, PluginHost};
use netcatty_plugins::interactions::InteractionSurface;
use netcatty_plugins::manager::InstallRequest;
use netcatty_plugins::permissions::{PermissionDecisionHost, PromptSurface};
use netcatty_plugins::runtime::default_node_runtime_config;
use netcatty_plugins::secrets::SecretCipher;
use netcatty_plugins::source::Source;
use netcatty_plugins::{PluginError, PluginResult};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tauri::ipc::Channel;
use tauri::{AppHandle, Emitter, Manager, Runtime, UriSchemeContext, WebviewWindow};

pub use netcatty_plugins::browser::SCHEME;

mod providers;

/// Managed plugin state.
pub struct PluginsState {
    host: OnceLock<Result<Arc<PluginHost>, String>>,
    pub browser: Arc<BrowserRuntimeHost>,
    decisions: OnceLock<Arc<PermissionDecisionHost>>,
    scope_catalogs: Mutex<HashMap<String, Value>>,
    pub app_root: PathBuf,
}

impl PluginsState {
    pub fn host(&self) -> CmdResult<Arc<PluginHost>> {
        match self.host.get() {
            Some(Ok(host)) => Ok(host.clone()),
            Some(Err(err)) => Err(CoreError::unsupported(format!("Plugin runtime is disabled or unavailable: {err}"))),
            None => Err(CoreError::unsupported("Plugin runtime is disabled or unavailable")),
        }
    }
}

/// Locate the repository / bundle root holding `electron/plugins/runtime`
/// and `node_modules/@netcatty/*` (bundled resource dir first, then the
/// source checkout this binary was built from).
pub fn resolve_app_root<R: Runtime>(app: &AppHandle<R>) -> PathBuf {
    if let Ok(dir) = std::env::var("NETCATTY_PLUGIN_APP_ROOT") {
        return PathBuf::from(dir);
    }
    if let Ok(resources) = app.path().resource_dir() {
        let candidate = resources.join("plugin-runtime");
        if candidate.join("electron/plugins/runtime/runtimePeer.mjs").exists() {
            return candidate;
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap_or_else(|_| PathBuf::from("."))
}

/// Credential cipher of the app (`AppState::cipher`).
struct AppCipher<R: Runtime>(AppHandle<R>);

impl<R: Runtime> SecretCipher for AppCipher<R> {
    fn available(&self) -> bool {
        self.0.try_state::<AppState<R>>().is_some_and(|s| s.cipher().available())
    }
    fn encrypt(&self, plaintext: &str) -> PluginResult<Vec<u8>> {
        let state = self.0.try_state::<AppState<R>>().ok_or_else(|| PluginError::unavailable("credential cipher unavailable"))?;
        let cipher = state.cipher();
        if !cipher.available() {
            return Err(PluginError::unavailable("Secure OS-backed encryption is unavailable for plugin secrets"));
        }
        let value = cipher.encrypt(plaintext).map_err(|_| PluginError::unavailable("OS-backed plugin secret encryption failed"))?;
        Ok(value.into_bytes())
    }
    fn decrypt(&self, ciphertext: &[u8]) -> PluginResult<String> {
        let state = self.0.try_state::<AppState<R>>().ok_or_else(|| PluginError::unavailable("credential cipher unavailable"))?;
        let text = std::str::from_utf8(ciphertext).map_err(|_| PluginError::rpc(netcatty_plugins::codes::DATA_LOSS, "Plugin secret could not be decrypted"))?;
        state.cipher().decrypt(text).map_err(|_| PluginError::rpc(netcatty_plugins::codes::DATA_LOSS, "Plugin secret could not be decrypted"))
    }
}

struct AppEvents<R: Runtime>(AppHandle<R>);
impl<R: Runtime> HostEvents for AppEvents<R> {
    fn emit(&self, channel: &str, payload: Value) {
        crate::events::emit(&self.0, channel, payload);
    }
}

fn window<R: Runtime>(app: &AppHandle<R>, label: &str) -> Option<WebviewWindow<R>> {
    app.get_webview_window(label)
}

fn usable<R: Runtime>(app: &AppHandle<R>, label: &str) -> bool {
    window(app, label).is_some_and(|w| w.is_visible().unwrap_or(false) && w.is_focused().unwrap_or(false))
}

struct AppSurface<R: Runtime>(AppHandle<R>);

impl<R: Runtime> PromptSurface for AppSurface<R> {
    fn emit(&self, owner: &str, payload: Value) -> bool {
        self.0.emit_to(owner, channels::PERMISSION_PROMPT, payload).is_ok()
    }
    fn owner_usable(&self, owner: &str) -> bool {
        usable(&self.0, owner)
    }
}

impl<R: Runtime> InteractionSurface for AppSurface<R> {
    fn emit(&self, owner: &str, payload: Value) -> bool {
        self.0.emit_to(owner, channels::INTERACTION, payload).is_ok()
    }
    fn owner_usable(&self, owner: &str) -> bool {
        usable(&self.0, owner)
    }
    fn read_clipboard(&self) -> Option<String> {
        arboard::Clipboard::new().ok()?.get_text().ok()
    }
    fn write_clipboard(&self, text: &str) -> bool {
        arboard::Clipboard::new().and_then(|mut c| c.set_text(text.to_string())).is_ok()
    }
    fn terminal_binding(&self, session_id: &str) -> Option<String> {
        let state = self.0.try_state::<AppState<R>>()?;
        state.sessions.get(session_id).map(|entry| format!("{:p}", Arc::as_ptr(&entry)))
    }
}

struct AppRendererRuntime<R: Runtime>(AppHandle<R>);
impl<R: Runtime> RendererRuntimeHost for AppRendererRuntime<R> {
    fn launch(&self, runtime_id: &str, url: &str) -> bool {
        self.0
            .emit_to("main", netcatty_plugins::browser::LAUNCH_EVENT, json!({ "runtimeId": runtime_id, "url": url }))
            .is_ok()
    }
    fn stop(&self, runtime_id: &str) {
        let _ = self.0.emit_to("main", netcatty_plugins::browser::STOP_EVENT, json!({ "runtimeId": runtime_id }));
    }
}

/// Construct the host and start recovery / eager plugins in the background.
pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    let handle = app.handle().clone();
    let app_root = resolve_app_root(&handle);
    let browser = BrowserRuntimeHost::new(BrowserResources::from_app_root(&app_root));
    browser.set_renderer(Arc::new(AppRendererRuntime(handle.clone())));
    let state = PluginsState {
        host: OnceLock::new(),
        browser: browser.clone(),
        decisions: OnceLock::new(),
        scope_catalogs: Mutex::new(HashMap::new()),
        app_root: app_root.clone(),
    };
    let paths = netcatty_store::AppPaths::resolve();
    let allow_advanced = netcatty_plugins::constants::is_plugin_development_enabled();
    let created = PluginHost::new(HostConfig {
        user_data: paths.data_dir.clone(),
        netcatty_version: app.package_info().version.to_string(),
        allow_advanced_plugins: allow_advanced,
        node: allow_advanced.then(|| default_node_runtime_config(&app_root)),
        cipher: Arc::new(AppCipher(handle.clone())),
        events: Arc::new(AppEvents(handle.clone())),
    });
    match created {
        Ok(host) => {
            host.supervisor.set_browser_launcher(Arc::new(BrowserLauncher { host: browser }));
            let surface = Arc::new(AppSurface(handle.clone()));
            let decisions = Arc::new(PermissionDecisionHost::new(surface.clone()));
            host.permissions.set_decision_provider(decisions.clone());
            host.interactions.set_surface(surface);
            let _ = state.decisions.set(decisions);
            let _ = state.host.set(Ok(host.clone()));
            tauri::async_runtime::spawn(async move {
                if let Err(err) = host.manager.initialize().await {
                    tracing::warn!(error = %err, "plugin host initialization failed");
                }
            });
        }
        Err(err) => {
            tracing::warn!(error = %err, "plugin host unavailable");
            let _ = state.host.set(Err(err.message().to_string()));
        }
    }
    app.manage(state);
}

/// `netcatty-plugin://localhost/<token>/…` (Windows: `http://netcatty-plugin.localhost/…`).
pub fn protocol<R: Runtime>(ctx: UriSchemeContext<'_, R>, request: tauri::http::Request<Vec<u8>>) -> tauri::http::Response<Cow<'static, [u8]>> {
    let response = match ctx.app_handle().try_state::<PluginsState>() {
        Some(state) => state.browser.serve(request.method().as_str(), request.uri().path()),
        None => netcatty_plugins::browser::ProtocolResponse { status: 404, headers: vec![], body: b"Not Found".to_vec() },
    };
    let mut builder = tauri::http::Response::builder().status(response.status);
    for (k, v) in response.headers {
        builder = builder.header(k, v);
    }
    builder.body(Cow::Owned(response.body)).unwrap_or_else(|_| tauri::http::Response::new(Cow::Borrowed(&b""[..])))
}

/// Shut plugin runtimes down on exit (bounded by the 2 s deactivate deadline).
pub fn shutdown<R: Runtime>(app: &AppHandle<R>) {
    if let Some(state) = app.try_state::<PluginsState>() {
        if let Ok(host) = state.host() {
            tauri::async_runtime::block_on(async move {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(4), host.shutdown()).await;
            });
        }
    }
}

// ---- browser runtime relay -------------------------------------------------

#[tauri::command]
pub fn plugin_runtime_attach(state: tauri::State<'_, PluginsState>, runtime_id: String, channel: Channel<Value>) -> bool {
    state.browser.attach(&runtime_id, Box::new(move |message| channel.send(message).is_ok()))
}

#[tauri::command]
pub fn plugin_runtime_messages(state: tauri::State<'_, PluginsState>, runtime_id: String, messages: Vec<Value>) -> bool {
    state.browser.deliver(&runtime_id, messages)
}

#[tauri::command]
pub fn plugin_runtime_exited(state: tauri::State<'_, PluginsState>, runtime_id: String, reason: Option<String>) {
    state.browser.exited(&runtime_id, reason.as_deref().unwrap_or("Plugin renderer closed"));
}

/// The main renderer (re)loaded: every iframe of the previous document is gone.
#[tauri::command]
pub fn plugin_runtime_reset(state: tauri::State<'_, PluginsState>) {
    state.browser.renderer_reset();
}

// ---- management -------------------------------------------------------------------

fn s<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

fn plugin_id(payload: &Value) -> CmdResult<String> {
    let id = s(payload, "pluginId").unwrap_or("");
    if !netcatty_plugins::contract::is_valid("PluginId", &json!(id)) {
        return Err(CoreError::invalid("Plugin ID is invalid"));
    }
    Ok(id.to_string())
}

fn to_value<T: serde::Serialize>(value: T) -> CmdResult<Value> {
    serde_json::to_value(value).map_err(|e| CoreError::internal(e.to_string()))
}

const SCOPE_KINDS: [&str; 4] = ["workspace", "host", "session", "device"];

/// `normalizePluginScopeCatalog`.
pub fn normalize_scope_catalog(value: &Value) -> CmdResult<Value> {
    let mut out = serde_json::Map::new();
    let mut total = 0;
    for kind in SCOPE_KINDS {
        let mut seen = std::collections::HashSet::new();
        let mut entries = Vec::new();
        for entry in value.get(kind).and_then(Value::as_array).cloned().unwrap_or_default() {
            let id = entry["id"].as_str().unwrap_or("").trim().to_string();
            let label = entry["label"].as_str().unwrap_or("").trim().to_string();
            if id.is_empty() || id.len() > 256 || id.contains('\0') || label.is_empty() || label.len() > 512 || !seen.insert(id.clone()) {
                continue;
            }
            total += 1;
            if total > 4096 {
                return Err(CoreError::invalid("Plugin setting scope catalog is too large"));
            }
            entries.push(json!({ "id": id, "label": label }));
        }
        out.insert(kind.into(), Value::Array(entries));
    }
    Ok(Value::Object(out))
}

fn merged_scope_catalog(state: &PluginsState) -> Value {
    let mut catalogs: Vec<Value> = state.scope_catalogs.lock().values().cloned().collect();
    catalogs.push(json!({ "device": [{ "id": "device", "label": "This device" }] }));
    let mut out = serde_json::Map::new();
    let mut total = 0;
    for kind in SCOPE_KINDS {
        let mut seen = std::collections::HashSet::new();
        let mut list = Vec::new();
        for catalog in &catalogs {
            for entry in catalog.get(kind).and_then(Value::as_array).cloned().unwrap_or_default() {
                let id = entry["id"].as_str().unwrap_or("").to_string();
                if total >= 4096 || !seen.insert(id) {
                    continue;
                }
                total += 1;
                list.push(entry);
            }
        }
        out.insert(kind.into(), Value::Array(list));
    }
    Value::Object(out)
}

/// Methods that degrade to a fallback instead of failing while the host is
/// unavailable (`handlePassive`).
fn passive_fallback(method: &str, state: &PluginsState) -> Option<Value> {
    match method {
        "terminal-providers" | "terminal-session-event" | "extension-providers" => Some(json!([])),
        "sync-sidecars-collect" => Some(Value::Null),
        "sync-sidecars-apply" => Some(json!({ "applied": false })),
        "credential-catalog-update" => Some(json!(0)),
        "get-scope-catalog" => Some(merged_scope_catalog(state)),
        "set-scope-catalog" => Some(Value::Null),
        _ => None,
    }
}

/// `netcatty:plugins:status`.
fn status(state: &PluginsState) -> Value {
    match state.host() {
        Ok(host) => json!({
            "available": host.manager.is_initialized(),
            "experimental": true,
            "credentialStorageAvailable": host.capabilities.catalog.is_available(),
        }),
        Err(_) => json!({ "available": false, "experimental": true }),
    }
}

/// One management call (`netcatty:plugins:<method>`).
#[tauri::command]
pub async fn plugin_call<R: Runtime>(
    app: AppHandle<R>,
    window: tauri::Window<R>,
    method: String,
    payload: Option<Value>,
) -> CmdResult<Value> {
    let state = app.state::<PluginsState>();
    let payload = payload.unwrap_or(Value::Null);
    let owner = window.label().to_string();
    match method.as_str() {
        "status" => return Ok(status(&state)),
        "host-available-sync" => return Ok(json!(state.host().is_ok())),
        _ => {}
    }
    let host = match state.host() {
        Ok(host) => host,
        Err(err) => return passive_fallback(&method, &state).ok_or(err),
    };
    if let Err(err) = host.manager.initialize().await {
        return passive_fallback(&method, &state).ok_or_else(|| CoreError::unsupported(format!("Plugin runtime is disabled or unavailable: {err}")));
    }
    let result = dispatch(&app, &state, &host, &owner, &method, payload).await;
    result.map_err(CoreError::from)
}

async fn dispatch<R: Runtime>(
    app: &AppHandle<R>,
    state: &PluginsState,
    host: &Arc<PluginHost>,
    owner: &str,
    method: &str,
    payload: Value,
) -> PluginResult<Value> {
    let ser = |v: Result<Value, CoreError>| v.map_err(|e| PluginError::host(e.message));
    match method {
        "list" => ser(to_value(host.manager.list().await?)),
        "install" => {
            let path = s(&payload, "archivePath").ok_or_else(|| PluginError::invalid("Plugin package path is required"))?;
            let plugin = host
                .manager
                .install(InstallRequest {
                    archive_path: PathBuf::from(path),
                    enable: payload.get("enable").and_then(Value::as_bool),
                    source: Source::local(),
                    catalog: None,
                })
                .await?;
            ser(to_value(plugin))
        }
        "set-enabled" => {
            let id = s(&payload, "pluginId").unwrap_or("");
            ser(to_value(host.manager.set_enabled(id, payload["enabled"] == json!(true), None).await?))
        }
        "restart" => ser(to_value(host.manager.restart(s(&payload, "pluginId").unwrap_or("")).await?)),
        "uninstall" => Ok(json!(host.manager.uninstall(s(&payload, "pluginId").unwrap_or("")).await?)),
        "source-binding" => {
            let id = plugin_id(&payload).map_err(|e| PluginError::invalid(e.message))?;
            ser(to_value(host.database.get_retained_plugin_source(&id)?))
        }
        "reset-source" => {
            let id = plugin_id(&payload).map_err(|e| PluginError::invalid(e.message))?;
            host.manager.reset_uninstalled_source(&id, s(&payload, "expectedSourceId").unwrap_or("")).await?;
            Ok(Value::Null)
        }
        "log-status" => Ok(host.logs.status()),
        "log-configure" => host.logs.configure(&payload),
        "log-open" => {
            use tauri_plugin_opener::OpenerExt;
            let dir = host.logs.ensure_folder()?;
            app.opener()
                .open_path(dir.to_string_lossy(), None::<&str>)
                .map_err(|_| PluginError::host("Could not open plugin log folder"))?;
            Ok(host.logs.status())
        }
        "log-export" => {
            use tauri_plugin_dialog::DialogExt;
            let (tx, rx) = tokio::sync::oneshot::channel();
            app.dialog()
                .file()
                .set_title("Export local plugin logs")
                .set_file_name("netcatty-plugin-logs.jsonl")
                .save_file(move |p| {
                    let _ = tx.send(p);
                });
            match rx.await.ok().flatten().and_then(|p| p.into_path().ok()) {
                Some(path) => host.logs.export_to(&path),
                None => Ok(host.logs.status()),
            }
        }
        "log-clear" => {
            use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
            let dialog = app
                .dialog()
                .message("Delete the saved local audit and diagnostic files? The bounded security history in plugin permissions is kept.")
                .title("Clear local plugin logs?")
                .kind(MessageDialogKind::Warning)
                .buttons(MessageDialogButtons::OkCancelCustom("Clear logs".into(), "Cancel".into()));
            let confirmed = tauri::async_runtime::spawn_blocking(move || dialog.blocking_show()).await.unwrap_or(false);
            if confirmed {
                host.logs.clear()
            } else {
                Ok(host.logs.status())
            }
        }
        "permission-ready" => {
            let decisions = state.decisions.get().ok_or_else(|| PluginError::host("Plugin permissions are unavailable"))?;
            Ok(json!(decisions.set_ready(owner, payload["ready"] == json!(true))))
        }
        "permission-response" => {
            let decisions = state.decisions.get().ok_or_else(|| PluginError::host("Plugin permissions are unavailable"))?;
            Ok(json!(decisions.respond(owner, &payload)?))
        }
        "set-permission-mode" => {
            let id = plugin_id(&payload).map_err(|e| PluginError::invalid(e.message))?;
            let plugin = host.database.get_active_plugin(&id)?.ok_or_else(|| PluginError::host("Plugin permissions are unavailable"))?;
            if s(&payload, "policyRevision") != Some(host.permissions.policy_revision(&id, plugin.active_version.as_deref()).as_str()) {
                return Err(PluginError::host("Plugin permissions changed; refresh before editing"));
            }
            host.permissions.set_mode(&id, plugin.manifest.as_ref().unwrap_or(&Value::Null), s(&payload, "permission").unwrap_or(""), s(&payload, "mode").unwrap_or(""))?;
            Ok(json!(true))
        }
        "permissions" => {
            let id = plugin_id(&payload).map_err(|e| PluginError::invalid(e.message))?;
            let plugin = host.database.get_active_plugin(&id)?;
            let identity = host.supervisor.get_runtime_identity(&id);
            let current = match (&plugin, &identity) {
                (Some(p), Some(i)) if p.enabled && p.active_version.as_deref() == Some(i.plugin_version.as_str()) => {
                    Some((p.manifest.clone().unwrap_or(Value::Null), i.security_principal.clone()))
                }
                _ => None,
            };
            let groups = host.permissions.describe_grants(&id, current.as_ref().map(|(m, p)| (m, p.as_str())))?;
            let mut grants = Vec::new();
            for scope in ["always", "application", "session"] {
                for grant in groups[scope].as_array().cloned().unwrap_or_default() {
                    grants.push(json!({
                        "permission": grant["permission"], "resource": grant["resource"], "resourceKind": grant["resourceKind"],
                        "scope": scope, "sessionId": grant["sessionId"], "grantedAt": grant["grantedAt"],
                        "matchesCurrentActivation": grant["matchesCurrentActivation"],
                    }));
                }
            }
            let actions = ["completed", "cancelled", "preview-confirmed", "share-confirmed", "copy-confirmed", "draft-reviewed", "action-confirmed", "action-claimed"];
            let audit: Vec<Value> = host
                .database
                .list_security_audit(&id, 100)?
                .into_iter()
                .map(|entry| {
                    let mut out = json!({ "event": entry.event, "createdAt": entry.created_at });
                    if let Some(p) = entry.details["permission"].as_str() {
                        out["permission"] = json!(p);
                    }
                    if let Some(sc) = entry.details["scope"].as_str() {
                        out["scope"] = json!(sc);
                    }
                    if let Some(m) = entry.details["mode"].as_str().filter(|m| ["allow", "ask", "deny"].contains(m)) {
                        out["mode"] = json!(m);
                    }
                    if let Some(a) = entry.details["action"].as_str().filter(|a| actions.contains(a)) {
                        out["action"] = json!(a);
                    }
                    out
                })
                .collect();
            let mut out = json!({ "grants": grants, "audit": audit });
            if let Some(p) = &plugin {
                out["policies"] = json!(host.permissions.describe_policies(&id, p.manifest.as_ref().unwrap_or(&Value::Null))?);
                out["policyRevision"] = json!(host.permissions.policy_revision(&id, p.active_version.as_deref()));
            }
            Ok(out)
        }
        "revoke-permissions" => {
            let id = plugin_id(&payload).map_err(|e| PluginError::invalid(e.message))?;
            ser(to_value(host.manager.revoke_permissions(&id).await?))
        }
        "interaction-ready" => Ok(json!(host.interactions.set_ready(owner, payload["ready"] == json!(true))?)),
        "interaction-response" => host.interactions.respond(owner, &payload),
        "terminal-target" => Ok(json!(host.interactions.set_terminal_target(owner, &payload)?)),
        "contributions" => {
            let mut options = payload;
            if options.is_null() {
                options = json!({});
            }
            host.contributions.snapshot(&options)
        }
        "execute-command" => {
            host.contributions
                .execute_command(s(&payload, "command").unwrap_or(""), payload.get("args").cloned(), "renderer", payload.get("context").cloned(), None)
                .await
        }
        "update-setting" => {
            host.contributions
                .update_setting(s(&payload, "pluginId").unwrap_or(""), s(&payload, "settingId").unwrap_or(""), payload.get("value").unwrap_or(&Value::Null), s(&payload, "scopeId"), "host")
                .await
        }
        "reset-setting" => host.contributions.reset_setting(s(&payload, "pluginId").unwrap_or(""), s(&payload, "settingId").unwrap_or(""), s(&payload, "scopeId")).await,
        "set-environment" => {
            host.contributions.set_environment(if payload.is_null() { json!({}) } else { payload }).await?;
            Ok(Value::Null)
        }
        "get-scope-catalog" => Ok(merged_scope_catalog(state)),
        "set-scope-catalog" => {
            let catalog = normalize_scope_catalog(&payload).map_err(|e| PluginError::invalid(e.message))?;
            state.scope_catalogs.lock().insert(owner.to_string(), catalog);
            crate::events::emit(app, channels::SCOPE_CATALOG_CHANGED, merged_scope_catalog(state));
            Ok(Value::Null)
        }
        "credential-catalog-update" => Ok(json!(host.capabilities.catalog.update(&payload["entries"])?)),
        other => providers::dispatch(app, state, host, owner, other, payload).await,
    }
}
