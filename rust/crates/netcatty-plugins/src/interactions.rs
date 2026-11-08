//! Host interactions (ports of `hostInteractionService.cjs` and
//! `terminalSelectionAuthority.cjs`): `ui.interact` input / quick pick /
//! clipboard / terminal selection sharing / terminal input drafts.
//!
//! The renderer owns presentation: requests are emitted on
//! `netcatty:plugins:host-interaction` to the ready, focused main window and
//! answered through `respondPluginInteraction` with an HMAC'd one-use action
//! token. Admission, quotas, audit (fixed metadata only) and result
//! validation stay in the host.

use crate::contract;
use crate::database::PluginDatabase;
use crate::error::{codes, PluginError, PluginResult};
use crate::permissions::PermissionEngine;
use crate::quota::QuotaManager;
use crate::registry::{AuthorizationSpec, CallContext, HostRpcRegistry, RegisterOptions};
use hmac::{Hmac, KeyInit, Mac};
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

pub const INTERACTION_CHANNEL: &str = "netcatty:plugins:host-interaction";

fn limits() -> Value {
    contract::def_const("HostInteractionLimits").cloned().unwrap_or_else(|| json!({}))
}
fn limit(name: &str, fallback: u64) -> u64 {
    limits()[name].as_u64().unwrap_or(fallback)
}

fn fail(code: i64, message: &str) -> PluginError {
    PluginError::rpc(code, message)
}

/// Renderer / OS side of interactions.
pub trait InteractionSurface: Send + Sync {
    /// Emit to the owner window; false when it cannot be shown.
    fn emit(&self, owner: &str, payload: Value) -> bool;
    /// Owner window exists, is visible, focused and the app is unlocked.
    fn owner_usable(&self, owner: &str) -> bool;
    fn read_clipboard(&self) -> Option<String>;
    fn write_clipboard(&self, text: &str) -> bool;
    /// Opaque binding of a live terminal session (changes on reconnect);
    /// `None` when the session is not alive.
    fn terminal_binding(&self, session_id: &str) -> Option<String>;
}

#[derive(Clone)]
struct TerminalTarget {
    owner: String,
    session_id: String,
    renderer_id: String,
    label: String,
    plugin_id: String,
    private_owner: String,
    binding: String,
    resource: String,
}

struct Pending {
    owner: String,
    plugin_id: String,
    plugin_version: String,
    runtime_id: String,
    params: Value,
    phase: String,
    action_token: Option<String>,
    expires_at: i64,
    preview_text: Option<String>,
    permission_mode: String,
    terminal: Option<TerminalTarget>,
    tx: Option<oneshot::Sender<PluginResult<Value>>>,
}

struct Handle {
    target: TerminalTarget,
    expires_at: i64,
    plugin_version: String,
    runtime_id: String,
}

pub struct InteractionService {
    database: Arc<PluginDatabase>,
    permissions: Arc<PermissionEngine>,
    quota: Arc<QuotaManager>,
    surface: Mutex<Option<Arc<dyn InteractionSurface>>>,
    key: [u8; 32],
    owner: Mutex<Option<String>>,
    pending: Mutex<HashMap<String, Pending>>,
    rates: Mutex<HashMap<String, (Instant, u64)>>,
    target: Mutex<Option<(String, String, String, String)>>,
    handles: Mutex<HashMap<String, Handle>>,
    closed: Mutex<bool>,
}

fn text_bytes(text: &str) -> PluginResult<String> {
    if text.len() as u64 > limit("textBytes", 4096) || text.contains('\0') {
        return Err(fail(codes::RESOURCE_EXHAUSTED, "Host interaction text exceeds its limit"));
    }
    Ok(text.to_string())
}

fn has_feature(manifest: &Value, feature: &str) -> bool {
    ["required", "optional"].iter().any(|k| manifest["features"][k].as_array().is_some_and(|a| a.iter().any(|f| f == feature)))
}

/// `assertInteractionRequest`.
pub fn assert_interaction_request(params: Value) -> PluginResult<Value> {
    if !contract::is_valid("HostInteractionRequest", &params) {
        return Err(fail(codes::INVALID_ARGUMENT, "Host interaction request is invalid"));
    }
    if serde_json::to_string(&params)?.len() as u64 > limit("requestBytes", 65536) {
        return Err(fail(codes::RESOURCE_EXHAUSTED, "Host interaction request exceeds its limit"));
    }
    match params["kind"].as_str().unwrap_or("") {
        "input" => {
            text_bytes(params["initialValue"].as_str().unwrap_or(""))?;
        }
        "clipboard.write" => {
            text_bytes(params["text"].as_str().unwrap_or(""))?;
        }
        "terminal.input.propose" => {
            if params["text"].as_str().unwrap_or("").len() as u64 > limit("textBytes", 4096) {
                return Err(fail(codes::RESOURCE_EXHAUSTED, "Terminal input draft exceeds its limit"));
            }
        }
        "quickPick" => {
            let items = params["items"].as_array().cloned().unwrap_or_default();
            let ids: std::collections::HashSet<String> = items.iter().map(|i| i["id"].to_string()).collect();
            if ids.len() != items.len() {
                return Err(fail(codes::INVALID_ARGUMENT, "Host interaction choice IDs must be unique"));
            }
        }
        _ => {}
    }
    Ok(params)
}

impl InteractionService {
    pub fn new(database: Arc<PluginDatabase>, permissions: Arc<PermissionEngine>, quota: Arc<QuotaManager>) -> Arc<Self> {
        let service = Arc::new(Self {
            database,
            permissions: permissions.clone(),
            quota,
            surface: Mutex::new(None),
            key: rand::random(),
            owner: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            rates: Mutex::new(HashMap::new()),
            target: Mutex::new(None),
            handles: Mutex::new(HashMap::new()),
            closed: Mutex::new(false),
        });
        let weak = Arc::downgrade(&service);
        permissions.on_did_revoke(Arc::new(move |event: &Value| {
            if let (Some(service), Some(plugin)) = (weak.upgrade(), event["pluginId"].as_str()) {
                service.release_plugin(plugin);
            }
        }));
        service
    }

    pub fn set_surface(&self, surface: Arc<dyn InteractionSurface>) {
        *self.surface.lock() = Some(surface);
    }

    fn surface(&self) -> PluginResult<Arc<dyn InteractionSurface>> {
        self.surface.lock().clone().ok_or_else(|| fail(codes::UNAVAILABLE, "Host interactions are unavailable"))
    }

    fn assert_window(&self, owner: Option<&str>) -> PluginResult<String> {
        let current = self.owner.lock().clone();
        let owner = owner.map(str::to_string).or(current.clone());
        let surface = self.surface()?;
        match owner {
            Some(o) if !*self.closed.lock() && Some(&o) == current.as_ref() && surface.owner_usable(&o) => Ok(o),
            _ => Err(fail(codes::UNAVAILABLE, "Host interactions require the focused unlocked main window")),
        }
    }

    pub fn set_ready(&self, owner: &str, ready: bool) -> PluginResult<bool> {
        if !ready {
            self.release_window(owner);
            return Ok(true);
        }
        if *self.closed.lock() {
            return Err(fail(codes::UNAVAILABLE, "Host interactions are unavailable"));
        }
        let previous = self.owner.lock().clone();
        if previous.as_deref() == Some(owner) {
            return Ok(true);
        }
        if let Some(previous) = previous {
            self.release_window(&previous);
        }
        *self.owner.lock() = Some(owner.to_string());
        Ok(true)
    }

    fn token(&self, id: &str, entry: &Pending) -> String {
        let nonce_bytes: [u8; 24] = rand::random();
        let nonce = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, nonce_bytes);
        let binding = json!([nonce, id, entry.plugin_id, entry.plugin_version, entry.runtime_id, entry.owner, entry.params["kind"], entry.phase, entry.expires_at, entry.terminal.as_ref().map(|t| t.resource.clone())]).to_string();
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key).expect("key");
        mac.update(binding.as_bytes());
        format!("{nonce}.{}", base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, mac.finalize().into_bytes()))
    }

    fn present(&self, id: &str) -> PluginResult<()> {
        let (owner, payload) = {
            let mut pending = self.pending.lock();
            let entry = pending.get_mut(id).ok_or_else(|| fail(codes::CANCELLED, "Host interaction was cancelled"))?;
            let token = self.token(id, entry);
            entry.action_token = Some(token.clone());
            let mut payload = json!({
                "requestId": id, "actionToken": token, "pluginId": entry.plugin_id, "pluginVersion": entry.plugin_version,
                "expiresAt": entry.expires_at, "phase": entry.phase, "request": entry.params, "permissionMode": entry.permission_mode,
            });
            if let Some(t) = &entry.terminal {
                payload["terminalSessionId"] = json!(t.session_id);
                payload["terminalRendererId"] = json!(t.renderer_id);
                payload["terminalLabel"] = json!(t.label);
            }
            if let Some(preview) = &entry.preview_text {
                payload["previewText"] = json!(preview);
            }
            (entry.owner.clone(), payload)
        };
        if self.surface()?.emit(&owner, payload) {
            Ok(())
        } else {
            Err(fail(codes::UNAVAILABLE, "Host interaction window is unavailable"))
        }
    }

    fn finish(&self, id: &str, result: PluginResult<Value>) -> bool {
        let Some(mut entry) = self.pending.lock().remove(id) else { return false };
        if let Ok(surface) = self.surface() {
            surface.emit(&entry.owner, json!({ "requestId": id, "closed": true }));
        }
        let result = match result {
            Ok(value) if !contract::is_valid("HostInteractionResult", &value) => Err(fail(codes::INTERNAL, "Host interaction result is invalid")),
            other => other,
        };
        if let Some(tx) = entry.tx.take() {
            let _ = tx.send(result);
        }
        true
    }

    fn audit(&self, plugin_id: &str, kind: &str, action: &str) -> PluginResult<()> {
        self.database
            .record_security_audit(plugin_id, "ui.interaction", &json!({ "kind": kind, "action": action }))
            .map_err(|_| fail(codes::UNAVAILABLE, "Host interaction audit is unavailable"))
    }

    fn private_owner(&self, plugin_id: &str) -> PluginResult<String> {
        let owner = self.database.private_owner(plugin_id).map_err(|_| fail(codes::PERMISSION_DENIED, "Terminal sharing source owner is unavailable"))?;
        if self.database.public_plugin_id(&owner).as_deref() != Some(plugin_id) {
            return Err(fail(codes::PERMISSION_DENIED, "Terminal sharing source owner is unavailable"));
        }
        Ok(owner)
    }

    fn capture_terminal(&self, owner: &str, ctx: &CallContext) -> PluginResult<TerminalTarget> {
        if !has_feature(&ctx.identity.manifest, "terminal.selection-sharing") {
            return Err(fail(codes::UNSUPPORTED, "Terminal sharing feature was not declared"));
        }
        let target = self.target.lock().clone();
        let Some((target_owner, session_id, renderer_id, label)) = target.filter(|t| t.0 == owner) else {
            return Err(fail(codes::FAILED_PRECONDITION, "Select a live terminal in the main window first"));
        };
        let binding = self.surface()?.terminal_binding(&session_id).ok_or_else(|| fail(codes::UNAVAILABLE, "Selected terminal has no active owned worker connection"))?;
        Ok(TerminalTarget {
            resource: format!("terminal-session:{session_id}:window:{target_owner}:worker:{binding}:renderer:{renderer_id}"),
            owner: target_owner,
            session_id,
            renderer_id,
            label,
            plugin_id: ctx.plugin_id().to_string(),
            private_owner: self.private_owner(ctx.plugin_id())?,
            binding,
        })
    }

    fn terminal_current(&self, target: &TerminalTarget) -> bool {
        let selected = self.target.lock().clone();
        selected.is_some_and(|(o, s, r, _)| o == target.owner && s == target.session_id && r == target.renderer_id)
            && self.private_owner(&target.plugin_id).ok().as_deref() == Some(target.private_owner.as_str())
            && self.surface().ok().and_then(|s| s.terminal_binding(&target.session_id)).as_deref() == Some(target.binding.as_str())
    }

    fn resolve_handle(&self, handle: &str, ctx: &CallContext) -> PluginResult<TerminalTarget> {
        if !has_feature(&ctx.identity.manifest, "terminal.input-drafts") {
            return Err(fail(codes::UNSUPPORTED, "Terminal sharing feature was not declared"));
        }
        let now = crate::constants::now_ms();
        let target = {
            let mut handles = self.handles.lock();
            handles.retain(|_, h| h.expires_at > now);
            let entry = handles.get(handle).filter(|h| {
                h.target.plugin_id == ctx.plugin_id() && h.plugin_version == ctx.identity.plugin_version && h.runtime_id == ctx.identity.runtime_id
            });
            entry.map(|h| h.target.clone()).ok_or_else(|| fail(codes::PERMISSION_DENIED, "Terminal selection handle is unavailable"))?
        };
        if target.private_owner != self.private_owner(ctx.plugin_id())? || !self.terminal_current(&target) {
            return Err(fail(codes::CANCELLED, "Selected terminal connection, renderer, source or owner changed"));
        }
        Ok(target)
    }

    fn issue_handle(&self, target: &TerminalTarget, plugin_version: &str, runtime_id: &str) -> PluginResult<Value> {
        let l = contract::def_const("TerminalSelectionSharingLimits").cloned().unwrap_or_else(|| json!({}));
        let mut handles = self.handles.lock();
        if handles.len() as u64 >= l["handlesTotal"].as_u64().unwrap_or(64)
            || handles.values().filter(|h| h.runtime_id == runtime_id).count() as u64 >= l["handlesPerRuntime"].as_u64().unwrap_or(8)
        {
            return Err(fail(codes::RESOURCE_EXHAUSTED, "Terminal selection handle limit reached"));
        }
        let expires_at = crate::constants::now_ms() + l["handleTtlMs"].as_i64().unwrap_or(300_000);
        let nonce_bytes: [u8; 24] = rand::random();
        let nonce = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, nonce_bytes);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key).expect("key");
        mac.update(json!([nonce, target.resource, target.private_owner, plugin_version, runtime_id, expires_at]).to_string().as_bytes());
        let handle = format!("{nonce}.{}", base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, mac.finalize().into_bytes()));
        handles.insert(handle.clone(), Handle { target: target.clone(), expires_at, plugin_version: plugin_version.into(), runtime_id: runtime_id.into() });
        Ok(json!({ "handle": handle, "expiresAt": expires_at }))
    }

    /// `setTerminalTarget(sender, target)`.
    pub fn set_terminal_target(&self, owner: &str, payload: &Value) -> PluginResult<bool> {
        if !contract::is_valid("HostTerminalTarget", payload) {
            return Err(fail(codes::INVALID_ARGUMENT, "Invalid selected terminal target"));
        }
        if self.owner.lock().as_deref().is_some_and(|o| o != owner) {
            return Err(fail(codes::PERMISSION_DENIED, "Selected terminal belongs to another window"));
        }
        *self.target.lock() = payload["sessionId"].as_str().map(|s| {
            (owner.to_string(), s.to_string(), payload["rendererId"].as_str().unwrap_or("").to_string(), payload["label"].as_str().unwrap_or("").to_string())
        });
        Ok(true)
    }

    fn authorization(&self, params: &Value, ctx: &CallContext) -> PluginResult<Value> {
        let kind = params["kind"].as_str().unwrap_or("");
        if kind == "terminal.selection.read" || kind == "terminal.input.propose" {
            let owner = self.assert_window(None)?;
            let target = if kind == "terminal.selection.read" {
                self.capture_terminal(&owner, ctx)?
            } else {
                self.resolve_handle(params["handle"].as_str().unwrap_or(""), ctx)?
            };
            return Ok(json!({
                "permission": kind, "resources": [target.resource],
                "reason": if kind == "terminal.selection.read" { "Preview and explicitly share the selected terminal text" } else { "Open an editable host draft without sending terminal input" },
                "operationId": kind, "allowedScopes": ["once"], "deferDecision": true,
            }));
        }
        let permission = match kind {
            "clipboard.read" => "clipboard.read",
            "clipboard.write" => "clipboard.write",
            _ => "ui.interact",
        };
        let clipboard = permission.starts_with("clipboard.");
        let mut auth = json!({
            "permission": permission, "resources": [if clipboard { "clipboard:text" } else { "*" }],
            "reason": if clipboard { "Explicitly share or replace clipboard text" } else { "Show a host input or choice dialog" },
            "operationId": format!("ui:{kind}"), "deferDecision": true,
        });
        if clipboard {
            auth["allowedScopes"] = json!(["once"]);
        }
        Ok(auth)
    }

    fn admit(&self, params: &Value, ctx: &CallContext) -> PluginResult<String> {
        let owner = self.assert_window(None)?;
        let now = Instant::now();
        let mut rates = self.rates.lock();
        let rate = rates.entry(ctx.identity.runtime_id.clone()).or_insert((now, 0));
        if now.duration_since(rate.0) >= Duration::from_secs(60) {
            *rate = (now, 0);
        }
        let pending = self.pending.lock();
        if rate.1 >= limit("requestsPerMinute", 10)
            || pending.len() as u64 >= limit("pendingTotal", 8)
            || pending.values().any(|p| p.runtime_id == ctx.identity.runtime_id || p.owner == owner)
        {
            return Err(fail(codes::RESOURCE_EXHAUSTED, "Host interaction limit reached"));
        }
        rate.1 += 1;
        drop(pending);
        self.quota.charge_bytes(&ctx.identity.runtime_id, "ui", serde_json::to_string(params)?.len() as u64)?;
        Ok(owner)
    }

    async fn request(&self, params: Value, ctx: Arc<CallContext>) -> PluginResult<Value> {
        ctx.assert_active()?;
        let owner = self.admit(&params, &ctx)?;
        let kind = params["kind"].as_str().unwrap_or("").to_string();
        let terminal = match kind.as_str() {
            "terminal.selection.read" => Some(self.capture_terminal(&owner, &ctx)?),
            "terminal.input.propose" => Some(self.resolve_handle(params["handle"].as_str().unwrap_or(""), &ctx)?),
            _ => None,
        };
        let authorization = ctx.authorization.clone().unwrap_or(self.authorization(&params, &ctx)?);
        let mode = self.permissions.get_mode(ctx.plugin_id(), ctx.identity.source_owner.as_deref(), authorization["permission"].as_str().unwrap_or("ui.interact"))?;
        if mode == "deny" {
            return Err(fail(codes::PERMISSION_DENIED, "Plugin permission is disabled"));
        }
        let surface = self.surface()?;
        if mode == "allow" && kind.starts_with("clipboard.") {
            ctx.assert_active()?;
            self.assert_window(Some(&owner))?;
            self.audit(ctx.plugin_id(), &kind, "completed")?;
            if kind == "clipboard.write" {
                if !surface.write_clipboard(params["text"].as_str().unwrap_or("")) {
                    return Err(fail(codes::UNAVAILABLE, "Host clipboard write failed"));
                }
                return Ok(json!({ "cancelled": false, "value": true }));
            }
            let text = text_bytes(&surface.read_clipboard().ok_or_else(|| fail(codes::UNAVAILABLE, "Host clipboard text is unavailable"))?)?;
            self.quota.charge_bytes(&ctx.identity.runtime_id, "clipboard", text.len() as u64)?;
            ctx.assert_active()?;
            return Ok(json!({ "cancelled": false, "value": text }));
        }
        let timeout = limit("timeoutMs", 60_000);
        let id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        let mut entry = Pending {
            owner,
            plugin_id: ctx.plugin_id().to_string(),
            plugin_version: ctx.identity.plugin_version.clone(),
            runtime_id: ctx.identity.runtime_id.clone(),
            params: params.clone(),
            phase: "request".into(),
            action_token: None,
            expires_at: crate::constants::now_ms() + timeout as i64,
            preview_text: None,
            permission_mode: mode,
            terminal,
            tx: Some(tx),
        };
        if kind == "clipboard.read" {
            let text = text_bytes(&surface.read_clipboard().ok_or_else(|| fail(codes::UNAVAILABLE, "Host clipboard text is unavailable"))?)?;
            self.quota.charge_bytes(&ctx.identity.runtime_id, "clipboard", text.len() as u64)?;
            entry.preview_text = Some(text);
            entry.phase = "preview".into();
        }
        self.pending.lock().insert(id.clone(), entry);
        if self.present(&id).is_err() {
            self.finish(&id, Err(fail(codes::UNAVAILABLE, "Host interaction window is unavailable")));
        }
        tokio::select! {
            result = rx => result.unwrap_or_else(|_| Err(fail(codes::CANCELLED, "Host interaction was cancelled"))),
            _ = ctx.signal.cancelled() => {
                self.finish(&id, Err(fail(codes::CANCELLED, "Host interaction was cancelled")));
                Err(fail(codes::CANCELLED, "Host interaction was cancelled"))
            }
            _ = tokio::time::sleep(Duration::from_millis(timeout)) => {
                self.finish(&id, Err(fail(codes::DEADLINE_EXCEEDED, "Host interaction expired")));
                Err(fail(codes::DEADLINE_EXCEEDED, "Host interaction expired"))
            }
        }
    }

    /// `respond(sender, response)` → `true` / `false` (stale) / error.
    pub fn respond(&self, owner: &str, response: &Value) -> PluginResult<Value> {
        self.assert_window(Some(owner))?;
        if !contract::is_valid("HostInteractionResponse", response) {
            return Err(fail(codes::INVALID_ARGUMENT, "Host interaction response is invalid"));
        }
        let id = response["requestId"].as_str().unwrap_or("").to_string();
        let supplied = response["actionToken"].as_str().unwrap_or("");
        let (kind, phase, plugin_id, permission_mode, terminal, preview) = {
            let mut pending = self.pending.lock();
            let Some(entry) = pending.get_mut(&id) else { return Ok(json!(false)) };
            let expected = entry.action_token.clone().unwrap_or_default();
            if entry.owner != owner || expected.is_empty() || crate::constants::now_ms() >= entry.expires_at
                || expected.len() != supplied.len()
                || expected.bytes().zip(supplied.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0
            {
                return Ok(json!(false));
            }
            entry.action_token = None;
            (
                entry.params["kind"].as_str().unwrap_or("").to_string(),
                entry.phase.clone(),
                entry.plugin_id.clone(),
                entry.permission_mode.clone(),
                entry.terminal.clone(),
                entry.preview_text.clone(),
            )
        };
        let outcome = (|| -> PluginResult<Value> {
            if let Some(t) = &terminal {
                if !self.terminal_current(t) {
                    return Err(fail(codes::CANCELLED, "Selected terminal connection, renderer, source or owner changed"));
                }
            }
            let action = response["action"].as_str().unwrap_or("");
            if action == "cancel" {
                self.audit(&plugin_id, &kind, "cancelled")?;
                self.finish(&id, Ok(json!({ "cancelled": true })));
                return Ok(json!(true));
            }
            if kind == "terminal.selection.read" && phase == "request" {
                if action != "preview" {
                    return Err(fail(codes::INVALID_ARGUMENT, "Terminal sharing requires a preview action"));
                }
                let text = text_bytes(response["value"].as_str().unwrap_or(""))?;
                if text.is_empty() {
                    return Err(fail(codes::FAILED_PRECONDITION, "Select terminal text before requesting a share"));
                }
                self.audit(&plugin_id, &kind, "preview-confirmed")?;
                let (version, runtime) = {
                    let pending = self.pending.lock();
                    let e = pending.get(&id).ok_or_else(|| fail(codes::CANCELLED, "Host interaction was cancelled"))?;
                    (e.plugin_version.clone(), e.runtime_id.clone())
                };
                self.quota.charge_bytes(&runtime, "terminal", text.len() as u64)?;
                if permission_mode == "allow" {
                    self.audit(&plugin_id, &kind, "completed")?;
                    let mut value = self.issue_handle(terminal.as_ref().expect("terminal"), &version, &runtime)?;
                    value["text"] = json!(text);
                    self.finish(&id, Ok(json!({ "cancelled": false, "value": value })));
                    return Ok(json!(true));
                }
                if let Some(e) = self.pending.lock().get_mut(&id) {
                    e.preview_text = Some(text);
                    e.phase = "preview".into();
                }
                self.present(&id)?;
                return Ok(json!(true));
            }
            if action != "submit" {
                return Err(fail(codes::INVALID_ARGUMENT, "Host interaction action is invalid"));
            }
            let params = self.pending.lock().get(&id).map(|e| e.params.clone()).unwrap_or(Value::Null);
            let mut value = match kind.as_str() {
                "input" => {
                    if !contract::is_valid("HostSingleLineInputText", &response["value"]) {
                        return Err(fail(codes::INVALID_ARGUMENT, "Host input must be a single line"));
                    }
                    json!(text_bytes(response["value"].as_str().unwrap_or(""))?)
                }
                "quickPick" => {
                    let choice = response["value"].as_str().unwrap_or("");
                    if !params["items"].as_array().is_some_and(|items| items.iter().any(|i| i["id"] == choice)) {
                        return Err(fail(codes::INVALID_ARGUMENT, "Host interaction choice is invalid"));
                    }
                    json!(choice)
                }
                "terminal.selection.read" => {
                    if phase != "preview" || preview.is_none() {
                        return Err(fail(codes::FAILED_PRECONDITION, "Terminal selection was not previewed"));
                    }
                    Value::Null
                }
                "clipboard.read" => json!(preview.clone().unwrap_or_default()),
                _ => json!(true),
            };
            let action_name = match kind.as_str() {
                "terminal.input.propose" => "draft-reviewed",
                "clipboard.write" => "copy-confirmed",
                _ => "share-confirmed",
            };
            self.audit(&plugin_id, &kind, action_name)?;
            if kind == "terminal.selection.read" {
                let (version, runtime) = {
                    let pending = self.pending.lock();
                    let e = pending.get(&id).ok_or_else(|| fail(codes::CANCELLED, "Host interaction was cancelled"))?;
                    (e.plugin_version.clone(), e.runtime_id.clone())
                };
                value = self.issue_handle(terminal.as_ref().expect("terminal"), &version, &runtime)?;
                value["text"] = json!(preview.unwrap_or_default());
            }
            if kind == "clipboard.write" && !self.surface()?.write_clipboard(params["text"].as_str().unwrap_or("")) {
                return Err(fail(codes::UNAVAILABLE, "Host clipboard write failed"));
            }
            self.finish(&id, Ok(json!({ "cancelled": false, "value": value })));
            Ok(json!(true))
        })();
        match outcome {
            Ok(v) => Ok(v),
            Err(err) => {
                self.finish(&id, Err(err.clone()));
                Err(err)
            }
        }
    }

    pub fn release_window(&self, owner: &str) {
        let mut current = self.owner.lock();
        if current.as_deref() != Some(owner) {
            return;
        }
        *current = None;
        drop(current);
        if self.target.lock().as_ref().is_some_and(|t| t.0 == owner) {
            *self.target.lock() = None;
        }
        let ids: Vec<String> = self.pending.lock().iter().filter(|(_, p)| p.owner == owner).map(|(k, _)| k.clone()).collect();
        for id in ids {
            self.finish(&id, Err(fail(codes::CANCELLED, "Host interaction window closed")));
        }
    }

    pub fn release_plugin(&self, plugin_id: &str) {
        self.handles.lock().retain(|_, h| h.target.plugin_id != plugin_id);
        let ids: Vec<String> = self.pending.lock().iter().filter(|(_, p)| p.plugin_id == plugin_id).map(|(k, _)| k.clone()).collect();
        for id in ids {
            self.finish(&id, Err(fail(codes::CANCELLED, "Plugin access was revoked")));
        }
    }

    pub fn release_runtime(&self, runtime_id: &str) {
        self.handles.lock().retain(|_, h| h.runtime_id != runtime_id);
        self.cancel_runtime_requests(runtime_id, "Plugin runtime stopped");
        self.rates.lock().remove(runtime_id);
    }

    pub fn cancel_runtime_requests(&self, runtime_id: &str, reason: &str) {
        let ids: Vec<String> = self.pending.lock().iter().filter(|(_, p)| p.runtime_id == runtime_id).map(|(k, _)| k.clone()).collect();
        for id in ids {
            self.finish(&id, Err(fail(codes::CANCELLED, reason)));
        }
    }

    pub fn cancel_all(&self) {
        self.handles.lock().clear();
        let ids: Vec<String> = self.pending.lock().keys().cloned().collect();
        for id in ids {
            self.finish(&id, Err(fail(codes::CANCELLED, "Host interaction was cancelled")));
        }
    }

    pub fn shutdown(&self) {
        *self.closed.lock() = true;
        self.cancel_all();
        *self.owner.lock() = None;
    }

    pub fn register(self: &Arc<Self>, registry: &HostRpcRegistry) -> PluginResult<()> {
        let me = self.clone();
        let auth_me = self.clone();
        registry.register_request(
            "ui.interact",
            RegisterOptions {
                metadata: json!({ "capability": "ui", "mutating": true }),
                authorization: AuthorizationSpec::Dynamic(Arc::new(move |params: Value, ctx: Arc<CallContext>| {
                    let me = auth_me.clone();
                    Box::pin(async move { me.authorization(&params, &ctx).map(Some) })
                })),
                validate: Some(Arc::new(assert_interaction_request)),
            },
            move |params, ctx| {
                let me = me.clone();
                async move { me.request(params, ctx).await }
            },
        )
    }
}
