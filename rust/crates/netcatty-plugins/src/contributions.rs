//! UI contributions, settings, commands, views and environment (port of
//! `electron/plugins/contributionService.cjs`).

use crate::context_keys::{assert_plugin_context_key, evaluate_expression};
use crate::contract;
use crate::database::{PluginDatabase, PluginRecord};
use crate::error::{codes, PluginError, PluginResult};
use crate::package::manifest::{pattern_matches, restricted_schema_accepts, setting_pattern_error};
use crate::registry::{static_auth, HostRpcRegistry, RegisterOptions, RuntimeIdentity};
use crate::secrets::PluginSecretStore;
use crate::supervisor::RuntimeSupervisor;
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub const MAX_SETTING_BYTES: usize = 128 * 1024;
const MAX_PATTERN_VALUE_LENGTH: usize = 4096;
const SETTINGS_SCOPES: &[&str] = &["application", "workspace", "host", "session", "device"];

fn invalid(message: impl Into<String>) -> PluginError {
    PluginError::invalid(message)
}

pub fn assert_json_value(value: &Value, label: &str) -> PluginResult<()> {
    contract::assert_json_value(value, MAX_SETTING_BYTES)
        .map_err(|e| invalid(format!("Plugin {label} must be a bounded JSON value: {}", e.message())))
}

/// `resolveLocalizedText`.
pub fn localize(value: Option<&Value>, locale: &str) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(map)) => {
            let base = locale.split('-').next().unwrap_or(locale);
            [locale, base, "en", "default"]
                .iter()
                .find_map(|k| map.get(*k).and_then(Value::as_str))
                .or_else(|| map.values().next().and_then(Value::as_str))
                .unwrap_or("")
                .to_string()
        }
        _ => String::new(),
    }
}

/// `normalizeScopeId`.
pub fn normalize_scope_id(scope: &str, scope_id: Option<&str>) -> PluginResult<String> {
    if !SETTINGS_SCOPES.contains(&scope) {
        return Err(invalid("Plugin setting scope is invalid"));
    }
    if scope == "application" {
        return Ok("application".into());
    }
    let value = match (scope, scope_id) {
        ("device", None) => "device",
        (_, Some(v)) => v,
        _ => "",
    };
    let len = value.encode_utf16().count();
    if !(1..=256).contains(&len) || value.contains('\0') {
        return Err(invalid(format!("Plugin {scope} setting requires a valid scope ID")));
    }
    Ok(value.to_string())
}

/// `secretSettingKey`.
pub fn secret_setting_key(setting_id: &str, scope: &str, scope_id: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!("{scope}\0{scope_id}").as_bytes()));
    format!("setting:{setting_id}:{}", &digest[..32])
}

fn contributions<'a>(manifest: &'a Value, kind: &str) -> &'a [Value] {
    manifest
        .get("contributes")
        .and_then(|c| c.get(kind))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn get_contribution<'a>(manifest: &'a Value, kind: &str, id: &str) -> Option<&'a Value> {
    contributions(manifest, kind)
        .iter()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(id) || item.get("command").and_then(Value::as_str) == Some(id))
}

/// `assertSettingValue`.
pub fn assert_setting_value(setting: &Value, value: &Value) -> PluginResult<()> {
    assert_json_value(value, "setting value")?;
    let id = setting["id"].as_str().unwrap_or("");
    let options: Vec<&str> = setting.get("options").and_then(Value::as_array).map(|o| o.iter().filter_map(|x| x["value"].as_str()).collect()).unwrap_or_default();
    match setting["control"].as_str().unwrap_or("") {
        "switch" => {
            if !value.is_boolean() {
                return Err(invalid(format!("{id} must be a boolean")));
            }
        }
        "radio" | "select" => {
            if !value.as_str().is_some_and(|v| options.is_empty() || options.contains(&v)) {
                return Err(invalid(format!("{id} must use a declared option")));
            }
        }
        "multiselect" => {
            let ok = value.as_array().is_some_and(|items| {
                let unique: std::collections::HashSet<&Value> = items.iter().collect();
                unique.len() == items.len() && items.iter().all(|i| i.as_str().is_some_and(|v| options.is_empty() || options.contains(&v)))
            });
            if !ok {
                return Err(invalid(format!("{id} must be a unique list of declared options")));
            }
        }
        "number" | "slider" => {
            let number = value.as_f64().filter(|f| f.is_finite()).ok_or_else(|| invalid(format!("{id} must be finite")))?;
            if setting["minimum"].as_f64().is_some_and(|m| number < m) {
                return Err(invalid(format!("{id} is below its minimum")));
            }
            if setting["maximum"].as_f64().is_some_and(|m| number > m) {
                return Err(invalid(format!("{id} is above its maximum")));
            }
            if let Some(step) = setting["step"].as_f64() {
                let steps = (number - setting["minimum"].as_f64().unwrap_or(0.0)) / step;
                let tolerance = f64::EPSILON * steps.abs().max(1.0) * 16.0;
                if (steps - steps.round()).abs() > tolerance {
                    return Err(invalid(format!("{id} does not align to its step")));
                }
            }
        }
        "list" | "table" => {
            if !value.is_array() {
                return Err(invalid(format!("{id} must be an array")));
            }
            let schema = setting.get("valueSchema").cloned().unwrap_or(Value::Null);
            if !crate::package::manifest::restricted_setting_schema_errors(&schema, Some("array")).is_empty()
                || !restricted_schema_accepts(&schema, value)?
            {
                return Err(invalid(format!("{id} does not match its value schema")));
            }
        }
        _ => {
            let text = value.as_str().ok_or_else(|| invalid(format!("{id} must be a string")))?;
            if let Some(pattern) = setting["pattern"].as_str() {
                if text.encode_utf16().count() > MAX_PATTERN_VALUE_LENGTH {
                    return Err(invalid(format!("{id} exceeds the patterned text limit")));
                }
                if setting_pattern_error(pattern).is_some() {
                    return Err(invalid(format!("{id} has an unsafe pattern")));
                }
                if !pattern_matches(pattern, text) {
                    return Err(invalid(format!("{id} does not match its pattern")));
                }
            }
        }
    }
    Ok(())
}

fn platform_keybinding(keybinding: &Value) -> Option<Value> {
    let key = if cfg!(target_os = "macos") {
        keybinding.get("mac")
    } else if cfg!(windows) {
        keybinding.get("windows")
    } else {
        keybinding.get("linux")
    };
    key.or_else(|| keybinding.get("key")).cloned()
}

pub fn is_contribution_available(plugin: &PluginRecord) -> bool {
    plugin.enabled && plugin.manifest.is_some() && plugin.runtime.quarantined_at.is_none()
}

fn activates_on_startup(manifest: &Value) -> bool {
    manifest
        .get("activationEvents")
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|e| e == "onStartupFinished"))
}

/// Contribution change event (`netcatty:plugins:contributions-changed`).
pub type ChangeListener = Arc<dyn Fn(&Value) + Send + Sync>;
/// `views.postMessage` from a plugin (`{ pluginId, viewId, message }`).
pub type ViewMessageListener = Arc<dyn Fn(&Value) + Send + Sync>;

pub struct ContributionService {
    database: Arc<PluginDatabase>,
    secrets: Arc<PluginSecretStore>,
    pub supervisor: Arc<RuntimeSupervisor>,
    context_keys: Mutex<Map<String, Value>>,
    context_key_owners: Mutex<HashMap<String, String>>,
    listeners: Mutex<Vec<ChangeListener>>,
    view_listeners: Mutex<Vec<ViewMessageListener>>,
    environment: Mutex<Option<Value>>,
    environment_revision: Mutex<u64>,
    environment_seeded: Mutex<HashMap<String, (String, u64)>>,
    pub locale: Mutex<String>,
    pub on_command_finished: Mutex<Option<Arc<dyn Fn(&str) + Send + Sync>>>,
    active_commands: Mutex<HashMap<String, usize>>,
    initialized: Mutex<bool>,
}

impl ContributionService {
    pub fn new(database: Arc<PluginDatabase>, secrets: Arc<PluginSecretStore>, supervisor: Arc<RuntimeSupervisor>) -> Arc<Self> {
        Arc::new(Self {
            database,
            secrets,
            supervisor,
            context_keys: Mutex::new(Map::new()),
            context_key_owners: Mutex::new(HashMap::new()),
            listeners: Mutex::new(Vec::new()),
            view_listeners: Mutex::new(Vec::new()),
            environment: Mutex::new(None),
            environment_revision: Mutex::new(0),
            environment_seeded: Mutex::new(HashMap::new()),
            locale: Mutex::new("en".into()),
            on_command_finished: Mutex::new(None),
            active_commands: Mutex::new(HashMap::new()),
            initialized: Mutex::new(false),
        })
    }

    pub fn on_did_change(&self, listener: ChangeListener) {
        self.listeners.lock().push(listener);
    }

    pub fn on_did_post_view_message(&self, listener: ViewMessageListener) {
        self.view_listeners.lock().push(listener);
    }

    pub fn emit_change(&self, reason: &str, plugin_id: Option<&str>) {
        let event = json!({ "reason": reason, "pluginId": plugin_id, "revision": crate::constants::now_ms() });
        let listeners = self.listeners.lock().clone();
        for l in listeners {
            l(&event);
        }
    }

    pub fn get_environment(&self) -> Option<Value> {
        self.environment.lock().clone()
    }

    pub fn register_rpc_capabilities(self: &Arc<Self>, registry: &HostRpcRegistry) -> PluginResult<()> {
        let me = self.clone();
        registry.register_request(
            "settings.get",
            RegisterOptions::new(json!({ "capability": "settings", "mutating": false, "permission": "settings.read" }), static_auth("settings.read", "Read plugin settings")),
            move |params, ctx| {
                let me = me.clone();
                async move {
                    let value = me.get_setting(ctx.plugin_id(), params["settingId"].as_str().unwrap_or(""), params["scopeId"].as_str())?;
                    Ok(match value {
                        Some(v) => json!({ "found": true, "value": v }),
                        None => json!({ "found": false }),
                    })
                }
            },
        )?;
        let me = self.clone();
        registry.register_request(
            "settings.update",
            RegisterOptions::new(json!({ "capability": "settings", "mutating": true, "permission": "settings.write" }), static_auth("settings.write", "Update plugin settings")),
            move |params, ctx| {
                let me = me.clone();
                async move {
                    me.update_setting(ctx.plugin_id(), params["settingId"].as_str().unwrap_or(""), &params["value"], params["scopeId"].as_str(), "plugin")
                        .await
                }
            },
        )?;
        let me = self.clone();
        registry.register_request(
            "commands.execute",
            RegisterOptions::new(json!({ "capability": "commands", "mutating": true, "permission": "commands" }), static_auth("commands", "Execute a plugin command")),
            move |params, ctx| {
                let me = me.clone();
                async move {
                    me.execute_command(
                        params["command"].as_str().unwrap_or(""),
                        params.get("args").cloned(),
                        "plugin",
                        None,
                        Some(ctx.plugin_id().to_string()),
                    )
                    .await
                }
            },
        )?;
        let me = self.clone();
        registry.register_request(
            "contextKeys.set",
            RegisterOptions::public(json!({ "capability": "contextKeys", "mutating": true })),
            move |params, ctx| {
                let me = me.clone();
                async move {
                    let key = assert_plugin_context_key(ctx.plugin_id(), params["key"].as_str().unwrap_or(""))?;
                    let value = params.get("value").cloned().unwrap_or(Value::Null);
                    assert_json_value(&value, "Context Key value")?;
                    {
                        let mut owners = me.context_key_owners.lock();
                        if owners.get(&key).is_some_and(|o| o != ctx.plugin_id()) {
                            return Err(invalid("Plugin Context Key is owned by another plugin"));
                        }
                        owners.insert(key.clone(), ctx.plugin_id().to_string());
                    }
                    me.context_keys.lock().insert(key, value);
                    me.emit_change("context-key", Some(ctx.plugin_id()));
                    Ok(Value::Null)
                }
            },
        )?;
        let me = self.clone();
        registry.register_request(
            "views.getState",
            RegisterOptions::new(json!({ "capability": "views", "mutating": false, "permission": "views" }), static_auth("views", "Restore plugin view state")),
            move |params, ctx| {
                let me = me.clone();
                async move {
                    let view = owned_contribution(&ctx.identity.manifest, "views", params["viewId"].as_str().unwrap_or(""), ctx.plugin_id())?;
                    let scope = normalize_scope_id("session", params["scopeId"].as_str())?;
                    Ok(json!({ "state": me.database.get_view_state(ctx.plugin_id(), view["id"].as_str().unwrap_or(""), &scope)? }))
                }
            },
        )?;
        let me = self.clone();
        registry.register_request(
            "views.setState",
            RegisterOptions::new(json!({ "capability": "views", "mutating": true, "permission": "views" }), static_auth("views", "Persist plugin view state")),
            move |params, ctx| {
                let me = me.clone();
                async move {
                    let view = owned_contribution(&ctx.identity.manifest, "views", params["viewId"].as_str().unwrap_or(""), ctx.plugin_id())?;
                    let scope = normalize_scope_id("session", params["scopeId"].as_str())?;
                    let state = params.get("state").cloned().unwrap_or(Value::Null);
                    assert_json_value(&state, "view state")?;
                    me.database.set_view_state(ctx.plugin_id(), view["id"].as_str().unwrap_or(""), &scope, &state)?;
                    Ok(Value::Null)
                }
            },
        )?;
        let me = self.clone();
        registry.register_notification(
            "views.postMessage",
            RegisterOptions::new(json!({ "capability": "views", "mutating": true, "permission": "views" }), static_auth("views", "Message a plugin view")),
            move |params, ctx| {
                let me = me.clone();
                async move {
                    let view = owned_contribution(&ctx.identity.manifest, "views", params["viewId"].as_str().unwrap_or(""), ctx.plugin_id())?;
                    let message = params.get("message").cloned().unwrap_or(Value::Null);
                    assert_json_value(&message, "view message")?;
                    let event = json!({ "pluginId": ctx.plugin_id(), "viewId": view["id"], "message": message });
                    let listeners = me.view_listeners.lock().clone();
                    for l in listeners {
                        l(&event);
                    }
                    Ok(Value::Null)
                }
            },
        )?;
        Ok(())
    }

    /// Start plugins that declare `onStartupFinished`.
    pub async fn initialize(&self) {
        {
            let mut initialized = self.initialized.lock();
            if *initialized {
                return;
            }
            *initialized = true;
        }
        for plugin in self.database.list_plugins().unwrap_or_default() {
            if !plugin.enabled || plugin.runtime.quarantined_at.is_some() || !plugin.manifest.as_ref().is_some_and(activates_on_startup) {
                continue;
            }
            let _ = self.start_plugin(&plugin.id).await;
        }
        self.emit_change("initialized", None);
    }

    pub async fn on_plugin_enabled(&self, plugin_id: &str) -> PluginResult<PluginRecord> {
        let plugin = self
            .database
            .get_active_plugin(plugin_id)?
            .filter(|p| p.enabled)
            .ok_or_else(|| PluginError::not_found(format!("Plugin is not enabled: {plugin_id}")))?;
        if plugin.manifest.as_ref().is_some_and(activates_on_startup) {
            self.start_plugin(plugin_id).await?;
        }
        self.emit_change("plugin-enabled", Some(plugin_id));
        Ok(plugin)
    }

    pub fn on_plugin_disabled(&self, plugin_id: &str) {
        self.clear_runtime_owned_state(plugin_id);
        self.emit_change("plugin-disabled", Some(plugin_id));
    }

    pub fn on_runtime_state_changed(&self, plugin_id: &str, status: &str) {
        if !matches!(status, "stopped" | "error" | "quarantined") {
            return;
        }
        self.clear_runtime_owned_state(plugin_id);
        self.emit_change(&format!("runtime-{status}"), Some(plugin_id));
    }

    fn clear_runtime_owned_state(&self, plugin_id: &str) {
        self.environment_seeded.lock().remove(plugin_id);
        let mut owners = self.context_key_owners.lock();
        let keys: Vec<String> = owners.iter().filter(|(_, o)| *o == plugin_id).map(|(k, _)| k.clone()).collect();
        let mut context = self.context_keys.lock();
        for key in keys {
            owners.remove(&key);
            context.remove(&key);
        }
    }

    fn find_contribution(&self, kind: &str, id: &str) -> PluginResult<(PluginRecord, Value)> {
        if id.is_empty() {
            return Err(invalid(format!("Plugin {kind} ID is required")));
        }
        for plugin in self.database.list_plugins()? {
            if !is_contribution_available(&plugin) {
                continue;
            }
            if let Some(found) = plugin.manifest.as_ref().and_then(|m| get_contribution(m, kind, id)).cloned() {
                return Ok((plugin, found));
            }
        }
        Err(PluginError::not_found(format!("Plugin {kind} contribution was not found: {id}")))
    }

    async fn start_plugin(&self, plugin_id: &str) -> PluginResult<Arc<RuntimeIdentity>> {
        let identity = self.supervisor.start(plugin_id).await?;
        let environment = self.environment.lock().clone();
        let Some(environment) = environment else { return Ok(identity) };
        let revision = *self.environment_revision.lock();
        if self.environment_seeded.lock().get(plugin_id).is_some_and(|(rid, rev)| rid == &identity.runtime_id && *rev == revision) {
            return Ok(identity);
        }
        self.supervisor.notify(plugin_id, "plugin.environment.changed", environment, None).await?;
        self.environment_seeded.lock().insert(plugin_id.to_string(), (identity.runtime_id.clone(), revision));
        Ok(identity)
    }

    async fn ensure_activated(&self, plugin: &PluginRecord, event: &str) -> PluginResult<Arc<RuntimeIdentity>> {
        let declared = plugin
            .manifest
            .as_ref()
            .and_then(|m| m.get("activationEvents"))
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|e| e == event || e == "onStartupFinished"));
        let contribution_event = event.starts_with("onCommand:") || event.starts_with("onView:") || event.starts_with("onProvider:");
        if !declared && !contribution_event {
            return Err(PluginError::precondition(format!("Plugin activation event is not declared: {event}")));
        }
        self.start_plugin(&plugin.id).await
    }

    fn context(&self, extra: Option<&Value>) -> Map<String, Value> {
        let mut map = extra.and_then(Value::as_object).cloned().unwrap_or_default();
        for (k, v) in self.context_keys.lock().iter() {
            map.insert(k.clone(), v.clone());
        }
        map
    }

    /// `executeCommand(commandId, args, invocation)`.
    pub async fn execute_command(
        &self,
        command_id: &str,
        args: Option<Value>,
        source: &str,
        context: Option<Value>,
        caller_plugin_id: Option<String>,
    ) -> PluginResult<Value> {
        let (plugin, contribution) = self.find_contribution("commands", command_id)?;
        if caller_plugin_id.as_ref().is_some_and(|c| c != &plugin.id) {
            return Err(PluginError::denied("Plugins may execute only their own declared commands"));
        }
        let keys = self.context(context.as_ref());
        if !evaluate_expression(contribution.get("enablement"), &keys) {
            return Err(PluginError::precondition(format!("Plugin command is disabled: {command_id}")));
        }
        assert_json_value(args.as_ref().unwrap_or(&Value::Null), "command arguments")?;
        let interactive = contribution.get("interactive").and_then(Value::as_bool) == Some(true);
        let interactive_feature = contract::def_const_str("InteractiveCommandFeature");
        if interactive
            && !plugin
                .manifest
                .as_ref()
                .and_then(|m| m["features"]["required"].as_array())
                .is_some_and(|r| r.iter().any(|f| f == interactive_feature))
        {
            return Err(PluginError::precondition("Interactive command feature is required"));
        }
        let identity = self.ensure_activated(&plugin, &format!("onCommand:{command_id}")).await?;
        let runtime_id = identity.runtime_id.clone();
        *self.active_commands.lock().entry(runtime_id.clone()).or_insert(0) += 1;
        let mut params = json!({ "command": command_id, "invocation": { "source": source, "context": context.unwrap_or_else(|| json!({})) } });
        if let Some(args) = args {
            params["args"] = args;
        }
        let timeout = interactive.then(|| {
            Duration::from_millis(contract::def_const("InteractiveCommandLimits").and_then(|l| l["timeoutMs"].as_u64()).unwrap_or(300_000))
        });
        let result = self
            .supervisor
            .request(&plugin.id, "plugin.command.execute", params, Some(&identity), timeout, None)
            .await;
        let remaining = {
            let mut active = self.active_commands.lock();
            let count = active.get(&runtime_id).copied().unwrap_or(1).saturating_sub(1);
            if count == 0 {
                active.remove(&runtime_id);
            } else {
                active.insert(runtime_id.clone(), count);
            }
            count
        };
        if result.is_err() || remaining == 0 {
            let callback = self.on_command_finished.lock().clone();
            if let Some(cb) = callback {
                cb(&runtime_id);
            }
        }
        result
    }

    /// `activateView(viewId, { context })`.
    pub async fn activate_view(&self, view_id: &str, context: Option<&Value>) -> PluginResult<(PluginRecord, Value, Arc<RuntimeIdentity>)> {
        let (plugin, contribution) = self.find_contribution("views", view_id)?;
        if !evaluate_expression(contribution.get("when"), &self.context(context)) {
            return Err(PluginError::precondition(format!("Plugin view is unavailable: {view_id}")));
        }
        let identity = self.ensure_activated(&plugin, &format!("onView:{view_id}")).await?;
        Ok((plugin, contribution, identity))
    }

    /// `assertViewActivationCurrent`.
    pub fn assert_view_activation_current(&self, plugin_id: &str, version: &str, view_id: &str, runtime_id: &str, context: Option<&Value>) -> PluginResult<PluginRecord> {
        let (plugin, contribution) = self.find_contribution("views", view_id)?;
        if plugin.id != plugin_id || plugin.active_version.as_deref() != Some(version) {
            return Err(PluginError::precondition("Plugin view ownership changed while opening"));
        }
        if !evaluate_expression(contribution.get("when"), &self.context(context)) {
            return Err(PluginError::precondition(format!("Plugin view is unavailable: {view_id}")));
        }
        let identity = self.supervisor.get_runtime_identity(&plugin.id);
        if !identity.is_some_and(|i| i.runtime_id == runtime_id && i.plugin_version == version) {
            return Err(PluginError::precondition("Plugin view runtime ownership changed while opening"));
        }
        Ok(plugin)
    }

    /// `activateProvider(providerId)`.
    pub async fn activate_provider(&self, provider_id: &str) -> PluginResult<(PluginRecord, Value, Arc<RuntimeIdentity>)> {
        let (plugin, contribution) = self.find_contribution("providers", provider_id)?;
        let identity = self.ensure_activated(&plugin, &format!("onProvider:{provider_id}")).await?;
        Ok((plugin, contribution, identity))
    }

    /// `listProviders({ kind, locale })`.
    pub fn list_providers(&self, kind: Option<&str>, locale: Option<&str>) -> PluginResult<Vec<Value>> {
        let locale = locale.map(str::to_string).unwrap_or_else(|| self.locale.lock().clone());
        let mut out = Vec::new();
        for plugin in self.database.list_plugins()? {
            if !is_contribution_available(&plugin) {
                continue;
            }
            let manifest = plugin.manifest.as_ref().expect("available");
            for provider in contributions(manifest, "providers") {
                if kind.is_some_and(|k| provider["kind"].as_str() != Some(k)) {
                    continue;
                }
                let mut provider = provider.clone();
                provider["label"] = json!(localize(provider.get("label"), &locale));
                if provider.get("description").is_some() {
                    provider["description"] = json!(localize(provider.get("description"), &locale));
                }
                out.push(json!({
                    "pluginId": plugin.id,
                    "pluginVersion": plugin.active_version,
                    "pluginDisplayName": localize(manifest.get("displayName").or(manifest.get("name")), &locale),
                    "provider": provider,
                }));
            }
        }
        Ok(out)
    }

    fn setting_record(&self, plugin_id: &str, setting_id: &str) -> PluginResult<(PluginRecord, Value)> {
        let plugin = self
            .database
            .get_active_plugin(plugin_id)?
            .filter(is_contribution_available)
            .ok_or_else(|| PluginError::not_found(format!("Plugin is not enabled: {plugin_id}")))?;
        let setting = owned_contribution(plugin.manifest.as_ref().expect("available"), "settings", setting_id, plugin_id)?;
        Ok((plugin, setting))
    }

    pub fn get_setting(&self, plugin_id: &str, setting_id: &str, scope_id: Option<&str>) -> PluginResult<Option<Value>> {
        let (_, setting) = self.setting_record(plugin_id, setting_id)?;
        let scope = setting["scope"].as_str().unwrap_or("application");
        let scope_id = normalize_scope_id(scope, scope_id)?;
        let id = setting["id"].as_str().unwrap_or("");
        if setting["secret"].as_bool() == Some(true) {
            return self.secrets.get_reference(plugin_id, &secret_setting_key(id, scope, &scope_id));
        }
        Ok(self.database.get_setting(plugin_id, id, scope, &scope_id)?.or_else(|| setting.get("default").cloned()))
    }

    pub async fn update_setting(&self, plugin_id: &str, setting_id: &str, value: &Value, scope_id: Option<&str>, source: &str) -> PluginResult<Value> {
        let (_, setting) = self.setting_record(plugin_id, setting_id)?;
        let scope = setting["scope"].as_str().unwrap_or("application").to_string();
        let scope_id = normalize_scope_id(&scope, scope_id)?;
        assert_setting_value(&setting, value)?;
        let id = setting["id"].as_str().unwrap_or("").to_string();
        if setting["secret"].as_bool() == Some(true) {
            self.secrets.set(plugin_id, &secret_setting_key(&id, &scope, &scope_id), value.as_str().unwrap_or(""), false)?;
        } else {
            self.database.set_setting(plugin_id, &id, &scope, &scope_id, value, None)?;
        }
        self.emit_change("setting-updated", Some(plugin_id));
        let _ = self
            .supervisor
            .notify(plugin_id, "plugin.settings.changed", json!({ "settingId": id, "scope": scope, "scopeId": scope_id, "source": source }), None)
            .await;
        Ok(json!({ "restartRequired": setting["restartRequired"].as_bool() == Some(true) }))
    }

    pub async fn reset_setting(&self, plugin_id: &str, setting_id: &str, scope_id: Option<&str>) -> PluginResult<Value> {
        let (_, setting) = self.setting_record(plugin_id, setting_id)?;
        if setting["required"].as_bool() == Some(true) && setting.get("default").is_none() {
            return Err(invalid(format!("{setting_id} is required")));
        }
        let scope = setting["scope"].as_str().unwrap_or("application").to_string();
        let scope_id = normalize_scope_id(&scope, scope_id)?;
        let id = setting["id"].as_str().unwrap_or("").to_string();
        if setting["secret"].as_bool() == Some(true) {
            self.secrets.delete(plugin_id, &secret_setting_key(&id, &scope, &scope_id))?;
        } else {
            self.database.delete_setting(plugin_id, &id, &scope, &scope_id)?;
            let _ = self.database.delete_sync_sidecar(plugin_id, "settings", &format!("{id}\0{scope}\0{scope_id}"));
        }
        self.emit_change("setting-reset", Some(plugin_id));
        let _ = self
            .supervisor
            .notify(plugin_id, "plugin.settings.changed", json!({ "settingId": id, "scope": scope, "scopeId": scope_id, "source": "host" }), None)
            .await;
        Ok(json!({ "restartRequired": setting["restartRequired"].as_bool() == Some(true) }))
    }

    /// `snapshot({ locale, context, menuContexts, scopeIds, platform })`.
    pub fn snapshot(&self, options: &Value) -> PluginResult<Value> {
        let locale = options["locale"].as_str().map(str::to_string).unwrap_or_else(|| self.locale.lock().clone());
        let context = self.context(options.get("context"));
        let mut plugins = Vec::new();
        for plugin in self.database.list_plugins()? {
            if !is_contribution_available(&plugin) {
                continue;
            }
            let manifest = plugin.manifest.as_ref().expect("available");
            let l = |v: Option<&Value>| localize(v, &locale);
            let commands: Vec<Value> = contributions(manifest, "commands")
                .iter()
                .map(|c| {
                    let mut c = c.clone();
                    c["title"] = json!(l(c.get("title")));
                    for key in ["category", "description"] {
                        if c.get(key).is_some() {
                            c[key] = json!(l(c.get(key)));
                        }
                    }
                    c["enabled"] = json!(evaluate_expression(c.get("enablement"), &context));
                    c
                })
                .collect();
            let command_by_id: HashMap<String, Value> = commands.iter().map(|c| (c["id"].as_str().unwrap_or("").to_string(), c.clone())).collect();
            let keybindings: Vec<Value> = contributions(manifest, "keybindings")
                .iter()
                .map(|k| {
                    let mut k = k.clone();
                    let command_enabled = command_by_id.get(k["command"].as_str().unwrap_or("")).map(|c| c["enabled"] != json!(false)).unwrap_or(true);
                    k["enabled"] = json!(evaluate_expression(k.get("when"), &context) && command_enabled);
                    k
                })
                .collect();
            let mut keybinding_by_command: HashMap<String, Value> = HashMap::new();
            for k in &keybindings {
                if k["enabled"] == json!(true) {
                    keybinding_by_command.entry(k["command"].as_str().unwrap_or("").to_string()).or_insert_with(|| k.clone());
                }
            }
            let menus: Vec<Value> = contributions(manifest, "menus")
                .iter()
                .enumerate()
                .map(|(index, m)| {
                    let location = m["location"].as_str().unwrap_or("");
                    let menu_context = self.context(options.get("menuContexts").and_then(|mc| mc.get(location)).or(options.get("context")));
                    let command = command_by_id.get(m["command"].as_str().unwrap_or(""));
                    let mut menu = m.clone();
                    menu["id"] = json!(format!("{}:menu:{index}", plugin.id));
                    menu["title"] = if m.get("title").is_some() {
                        json!(l(m.get("title")))
                    } else {
                        command.map(|c| c["title"].clone()).unwrap_or_else(|| m["command"].clone())
                    };
                    menu["visible"] = json!(evaluate_expression(m.get("when"), &menu_context));
                    menu["enabled"] = json!(
                        evaluate_expression(m.get("enablement"), &menu_context)
                            && evaluate_expression(command.and_then(|c| c.get("enablement")), &menu_context)
                    );
                    if m.get("checked").is_some() {
                        menu["checked"] = json!(evaluate_expression(m.get("checked"), &menu_context));
                    }
                    if m["showKeybinding"] != json!(false) {
                        if let Some(shortcut) = keybinding_by_command.get(m["command"].as_str().unwrap_or("")).and_then(platform_keybinding) {
                            menu["shortcut"] = shortcut;
                        }
                    }
                    menu
                })
                .collect();
            let settings: Vec<Value> = contributions(manifest, "settings")
                .iter()
                .map(|s| {
                    let scope = s["scope"].as_str().unwrap_or("application");
                    let requested = options.get("scopeIds").and_then(|ids| ids.get(scope)).and_then(Value::as_str);
                    let scope_id = match scope {
                        "application" => Some("application".to_string()),
                        "device" => Some(requested.unwrap_or("device").to_string()),
                        _ => requested.map(str::to_string),
                    };
                    let id = s["id"].as_str().unwrap_or("");
                    let secret = s["secret"].as_bool() == Some(true);
                    let stored = scope_id.as_ref().and_then(|sid| {
                        if secret {
                            self.secrets.get_reference(&plugin.id, &secret_setting_key(id, scope, sid)).ok().flatten()
                        } else {
                            self.database.get_setting(&plugin.id, id, scope, sid).ok().flatten()
                        }
                    });
                    let mut out = s.clone();
                    out["label"] = json!(l(s.get("label")));
                    for key in ["group", "description", "placeholder"] {
                        if s.get(key).is_some() {
                            out[key] = json!(l(s.get(key)));
                        }
                    }
                    if let Some(options) = s.get("options").and_then(Value::as_array) {
                        out["options"] = Value::Array(
                            options
                                .iter()
                                .map(|o| {
                                    let mut o = o.clone();
                                    o["label"] = json!(l(o.get("label")));
                                    if o.get("description").is_some() {
                                        o["description"] = json!(l(o.get("description")));
                                    }
                                    o
                                })
                                .collect(),
                        );
                    }
                    out["visible"] = json!(evaluate_expression(s.get("when"), &context));
                    out["configured"] = json!(stored.as_ref().is_some_and(|v| !v.is_null()));
                    if secret {
                        out.as_object_mut().map(|o| o.remove("value"));
                    } else {
                        out["value"] = stored.or_else(|| s.get("default").cloned()).unwrap_or(Value::Null);
                    }
                    out["scopeId"] = json!(scope_id);
                    out
                })
                .collect();
            let views: Vec<Value> = contributions(manifest, "views")
                .iter()
                .map(|v| {
                    let mut v = v.clone();
                    v["title"] = json!(l(v.get("title")));
                    v["visible"] = json!(evaluate_expression(v.get("when"), &context));
                    v
                })
                .collect();
            plugins.push(json!({
                "id": plugin.id,
                "version": plugin.active_version,
                "displayName": l(manifest.get("displayName").or(manifest.get("name"))),
                "description": l(manifest.get("description")),
                "commands": commands,
                "keybindings": keybindings,
                "menus": menus,
                "settings": settings,
                "views": views,
            }));
        }
        Ok(json!({ "locale": locale, "plugins": plugins }))
    }

    /// `setEnvironment(environment)`: broadcast to running plugins.
    pub async fn set_environment(&self, environment: Value) -> PluginResult<()> {
        assert_json_value(&environment, "environment")?;
        *self.environment.lock() = Some(environment.clone());
        let revision = {
            let mut r = self.environment_revision.lock();
            *r += 1;
            *r
        };
        for plugin in self.database.list_plugins()? {
            if !plugin.enabled || plugin.runtime.status != "running" {
                continue;
            }
            if self.supervisor.notify(&plugin.id, "plugin.environment.changed", environment.clone(), None).await.is_ok() {
                if let Some(identity) = self.supervisor.get_runtime_identity(&plugin.id) {
                    self.environment_seeded.lock().insert(plugin.id.clone(), (identity.runtime_id.clone(), revision));
                }
            }
        }
        self.emit_change("environment", None);
        Ok(())
    }
}

/// `#assertOwnedContribution`.
pub fn owned_contribution(manifest: &Value, kind: &str, id: &str, plugin_id: &str) -> PluginResult<Value> {
    if !id.starts_with(&format!("{plugin_id}.")) {
        return Err(PluginError::rpc(codes::INVALID_ARGUMENT, format!("Plugin {kind} ID is invalid")));
    }
    get_contribution(manifest, kind, id)
        .cloned()
        .ok_or_else(|| PluginError::not_found(format!("Plugin {kind} contribution was not found: {id}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setting_values() {
        let text = json!({ "id": "a.b.c", "control": "text", "pattern": "^[a-z]+$" });
        assert!(assert_setting_value(&text, &json!("abc")).is_ok());
        assert!(assert_setting_value(&text, &json!("ABC")).is_err());
        let num = json!({ "id": "a.b.n", "control": "slider", "minimum": 0, "maximum": 10, "step": 0.5 });
        assert!(assert_setting_value(&num, &json!(2.5)).is_ok());
        assert!(assert_setting_value(&num, &json!(2.25)).is_err());
        assert!(assert_setting_value(&num, &json!(11)).is_err());
        let select = json!({ "id": "a.b.s", "control": "select", "options": [{ "value": "x" }] });
        assert!(assert_setting_value(&select, &json!("y")).is_err());
        assert_eq!(normalize_scope_id("application", Some("zzz")).unwrap(), "application");
        assert_eq!(normalize_scope_id("device", None).unwrap(), "device");
        assert!(normalize_scope_id("host", None).is_err());
        assert_eq!(secret_setting_key("x", "application", "application").len(), "setting:x:".len() + 32);
        assert_eq!(localize(Some(&json!({ "en": "Hi", "zh-CN": "你好" })), "zh-CN"), "你好");
        assert_eq!(localize(Some(&json!({ "en": "Hi" })), "fr"), "Hi");
    }
}
