//! Terminal and extension Providers (ports of
//! `terminalProviderService.cjs` and `extensionProviderService.cjs`).
//!
//! * Terminal Providers (completion, decoration, link, hover, matcher,
//!   semantic, prompt, background, theme): permission-checked
//!   `provider.invoke` fan-out with deadlines, result validation and
//!   lifecycle (`plugin.terminal.event`) delivery to authorized plugins.
//! * Extension Providers: `connection` (byte-stream sessions), `authentication`
//!   (challenge loop with one-use secret leases), `importer` (streamed input,
//!   JSONL output) and `sync` (inline or streamed encrypted objects).
//!
//! Result validation keeps the contract schema checks plus the security
//! relevant per-kind checks (visible text, colors, link schemes, ranges);
//! purely cosmetic bounds that the renderer re-checks are not duplicated.

use crate::capabilities::{LeaseCredential, SecretLeaseStore};
use crate::contract;
use crate::contributions::ContributionService;
use crate::error::{codes, PluginError, PluginResult};
use crate::permissions::{AuthContext, AuthorizationRequest, PermissionEngine};
use crate::registry::{HostRpcRegistry, RuntimeIdentity};
use crate::rpc::{IncomingHandlers, IncomingStream, OutgoingStream, StreamChunk};
use crate::supervisor::RuntimeSupervisor;
use base64::Engine;
use futures::future::BoxFuture;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
pub const MAX_PROVIDER_JSON_BYTES: usize = 128 * 1024;
pub const STREAM_WINDOW_BYTES: u64 = 256 * 1024;
const MAX_TERMINAL_PROVIDERS_PER_REQUEST: usize = 32;

fn invalid(message: impl Into<String>) -> PluginError {
    PluginError::invalid(message)
}

fn bounded(value: &Value, label: &str) -> PluginResult<()> {
    contract::assert_json_value(value, MAX_PROVIDER_JSON_BYTES).map_err(|e| invalid(format!("{label} must be a bounded JSON value: {}", e.message())))
}

fn deadline(value: Option<&Value>, default: u64) -> PluginResult<u64> {
    match value {
        None | Some(Value::Null) => Ok(default),
        Some(v) => v.as_u64().filter(|d| (1..=300_000).contains(d)).ok_or_else(|| invalid("Provider deadline is invalid")),
    }
}

fn visible(value: &Value, label: &str, max: usize) -> PluginResult<String> {
    let s = value.as_str().filter(|s| !s.is_empty() && s.encode_utf16().count() <= max && !s.contains('\0')).ok_or_else(|| invalid(format!("{label} is invalid")))?;
    if s.chars().any(|c| {
        let c = c as u32;
        c <= 0x1f || (0x7f..=0x9f).contains(&c) || (0x202a..=0x202e).contains(&c) || (0x2066..=0x2069).contains(&c)
    }) {
        return Err(invalid(format!("{label} contains unsafe control characters")));
    }
    Ok(s.to_string())
}

fn color(value: &Value, label: &str) -> PluginResult<()> {
    if value.is_null() {
        return Ok(());
    }
    let s = value.as_str().unwrap_or("");
    let ok = s.starts_with('#') && (s.len() == 7 || s.len() == 9) && s[1..].chars().all(|c| c.is_ascii_hexdigit());
    if ok {
        Ok(())
    } else {
        Err(invalid(format!("{label} is invalid")))
    }
}

fn identity_context(identity: &RuntimeIdentity, signal: Option<CancellationToken>) -> AuthContext {
    identity.auth_context(signal, None)
}

// ---- terminal providers --------------------------------------------------------

pub const TERMINAL_PROVIDER_KINDS: &[(&str, &str, &[&str])] = &[
    ("terminal.completion", "provideCompletions", &["provider.terminal", "terminal.complete"]),
    ("terminal.decoration", "provideDecorations", &["provider.terminal", "terminal.output", "terminal.decorate"]),
    ("terminal.link", "provideLinks", &["provider.terminal", "terminal.output", "terminal.decorate"]),
    ("terminal.hover", "provideHovers", &["provider.terminal", "terminal.output", "terminal.decorate"]),
    ("terminal.matcher", "provideMatches", &["provider.terminal", "terminal.output", "terminal.decorate"]),
    ("terminal.semantic", "provideSemantics", &["provider.terminal", "terminal.input", "terminal.decorate"]),
    ("terminal.prompt", "provideAnnotations", &["provider.terminal", "terminal.output", "terminal.decorate"]),
    ("terminal.background", "provideBackgrounds", &["provider.terminal", "terminal.decorate"]),
    ("terminal.theme", "provideTheme", &["provider.terminal", "terminal.decorate"]),
];

fn terminal_kind(kind: &str) -> PluginResult<&'static (&'static str, &'static str, &'static [&'static str])> {
    TERMINAL_PROVIDER_KINDS.iter().find(|(k, _, _)| *k == kind).ok_or_else(|| {
        if kind.starts_with("terminal.interceptor.") {
            PluginError::rpc(codes::UNSUPPORTED, "Raw terminal interceptor providers require the privileged transport")
        } else {
            invalid("Terminal Provider kind is invalid")
        }
    })
}

/// `normalizeTerminalSessionSnapshot`.
pub fn normalize_session(value: &Value) -> PluginResult<Value> {
    let o = value.as_object().ok_or_else(|| invalid("Terminal session snapshot must be an object"))?;
    let protocol = o.get("protocol").and_then(Value::as_str).unwrap_or("");
    if protocol.is_empty() || protocol.len() > 256 || !protocol.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) || !protocol.chars().all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c)) {
        return Err(invalid("Terminal session protocol is invalid"));
    }
    if !matches!(o.get("status").and_then(Value::as_str), Some("connecting" | "connected" | "disconnected")) {
        return Err(invalid("Terminal session status is invalid"));
    }
    let mut out = json!({ "sessionId": visible(&o.get("sessionId").cloned().unwrap_or(Value::Null), "Terminal session ID", 256)?, "protocol": protocol, "status": o["status"] });
    for (key, max) in [("hostId", 512), ("workspaceId", 512), ("cwd", 4096), ("title", 1024)] {
        if let Some(v) = o.get(key).filter(|v| !v.is_null()) {
            let s = v.as_str().filter(|s| !s.is_empty() && s.len() <= max && !s.contains('\0')).ok_or_else(|| invalid(format!("Terminal {key} is invalid")))?;
            out[key] = json!(s);
        }
    }
    if let Some(v) = o.get("shellType").filter(|v| !v.is_null()) {
        if !matches!(v.as_str(), Some("posix" | "fish" | "powershell" | "cmd" | "unknown")) {
            return Err(invalid("Terminal session shell type is invalid"));
        }
        out["shellType"] = v.clone();
    }
    for key in ["cols", "rows"] {
        if let Some(v) = o.get(key).filter(|v| !v.is_null()) {
            out[key] = json!(v.as_u64().filter(|n| (1..=16_384).contains(n)).ok_or_else(|| invalid(format!("Terminal session {key} is invalid")))?);
        }
    }
    if let Some(v) = o.get("alternateScreen").filter(|v| !v.is_null()) {
        out["alternateScreen"] = json!(v.as_bool().ok_or_else(|| invalid("Terminal alternate-screen state is invalid"))?);
    }
    Ok(out)
}

fn assert_terminal_result(kind: &str, value: &Value, payload: &Value) -> PluginResult<()> {
    match kind {
        "terminal.completion" => {
            for item in value["items"].as_array().filter(|a| a.len() <= 100).ok_or_else(|| invalid("Terminal completion items are invalid"))? {
                let text = visible(&item["text"], "Terminal completion text", 4096)?;
                if !item["displayText"].is_null() && visible(&item["displayText"], "Terminal completion display text", 4096)? != text {
                    return Err(invalid("Terminal completion display text must match the inserted text"));
                }
                if !item["description"].is_null() {
                    visible(&item["description"], "Terminal completion description", 2048)?;
                }
            }
        }
        "terminal.decoration" => {
            for rule in value["rules"].as_array().filter(|a| a.len() <= 64).ok_or_else(|| invalid("Terminal decoration rules are invalid"))? {
                visible(&rule["id"], "Terminal decoration rule ID", 128)?;
                visible(&rule["label"], "Terminal decoration rule label", 256)?;
                for p in rule["patterns"].as_array().filter(|a| !a.is_empty() && a.len() <= 16).ok_or_else(|| invalid("Terminal decoration rule patterns are invalid"))? {
                    visible(p, "Terminal decoration pattern", 512)?;
                }
                if !rule["color"].is_string() {
                    return Err(invalid("Terminal decoration rule color is required"));
                }
                color(&rule["color"], "Terminal decoration rule color")?;
            }
        }
        "terminal.link" | "terminal.hover" => {
            let (property, label) = if kind == "terminal.link" { ("links", "Terminal link") } else { ("hovers", "Terminal hover") };
            let line_len = payload["line"].as_str().map(|l| l.encode_utf16().count()).unwrap_or(0);
            for item in value[property].as_array().filter(|a| a.len() <= 64).ok_or_else(|| invalid(format!("{label} result is invalid")))? {
                let (start, length) = (item["start"].as_u64().unwrap_or(u64::MAX) as usize, item["length"].as_u64().unwrap_or(0) as usize);
                if length < 1 || start > line_len || length > line_len - start {
                    return Err(invalid(format!("{label} range is invalid")));
                }
                if kind == "terminal.link" {
                    let uri = visible(&item["uri"], "Terminal link URI", 2048)?;
                    let parsed = url::Url::parse(&uri).map_err(|_| invalid("Terminal link URI is invalid"))?;
                    if !matches!(parsed.scheme(), "http" | "https") || !parsed.username().is_empty() || parsed.password().is_some() {
                        return Err(invalid("Terminal link URI is invalid"));
                    }
                } else {
                    visible(&item["contents"], "Terminal hover contents", 2048)?;
                }
            }
        }
        "terminal.theme" => {
            let colors = value["colors"].as_object().ok_or_else(|| invalid("Terminal theme colors must be an object"))?;
            if value.as_object().is_some_and(|o| o.keys().any(|k| k != "colors")) {
                return Err(invalid("Terminal theme result contains an unknown property"));
            }
            for (key, c) in colors {
                color(c, &format!("Terminal theme {key}"))?;
            }
        }
        "terminal.background" => {
            for layer in value["layers"].as_array().filter(|a| a.len() <= 4).ok_or_else(|| invalid("Terminal background layers are invalid"))? {
                visible(&layer["id"], "Terminal background layer ID", 128)?;
                color(&layer["color"], "Terminal background layer color")?;
                if layer["opacity"].as_f64().is_some_and(|o| !(0.0..=0.35).contains(&o)) {
                    return Err(invalid("Terminal background layer opacity is invalid"));
                }
            }
        }
        "terminal.prompt" => {
            for a in value["annotations"].as_array().filter(|a| a.len() <= 8).ok_or_else(|| invalid("Terminal prompt annotations are invalid"))? {
                visible(&a["text"], "Terminal prompt annotations text", 512)?;
                color(&a["color"], "Terminal prompt annotations color")?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub struct TerminalProviderService {
    contributions: Arc<ContributionService>,
    supervisor: Arc<RuntimeSupervisor>,
    permissions: Arc<PermissionEngine>,
    lifecycle: Mutex<HashMap<String, (Arc<RuntimeIdentity>, String)>>,
    pub requests: Mutex<HashMap<String, CancellationToken>>,
}

impl TerminalProviderService {
    pub fn new(contributions: Arc<ContributionService>, supervisor: Arc<RuntimeSupervisor>, permissions: Arc<PermissionEngine>) -> Self {
        Self { contributions, supervisor, permissions, lifecycle: Mutex::new(HashMap::new()), requests: Mutex::new(HashMap::new()) }
    }

    /// `listProviders({ kind, locale, preferredProviderIds })`.
    pub fn list(&self, options: &Value) -> PluginResult<Vec<Value>> {
        let kind = terminal_kind(options["kind"].as_str().unwrap_or(""))?.0;
        let preferred: Vec<String> = options["preferredProviderIds"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
        if preferred.len() > 256 || preferred.iter().collect::<HashSet<_>>().len() != preferred.len() {
            return Err(invalid("Preferred Terminal Provider IDs are invalid"));
        }
        let rank = |id: &str| preferred.iter().position(|p| p == id).unwrap_or(usize::MAX);
        let mut providers = self.contributions.list_providers(Some(kind), options["locale"].as_str())?;
        providers.sort_by(|a, b| {
            let (ia, ib) = (a["provider"]["id"].as_str().unwrap_or(""), b["provider"]["id"].as_str().unwrap_or(""));
            rank(ia).cmp(&rank(ib)).then_with(|| a["pluginId"].as_str().cmp(&b["pluginId"].as_str())).then_with(|| ia.cmp(ib))
        });
        Ok(providers)
    }

    async fn invoke(&self, provider_id: &str, kind: &'static str, operation: &str, payload: &Value, deadline_ms: u64, signal: &CancellationToken) -> PluginResult<Value> {
        let (_, _, permissions) = terminal_kind(kind)?;
        let request_id = format!("provider-{}", uuid::Uuid::new_v4());
        let request = json!({ "providerId": provider_id, "operation": operation, "requestId": request_id, "payload": payload, "deadlineMs": deadline_ms });
        contract::assert_provider_request(&request).map_err(|e| invalid(e.message().to_string()))?;
        let (plugin, provider, identity) = self.contributions.activate_provider(provider_id).await?;
        if provider["kind"] != kind {
            return Err(PluginError::precondition("Plugin Provider kind changed during activation"));
        }
        let session = normalize_session(&payload["session"]).ok();
        let mut scope = String::new();
        for permission in permissions.iter() {
            let grant = self
                .permissions
                .authorize(
                    &identity_context(&identity, Some(signal.clone())),
                    &AuthorizationRequest {
                        permission: (*permission).into(),
                        resources: vec!["*".into()],
                        reason: Some(format!("Use {provider_id} for {kind}")),
                        operation_id: Some(format!("{kind}:{provider_id}")),
                        session_id: session.as_ref().and_then(|s| s["sessionId"].as_str().map(str::to_string)),
                        ..Default::default()
                    },
                )
                .await?;
            if *permission == "provider.terminal" {
                scope = grant.scope;
            }
        }
        if let Some(session) = &session {
            self.supervisor.notify(&plugin.id, "plugin.terminal.event", json!({ "type": "snapshot", "session": session }), Some(&identity)).await?;
        }
        let mut params = request.clone();
        params["kind"] = json!(kind);
        let raw = self.supervisor.request(&plugin.id, "provider.invoke", params, Some(&identity), Some(Duration::from_millis(deadline_ms)), Some(signal.clone())).await?;
        let checked = (|| -> PluginResult<()> {
            contract::assert_provider_result(&raw)?;
            if raw["status"] == "ok" {
                assert_terminal_result(kind, &raw["result"], payload)?;
            }
            Ok(())
        })();
        if let Err(err) = checked {
            return Err(PluginError::rpc(codes::DATA_LOSS, format!("Plugin Provider returned an invalid result: {}", err.message())));
        }
        if raw["requestId"] != json!(request_id) {
            return Err(PluginError::rpc(codes::DATA_LOSS, "Plugin Provider returned a mismatched request ID"));
        }
        if raw["status"] == "ok" && scope != "once" {
            if let Some(session_id) = session.as_ref().and_then(|s| s["sessionId"].as_str()) {
                self.lifecycle.lock().insert(format!("{}\0{session_id}", plugin.id), (identity.clone(), session_id.to_string()));
            }
        }
        let mut out = raw.clone();
        out["pluginId"] = json!(plugin.id);
        out["pluginVersion"] = json!(plugin.active_version);
        out["runtimeId"] = json!(identity.runtime_id);
        out["providerId"] = json!(provider_id);
        out["kind"] = json!(kind);
        Ok(out)
    }

    /// `provide(request)` → per-provider results / failures.
    pub async fn provide(&self, params: &Value, signal: CancellationToken) -> PluginResult<Value> {
        let kind = terminal_kind(params["kind"].as_str().unwrap_or(""))?;
        let operation = params["operation"].as_str().filter(|o| !o.is_empty() && o.len() <= 128).ok_or_else(|| invalid("Terminal Provider operation is invalid"))?;
        if kind.1 != operation {
            return Err(invalid("Terminal Provider operation does not match its kind"));
        }
        let session = normalize_session(&params["session"])?;
        let payload = match params.get("payload") {
            Some(Value::Object(map)) => {
                let mut p = Value::Object(map.clone());
                p["session"] = session.clone();
                p
            }
            None | Some(Value::Null) => json!({ "session": session }),
            Some(other) => json!({ "session": session, "value": other }),
        };
        bounded(&payload, "Provider request payload")?;
        let deadline_ms = deadline(params.get("deadlineMs"), 1_500)?;
        let providers = self.list(&json!({ "kind": kind.0, "locale": params["locale"], "preferredProviderIds": params["preferredProviderIds"] }))?;
        let futures = providers.into_iter().take(MAX_TERMINAL_PROVIDERS_PER_REQUEST).map(|entry| {
            let payload = payload.clone();
            let signal = signal.clone();
            async move {
                let provider_id = entry["provider"]["id"].as_str().unwrap_or("").to_string();
                match self.invoke(&provider_id, kind.0, operation, &payload, deadline_ms, &signal).await {
                    Ok(v) => v,
                    Err(err) => {
                        let mut out = json!({ "pluginId": entry["pluginId"], "pluginVersion": entry["pluginVersion"], "providerId": provider_id, "kind": kind.0, "requestId": format!("provider-{}", uuid::Uuid::new_v4()) });
                        if signal.is_cancelled() || err.code() == Some(codes::CANCELLED) {
                            out["status"] = json!("cancelled");
                        } else {
                            out["status"] = json!("failed");
                            out["error"] = json!({ "code": err.code().unwrap_or(codes::INTERNAL), "message": err.message().chars().take(2048).collect::<String>() });
                        }
                        out
                    }
                }
            }
        });
        Ok(Value::Array(futures::future::join_all(futures).await))
    }

    /// `publishSessionEvent(event)` → `[{ pluginId, delivered }]`.
    pub async fn publish_session_event(&self, event: &Value) -> PluginResult<Value> {
        let types = ["snapshot", "created", "connected", "reconnected", "cwdChanged", "titleChanged", "resized", "alternateScreenChanged", "commandSubmitted", "commandCompleted", "disconnected", "disposed"];
        let kind = event["type"].as_str().filter(|t| types.contains(t)).ok_or_else(|| invalid("Terminal session event is invalid"))?;
        let mut normalized = json!({ "type": kind, "session": normalize_session(&event["session"])? });
        if let Some(code) = event.get("exitCode").filter(|c| !c.is_null()) {
            normalized["exitCode"] = json!(code.as_i64().ok_or_else(|| invalid("Terminal session exit code is invalid"))?);
        }
        let session_id = normalized["session"]["sessionId"].as_str().unwrap_or("").to_string();
        let mut plugin_ids: Vec<String> = self
            .contributions
            .list_providers(None, None)?
            .iter()
            .filter(|e| e["provider"]["kind"].as_str().is_some_and(|k| terminal_kind(k).is_ok()))
            .filter_map(|e| e["pluginId"].as_str().map(str::to_string))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        plugin_ids.sort();
        let mut out = Vec::new();
        for plugin_id in plugin_ids {
            let key = format!("{plugin_id}\0{session_id}");
            let authorization = self.lifecycle.lock().get(&key).cloned();
            let Some((identity, _)) = authorization else {
                out.push(json!({ "pluginId": plugin_id, "delivered": false }));
                continue;
            };
            let current = self.supervisor.get_runtime_identity(&plugin_id);
            let delivered = current.is_some_and(|c| c.runtime_id == identity.runtime_id)
                && self
                    .permissions
                    .authorize(
                        &identity_context(&identity, None),
                        &AuthorizationRequest {
                            permission: "provider.terminal".into(),
                            resources: vec!["*".into()],
                            reason: Some("Receive Terminal Provider lifecycle metadata".into()),
                            operation_id: Some(format!("terminal.lifecycle:{session_id}")),
                            session_id: Some(session_id.clone()),
                            interactive: Some(false),
                            ..Default::default()
                        },
                    )
                    .await
                    .is_ok()
                && self.supervisor.notify(&plugin_id, "plugin.terminal.event", normalized.clone(), Some(&identity)).await.is_ok();
            if !delivered || kind == "disposed" {
                self.lifecycle.lock().remove(&key);
            }
            out.push(json!({ "pluginId": plugin_id, "delivered": delivered }));
        }
        if kind == "disposed" {
            self.lifecycle.lock().retain(|_, (_, s)| s != &session_id);
        }
        Ok(Value::Array(out))
    }
}

// ---- extension providers --------------------------------------------------------

const EXTENSION_KINDS: &[(&str, &str, &[&str])] = &[
    ("connection", "provider.connection", &["validateConfiguration", "probe", "open", "resize", "signal", "reconnect", "close", "getStatus"]),
    ("authentication", "provider.authentication", &["begin", "respond", "cancel"]),
    ("importer", "provider.importer", &["detect", "parse"]),
    ("sync", "provider.sync", &["connect", "disconnect", "getAccount", "getCapabilities", "readObject", "writeObject", "deleteObject"]),
];

fn extension_kind(kind: &str) -> PluginResult<&'static (&'static str, &'static str, &'static [&'static str])> {
    EXTENSION_KINDS.iter().find(|(k, _, _)| *k == kind).ok_or_else(|| invalid("Extension Provider kind is invalid"))
}

type Activation = (crate::database::PluginRecord, Value, Arc<RuntimeIdentity>);

/// Binder of an expected incoming stream.
type Binder = Box<dyn FnOnce(&IncomingStream) -> bool + Send>;

/// Output sink of a plugin connection.
pub trait ConnectionSink: Send + Sync {
    fn data(&self, bytes: Vec<u8>);
    fn closed(&self, reason: Value);
}

struct ConnectionSession {
    provider_id: String,
    plugin_connection_id: Value,
    activation: Activation,
    input: OutgoingStream,
    output_stream_id: String,
}

pub struct ExtensionProviderService {
    contributions: Arc<ContributionService>,
    supervisor: Arc<RuntimeSupervisor>,
    permissions: Arc<PermissionEngine>,
    leases: Arc<SecretLeaseStore>,
    expectations: Arc<Mutex<HashMap<String, Binder>>>,
    sessions: Mutex<HashMap<String, Arc<ConnectionSession>>>,
    pub requests: Mutex<HashMap<String, CancellationToken>>,
}

/// Collected incoming stream bytes (sync read / importer output).
struct Collector {
    rx: oneshot::Receiver<PluginResult<Vec<u8>>>,
}

impl ExtensionProviderService {
    pub fn new(contributions: Arc<ContributionService>, supervisor: Arc<RuntimeSupervisor>, permissions: Arc<PermissionEngine>, leases: Arc<SecretLeaseStore>, registry: &HostRpcRegistry) -> Arc<Self> {
        let expectations: Arc<Mutex<HashMap<String, Binder>>> = Arc::default();
        let map = expectations.clone();
        registry.register_incoming_stream(Arc::new(move |stream: &IncomingStream, identity: &Arc<RuntimeIdentity>| {
            let binder = map.lock().remove(&format!("{}\0{}", identity.runtime_id, stream.stream_id));
            binder.is_some_and(|b| b(stream))
        }));
        Arc::new(Self { contributions, supervisor, permissions, leases, expectations, sessions: Mutex::new(HashMap::new()), requests: Mutex::new(HashMap::new()) })
    }

    pub fn list(&self, options: &Value) -> PluginResult<Vec<Value>> {
        let kind = extension_kind(options["kind"].as_str().unwrap_or(""))?.0;
        self.contributions.list_providers(Some(kind), options["locale"].as_str())
    }

    async fn activate(&self, provider_id: &str, kind: &str, signal: &CancellationToken) -> PluginResult<Activation> {
        let (_, permission, _) = extension_kind(kind)?;
        let (plugin, provider, identity) = self.contributions.activate_provider(provider_id).await?;
        if provider["kind"] != kind {
            return Err(PluginError::precondition("Extension Provider kind changed during activation"));
        }
        self.permissions
            .authorize(
                &identity_context(&identity, Some(signal.clone())),
                &AuthorizationRequest {
                    permission: (*permission).into(),
                    resources: vec![provider_id.into()],
                    reason: Some(format!("Use {provider_id} as a {kind} Provider")),
                    operation_id: Some(format!("{kind}:{provider_id}")),
                    ..Default::default()
                },
            )
            .await?;
        Ok((plugin, provider, identity))
    }

    /// `invoke({ providerId, kind, operation, payload, deadlineMs })`.
    pub async fn invoke(&self, params: &Value, activation: Option<&Activation>, signal: &CancellationToken) -> PluginResult<Value> {
        let (kind, _, operations) = extension_kind(params["kind"].as_str().unwrap_or(""))?;
        let operation = params["operation"].as_str().filter(|o| operations.contains(o)).ok_or_else(|| invalid("Extension Provider operation is invalid"))?;
        let deadline_ms = deadline(params.get("deadlineMs"), 30_000)?;
        let provider_id = params["providerId"].as_str().unwrap_or("");
        let request_id = params["requestId"].as_str().map(str::to_string).unwrap_or_else(|| format!("provider-{}", uuid::Uuid::new_v4()));
        let mut request = json!({ "providerId": provider_id, "operation": operation, "requestId": request_id, "deadlineMs": deadline_ms });
        if let Some(payload) = params.get("payload").filter(|p| !p.is_null()) {
            bounded(payload, "Extension Provider payload")?;
            request["payload"] = payload.clone();
        }
        contract::assert_provider_request(&request).map_err(|e| invalid(e.message().to_string()))?;
        let owned;
        let (plugin, provider, identity) = match activation {
            Some(a) => a,
            None => {
                owned = self.activate(provider_id, kind, signal).await?;
                &owned
            }
        };
        if let (Some(schema), Some(configuration)) = (provider.get("configurationSchema"), request["payload"].get("configuration")) {
            let mut schema = schema.clone();
            if *kind == "sync" {
                let write_only: HashSet<String> = schema["properties"].as_object().map(|p| p.iter().filter(|(_, c)| c["writeOnly"] == true).map(|(k, _)| k.clone()).collect()).unwrap_or_default();
                if let Some(required) = schema["required"].as_array_mut() {
                    required.retain(|n| n.as_str().is_some_and(|n| !["password", "token", "secret", "apiKey", "accessToken"].contains(&n) && !write_only.contains(n)));
                }
            }
            if !crate::package::manifest::restricted_schema_accepts(&schema, configuration)? {
                return Err(invalid("Provider configuration failed host schema validation"));
            }
        }
        let mut wire = request.clone();
        wire["kind"] = json!(kind);
        let raw = self.supervisor.request(&plugin.id, "provider.invoke", wire, Some(identity), Some(Duration::from_millis(deadline_ms)), Some(signal.clone())).await?;
        if contract::assert_provider_result(&raw).is_err() || bounded(&raw, "Extension Provider result").is_err() {
            return Err(PluginError::rpc(codes::DATA_LOSS, "Extension Provider returned an invalid result"));
        }
        if raw["requestId"] != json!(request_id) {
            return Err(PluginError::rpc(codes::DATA_LOSS, "Extension Provider returned a mismatched request ID"));
        }
        match raw["status"].as_str() {
            Some("failed") => Err(PluginError::Rpc { code: raw["error"]["code"].as_i64().unwrap_or(codes::INTERNAL), message: raw["error"]["message"].as_str().unwrap_or("Provider failed").into(), data: raw["error"].get("data").cloned() }),
            Some("cancelled") => Err(PluginError::cancelled()),
            _ => Ok(raw["result"].clone()),
        }
    }

    fn expect(&self, identity: &RuntimeIdentity, stream_id: &str, binder: Binder) {
        self.expectations.lock().insert(format!("{}\0{stream_id}", identity.runtime_id), binder);
    }

    fn unexpect(&self, identity: &RuntimeIdentity, stream_id: &str) {
        self.expectations.lock().remove(&format!("{}\0{stream_id}", identity.runtime_id));
    }

    /// Expect a byte stream, collect it fully (bounded).
    fn collect(&self, identity: &RuntimeIdentity, stream_id: &str, max: usize, mut on_chunk: Option<Box<dyn FnMut(&[u8]) -> PluginResult<()> + Send>>) -> Collector {
        let (tx, rx) = oneshot::channel();
        let tx = Arc::new(Mutex::new(Some(tx)));
        self.expect(
            identity,
            stream_id,
            Box::new(move |stream: &IncomingStream| {
                let buffer = Arc::new(Mutex::new(Vec::new()));
                let (b1, t1, b2, t2) = (buffer.clone(), tx.clone(), buffer, tx);
                stream
                    .bind(IncomingHandlers {
                        on_chunk: Box::new(move |chunk, release| {
                            let StreamChunk::Bytes(bytes) = chunk else {
                                if let Some(tx) = t1.lock().take() {
                                    let _ = tx.send(Err(PluginError::rpc(codes::DATA_LOSS, "Plugin stream must be binary")));
                                }
                                return;
                            };
                            let mut buf = b1.lock();
                            if buf.len() + bytes.len() > max {
                                if let Some(tx) = t1.lock().take() {
                                    let _ = tx.send(Err(PluginError::exhausted("Plugin stream exceeds its size limit")));
                                }
                                return;
                            }
                            if let Some(cb) = on_chunk.as_mut() {
                                if let Err(err) = cb(&bytes) {
                                    if let Some(tx) = t1.lock().take() {
                                        let _ = tx.send(Err(err));
                                    }
                                    return;
                                }
                            }
                            buf.extend_from_slice(&bytes);
                            drop(buf);
                            release();
                        }),
                        on_close: Some(Box::new(move |reason| {
                            if let Some(tx) = t2.lock().take() {
                                let _ = tx.send(if reason == "end" { Ok(std::mem::take(&mut *b2.lock())) } else { Err(PluginError::rpc(codes::DATA_LOSS, "Plugin stream did not end normally")) });
                            }
                        })),
                    })
                    .is_ok()
            }),
        );
        Collector { rx }
    }

    async fn write_stream(stream: &OutgoingStream, bytes: &[u8]) -> PluginResult<()> {
        for chunk in bytes.chunks(STREAM_WINDOW_BYTES as usize) {
            stream.write_bytes(chunk).await?;
        }
        stream.end()
    }

    // -- connections --

    /// `openConnection`; output goes to `sink`.
    pub async fn open_connection(&self, params: &Value, sink: Arc<dyn ConnectionSink>, signal: &CancellationToken) -> PluginResult<Value> {
        let provider_id = params["providerId"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| invalid("Connection Provider ID is invalid"))?.to_string();
        let configuration = params.get("configuration").cloned().unwrap_or_else(|| json!({}));
        bounded(&configuration, "Connection configuration")?;
        let (columns, rows) = (params["columns"].as_u64().unwrap_or(0), params["rows"].as_u64().unwrap_or(0));
        if !(1..=16_384).contains(&columns) || !(1..=16_384).contains(&rows) {
            return Err(invalid("Plugin connection dimensions are invalid"));
        }
        let activation = self.activate(&provider_id, "connection", signal).await?;
        let session_id = params["sessionId"].as_str().map(str::to_string).unwrap_or_else(|| format!("plugin-session-{}", uuid::Uuid::new_v4()));
        if self.sessions.lock().contains_key(&session_id) {
            return Err(PluginError::rpc(codes::ALREADY_EXISTS, "Plugin session already exists"));
        }
        let operation_id = format!("connection:{}", uuid::Uuid::new_v4());
        let input_id = format!("{operation_id}:input");
        let output_id = format!("{operation_id}:output");
        let (opened_tx, opened_rx) = oneshot::channel::<()>();
        let opened_tx = Mutex::new(Some(opened_tx));
        let output_sink = sink.clone();
        self.expect(
            &activation.2,
            &output_id,
            Box::new(move |stream: &IncomingStream| {
                let (s1, s2) = (output_sink.clone(), output_sink);
                let ok = stream
                    .bind(IncomingHandlers {
                        on_chunk: Box::new(move |chunk, release| {
                            if let StreamChunk::Bytes(bytes) = chunk {
                                s1.data(bytes);
                            }
                            release();
                        }),
                        on_close: Some(Box::new(move |reason| s2.closed(reason))),
                    })
                    .is_ok();
                if let Some(tx) = opened_tx.lock().take() {
                    let _ = tx.send(());
                }
                ok
            }),
        );
        let mut payload = json!({
            "operationId": operation_id, "configuration": configuration, "columns": columns, "rows": rows,
            "inputStreamId": input_id, "outputStreamId": output_id, "windowBytes": STREAM_WINDOW_BYTES,
        });
        for key in ["credential", "authenticationProviderId"] {
            if let Some(v) = params.get(key).filter(|v| !v.is_null()) {
                payload[key] = v.clone();
            }
        }
        let request = json!({ "providerId": provider_id, "kind": "connection", "operation": "open", "payload": payload, "deadlineMs": params["deadlineMs"] });
        let invoke = self.invoke(&request, Some(&activation), signal);
        tokio::pin!(invoke);
        let outcome: PluginResult<Value> = async {
            tokio::select! {
                r = opened_rx => r.map_err(|_| PluginError::unavailable("Plugin connection output closed during startup"))?,
                r = &mut invoke => { let _ = r?; return Err(PluginError::unavailable("Plugin connection did not open its output stream")); }
            }
            let input = self.supervisor.open_stream(&activation.0.id, &input_id, STREAM_WINDOW_BYTES, Some(&activation.2), None).await?;
            let result = invoke.await?;
            self.sessions.lock().insert(
                session_id.clone(),
                Arc::new(ConnectionSession { provider_id: provider_id.clone(), plugin_connection_id: result["connectionId"].clone(), activation: activation.clone(), input, output_stream_id: output_id.clone() }),
            );
            Ok(json!({ "sessionId": session_id, "providerId": provider_id, "status": result["status"], "diagnostics": result.get("diagnostics").cloned().unwrap_or_else(|| json!([])) }))
        }
        .await;
        if outcome.is_err() {
            self.unexpect(&activation.2, &output_id);
        }
        outcome
    }

    pub async fn write(&self, session_id: &str, bytes: &[u8]) -> PluginResult<()> {
        let session = self.sessions.lock().get(session_id).cloned().ok_or_else(|| PluginError::not_found("Plugin connection session was not found"))?;
        if bytes.is_empty() {
            return session.input.write_bytes(bytes).await;
        }
        for chunk in bytes.chunks(STREAM_WINDOW_BYTES as usize) {
            session.input.write_bytes(chunk).await?;
        }
        Ok(())
    }

    pub async fn control(&self, session_id: &str, operation: &str, payload: &Value) -> PluginResult<Value> {
        let session = self.sessions.lock().get(session_id).cloned().ok_or_else(|| PluginError::not_found("Plugin connection session was not found"))?;
        if operation == "close" {
            self.sessions.lock().remove(session_id);
        }
        let mut p = if payload.is_object() { payload.clone() } else { json!({}) };
        p["connectionId"] = session.plugin_connection_id.clone();
        p["operationId"] = json!(format!("connection:{operation}:{}", uuid::Uuid::new_v4()));
        let result = self
            .invoke(&json!({ "providerId": session.provider_id, "kind": "connection", "operation": operation, "payload": p }), Some(&session.activation), &CancellationToken::new())
            .await;
        if operation == "close" {
            let _ = session.input.cancel();
            if let Ok(router) = self.supervisor.router(&session.activation.0.id).await {
                let _ = router.cancel_incoming(&session.output_stream_id, json!("closed"));
            }
        }
        result
    }

    pub fn close_local(&self, session_id: &str) {
        if let Some(session) = self.sessions.lock().remove(session_id) {
            let _ = session.input.cancel();
        }
    }

    pub fn has_session(&self, session_id: &str) -> bool {
        self.sessions.lock().contains_key(session_id)
    }

    // -- authentication --

    /// Challenge loop; `challenge` asks the renderer and returns the response.
    pub async fn authenticate<F>(&self, params: &Value, challenge: F, signal: &CancellationToken) -> PluginResult<Value>
    where
        F: Fn(Value) -> BoxFuture<'static, PluginResult<Value>>,
    {
        let provider_id = params["providerId"].as_str().unwrap_or("").to_string();
        let operation_id = format!("authentication:{}", uuid::Uuid::new_v4());
        let activation = self.activate(&provider_id, "authentication", signal).await?;
        let connection_provider_id = params["connectionProviderId"].as_str().unwrap_or("");
        let connection = self
            .contributions
            .list_providers(Some("connection"), None)?
            .into_iter()
            .find(|e| e["provider"]["id"] == connection_provider_id)
            .ok_or_else(|| PluginError::not_found("Connection Provider was not found"))?;
        let mut payload = json!({ "operationId": operation_id, "connectionProviderId": connection_provider_id, "configuration": params.get("configuration").cloned().unwrap_or_else(|| json!({})) });
        if let Some(c) = params.get("credential").filter(|c| !c.is_null()) {
            payload["credential"] = c.clone();
        }
        let run = async {
            let mut result = self.invoke(&json!({ "providerId": provider_id, "kind": "authentication", "operation": "begin", "payload": payload }), Some(&activation), signal).await?;
            let mut count = 0;
            while result["status"] == "challenge" {
                count += 1;
                if count > 32 {
                    return Err(PluginError::exhausted("Authentication challenge limit exceeded"));
                }
                let item = result["challenge"].clone();
                let mut response = challenge(item.clone()).await?;
                if matches!(item["kind"].as_str(), Some("password" | "otp")) {
                    let secret = response.as_str().unwrap_or("").to_string();
                    response = self.leases.issue_resolved(&activation.2.plugin_id, &activation.2.runtime_id, secret, &operation_id, 30_000)?;
                }
                result = self
                    .invoke(&json!({ "providerId": provider_id, "kind": "authentication", "operation": "respond", "payload": { "operationId": operation_id, "challengeId": item["id"], "response": response } }), Some(&activation), signal)
                    .await?;
            }
            if result["status"] == "authenticated" && result["credential"]["kind"] == "secret" && connection["pluginId"].as_str() != Some(activation.2.plugin_id.as_str()) {
                return Err(PluginError::precondition("Cross-plugin authentication must return a host-owned CredentialRef"));
            }
            Ok(result)
        };
        let result = run.await;
        if result.is_err() {
            let cancel = CancellationToken::new();
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                self.invoke(&json!({ "providerId": provider_id, "kind": "authentication", "operation": "cancel", "payload": { "operationId": operation_id }, "deadlineMs": 1000 }), Some(&activation), &cancel),
            )
            .await;
        }
        self.leases.revoke_operation(&activation.2.plugin_id, &operation_id);
        result
    }

    // -- importer --

    pub async fn detect_importer(&self, params: &Value, sample: &[u8], signal: &CancellationToken) -> PluginResult<Value> {
        let max = contract::def_const("ImporterLimits").and_then(|l| l["maxInputBytes"].as_u64()).unwrap_or(64 * 1024 * 1024) as usize;
        if sample.is_empty() || sample.len() > max {
            return Err(invalid("Importer sample size is invalid"));
        }
        let mut metadata = json!({ "sample": { "encoding": "base64", "data": "" } });
        for key in ["fileName", "mediaType"] {
            if let Some(v) = params[key].as_str() {
                metadata[key] = json!(v);
            }
        }
        let budget = (MAX_PROVIDER_JSON_BYTES - serde_json::to_string(&metadata)?.len()) / 4 * 3;
        metadata["sample"]["data"] = json!(B64.encode(&sample[..sample.len().min(budget)]));
        self.invoke(&json!({ "providerId": params["providerId"], "kind": "importer", "operation": "detect", "payload": metadata, "deadlineMs": params["deadlineMs"] }), None, signal).await
    }

    /// `parseImporter`: streams `data` in, collects JSONL records out.
    pub async fn parse_importer(&self, params: &Value, data: &[u8], progress: &(dyn Fn(Value) + Send + Sync), signal: &CancellationToken) -> PluginResult<Value> {
        let limits = contract::def_const("ImporterLimits").cloned().unwrap_or_else(|| json!({}));
        let provider_id = params["providerId"].as_str().unwrap_or("").to_string();
        if data.is_empty() || data.len() as u64 > limits["maxInputBytes"].as_u64().unwrap_or(64 << 20) {
            return Err(invalid("Importer input size is invalid"));
        }
        let activation = self.activate(&provider_id, "importer", signal).await?;
        let deadline_ms = deadline(params.get("deadlineMs"), 30_000)?;
        let operation_id = format!("importer:{}", uuid::Uuid::new_v4());
        let (input_id, output_id) = (format!("{operation_id}:input"), format!("{operation_id}:output"));
        let collector = self.collect(&activation.2, &output_id, limits["maxOutputBytes"].as_u64().unwrap_or(32 << 20) as usize, None);
        let mut payload = json!({ "operationId": operation_id, "inputStreamId": input_id, "outputStreamId": output_id, "windowBytes": STREAM_WINDOW_BYTES });
        for key in ["fileName", "mediaType", "options"] {
            if let Some(v) = params.get(key).filter(|v| !v.is_null()) {
                payload[key] = v.clone();
            }
        }
        let parse_request = json!({ "providerId": provider_id, "kind": "importer", "operation": "parse", "payload": payload, "deadlineMs": deadline_ms });
        let run = async {
            let invoke = self.invoke(&parse_request, Some(&activation), signal);
            let feed = async {
                let input = self.supervisor.open_stream(&activation.0.id, &input_id, STREAM_WINDOW_BYTES, Some(&activation.2), None).await?;
                Self::write_stream(&input, data).await
            };
            let (result, fed) = tokio::join!(invoke, feed);
            fed?;
            let result = result?;
            let bytes = collector.rx.await.map_err(|_| PluginError::rpc(codes::DATA_LOSS, "Importer output stream did not end normally"))??;
            let text = String::from_utf8(bytes).map_err(|_| PluginError::rpc(codes::DATA_LOSS, "Importer output must be UTF-8 JSONL"))?;
            let max_records = limits["maxRecords"].as_u64().unwrap_or(100_000) as usize;
            let mut records = Vec::new();
            let (mut parsed, mut warnings, mut errors) = (0i64, 0i64, 0i64);
            for line in text.lines().map(|l| l.trim_end_matches('\r')).filter(|l| !l.is_empty()) {
                if records.len() >= max_records || line.len() as u64 > limits["maxRecordBytes"].as_u64().unwrap_or(1 << 20) {
                    return Err(PluginError::exhausted("Importer output exceeds its record limits"));
                }
                let record: Value = serde_json::from_str(line).map_err(|_| PluginError::rpc(codes::DATA_LOSS, "Importer record is invalid"))?;
                match record["type"].as_str() {
                    Some("draft") => parsed += 1,
                    Some("warning") => warnings += 1,
                    Some("error") => errors += 1,
                    Some("progress") => progress(record.clone()),
                    _ => {}
                }
                records.push(record);
            }
            if result["parsed"].as_i64() != Some(parsed) || result["warnings"].as_i64() != Some(warnings) || result["errors"].as_i64() != Some(errors) {
                return Err(PluginError::rpc(codes::DATA_LOSS, "Importer completion counts do not match its streamed records"));
            }
            Ok(json!({ "providerId": provider_id, "result": result, "records": records }))
        };
        let outcome = tokio::time::timeout(Duration::from_millis(deadline_ms), run).await.unwrap_or_else(|_| Err(PluginError::deadline("Importer Provider exceeded its deadline")));
        self.unexpect(&activation.2, &output_id);
        self.leases.revoke_operation(&activation.2.plugin_id, &operation_id);
        outcome
    }

    // -- sync --

    fn sync_payload(params: &Value, operation: &str) -> Value {
        let mut payload = json!({ "operationId": format!("sync:{operation}:{}", uuid::Uuid::new_v4()) });
        for key in ["configuration", "credential", "key", "expectedRevision"] {
            if let Some(v) = params.get(key).filter(|v| !v.is_null() || key == "expectedRevision" && params.get(key).is_some()) {
                payload[key] = v.clone();
            }
        }
        if operation == "connect" && payload.get("configuration").is_none() {
            payload["configuration"] = json!({});
        }
        payload
    }

    /// `connect` / `disconnect` / `getAccount` / `getCapabilities` / `deleteObject`.
    pub async fn sync_simple(&self, operation: &str, params: &Value, signal: &CancellationToken) -> PluginResult<Value> {
        let payload = Self::sync_payload(params, operation);
        self.invoke(&json!({ "providerId": params["providerId"], "kind": "sync", "operation": operation, "payload": payload, "deadlineMs": params["deadlineMs"] }), None, signal).await
    }

    /// `readSyncObject` → `{ found, key, bytes?, revision?, contentType? }`.
    pub async fn read_sync_object(&self, params: &Value, signal: &CancellationToken) -> PluginResult<(Value, Option<Vec<u8>>)> {
        let provider_id = params["providerId"].as_str().unwrap_or("").to_string();
        let key = params["key"].as_str().filter(|k| !k.is_empty()).ok_or_else(|| invalid("Sync object key is invalid"))?.to_string();
        let max = contract::def_const("SyncLimits").and_then(|l| l["maxObjectBytes"].as_u64()).unwrap_or(64 << 20) as usize;
        let activation = self.activate(&provider_id, "sync", signal).await?;
        let operation_id = format!("sync:read:{}", uuid::Uuid::new_v4());
        let output_id = format!("{operation_id}:output");
        let collector = self.collect(&activation.2, &output_id, max, None);
        let result = self
            .invoke(&json!({ "providerId": provider_id, "kind": "sync", "operation": "readObject", "payload": { "key": key, "operationId": operation_id, "outputStreamId": output_id, "windowBytes": STREAM_WINDOW_BYTES }, "deadlineMs": params["deadlineMs"] }), Some(&activation), signal)
            .await;
        let outcome = (async {
            let result = result?;
            if result["found"] != true {
                return Ok((json!({ "found": false, "key": key }), None));
            }
            let bytes = if result["streamed"] == true {
                let bytes = collector.rx.await.map_err(|_| PluginError::rpc(codes::DATA_LOSS, "Sync object stream did not end normally"))??;
                if Some(bytes.len() as u64) != result["byteLength"].as_u64() {
                    return Err(PluginError::rpc(codes::DATA_LOSS, "Sync readObject stream size does not match byteLength"));
                }
                bytes
            } else {
                let bytes = B64.decode(result["data"].as_str().unwrap_or("")).map_err(|_| invalid("Sync readObject data is not valid base64"))?;
                if Some(bytes.len() as u64) != result["byteLength"].as_u64() {
                    return Err(invalid("Sync readObject byteLength does not match decoded data"));
                }
                bytes
            };
            Ok((json!({ "found": true, "key": key, "revision": result["revision"], "contentType": result["contentType"] }), Some(bytes)))
        })
        .await;
        self.unexpect(&activation.2, &output_id);
        outcome
    }

    /// `writeSyncObject` (inline below the inline limit unless `prefer_stream`).
    pub async fn write_sync_object(&self, params: &Value, bytes: &[u8], prefer_stream: bool, signal: &CancellationToken) -> PluginResult<Value> {
        let limits = contract::def_const("SyncLimits").cloned().unwrap_or_else(|| json!({}));
        if bytes.len() as u64 > limits["maxObjectBytes"].as_u64().unwrap_or(64 << 20) {
            return Err(invalid("Sync writeObject payload exceeds the size limit"));
        }
        let provider_id = params["providerId"].as_str().unwrap_or("").to_string();
        let activation = self.activate(&provider_id, "sync", signal).await?;
        let operation_id = format!("sync:write:{}", uuid::Uuid::new_v4());
        let use_stream = prefer_stream || bytes.len() as u64 > limits["inlineObjectBytes"].as_u64().unwrap_or(96 * 1024);
        let input_id = format!("{operation_id}:input");
        let mut payload = json!({ "key": params["key"], "operationId": operation_id, "byteLength": bytes.len() });
        if let Some(r) = params.get("expectedRevision") {
            payload["expectedRevision"] = r.clone();
        }
        if use_stream {
            payload["inputStreamId"] = json!(input_id);
            payload["windowBytes"] = json!(STREAM_WINDOW_BYTES);
        } else {
            payload["encoding"] = json!("base64");
            payload["data"] = json!(B64.encode(bytes));
        }
        let request = json!({ "providerId": provider_id, "kind": "sync", "operation": "writeObject", "payload": payload, "deadlineMs": params["deadlineMs"] });
        let invoke = self.invoke(&request, Some(&activation), signal);
        if !use_stream {
            return invoke.await;
        }
        let feed = async {
            let input = self.supervisor.open_stream(&activation.0.id, &input_id, STREAM_WINDOW_BYTES, Some(&activation.2), None).await?;
            Self::write_stream(&input, bytes).await
        };
        let (result, fed) = tokio::join!(invoke, feed);
        fed?;
        result
    }

    pub fn shutdown(&self) {
        let ids: Vec<String> = self.sessions.lock().keys().cloned().collect();
        for id in ids {
            self.close_local(&id);
        }
        self.expectations.lock().clear();
    }
}

impl SecretLeaseStore {
    /// Lease bound to an in-memory secret (authentication challenge answers).
    pub fn issue_resolved(&self, plugin_id: &str, runtime_id: &str, secret: String, operation_id: &str, ttl_ms: i64) -> PluginResult<Value> {
        self.issue(plugin_id, runtime_id, LeaseCredential::Inline(secret), operation_id, Some(ttl_ms))
    }
}

/// Renderer-side channel for in-flight request cancellation.
pub fn cancellation_registry() -> Mutex<HashMap<String, CancellationToken>> {
    Mutex::new(HashMap::new())
}

/// A typed receiver for connection output used by tests.
pub struct ChannelSink(pub mpsc::UnboundedSender<Result<Vec<u8>, Value>>);
impl ConnectionSink for ChannelSink {
    fn data(&self, bytes: Vec<u8>) {
        let _ = self.0.send(Ok(bytes));
    }
    fn closed(&self, reason: Value) {
        let _ = self.0.send(Err(reason));
    }
}
