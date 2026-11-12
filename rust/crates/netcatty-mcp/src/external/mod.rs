//! External MCP controller (Electron `externalMcpController.cjs`).
//!
//! Lets third-party MCP clients (Codex, Claude Code, Grok, any streamable
//! HTTP client) drive Netcatty sessions in the reserved
//! [`EXTERNAL_MCP_CHAT_SESSION_ID`] scope:
//!
//! * enable / disable with a dedicated external token (soft revoke on
//!   disable: sockets stay open, RPCs are rejected) and a 0600 discovery
//!   file read by the stdio helper (`NETCATTY_MCP_HELPER=external`);
//! * temporary mode with an idle auto-disable timer, persistent mode;
//! * optional streamable-HTTP endpoint ([`http`]);
//! * privacy redaction policy written into discovery;
//! * one-click client setup ([`setup`]) and the bundled skill ([`skill`]).

pub mod http;
pub mod setup;
pub mod skill;

use crate::discovery::{build_discovery_env, external_discovery_payload};
use crate::host::{ExternalHooks, McpHost, EXTERNAL_MCP_CHAT_SESSION_ID};
use crate::redaction::{normalize_redaction_config, RedactionConfig};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Weak};

pub const MODE_TEMPORARY: &str = "temporary";
pub const MODE_PERSISTENT: &str = "persistent";
pub const DEFAULT_IDLE_TIMEOUT_MINUTES: u64 = 10;
pub const MIN_IDLE_TIMEOUT_MINUTES: u64 = 1;
pub const MAX_IDLE_TIMEOUT_MINUTES: u64 = 24 * 60;

pub fn normalize_mode(v: Option<&str>) -> &'static str {
    if v == Some(MODE_PERSISTENT) {
        MODE_PERSISTENT
    } else {
        MODE_TEMPORARY
    }
}

pub fn normalize_idle_timeout_minutes(v: &Value) -> u64 {
    let n = match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    };
    match n.filter(|n| n.is_finite()) {
        None => DEFAULT_IDLE_TIMEOUT_MINUTES,
        Some(n) => (n.round().max(MIN_IDLE_TIMEOUT_MINUTES as f64) as u64).min(MAX_IDLE_TIMEOUT_MINUTES),
    }
}

struct Inner {
    enabled: bool,
    state: &'static str,
    error: Option<String>,
    mode: &'static str,
    idle_timeout_minutes: u64,
    session_idle_timeout_minutes: u64,
    last_activity_at: Option<u64>,
    idle_expires_at: Option<u64>,
    idle_timer: Option<tokio::task::JoinHandle<()>>,
    last_known_port: Option<u16>,
    last_known_token: Option<String>,
    redaction: RedactionConfig,
    http_enabled: bool,
    http_port: u16,
    http_allow_custom_bind: bool,
    http_listen_address: String,
    http_client_host: String,
    http_listening: bool,
    http_error: Option<String>,
    http_error_code: Option<String>,
    start_generation: u64,
}

/// The External MCP controller. Construct with [`ExternalMcpController::new`];
/// it registers itself as the host's [`ExternalHooks`].
pub struct ExternalMcpController {
    me: Weak<ExternalMcpController>,
    host: Arc<McpHost>,
    discovery_path: PathBuf,
    launcher: PathBuf,
    skill_path: Option<PathBuf>,
    inner: Mutex<Inner>,
    enable_lock: tokio::sync::Mutex<()>,
    http_lock: tokio::sync::Mutex<Option<http::HttpRuntime>>,
}

impl ExternalMcpController {
    pub fn new(host: Arc<McpHost>, discovery_path: PathBuf, launcher: PathBuf, skill_path: Option<PathBuf>) -> Arc<Self> {
        // Rotate any stale discovery from a previous process.
        let _ = std::fs::remove_file(&discovery_path);
        let ctl = Arc::new_cyclic(|me| Self {
            me: me.clone(),
            host: host.clone(),
            discovery_path,
            launcher,
            skill_path,
            inner: Mutex::new(Inner {
                enabled: false,
                state: "disabled",
                error: None,
                mode: MODE_TEMPORARY,
                idle_timeout_minutes: DEFAULT_IDLE_TIMEOUT_MINUTES,
                session_idle_timeout_minutes: crate::host::idle::DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES,
                last_activity_at: None,
                idle_expires_at: None,
                idle_timer: None,
                last_known_port: None,
                last_known_token: None,
                redaction: RedactionConfig::default(),
                http_enabled: false,
                http_port: http::DEFAULT_EXTERNAL_MCP_HTTP_PORT,
                http_allow_custom_bind: false,
                http_listen_address: "0.0.0.0".into(),
                http_client_host: String::new(),
                http_listening: false,
                http_error: None,
                http_error_code: None,
                start_generation: 0,
            }),
            enable_lock: tokio::sync::Mutex::new(()),
            http_lock: tokio::sync::Mutex::new(None),
        });
        host.set_external_hooks(Some(Arc::new(Hooks(Arc::downgrade(&ctl)))));
        ctl
    }

    pub fn chat_session_id(&self) -> &'static str {
        EXTERNAL_MCP_CHAT_SESSION_ID
    }

    pub fn discovery_env(&self) -> Vec<(String, String)> {
        build_discovery_env(Some(&self.discovery_path))
    }

    pub fn launcher_path(&self) -> String {
        self.launcher.to_string_lossy().into_owned()
    }

    /// Accept clients while starting/running once the switch is on.
    pub fn is_enabled(&self) -> bool {
        let i = self.inner.lock();
        i.enabled && matches!(i.state, "starting" | "running")
    }

    fn effective_listen(i: &Inner) -> String {
        if !i.http_allow_custom_bind {
            return http::DEFAULT_EXTERNAL_MCP_HTTP_HOST.into();
        }
        http::normalize_listen_address(&i.http_listen_address).unwrap_or_else(|_| i.http_listen_address.clone())
    }

    fn http_status(i: &Inner) -> Value {
        let state = if i.http_enabled && i.http_error.is_some() {
            "error"
        } else if i.http_enabled && i.http_listening {
            "running"
        } else if i.http_enabled && i.enabled {
            "starting"
        } else {
            "disabled"
        };
        let listen = Self::effective_listen(i);
        let url = http::build_client_url(&listen, i.http_port, &i.http_client_host);
        let (mut error, mut code) = (i.http_error.clone(), i.http_error_code.clone());
        if code.is_none() && http::is_wildcard_bind(&listen) && url.is_none() {
            code = Some("client_host_required".into());
            error = Some("Enter the IP clients should connect to. 0.0.0.0 is not a reachable address.".into());
        }
        json!({
            "enabled": i.http_enabled,
            "listening": i.http_listening,
            "port": i.http_port,
            "listenAddress": listen,
            "allowCustomBind": i.http_allow_custom_bind,
            "clientHost": i.http_client_host,
            "url": url,
            "bearerToken": if i.http_enabled && i.enabled { i.last_known_token.clone() } else { None },
            "state": state,
            "error": error,
            "errorCode": code,
        })
    }

    /// `getStatus` payload.
    pub fn status(&self) -> Value {
        let exposed = self.host.scoped_session_ids(Some(EXTERNAL_MCP_CHAT_SESSION_ID)).len();
        let permission_mode = self.host.permission_mode();
        let i = self.inner.lock();
        json!({
            "ok": true,
            "enabled": i.enabled,
            "state": i.state,
            "host": "127.0.0.1",
            "port": i.last_known_port,
            "discoveryPath": self.discovery_path.to_string_lossy(),
            "launcherPath": self.launcher_path(),
            "chatSessionId": EXTERNAL_MCP_CHAT_SESSION_ID,
            "exposedSessionCount": exposed,
            "mode": i.mode,
            "idleTimeoutMinutes": i.idle_timeout_minutes,
            "sessionIdleTimeoutMinutes": i.session_idle_timeout_minutes,
            "lastActivityAt": i.last_activity_at,
            "idleExpiresAt": i.idle_expires_at,
            "permissionMode": permission_mode,
            "hostRunning": i.last_known_port.is_some(),
            "error": i.error,
            "http": Self::http_status(&i),
            "redaction": crate::redaction::config_value(&i.redaction),
        })
    }

    fn write_discovery(&self) -> std::io::Result<()> {
        let (port, token, redaction) = {
            let i = self.inner.lock();
            match (i.last_known_port, i.last_known_token.clone()) {
                (Some(p), Some(t)) => (p, t, crate::redaction::config_value(&i.redaction)),
                _ => return Ok(()),
            }
        };
        let payload = external_discovery_payload(port, &token, &self.host.permission_mode(), EXTERNAL_MCP_CHAT_SESSION_ID, Some(&redaction));
        crate::host::tcp::write_json_private(&self.discovery_path, &payload)
    }

    fn schedule_idle_shutdown(&self) {
        let mut i = self.inner.lock();
        if let Some(t) = i.idle_timer.take() {
            t.abort();
        }
        if !i.enabled || i.state != "running" || i.mode != MODE_TEMPORARY {
            i.idle_expires_at = None;
            return;
        }
        let now = crate::host::now_ms();
        let last = *i.last_activity_at.get_or_insert(now);
        let expires = last + i.idle_timeout_minutes * 60_000;
        i.idle_expires_at = Some(expires);
        let me = self.me.clone();
        let delay = expires.saturating_sub(now);
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            i.idle_timer = Some(rt.spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                if let Some(me) = me.upgrade() {
                    me.inner.lock().idle_timer = None;
                    me.set_enabled(false).await;
                }
            }));
        }
    }

    /// Bump the activity clock (every external RPC).
    pub fn record_activity(&self) {
        {
            let mut i = self.inner.lock();
            if !i.enabled {
                return;
            }
            i.last_activity_at = Some(crate::host::now_ms());
        }
        self.schedule_idle_shutdown();
    }

    async fn start_runtime(&self) -> Result<(), String> {
        let port = self.host.get_or_create_host().await.map_err(|e| e.to_string())?;
        let token = self.host.issue_external_mcp_auth_token();
        if port == 0 || token.is_empty() {
            return Err("Failed to resolve MCP bridge port/token for external mode.".into());
        }
        {
            let mut i = self.inner.lock();
            i.last_known_port = Some(port);
            i.last_known_token = Some(token);
            if !i.enabled {
                return Err("External MCP was disabled during startup.".into());
            }
        }
        self.write_discovery().map_err(|e| e.to_string())?;
        self.inner.lock().last_activity_at = Some(crate::host::now_ms());
        self.host.sync_live_sessions_to_external_scope();
        self.apply_http().await;
        Ok(())
    }

    async fn stop_runtime(&self) {
        {
            let mut i = self.inner.lock();
            if let Some(t) = i.idle_timer.take() {
                t.abort();
            }
            i.idle_expires_at = None;
            i.last_known_port = None;
            i.last_known_token = None;
        }
        let _ = std::fs::remove_file(&self.discovery_path);
        // Soft revoke: reject reserved-scope RPCs while keeping sockets so
        // stdio clients can resume after re-enable.
        self.host.revoke_external_mcp_auth_token();
        self.host.apply_chat_session_cancelled(EXTERNAL_MCP_CHAT_SESSION_ID, true).await;
        self.host.cleanup_scoped_metadata(EXTERNAL_MCP_CHAT_SESSION_ID).await;
        // cleanup clears the cancel flag; re-assert it.
        self.host.set_chat_session_cancelled(EXTERNAL_MCP_CHAT_SESSION_ID, true);
        self.apply_http().await;
    }

    /// `setEnabled` (serialized).
    pub async fn set_enabled(&self, enable: bool) -> Value {
        let _guard = self.enable_lock.lock().await;
        let running = {
            let mut i = self.inner.lock();
            i.enabled = enable;
            if !enable {
                i.start_generation += 1;
                i.state = "disabled";
                i.error = None;
            }
            i.state == "running" && i.last_known_port.is_some() && i.last_known_token.is_some()
        };
        if !enable {
            self.stop_runtime().await;
            return self.status();
        }
        if running {
            let _ = self.write_discovery();
            self.schedule_idle_shutdown();
            return self.status();
        }
        let generation = {
            let mut i = self.inner.lock();
            i.start_generation += 1;
            i.state = "starting";
            i.error = None;
            i.start_generation
        };
        self.host.set_chat_session_cancelled(EXTERNAL_MCP_CHAT_SESSION_ID, false);
        match self.start_runtime().await {
            Ok(()) => {
                {
                    let mut i = self.inner.lock();
                    if !i.enabled || generation != i.start_generation {
                        i.state = "disabled";
                        i.error = None;
                        drop(i);
                        return self.status();
                    }
                    i.state = "running";
                }
                self.schedule_idle_shutdown();
            }
            Err(e) => {
                {
                    let mut i = self.inner.lock();
                    if generation != i.start_generation {
                        drop(i);
                        return self.status();
                    }
                    i.error = Some(e);
                    i.enabled = false;
                    i.state = "disabled";
                }
                self.stop_runtime().await;
            }
        }
        self.status()
    }

    /// `setConfig` + `whenHttpSettled`. Returns `{ ...status, ok: false,
    /// error }` for an invalid privacy policy.
    pub async fn set_config(&self, config: &Value) -> Value {
        if let Some(r) = config.get("redaction") {
            let next = match normalize_redaction_config(if r.is_null() { None } else { Some(r) }) {
                Ok(n) => n,
                Err(_) => {
                    let mut s = self.status();
                    s["ok"] = json!(false);
                    s["error"] = json!("Invalid privacy rules. Check CIDRs and regular expressions.");
                    return s;
                }
            };
            let previous = {
                let mut i = self.inner.lock();
                (next != i.redaction).then(|| std::mem::replace(&mut i.redaction, next))
            };
            if let Some(previous) = previous {
                if self.write_discovery().is_err() {
                    self.inner.lock().redaction = previous;
                    let mut s = self.status();
                    s["ok"] = json!(false);
                    s["error"] = json!("Privacy settings could not be saved. Retry before reconnecting clients.");
                    return s;
                }
            }
        }
        let (reschedule, session_idle) = {
            let mut i = self.inner.lock();
            let mode = config.get("mode").filter(|v| !v.is_null()).map(|v| normalize_mode(v.as_str())).unwrap_or(i.mode);
            let idle = config.get("idleTimeoutMinutes").filter(|v| !v.is_null()).map(normalize_idle_timeout_minutes).unwrap_or(i.idle_timeout_minutes);
            if let Some(v) = config.get("sessionIdleTimeoutMinutes").filter(|v| !v.is_null()) {
                i.session_idle_timeout_minutes = crate::host::idle::normalize_session_idle_timeout_minutes(v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())));
            }
            let changed = mode != i.mode || idle != i.idle_timeout_minutes;
            i.mode = mode;
            i.idle_timeout_minutes = idle;
            let reschedule = changed && i.enabled && i.state == "running";
            if reschedule {
                i.last_activity_at = Some(crate::host::now_ms());
            }
            (reschedule, i.session_idle_timeout_minutes)
        };
        self.host.set_session_idle_timeout_minutes(Some(session_idle as f64));
        if reschedule {
            self.schedule_idle_shutdown();
        }
        let truthy = |v: &Value| match v {
            Value::Bool(b) => *b,
            Value::Number(n) => n.as_f64() != Some(0.0),
            Value::String(s) => !s.is_empty(),
            Value::Null => false,
            _ => true,
        };
        let mut http_changed = false;
        {
            let mut i = self.inner.lock();
            if let Some(v) = config.get("httpEnabled").filter(|v| !v.is_null()) {
                if truthy(v) != i.http_enabled {
                    i.http_enabled = truthy(v);
                    http_changed = true;
                }
            }
            if let Some(v) = config.get("httpPort").filter(|v| !v.is_null()) {
                if let Ok(p) = http::normalize_http_port(v) {
                    if p != i.http_port {
                        i.http_port = p;
                        i.http_error = None;
                        i.http_error_code = None;
                        http_changed = true;
                    }
                }
            }
            let custom_requested = config.get("httpAllowCustomBind").is_some_and(truthy);
            if let Some(v) = config.get("httpAllowCustomBind").filter(|v| !v.is_null()) {
                if truthy(v) != i.http_allow_custom_bind {
                    i.http_allow_custom_bind = truthy(v);
                    http_changed = true;
                }
            }
            if let Some(v) = config.get("httpListenAddress").filter(|v| !v.is_null()) {
                match http::normalize_listen_address(v.as_str().unwrap_or("")) {
                    Ok(a) if a != i.http_listen_address => {
                        i.http_listen_address = a;
                        http_changed = true;
                    }
                    Ok(_) => {}
                    Err((code, msg)) if i.http_allow_custom_bind || custom_requested => {
                        i.http_error = Some(msg);
                        i.http_error_code = Some(code);
                    }
                    Err(_) => {}
                }
            }
            if let Some(v) = config.get("httpClientHost").filter(|v| !v.is_null()) {
                if let Ok(a) = http::normalize_client_host(v.as_str().unwrap_or("")) {
                    i.http_client_host = a;
                }
            }
        }
        if config.get("rotateHttpToken") == Some(&json!(true)) && self.is_enabled() {
            let token = self.host.issue_external_mcp_auth_token();
            self.inner.lock().last_known_token = Some(token);
            let _ = self.write_discovery();
        }
        if http_changed {
            self.apply_http().await;
        }
        self.status()
    }

    /// Bring the HTTP listener in line with the settings (serialized).
    async fn apply_http(&self) {
        let mut rt = self.http_lock.lock().await;
        if let Some(old) = rt.take() {
            old.stop().await;
        }
        let (want, host, port) = {
            let i = self.inner.lock();
            (i.enabled && i.http_enabled, Self::effective_listen(&i), i.http_port)
        };
        if !want {
            let mut i = self.inner.lock();
            i.http_listening = false;
            if !i.http_enabled {
                i.http_error = None;
                i.http_error_code = None;
            }
            return;
        }
        let Some(me) = self.me.upgrade() else {
            return;
        };
        let hooks: Arc<dyn http::HttpHooks> = Arc::new(HttpHooksImpl(Arc::downgrade(&me)));
        let custom_invalid = {
            let i = self.inner.lock();
            i.http_allow_custom_bind && http::normalize_listen_address(&i.http_listen_address).is_err()
        };
        let result = if custom_invalid {
            Err(("invalid_address".to_string(), "Listen address must be an IP address such as 0.0.0.0 or a vEthernet address.".to_string()))
        } else {
            http::start(&host, port, self.host.clone(), hooks).await
        };
        let mut i = self.inner.lock();
        match result {
            Ok(r) => {
                *rt = Some(r);
                i.http_listening = true;
                i.http_error = None;
                i.http_error_code = None;
            }
            Err((code, msg)) => {
                i.http_listening = false;
                i.http_error = Some(msg);
                i.http_error_code = Some(code);
            }
        }
    }

    /// `getUniversalSetupPrompt`.
    pub async fn universal_setup_prompt(&self) -> Value {
        let result = skill::read_bundled(self.skill_path.as_deref()).and_then(|content| skill::build_universal_setup_prompt(&self.launcher_path(), &self.discovery_env(), &content));
        match result {
            Ok(prompt) => json!({ "ok": true, "prompt": prompt, "error": null }),
            Err(e) => json!({ "ok": false, "prompt": "", "error": e }),
        }
    }

    fn client_setup(&self, client: &str) -> Option<setup::ClientSetup> {
        let client: &'static str = match client {
            "codex" => "codex",
            "claude" => "claude",
            "grok" => "grok",
            _ => return None,
        };
        Some(setup::ClientSetup { client, launcher: self.launcher_path(), discovery_env: self.discovery_env(), skill_source: self.skill_path.clone() })
    }

    /// `externalMcp{Codex,Claude,Grok}GetStatus`.
    pub async fn client_status(&self, client: &str) -> Value {
        match self.client_setup(client) {
            Some(s) => s.status().await,
            None => json!({ "ok": false, "error": format!("Unknown MCP client: {client}") }),
        }
    }

    /// `externalMcp{Codex,Claude,Grok}Add`.
    pub async fn client_add(&self, client: &str) -> Value {
        match self.client_setup(client) {
            Some(s) => s.add().await,
            None => json!({ "ok": false, "error": format!("Unknown MCP client: {client}") }),
        }
    }

    /// App shutdown: remove discovery, stop HTTP.
    pub async fn cleanup(&self) {
        {
            let mut i = self.inner.lock();
            if let Some(t) = i.idle_timer.take() {
                t.abort();
            }
            i.enabled = false;
            i.state = "disabled";
            i.last_known_port = None;
            i.last_known_token = None;
        }
        let _ = std::fs::remove_file(&self.discovery_path);
        self.apply_http().await;
    }

    fn on_bridge_host_ready(&self, port: u16) {
        if !self.is_enabled() {
            return;
        }
        // Never write the shared Catty/CLI token; only an issued external one.
        let Some(token) = self.host.external_mcp_auth_token() else {
            return;
        };
        {
            let mut i = self.inner.lock();
            if port != 0 {
                i.last_known_port = Some(port);
            }
            i.last_known_token = Some(token);
        }
        let _ = self.write_discovery();
    }

    fn on_permission_mode_changed(&self) {
        if self.is_enabled() && self.inner.lock().state == "running" {
            let _ = self.write_discovery();
        }
    }
}

struct Hooks(Weak<ExternalMcpController>);

impl ExternalHooks for Hooks {
    fn is_enabled(&self) -> bool {
        self.0.upgrade().is_some_and(|c| c.is_enabled())
    }
    fn record_activity(&self) {
        if let Some(c) = self.0.upgrade() {
            c.record_activity();
        }
    }
    fn on_permission_mode_changed(&self) {
        if let Some(c) = self.0.upgrade() {
            c.on_permission_mode_changed();
        }
    }
    fn on_bridge_host_ready(&self, port: u16) {
        if let Some(c) = self.0.upgrade() {
            c.on_bridge_host_ready(port);
        }
    }
}

struct HttpHooksImpl(Weak<ExternalMcpController>);

impl http::HttpHooks for HttpHooksImpl {
    fn token(&self) -> String {
        self.0.upgrade().and_then(|c| c.inner.lock().last_known_token.clone()).unwrap_or_default()
    }
    fn is_enabled(&self) -> bool {
        self.0.upgrade().is_some_and(|c| {
            let on = c.is_enabled();
            if on {
                c.record_activity();
            }
            on
        })
    }
    fn redaction_config(&self) -> Value {
        self.0.upgrade().map(|c| crate::redaction::config_value(&c.inner.lock().redaction)).unwrap_or(Value::Null)
    }
}


#[cfg(test)]
mod tests;
