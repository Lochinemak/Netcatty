//! Domain services behind the capability catalog (Electron
//! `capabilities/services/*.cjs`). Vault, port-forward rules and terminal
//! lifecycle data live in the renderer and are reached through the
//! [`VaultAgent`] request/response bridge; credentials never cross it.

use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

/// Waits for `snippets.run` / `scripts.run` with `wait=true` (1h + overhead).
pub const VAULT_AGENT_SCRIPT_WAIT_TIMEOUT_MS: u64 = 3_605_000;

/// Renderer request bridge (`netcatty:ai:vault-agent:request` / response).
#[async_trait::async_trait]
pub trait VaultAgent: Send + Sync {
    /// Ask the renderer to perform `op`; `timeout_ms` overrides the 15 s
    /// default. Failures are returned as `{ ok: false, error }`.
    async fn invoke(&self, op: &str, params: Value, timeout_ms: Option<u64>) -> Value;
}

/// Revalidates authorization right before a side effect.
pub type ExecGuard = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;

pub fn run_guard(guard: Option<&ExecGuard>) -> Result<(), String> {
    match guard {
        Some(g) => g(),
        None => Ok(()),
    }
}

fn pick(params: &Map<String, Value>, keys: &[&str]) -> Value {
    let mut out = Map::new();
    for key in keys {
        if let Some(v) = params.get(*key) {
            out.insert((*key).to_string(), v.clone());
        }
    }
    Value::Object(out)
}

fn parse_wait_flag(raw: Option<&Value>) -> bool {
    match raw {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(v) => {
            let s = match v {
                Value::String(s) => s.trim().to_lowercase(),
                other => other.to_string(),
            };
            matches!(s.as_str(), "true" | "1" | "yes")
        }
    }
}

/// Vault service method (`SERVICE_BINDINGS` `vault.*`) → renderer op.
pub async fn vault_service_call(agent: &dyn VaultAgent, method: &str, params: &Map<String, Value>) -> Value {
    let all = Value::Object(params.clone());
    let empty = json!({});
    let (op, args, timeout): (&str, Value, Option<u64>) = match method {
        "getHost" => ("host.get", pick(params, &["hostId"]), None),
        "listHosts" => ("host.list", empty, None),
        "openHost" => ("host.open", pick(params, &["hostId", "chatSessionId", "newTab", "workspaceId"]), None),
        "createHosts" => ("hosts.create", all, None),
        "updateHost" => ("host.update", all, None),
        "deleteHost" => ("host.delete", pick(params, &["hostId"]), None),
        "importHosts" => ("host.import", all, None),
        "getHostNotes" => ("host.notes.get", pick(params, &["hostId"]), None),
        "setHostNotes" => ("host.notes.set", pick(params, &["hostId", "notes"]), None),
        "listNotes" => ("note.list", empty, None),
        "getNote" => ("note.get", pick(params, &["noteId", "offset", "maxChars", "query", "expectedUpdatedAt"]), None),
        "createNote" => ("note.create", all, None),
        "updateNote" => ("note.update", all, None),
        "deleteNote" => ("note.delete", pick(params, &["noteId"]), None),
        "importNotes" => ("note.import", all, None),
        "listIdentities" => ("identity.list", empty, None),
        "listProxyProfiles" => ("proxyProfile.list", empty, None),
        "listGroups" => ("group.list", empty, None),
        "createGroup" => ("group.create", all, None),
        "updateGroup" => ("group.update", all, None),
        "deleteGroup" => ("group.delete", all, None),
        "listSnippets" => ("snippets.list", empty, None),
        "getSnippet" => ("snippets.get", pick(params, &["snippetId"]), None),
        "runSnippet" => (
            "snippets.run",
            pick(params, &["snippetId", "sessionId", "variables", "chatSessionId", "wait"]),
            parse_wait_flag(params.get("wait")).then_some(VAULT_AGENT_SCRIPT_WAIT_TIMEOUT_MS),
        ),
        "createSnippet" => ("snippets.create", all, None),
        "updateSnippet" => ("snippets.update", all, None),
        "deleteSnippet" => ("snippets.delete", all, None),
        "listScripts" => ("scripts.list", empty, None),
        "getScript" => {
            let id = params.get("scriptId").cloned().unwrap_or(Value::Null);
            ("scripts.get", json!({ "scriptId": id, "snippetId": id }), None)
        }
        "createScript" => ("scripts.create", all, None),
        "updateScript" => ("scripts.update", all, None),
        "deleteScript" => ("scripts.delete", all, None),
        "runScript" => (
            "scripts.run",
            all,
            parse_wait_flag(params.get("wait")).then_some(VAULT_AGENT_SCRIPT_WAIT_TIMEOUT_MS),
        ),
        "getScriptReference" => ("scripts.reference", empty, None),
        "listScriptRuns" => ("scripts.runs.list", all, None),
        "stopScriptRun" => ("scripts.run.stop", all, None),
        "pauseScriptRun" => ("scripts.run.pause", all, None),
        "resumeScriptRun" => ("scripts.run.resume", all, None),
        "setScriptTargets" => ("scripts.targets.set", all, None),
        "listHostConnectScripts" => ("host.connectScripts.list", all, None),
        "setHostConnectScripts" => ("host.connectScripts.set", all, None),
        other => return json!({ "ok": false, "error": format!("Capability handler \"{other}\" is unavailable.") }),
    };
    agent.invoke(op, args, timeout).await
}

/// Active tunnels of the port-forward runtime.
#[async_trait::async_trait]
pub trait PortForwardRuntime: Send + Sync {
    async fn list_tunnels(&self) -> Vec<Value>;
}

pub async fn portforward_service_call(
    agent: &dyn VaultAgent,
    runtime: &dyn PortForwardRuntime,
    method: &str,
    params: &Map<String, Value>,
) -> Value {
    let all = Value::Object(params.clone());
    match method {
        "listRules" => agent.invoke("portforward.rules.list", json!({}), None).await,
        "createRule" => agent.invoke("portforward.rules.create", all, None).await,
        "updateRule" => agent.invoke("portforward.rules.update", all, None).await,
        "duplicateRule" => agent.invoke("portforward.rules.duplicate", all, None).await,
        "deleteRule" => agent.invoke("portforward.rules.delete", all, None).await,
        "listTunnels" => json!({ "ok": true, "tunnels": runtime.list_tunnels().await }),
        "start" | "stop" => {
            agent
                .invoke(
                    &format!("portforward.{method}"),
                    json!({ "ruleId": params.get("ruleId"), "chatSessionId": params.get("chatSessionId") }),
                    None,
                )
                .await
        }
        other => json!({ "ok": false, "error": format!("Capability handler \"{other}\" is unavailable.") }),
    }
}

/// Terminal lifecycle hooks of the host (scope checks, cleanup).
#[async_trait::async_trait]
pub trait SessionHooks: Send + Sync {
    /// `{ ok: true, connected? }` or an error result.
    fn validate_reconnect(&self, params: &Map<String, Value>) -> Value;
    /// Renderer recovery state + `shellReady` / `busy`.
    async fn inspect_recovery(&self, params: &Map<String, Value>, timeout_ms: u64) -> Value;
    fn validate_close(&self, params: &Map<String, Value>) -> Value;
    async fn before_close(&self, params: &Map<String, Value>);
    async fn after_close(&self, params: &Map<String, Value>, closed: bool, not_found: bool);
    async fn on_closed(&self, session_id: &str);
}

fn is_ok(v: &Value) -> bool {
    v.get("ok").and_then(Value::as_bool) == Some(true)
}

fn err(msg: &str) -> Value {
    json!({ "ok": false, "error": msg })
}

#[derive(Clone, Copy)]
struct Incident {
    started_at: Instant,
    attempts: u32,
    next_at: Instant,
}

/// Session reconnect / recover / close (Electron `sessionService.cjs` +
/// `sessionRecoveryService.cjs`). Uses tokio time, so tests can pause it.
pub struct SessionService {
    agent: Arc<dyn VaultAgent>,
    hooks: Arc<dyn SessionHooks>,
    incidents: parking_lot::Mutex<HashMap<String, Incident>>,
    reconnecting: parking_lot::Mutex<HashSet<String>>,
    recovery_incidents: parking_lot::Mutex<HashMap<String, Instant>>,
    recovery_attempts: parking_lot::Mutex<HashMap<String, (u32, Instant)>>,
    recovery_running: parking_lot::Mutex<HashSet<String>>,
}

const BUDGET: Duration = Duration::from_millis(120_000);
const CALL_BUDGET: Duration = Duration::from_millis(20_000);

impl SessionService {
    pub fn new(agent: Arc<dyn VaultAgent>, hooks: Arc<dyn SessionHooks>) -> Self {
        Self {
            agent,
            hooks,
            incidents: Default::default(),
            reconnecting: Default::default(),
            recovery_incidents: Default::default(),
            recovery_attempts: Default::default(),
            recovery_running: Default::default(),
        }
    }

    pub fn forget_reconnect(&self, session_id: &str) {
        self.incidents.lock().remove(session_id);
    }

    pub fn forget_recovery(&self, session_id: &str) {
        self.recovery_incidents.lock().remove(session_id);
        self.recovery_attempts.lock().remove(session_id);
    }

    /// `session.reconnect`: bounded attempts (3 in 120 s, 2 s / 5 s backoff).
    pub async fn reconnect(&self, params: &Map<String, Value>, guard: Option<&ExecGuard>, deadline_at: Option<Instant>) -> Result<Value, String> {
        let Some(id) = params.get("sessionId").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(err("sessionId is required."));
        };
        let id = id.to_string();
        let validation = self.hooks.validate_reconnect(params);
        if !is_ok(&validation) {
            return Ok(validation);
        }
        run_guard(guard)?;
        let now = Instant::now();
        let deadline = deadline_at.unwrap_or(now + Duration::from_millis(5000));
        let timeout = deadline.saturating_duration_since(now).min(Duration::from_millis(5000));
        if timeout.is_zero() {
            return Ok(json!({ "ok": false, "started": false, "code": "RECONNECT_EXPIRED", "error": "Reconnect dispatch deadline expired." }));
        }
        if validation.get("connected").and_then(Value::as_bool) == Some(true) {
            self.incidents.lock().remove(&id);
            return Ok(json!({ "ok": true, "sessionId": id, "status": "connected", "started": false, "shellReady": false }));
        }
        if self.reconnecting.lock().contains(&id) {
            return Ok(json!({ "ok": true, "sessionId": id, "status": "reconnecting", "started": false }));
        }
        let incident = self.incidents.lock().get(&id).copied();
        if let Some(inc) = incident {
            if inc.attempts >= 3 || now.duration_since(inc.started_at) >= BUDGET {
                return Ok(json!({ "ok": false, "code": "RECONNECT_LIMIT", "error": "Recovery budget exhausted. Inspect the session or request user assistance; do not open repeated replacement tabs." }));
            }
            if now < inc.next_at {
                return Ok(json!({
                    "ok": false, "code": "RECONNECT_BACKOFF",
                    "retryAfterMs": inc.next_at.duration_since(now).as_millis() as u64,
                    "error": "Wait before retrying this session."
                }));
            }
        }
        self.reconnecting.lock().insert(id.clone());
        let next = Incident {
            started_at: incident.map(|i| i.started_at).unwrap_or(now),
            attempts: incident.map(|i| i.attempts).unwrap_or(0) + 1,
            next_at: now + Duration::from_millis(if incident.is_some() { 5000 } else { 2000 }),
        };
        self.incidents.lock().insert(id.clone(), next);
        let expires_at_ms = unix_ms() + timeout.as_millis() as u64;
        let result = self
            .agent
            .invoke(
                "session.reconnect",
                json!({ "sessionId": id, "expiresAt": expires_at_ms }),
                Some(timeout.as_millis() as u64),
            )
            .await;
        self.reconnecting.lock().remove(&id);
        let current = self.hooks.validate_reconnect(params);
        if !is_ok(&current) {
            return Ok(current);
        }
        run_guard(guard)?;
        if result.get("status").and_then(Value::as_str) == Some("connected") {
            self.incidents.lock().remove(&id);
        } else if result.get("started").and_then(Value::as_bool) == Some(false) {
            let mut incidents = self.incidents.lock();
            match incident {
                Some(prev) => incidents.insert(id.clone(), prev),
                None => incidents.remove(&id),
            };
        }
        Ok(result)
    }

    /// `session.recover`: inspect, reconnect with backoff, report readiness.
    /// Never executes commands or creates terminals.
    pub async fn recover(&self, params: &Map<String, Value>, guard: Option<&ExecGuard>) -> Result<Value, String> {
        let Some(id) = params.get("sessionId").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(err("sessionId is required."));
        };
        let id = id.to_string();
        let validate = || -> Result<Option<Value>, String> {
            let v = self.hooks.validate_reconnect(params);
            if !is_ok(&v) {
                return Ok(Some(if v.is_object() { v } else { err("Recovery not authorized.") }));
            }
            run_guard(guard)?;
            Ok(None)
        };
        if let Some(denied) = validate()? {
            return Ok(denied);
        }
        let pending = || {
            json!({ "ok": true, "sessionId": id, "status": "pending", "shellReady": false, "nextAction": "session_recover", "retryAfterMs": 1000 })
        };
        if !self.recovery_running.lock().insert(id.clone()) {
            return Ok(pending());
        }
        let result = self.recover_loop(params, &id, &validate, &pending).await;
        self.recovery_running.lock().remove(&id);
        result
    }

    async fn recover_loop(
        &self,
        params: &Map<String, Value>,
        id: &str,
        validate: &(dyn Fn() -> Result<Option<Value>, String> + Sync),
        pending: &(dyn Fn() -> Value + Sync),
    ) -> Result<Value, String> {
        let started_at = *self.recovery_incidents.lock().entry(id.to_string()).or_insert_with(Instant::now);
        let call_deadline = Instant::now() + CALL_BUDGET;
        let finish_connected = |state: &Value| -> Value {
            self.recovery_incidents.lock().remove(id);
            self.recovery_attempts.lock().remove(id);
            let shell_ready = match state.get("shellReady") {
                Some(Value::Bool(true)) => json!(true),
                Some(Value::Bool(false)) => json!(false),
                _ => Value::Null,
            };
            let mut out = state.clone();
            out["sessionId"] = json!(id);
            out["shellReady"] = shell_ready.clone();
            out["status"] = json!("ready");
            out["nextAction"] = json!(if shell_ready == json!(true) { "continue_task" } else { "inspect_shell" });
            out
        };
        let classify = |state: &Value| -> Option<Value> {
            if state.get("stopped").and_then(Value::as_bool) == Some(true) {
                return Some(json!({ "ok": false, "sessionId": id, "status": "stopped", "code": "RECOVERY_CANCELLED", "error": "The user stopped this terminal connection. Do not reconnect automatically." }));
            }
            if state.get("waitingForInput").and_then(Value::as_bool) == Some(true) {
                let mut out = state.clone();
                out["sessionId"] = json!(id);
                out["status"] = json!("needs_input");
                out["shellReady"] = json!(false);
                out["nextAction"] = json!("user_input");
                return Some(out);
            }
            if state.get("busy").and_then(Value::as_bool) == Some(true) {
                let mut out = state.clone();
                out["sessionId"] = json!(id);
                out["status"] = json!("busy");
                out["shellReady"] = json!(false);
                out["nextAction"] = json!("inspect_job");
                return Some(out);
            }
            None
        };
        while Instant::now() < call_deadline {
            if let Some(blocked) = validate()? {
                return Ok(blocked);
            }
            let budget = call_deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(2000));
            let state = self.hooks.inspect_recovery(params, budget.as_millis() as u64).await;
            if let Some(revoked) = validate()? {
                return Ok(revoked);
            }
            if !is_ok(&state) {
                return Ok(if state.is_object() { state } else { err("Recovery state is unavailable.") });
            }
            if let Some(out) = classify(&state) {
                return Ok(out);
            }
            let status = state.get("status").and_then(Value::as_str).unwrap_or("");
            if status == "connected" {
                return Ok(finish_connected(&state));
            }
            if Instant::now().duration_since(started_at) >= BUDGET {
                return Ok(json!({ "ok": false, "sessionId": id, "code": "RECOVERY_LIMIT", "error": "Recovery elapsed budget exhausted. Inspect the blocked session and continue independent authorized work." }));
            }
            let mut wait = Duration::from_millis(1000);
            let reconnecting = state.get("reconnecting").and_then(Value::as_bool) == Some(true);
            if status == "disconnected" && !reconnecting {
                if state.get("reconnectAllowed").and_then(Value::as_bool) != Some(true) {
                    let mut out = state.clone();
                    out["sessionId"] = json!(id);
                    out["status"] = json!("unavailable");
                    out["nextAction"] = json!("inspect_terminal");
                    return Ok(out);
                }
                let (attempts, next_at) = self.recovery_attempts.lock().get(id).copied().unwrap_or((0, Instant::now()));
                if attempts >= 3 {
                    return Ok(json!({ "ok": false, "sessionId": id, "code": "RECONNECT_LIMIT", "error": "Three recovery attempts exhausted without a restored connection." }));
                }
                if next_at > Instant::now() {
                    wait = next_at - Instant::now();
                } else {
                    let deadline = call_deadline.min(started_at + BUDGET);
                    let result = self.reconnect(params, None, Some(deadline)).await?;
                    let backoff = result.get("code").and_then(Value::as_str) == Some("RECONNECT_BACKOFF");
                    if result.get("started").and_then(Value::as_bool) != Some(false) && !backoff {
                        let attempts = attempts + 1;
                        let delay = if attempts == 1 { 2000 } else { 5000 };
                        self.recovery_attempts
                            .lock()
                            .insert(id.to_string(), (attempts, Instant::now() + Duration::from_millis(delay)));
                    }
                    if let Some(c) = validate()? {
                        return Ok(c);
                    }
                    if result.get("ok").and_then(Value::as_bool) == Some(false) {
                        if !backoff {
                            return Ok(result);
                        }
                        wait = Duration::from_millis(result.get("retryAfterMs").and_then(Value::as_u64).unwrap_or(1000).max(1000));
                    }
                }
            } else if !matches!(status, "connected" | "connecting" | "disconnected") {
                return Ok(json!({ "ok": false, "sessionId": id, "error": "Unknown terminal recovery state; inspect before retrying." }));
            }
            let wait_until = (Instant::now() + wait).min(call_deadline).min(started_at + BUDGET);
            while Instant::now() < wait_until {
                let step = wait_until.saturating_duration_since(Instant::now()).min(Duration::from_millis(1000));
                tokio::time::sleep(step).await;
                if let Some(c) = validate()? {
                    return Ok(c);
                }
            }
        }
        if let Some(blocked) = validate()? {
            return Ok(blocked);
        }
        let state = self.hooks.inspect_recovery(params, 2000).await;
        if let Some(revoked) = validate()? {
            return Ok(revoked);
        }
        if !is_ok(&state) {
            return Ok(if state.is_object() { state } else { err("Recovery state is unavailable.") });
        }
        if let Some(out) = classify(&state) {
            return Ok(out);
        }
        if state.get("status").and_then(Value::as_str) == Some("connected") {
            return Ok(finish_connected(&state));
        }
        Ok(pending())
    }

    /// `session.close` (scope-validated) / idle close (`skip_validation`).
    pub async fn close(&self, params: &Map<String, Value>, guard: Option<&ExecGuard>, skip_validation: bool) -> Result<Value, String> {
        let Some(session_id) = params.get("sessionId").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
            return Ok(err("sessionId is required."));
        };
        if !skip_validation {
            let v = self.hooks.validate_close(params);
            if v.get("ok").and_then(Value::as_bool) == Some(false) {
                return Ok(v);
            }
        }
        self.hooks.before_close(params).await;
        if let Err(e) = run_guard(guard) {
            self.hooks.after_close(params, false, false).await;
            return Err(e);
        }
        let result = self.agent.invoke("session.close", json!({ "sessionId": session_id }), None).await;
        let mut closed = false;
        if result.get("ok").and_then(Value::as_bool) != Some(false) {
            self.hooks.on_closed(session_id).await;
            closed = true;
        }
        let not_found = result
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|e| e.to_lowercase().contains("was not found"));
        self.hooks.after_close(params, closed, not_found).await;
        Ok(result)
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Default)]
    struct Agent {
        calls: Mutex<Vec<(String, Value, Option<u64>)>>,
        reply: Mutex<Option<Value>>,
    }
    #[async_trait::async_trait]
    impl VaultAgent for Agent {
        async fn invoke(&self, op: &str, params: Value, timeout: Option<u64>) -> Value {
            self.calls.lock().push((op.into(), params, timeout));
            self.reply.lock().clone().unwrap_or(json!({ "ok": true, "started": true }))
        }
    }

    #[tokio::test]
    async fn vault_service_maps_ops_and_params() {
        let agent = Agent::default();
        let p = json!({ "hostId": "host-1", "chatSessionId": "chat-1", "workspaceId": "current", "newTab": true, "x": 1 });
        vault_service_call(&agent, "openHost", p.as_object().unwrap()).await;
        let p = json!({ "hostId": "h", "ignored": "v" });
        vault_service_call(&agent, "deleteHost", p.as_object().unwrap()).await;
        let p = json!({ "snippetId": "s", "sessionId": "x", "wait": "true" });
        vault_service_call(&agent, "runSnippet", p.as_object().unwrap()).await;
        let calls = agent.calls.lock();
        assert_eq!(calls[0].0, "host.open");
        assert_eq!(calls[0].1, json!({ "hostId": "host-1", "chatSessionId": "chat-1", "newTab": true, "workspaceId": "current" }));
        assert_eq!(calls[1].1, json!({ "hostId": "h" }));
        assert_eq!(calls[2].2, Some(VAULT_AGENT_SCRIPT_WAIT_TIMEOUT_MS));
    }

    struct Hooks {
        allowed: Mutex<bool>,
        state: Mutex<Value>,
    }
    #[async_trait::async_trait]
    impl SessionHooks for Hooks {
        fn validate_reconnect(&self, _p: &Map<String, Value>) -> Value {
            if *self.allowed.lock() { json!({ "ok": true }) } else { json!({ "ok": false, "error": "scope revoked" }) }
        }
        async fn inspect_recovery(&self, _p: &Map<String, Value>, _t: u64) -> Value {
            self.state.lock().clone()
        }
        fn validate_close(&self, _p: &Map<String, Value>) -> Value {
            json!({ "ok": false, "error": "scope was cleaned" })
        }
        async fn before_close(&self, _p: &Map<String, Value>) {}
        async fn after_close(&self, _p: &Map<String, Value>, _c: bool, _n: bool) {}
        async fn on_closed(&self, _s: &str) {}
    }

    fn svc(state: Value) -> (SessionService, Arc<Agent>, Arc<Hooks>) {
        let agent = Arc::new(Agent::default());
        let hooks = Arc::new(Hooks { allowed: Mutex::new(true), state: Mutex::new(state) });
        (SessionService::new(agent.clone(), hooks.clone()), agent, hooks)
    }

    fn params(id: &str) -> Map<String, Value> {
        json!({ "sessionId": id }).as_object().unwrap().clone()
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_backoff_and_limit() {
        let (s, agent, _) = svc(json!({}));
        let p = params("s");
        assert_eq!(s.reconnect(&p, None, None).await.unwrap()["started"], true);
        assert_eq!(s.reconnect(&p, None, None).await.unwrap()["code"], "RECONNECT_BACKOFF");
        tokio::time::advance(Duration::from_millis(2000)).await;
        assert_eq!(s.reconnect(&p, None, None).await.unwrap()["started"], true);
        assert_eq!(s.reconnect(&p, None, None).await.unwrap()["retryAfterMs"], 5000);
        tokio::time::advance(Duration::from_millis(5000)).await;
        assert_eq!(s.reconnect(&p, None, None).await.unwrap()["started"], true);
        tokio::time::advance(Duration::from_millis(200_000)).await;
        assert_eq!(s.reconnect(&p, None, None).await.unwrap()["code"], "RECONNECT_LIMIT");
        assert_eq!(agent.calls.lock().len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_shares_budget_and_stops_after_three_attempts() {
        let (s, agent, _) = svc(json!({ "ok": true, "status": "disconnected", "reconnectAllowed": true }));
        let r = s.recover(&params("failed"), None).await.unwrap();
        assert_eq!(r["code"], "RECONNECT_LIMIT");
        assert_eq!(agent.calls.lock().len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_reports_ready_and_advisory_readiness() {
        let (s, _, _) = svc(json!({ "ok": true, "status": "connected", "shellReady": null }));
        let r = s.recover(&params("s"), None).await.unwrap();
        assert_eq!(r["status"], "ready");
        assert_eq!(r["nextAction"], "inspect_shell");
        let (s, agent, _) = svc(json!({ "ok": true, "status": "connected", "shellReady": true }));
        let r = s.recover(&params("s"), None).await.unwrap();
        assert_eq!(r["nextAction"], "continue_task");
        assert!(agent.calls.lock().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_stops_for_auth_busy_unavailable_and_user_stop() {
        for (state, expected) in [
            (json!({ "ok": true, "status": "disconnected", "waitingForInput": true }), "needs_input"),
            (json!({ "ok": true, "status": "connected", "busy": true }), "busy"),
            (json!({ "ok": true, "status": "disconnected", "reconnectAllowed": false }), "unavailable"),
            (json!({ "ok": true, "status": "disconnected", "stopped": true, "reconnectAllowed": true }), "stopped"),
        ] {
            let (s, agent, _) = svc(state);
            assert_eq!(s.recover(&params("s"), None).await.unwrap()["status"], expected);
            assert!(agent.calls.lock().is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn still_connecting_budget_returns_pending() {
        let (s, _, _) = svc(json!({ "ok": true, "status": "connecting" }));
        let r = s.recover(&params("s"), None).await.unwrap();
        assert_eq!(r["status"], "pending");
        assert_eq!(r["shellReady"], false);
    }

    #[tokio::test]
    async fn close_validates_scope_unless_tracked() {
        let (s, agent, _) = svc(json!({}));
        *agent.reply.lock() = Some(json!({ "ok": true, "status": "closed" }));
        assert_eq!(s.close(&params("x"), None, false).await.unwrap()["ok"], false);
        assert!(agent.calls.lock().is_empty());
        assert_eq!(s.close(&params("x"), None, true).await.unwrap()["ok"], true);
        assert_eq!(agent.calls.lock()[0].0, "session.close");
        let calls = AtomicU32::new(0);
        let guard: ExecGuard = Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err("start a new chat".into())
        });
        assert!(s.close(&params("x"), Some(&guard), true).await.is_err());
        assert_eq!(agent.calls.lock().len(), 1);
    }
}
