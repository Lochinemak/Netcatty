//! Service-backed capability RPC dispatch (Electron
//! `mcpServerBridge/capabilityRpcDispatch.cjs`): routes `vault/*`,
//! `portforward/*`, `session/*` (and their `public/*` aliases) to the
//! services with the permission policy, grants and approvals applied.

use crate::catalog::*;
use crate::grants::PermissionGrant;
use crate::policy::{evaluate_permission_with_grants, PermissionRequest, USER_DENIED_MESSAGE};
use crate::registry::capability_by_rpc_method;
use crate::services::{portforward_service_call, run_guard, vault_service_call, ExecGuard, PortForwardRuntime, SessionService, VaultAgent};
use crate::surfaces::mcp_tool_name_for_rpc_method;
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// Per-call context (`approvalContext`).
#[derive(Clone, Default)]
pub struct DispatchContext {
    /// Identity of the external MCP client (socket / HTTP session).
    pub external_client: Option<u64>,
    pub before_execute: Option<ExecGuard>,
}

/// Host hooks the dispatcher needs.
#[async_trait::async_trait]
pub trait CapabilityHost: Send + Sync {
    fn permission_mode(&self) -> String;
    fn permission_grants(&self) -> Vec<PermissionGrant>;
    fn is_chat_session_cancelled(&self, chat_session_id: Option<&str>) -> bool;
    /// `{ sessionId, hostId, label, hostname }` of `params.sessionId`.
    fn approval_target(&self, params: &Map<String, Value>) -> Option<Value>;
    fn has_session_approval(&self, ctx: &DispatchContext) -> bool;
    async fn request_approval(
        &self,
        tool_name: &str,
        args: Value,
        chat_session_id: Option<String>,
        target: Option<Value>,
        ctx: &DispatchContext,
    ) -> bool;
    /// Opaque scope generation captured before `host_open`.
    fn capture_host_open_scope(&self, chat_session_id: Option<&str>) -> Value;
    /// Bind an opened session to the chat; `Some(false)` = binding revoked.
    async fn on_host_opened(&self, chat_session_id: Option<&str>, session_id: &str, generation: Value, result: &Value) -> Option<bool>;
}

/// `(domain, method)` of a service-backed capability.
pub fn service_binding(capability_id: &str) -> Option<(&'static str, &'static str)> {
    Some(match capability_id {
        "vault.host.get" => ("vault", "getHost"),
        "vault.host.list" => ("vault", "listHosts"),
        "vault.host.open" => ("vault", "openHost"),
        "vault.hosts.create" => ("vault", "createHosts"),
        "vault.host.update" => ("vault", "updateHost"),
        "vault.host.delete" => ("vault", "deleteHost"),
        "vault.host.import" => ("vault", "importHosts"),
        "vault.host.notes.get" => ("vault", "getHostNotes"),
        "vault.host.notes.set" => ("vault", "setHostNotes"),
        "vault.note.list" => ("vault", "listNotes"),
        "vault.note.get" => ("vault", "getNote"),
        "vault.note.create" => ("vault", "createNote"),
        "vault.note.update" => ("vault", "updateNote"),
        "vault.note.delete" => ("vault", "deleteNote"),
        "vault.note.import" => ("vault", "importNotes"),
        "vault.identity.list" => ("vault", "listIdentities"),
        "vault.proxyProfile.list" => ("vault", "listProxyProfiles"),
        "vault.group.list" => ("vault", "listGroups"),
        "vault.group.create" => ("vault", "createGroup"),
        "vault.group.update" => ("vault", "updateGroup"),
        "vault.group.delete" => ("vault", "deleteGroup"),
        "vault.snippets.list" => ("vault", "listSnippets"),
        "vault.snippets.get" => ("vault", "getSnippet"),
        "vault.snippets.run" => ("vault", "runSnippet"),
        "vault.snippets.create" => ("vault", "createSnippet"),
        "vault.snippets.update" => ("vault", "updateSnippet"),
        "vault.snippets.delete" => ("vault", "deleteSnippet"),
        "vault.scripts.list" => ("vault", "listScripts"),
        "vault.scripts.get" => ("vault", "getScript"),
        "vault.scripts.create" => ("vault", "createScript"),
        "vault.scripts.update" => ("vault", "updateScript"),
        "vault.scripts.delete" => ("vault", "deleteScript"),
        "vault.scripts.run" => ("vault", "runScript"),
        "vault.scripts.reference" => ("vault", "getScriptReference"),
        "vault.scripts.runs.list" => ("vault", "listScriptRuns"),
        "vault.scripts.run.stop" => ("vault", "stopScriptRun"),
        "vault.scripts.run.pause" => ("vault", "pauseScriptRun"),
        "vault.scripts.run.resume" => ("vault", "resumeScriptRun"),
        "vault.scripts.targets.set" => ("vault", "setScriptTargets"),
        "vault.host.connectScripts.list" => ("vault", "listHostConnectScripts"),
        "vault.host.connectScripts.set" => ("vault", "setHostConnectScripts"),
        "portforward.rules.list" => ("portforward", "listRules"),
        "portforward.rules.create" => ("portforward", "createRule"),
        "portforward.rules.update" => ("portforward", "updateRule"),
        "portforward.rules.duplicate" => ("portforward", "duplicateRule"),
        "portforward.rules.delete" => ("portforward", "deleteRule"),
        "portforward.tunnels.list" => ("portforward", "listTunnels"),
        "portforward.start" => ("portforward", "start"),
        "portforward.stop" => ("portforward", "stop"),
        "session.close" => ("session", "close"),
        "session.reconnect" => ("session", "reconnect"),
        "session.recover" => ("session", "recover"),
        _ => return None,
    })
}

/// Capability and surface for a non-`netcatty/` method.
pub fn resolve_capability_surface(rpc_method: &str) -> Option<(&'static Capability, &'static str)> {
    for surface in [SURFACE_PUBLIC, SURFACE_GLOBAL, SURFACE_BUILTIN] {
        if rpc_method.starts_with("netcatty/") && surface != SURFACE_BUILTIN {
            continue;
        }
        if let Some(cap) = capability_by_rpc_method(rpc_method, surface) {
            return Some((cap, surface));
        }
    }
    None
}

pub struct CapabilityDispatcher {
    pub agent: Arc<dyn VaultAgent>,
    pub portforward: Arc<dyn PortForwardRuntime>,
    pub sessions: Arc<SessionService>,
    pub host: Arc<dyn CapabilityHost>,
}

impl CapabilityDispatcher {
    /// `Ok(None)` = not a service-backed method (UNROUTED). `Err` = a
    /// guard rejected execution (surfaced as a JSON-RPC error).
    pub async fn dispatch(&self, rpc_method: &str, params: &Map<String, Value>, ctx: &DispatchContext) -> Result<Option<Value>, String> {
        if rpc_method.starts_with("netcatty/") {
            return Ok(None);
        }
        let Some((cap, surface)) = resolve_capability_surface(rpc_method) else {
            return Ok(None);
        };
        if !cap.is_implemented() {
            return Ok(Some(json!({
                "ok": false,
                "code": "CAPABILITY_NOT_IMPLEMENTED",
                "error": format!("Capability \"{}\" is not implemented yet.", cap.id),
            })));
        }
        let Some((domain, method)) = service_binding(&cap.id) else {
            return Ok(None);
        };
        let chat = params.get("chatSessionId").and_then(Value::as_str);
        let mode = self.host.permission_mode();
        let mut approval_target = if matches!(cap.id.as_str(), "session.close" | "session.reconnect" | "session.recover") {
            self.host.approval_target(params)
        } else {
            None
        };
        if cap.id == "vault.host.open" && mode == MODE_CONFIRM {
            let requested = params.get("hostId").and_then(Value::as_str).unwrap_or("").trim().to_string();
            let mut host = Value::Null;
            if !requested.is_empty() {
                let lookup = vault_service_call(&*self.agent, "getHost", json!({ "hostId": requested }).as_object().unwrap()).await;
                if lookup.pointer("/host/id").and_then(Value::as_str) == Some(&requested) {
                    host = lookup["host"].clone();
                }
            }
            let grantable = !host.is_null()
                && host.get("ephemeral").and_then(Value::as_bool) != Some(true)
                && !matches!(host.get("protocol").and_then(Value::as_str), Some("serial") | Some("local"));
            let label = host
                .get("label")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .or_else(|| host.get("hostname").and_then(Value::as_str).filter(|s| !s.is_empty()))
                .unwrap_or(&requested)
                .to_string();
            approval_target = Some(json!({
                "sessionId": "",
                "hostId": if grantable { requested.clone() } else { String::new() },
                "label": label,
                "hostname": host.get("hostname").and_then(Value::as_str).unwrap_or(""),
            }));
        }
        let host_id = approval_target.as_ref().and_then(|t| t.get("hostId")).and_then(Value::as_str).map(str::to_string);
        let grants = self.host.permission_grants();
        let decision = evaluate_permission_with_grants(
            &PermissionRequest {
                rpc_method,
                surface,
                permission_mode: &mode,
                params,
                chat_session_cancelled: self.host.is_chat_session_cancelled(chat),
                host_id: host_id.as_deref().filter(|s| !s.is_empty()),
            },
            &grants,
        );
        if !decision.allowed {
            return Ok(Some(json!({ "ok": false, "error": decision.error })));
        }
        if decision.requires_approval && !self.host.has_session_approval(ctx) {
            let mut args = params.clone();
            args.remove("chatSessionId");
            let tool_name = mcp_tool_name_for_rpc_method(rpc_method, surface)
                .or_else(|| cap.surface(SURFACE_PUBLIC).and_then(|b| b.mcp_tool.clone()))
                .unwrap_or_else(|| cap.id.clone());
            let approved = self
                .host
                .request_approval(&tool_name, Value::Object(args), chat.map(str::to_string), approval_target.clone(), ctx)
                .await;
            if !approved {
                return Ok(Some(json!({ "ok": false, "error": USER_DENIED_MESSAGE })));
            }
        }
        let generation = (cap.id == "vault.host.open").then(|| self.host.capture_host_open_scope(chat));
        run_guard(ctx.before_execute.as_ref())?;
        let result = match domain {
            "vault" => vault_service_call(&*self.agent, method, params).await,
            "portforward" => portforward_service_call(&*self.agent, &*self.portforward, method, params).await,
            "session" => match method {
                "close" => self.sessions.close(params, ctx.before_execute.as_ref(), false).await?,
                "reconnect" => self.sessions.reconnect(params, ctx.before_execute.as_ref(), None).await?,
                "recover" => self.sessions.recover(params, ctx.before_execute.as_ref()).await?,
                _ => json!({ "ok": false, "error": format!("Capability handler \"{}\" is unavailable.", cap.id) }),
            },
            _ => json!({ "ok": false, "error": format!("Capability handler \"{}\" is unavailable.", cap.id) }),
        };
        if cap.id == "vault.host.open" && result.get("ok").and_then(Value::as_bool) != Some(false) {
            if let Some(session_id) = result.get("sessionId").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                let bound = self
                    .host
                    .on_host_opened(chat, session_id, generation.unwrap_or(Value::Null), &result)
                    .await;
                if bound == Some(false) {
                    return Ok(Some(json!({
                        "ok": false,
                        "code": "SESSION_SCOPE_BIND_FAILED",
                        "sessionId": session_id,
                        "error": "Host opened but its session could not be bound to the requesting chat scope.",
                    })));
                }
                if bound == Some(true) {
                    let mut out = result.clone();
                    out["scopeBound"] = json!(true);
                    return Ok(Some(out));
                }
            }
        }
        Ok(Some(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::SessionHooks;
    use parking_lot::Mutex;

    #[derive(Default)]
    struct Agent(Mutex<Vec<(String, Value)>>, Mutex<Option<Value>>);
    #[async_trait::async_trait]
    impl VaultAgent for Agent {
        async fn invoke(&self, op: &str, params: Value, _t: Option<u64>) -> Value {
            self.0.lock().push((op.into(), params.clone()));
            if op == "host.get" {
                return json!({ "ok": true, "host": { "id": params["hostId"], "label": "Prod", "hostname": "prod.example" } });
            }
            self.1.lock().clone().unwrap_or(json!({ "ok": true, "op": op }))
        }
    }
    struct Pf;
    #[async_trait::async_trait]
    impl PortForwardRuntime for Pf {
        async fn list_tunnels(&self) -> Vec<Value> {
            vec![json!({ "tunnelId": "t", "status": "active" })]
        }
    }
    struct NoHooks;
    #[async_trait::async_trait]
    impl SessionHooks for NoHooks {
        fn validate_reconnect(&self, _p: &Map<String, Value>) -> Value {
            json!({ "ok": true })
        }
        async fn inspect_recovery(&self, _p: &Map<String, Value>, _t: u64) -> Value {
            json!({ "ok": true, "status": "connected" })
        }
        fn validate_close(&self, _p: &Map<String, Value>) -> Value {
            json!({ "ok": false, "error": "Session \"s\" was not opened by the current AI scope." })
        }
        async fn before_close(&self, _p: &Map<String, Value>) {}
        async fn after_close(&self, _p: &Map<String, Value>, _c: bool, _n: bool) {}
        async fn on_closed(&self, _s: &str) {}
    }
    struct Host {
        mode: String,
        approve: bool,
        approvals: Mutex<Vec<(String, Option<Value>)>>,
        bind: Option<bool>,
    }
    #[async_trait::async_trait]
    impl CapabilityHost for Host {
        fn permission_mode(&self) -> String {
            self.mode.clone()
        }
        fn permission_grants(&self) -> Vec<PermissionGrant> {
            Vec::new()
        }
        fn is_chat_session_cancelled(&self, _c: Option<&str>) -> bool {
            false
        }
        fn approval_target(&self, _p: &Map<String, Value>) -> Option<Value> {
            None
        }
        fn has_session_approval(&self, _c: &DispatchContext) -> bool {
            false
        }
        async fn request_approval(&self, tool: &str, _a: Value, _c: Option<String>, target: Option<Value>, _x: &DispatchContext) -> bool {
            self.approvals.lock().push((tool.into(), target));
            self.approve
        }
        fn capture_host_open_scope(&self, _c: Option<&str>) -> Value {
            json!(1)
        }
        async fn on_host_opened(&self, _c: Option<&str>, _s: &str, _g: Value, _r: &Value) -> Option<bool> {
            self.bind
        }
    }

    fn dispatcher(mode: &str, approve: bool, bind: Option<bool>) -> (CapabilityDispatcher, Arc<Agent>, Arc<Host>) {
        let agent = Arc::new(Agent::default());
        let host = Arc::new(Host { mode: mode.into(), approve, approvals: Default::default(), bind });
        let sessions = Arc::new(SessionService::new(agent.clone(), Arc::new(NoHooks)));
        (CapabilityDispatcher { agent: agent.clone(), portforward: Arc::new(Pf), sessions, host: host.clone() }, agent, host)
    }

    fn p(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[tokio::test]
    async fn builtin_methods_are_unrouted() {
        let (d, _, _) = dispatcher(MODE_CONFIRM, true, None);
        assert!(d.dispatch("netcatty/exec", &p(json!({})), &DispatchContext::default()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn vault_reads_and_writes_with_approval() {
        let (d, agent, host) = dispatcher(MODE_CONFIRM, true, None);
        let r = d.dispatch("vault/host/notes/get", &p(json!({ "hostId": "h" })), &DispatchContext::default()).await.unwrap().unwrap();
        assert_eq!(r["op"], "host.notes.get");
        assert!(host.approvals.lock().is_empty());
        let r = d
            .dispatch("public/vault/hostNotes/set", &p(json!({ "hostId": "h", "notes": "x", "chatSessionId": "c" })), &DispatchContext::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r["ok"], true);
        assert_eq!(host.approvals.lock()[0].0, "host_notes_set");
        assert_eq!(agent.0.lock().last().unwrap().0, "host.notes.set");
    }

    #[tokio::test]
    async fn denial_blocks_and_observer_blocks() {
        let (d, agent, _) = dispatcher(MODE_CONFIRM, false, None);
        let r = d.dispatch("vault/notes/import", &p(json!({ "content": "# x" })), &DispatchContext::default()).await.unwrap().unwrap();
        assert_eq!(r["error"], USER_DENIED_MESSAGE);
        assert!(agent.0.lock().is_empty());
        let (d, agent, _) = dispatcher(MODE_OBSERVER, true, None);
        let r = d.dispatch("session/reconnect", &p(json!({ "sessionId": "s", "chatSessionId": "c" })), &DispatchContext::default()).await.unwrap().unwrap();
        assert_eq!(r["ok"], false);
        assert!(agent.0.lock().is_empty());
    }

    #[tokio::test]
    async fn host_open_names_host_and_reports_binding() {
        let (d, _, host) = dispatcher(MODE_CONFIRM, true, Some(false));
        let agent = Arc::new(Agent::default());
        *agent.1.lock() = Some(json!({ "ok": true, "sessionId": "opened-1" }));
        let d = CapabilityDispatcher { agent: agent.clone(), ..d };
        let r = d.dispatch("vault/hosts/open", &p(json!({ "hostId": "host-1", "chatSessionId": "c" })), &DispatchContext::default()).await.unwrap().unwrap();
        assert_eq!(r["code"], "SESSION_SCOPE_BIND_FAILED");
        let target = host.approvals.lock()[0].1.clone().unwrap();
        assert_eq!(target["hostId"], "host-1");
        assert_eq!(target["label"], "Prod");
    }

    #[tokio::test]
    async fn tunnels_list_from_runtime_and_close_respects_ownership() {
        let (d, agent, _) = dispatcher(MODE_AUTO, true, None);
        let r = d.dispatch("portforward/tunnels/list", &p(json!({})), &DispatchContext::default()).await.unwrap().unwrap();
        assert_eq!(r["tunnels"][0]["tunnelId"], "t");
        let r = d.dispatch("session/close", &p(json!({ "sessionId": "s", "chatSessionId": "c" })), &DispatchContext::default()).await.unwrap().unwrap();
        assert_eq!(r["ok"], false);
        assert!(agent.0.lock().is_empty());
    }

    #[test]
    fn every_implemented_vault_capability_has_a_binding() {
        for cap in all_capabilities().iter().filter(|c| c.domain == "vault" || c.domain == "portforward") {
            assert!(service_binding(&cap.id).is_some(), "{}", cap.id);
        }
    }
}
