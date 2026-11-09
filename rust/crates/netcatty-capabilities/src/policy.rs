//! Permission policy (Electron `electron/capabilities/policy.cjs`).

use crate::catalog::*;
use crate::grants::{match_permission_grant, GrantContext, PermissionGrant};
use crate::registry::{capability_by_rpc_method, rpc_methods_for_surface};
use serde_json::{Map, Value};

pub const OBSERVER_DENY_MESSAGE: &str = "Operation denied: permission mode is \"observer\" (read-only). Change to \"confirm\" or \"auto\" in Settings → AI → Safety to allow this action.";
pub const CHAT_SESSION_REQUIRED_MESSAGE: &str = "chatSessionId is required for write operations.";
pub const CHAT_SESSION_CANCELLED_MESSAGE: &str = "Operation cancelled: the SDK agent session was stopped.";
pub const USER_DENIED_MESSAGE: &str = "Operation denied by user.";

pub fn requires_approval_in_confirm_mode(capability: Option<&Capability>, surface: &str) -> bool {
    let Some(cap) = capability else {
        return false;
    };
    let binding = cap.surface(surface);
    if binding.and_then(|b| b.confirm_in_confirm_mode) == Some(true) {
        return true;
    }
    if cap.policy.bypasses_approval {
        return false;
    }
    cap.policy.write
}

pub fn is_blocked_in_observer_mode(capability: Option<&Capability>) -> bool {
    capability.is_some_and(|c| !c.policy.bypasses_observer_block && c.policy.write)
}

/// Decision of [`evaluate_rpc_permission`].
#[derive(Debug, Clone)]
pub struct PermissionDecision {
    pub allowed: bool,
    pub requires_approval: bool,
    pub error: Option<String>,
    pub capability: Option<&'static Capability>,
    pub matched_grant_id: Option<String>,
}

/// Inputs of a permission check.
pub struct PermissionRequest<'a> {
    pub rpc_method: &'a str,
    pub surface: &'a str,
    pub permission_mode: &'a str,
    pub params: &'a Map<String, Value>,
    pub chat_session_cancelled: bool,
    pub host_id: Option<&'a str>,
}

pub fn evaluate_rpc_permission(req: &PermissionRequest<'_>) -> PermissionDecision {
    let capability = capability_by_rpc_method(req.rpc_method, req.surface);
    let Some(cap) = capability else {
        return PermissionDecision { allowed: true, requires_approval: false, error: None, capability: None, matched_grant_id: None };
    };
    let deny = |msg: &str| PermissionDecision {
        allowed: false,
        requires_approval: false,
        error: Some(msg.to_string()),
        capability: Some(cap),
        matched_grant_id: None,
    };
    let has_chat = req.params.get("chatSessionId").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    if cap.policy.write && !has_chat && req.surface == SURFACE_BUILTIN {
        return deny(CHAT_SESSION_REQUIRED_MESSAGE);
    }
    if cap.policy.write && !cap.policy.bypasses_chat_cancel && req.chat_session_cancelled && req.surface == SURFACE_BUILTIN {
        return deny(CHAT_SESSION_CANCELLED_MESSAGE);
    }
    if req.permission_mode == MODE_OBSERVER && is_blocked_in_observer_mode(Some(cap)) {
        return deny(OBSERVER_DENY_MESSAGE);
    }
    let requires_approval = req.permission_mode == MODE_CONFIRM && requires_approval_in_confirm_mode(Some(cap), req.surface);
    PermissionDecision { allowed: true, requires_approval, error: None, capability: Some(cap), matched_grant_id: None }
}

pub fn evaluate_permission_with_grants(req: &PermissionRequest<'_>, grants: &[PermissionGrant]) -> PermissionDecision {
    let mut base = evaluate_rpc_permission(req);
    if !base.allowed || !base.requires_approval {
        return base;
    }
    let Some(cap) = base.capability else {
        return base;
    };
    let ctx = GrantContext {
        capability_id: &cap.id,
        chat_session_id: req.params.get("chatSessionId").and_then(Value::as_str),
        session_id: req.params.get("sessionId").and_then(Value::as_str),
        host_id: req.host_id,
        args: Some(req.params),
    };
    if let Some(grant) = match_permission_grant(grants, &ctx) {
        base.requires_approval = false;
        base.matched_grant_id = Some(grant.id.clone());
    }
    base
}

fn method_set(surface: &str, pred: impl Fn(&Capability) -> bool) -> Vec<String> {
    rpc_methods_for_surface(surface, true)
        .into_iter()
        .filter(|m| capability_by_rpc_method(m, surface).is_some_and(|c| c.is_implemented() && pred(c)))
        .collect()
}

pub fn builtin_write_rpc_methods() -> Vec<String> {
    method_set(SURFACE_BUILTIN, |c| c.policy.write)
}

pub fn builtin_approval_rpc_methods() -> Vec<String> {
    method_set(SURFACE_BUILTIN, |c| requires_approval_in_confirm_mode(Some(c), SURFACE_BUILTIN))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn eval(method: &str, surface: &str, mode: &str, params: Value, cancelled: bool) -> PermissionDecision {
        let p = params.as_object().cloned().unwrap_or_default();
        evaluate_rpc_permission(&PermissionRequest {
            rpc_method: method,
            surface,
            permission_mode: mode,
            params: &p,
            chat_session_cancelled: cancelled,
            host_id: None,
        })
    }

    #[test]
    fn builtin_write_and_approval_sets_match_legacy() {
        let mut writes = builtin_write_rpc_methods();
        writes.sort();
        let expected = [
            "netcatty/exec", "netcatty/jobStart", "netcatty/jobStop", "netcatty/sftp/chmod", "netcatty/sftp/delete",
            "netcatty/sftp/download", "netcatty/sftp/mkdir", "netcatty/sftp/rename", "netcatty/sftp/upload",
            "netcatty/sftp/write",
        ];
        assert_eq!(writes, expected);
        let approvals = builtin_approval_rpc_methods();
        assert!(!approvals.contains(&"netcatty/jobStop".to_string()));
        assert!(!approvals.contains(&"netcatty/setCancelled".to_string()));
        assert!(approvals.contains(&"netcatty/exec".to_string()));
    }

    #[test]
    fn observer_blocks_writes_but_allows_poll() {
        let chat = json!({ "chatSessionId": "c" });
        let d = eval("netcatty/exec", SURFACE_BUILTIN, MODE_OBSERVER, chat.clone(), false);
        assert!(!d.allowed);
        assert_eq!(d.error.as_deref(), Some(OBSERVER_DENY_MESSAGE));
        assert!(eval("netcatty/jobPoll", SURFACE_BUILTIN, MODE_OBSERVER, chat.clone(), false).allowed);
        assert!(eval("netcatty/jobStop", SURFACE_BUILTIN, MODE_OBSERVER, chat.clone(), true).allowed);
    }

    #[test]
    fn confirm_mode_and_surfaces() {
        let chat = json!({ "chatSessionId": "c" });
        assert!(eval("netcatty/exec", SURFACE_BUILTIN, MODE_CONFIRM, chat.clone(), false).requires_approval);
        assert!(!eval("netcatty/sftp/list", SURFACE_BUILTIN, MODE_CONFIRM, chat.clone(), false).requires_approval);
        assert!(eval("public/sftp/list", SURFACE_PUBLIC, MODE_CONFIRM, chat.clone(), false).requires_approval);
        assert!(eval("portforward/start", SURFACE_GLOBAL, MODE_CONFIRM, json!({}), false).requires_approval);
        assert!(eval("vault/host/notes/set", SURFACE_GLOBAL, MODE_CONFIRM, json!({}), false).requires_approval);
        let d = eval("netcatty/exec", SURFACE_BUILTIN, MODE_AUTO, json!({}), false);
        assert_eq!(d.error.as_deref(), Some(CHAT_SESSION_REQUIRED_MESSAGE));
        let d = eval("netcatty/sftp/write", SURFACE_BUILTIN, MODE_AUTO, chat.clone(), true);
        assert_eq!(d.error.as_deref(), Some(CHAT_SESSION_CANCELLED_MESSAGE));
        assert!(eval("netcatty/sftp/read", SURFACE_BUILTIN, MODE_AUTO, chat.clone(), true).allowed);
        assert!(eval("unknown/method", SURFACE_BUILTIN, MODE_OBSERVER, json!({}), false).allowed);
    }

    #[test]
    fn grants_skip_approval() {
        let params = json!({ "chatSessionId": "c", "sessionId": "s", "command": "ls -la" });
        let p = params.as_object().unwrap().clone();
        let grants = vec![PermissionGrant {
            id: "g".into(),
            capability_id: "terminal.execute".into(),
            session_pattern: "*".into(),
            created_at: 0.0,
            command_pattern: Some("ls *".into()),
            args_pattern: None,
            note: None,
        }];
        let d = evaluate_permission_with_grants(
            &PermissionRequest {
                rpc_method: "netcatty/exec",
                surface: SURFACE_BUILTIN,
                permission_mode: MODE_CONFIRM,
                params: &p,
                chat_session_cancelled: false,
                host_id: None,
            },
            &grants,
        );
        assert!(!d.requires_approval);
        assert_eq!(d.matched_grant_id.as_deref(), Some("g"));
    }
}
