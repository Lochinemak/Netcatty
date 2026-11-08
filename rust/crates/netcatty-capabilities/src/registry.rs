//! Capability lookups (Electron `registry.cjs`, `rpcTimeouts.cjs`,
//! `scope.cjs`).

use crate::catalog::*;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

struct Index {
    by_id: HashMap<&'static str, &'static Capability>,
    by_rpc: HashMap<String, &'static Capability>,
    by_mcp: HashMap<String, &'static Capability>,
    by_cli: HashMap<String, &'static Capability>,
    by_catty_tool: HashMap<String, &'static Capability>,
}

static INDEX: LazyLock<Index> = LazyLock::new(|| {
    let mut index = Index {
        by_id: HashMap::new(),
        by_rpc: HashMap::new(),
        by_mcp: HashMap::new(),
        by_cli: HashMap::new(),
        by_catty_tool: HashMap::new(),
    };
    for cap in all_capabilities() {
        index.by_id.insert(cap.id.as_str(), cap);
        for (surface, binding) in &cap.surfaces {
            if let Some(rpc) = &binding.rpc_method {
                index.by_rpc.insert(format!("{surface}:{rpc}"), cap);
            }
            if let Some(tool) = &binding.mcp_tool {
                index.by_mcp.insert(format!("{surface}:{tool}"), cap);
            }
            if let Some(cmd) = binding.command.as_ref().filter(|c| !c.is_empty()) {
                index.by_cli.insert(cmd.join(" "), cap);
            }
            if let Some(tool) = &binding.tool_name {
                index.by_catty_tool.insert(tool.clone(), cap);
            }
        }
    }
    index
});

pub fn capability_by_id(id: &str) -> Option<&'static Capability> {
    INDEX.by_id.get(id).copied()
}

pub fn capability_by_rpc_method(rpc_method: &str, surface: &str) -> Option<&'static Capability> {
    INDEX.by_rpc.get(&format!("{surface}:{rpc_method}")).copied()
}

pub fn capability_by_mcp_tool(tool: &str, surface: &str) -> Option<&'static Capability> {
    INDEX.by_mcp.get(&format!("{surface}:{tool}")).copied()
}

pub fn capability_by_cli_command(parts: &[String]) -> Option<&'static Capability> {
    INDEX.by_cli.get(&parts.join(" ")).copied()
}

pub fn capability_by_catty_tool(tool: &str) -> Option<&'static Capability> {
    INDEX.by_catty_tool.get(tool).copied()
}

/// Filter of [`list_capabilities`].
#[derive(Default)]
pub struct ListFilter<'a> {
    pub status: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub surface: Option<&'a str>,
}

pub fn list_capabilities(filter: &ListFilter<'_>) -> Vec<&'static Capability> {
    all_capabilities()
        .iter()
        .filter(|c| filter.status.is_none_or(|s| c.status == s))
        .filter(|c| filter.domain.is_none_or(|d| c.domain == d))
        .filter(|c| filter.surface.is_none_or(|s| c.surfaces.contains_key(s)))
        .collect()
}

pub fn rpc_methods_for_surface(surface: &str, implemented_only: bool) -> BTreeSet<String> {
    all_capabilities()
        .iter()
        .filter(|c| !implemented_only || c.is_implemented())
        .filter_map(|c| c.surface(surface).and_then(|b| b.rpc_method.clone()))
        .collect()
}

// ── RPC timeouts ──────────────────────────────────────────────────────

pub fn is_long_running_rpc_method(method: &str, surface: &str) -> bool {
    capability_by_rpc_method(method, surface).is_some_and(|c| c.policy.long_running)
}

pub fn is_approval_wait_rpc_method(method: &str, surface: &str, permission_mode: Option<&str>) -> bool {
    if permission_mode != Some(MODE_CONFIRM) {
        return false;
    }
    crate::policy::requires_approval_in_confirm_mode(capability_by_rpc_method(method, surface), surface)
}

/// Bridge-reported overrides of the client-side RPC timeout.
#[derive(Debug, Clone, Default)]
pub struct BridgeTimeouts {
    pub command_timeout_ms: Option<u64>,
    pub permission_mode: Option<String>,
    pub approval_timeout_ms: Option<u64>,
}

/// Client-side wait for an RPC response (operation + approval budgets).
pub fn resolve_rpc_timeout_ms(method: &str, surface: &str, bridge: &BridgeTimeouts) -> u64 {
    let operation = if is_long_running_rpc_method(method, surface) {
        bridge.command_timeout_ms.filter(|v| *v > 0).unwrap_or(DEFAULT_OPERATION_TIMEOUT_MS)
    } else {
        0
    };
    let approval = if is_approval_wait_rpc_method(method, surface, bridge.permission_mode.as_deref()) {
        bridge.approval_timeout_ms.filter(|v| *v > 0).unwrap_or(DEFAULT_APPROVAL_TIMEOUT_MS)
    } else {
        0
    };
    match (operation > 0, approval > 0) {
        (true, true) => DEFAULT_RPC_TIMEOUT_MS.max(approval + operation + RPC_TIMEOUT_BUFFER_MS),
        (true, false) => DEFAULT_RPC_TIMEOUT_MS.max(operation + RPC_TIMEOUT_BUFFER_MS),
        (false, true) => DEFAULT_RPC_TIMEOUT_MS.max(approval + RPC_TIMEOUT_BUFFER_MS),
        _ => DEFAULT_RPC_TIMEOUT_MS,
    }
}

// ── Scope helpers ─────────────────────────────────────────────────────

pub fn scope_error(code: &str, message: &str) -> Value {
    json!({ "ok": false, "code": code, "error": message })
}

/// `{ ok: true }` or a scope error.
pub fn validate_session_in_list(session_id: &str, allowed: Option<&[String]>) -> Value {
    if session_id.is_empty() {
        return scope_error("SESSION_REQUIRED", "sessionId is required.");
    }
    let Some(allowed) = allowed else {
        return scope_error("SCOPE_UNAVAILABLE", "Session scope is unavailable.");
    };
    if allowed.is_empty() {
        return scope_error("SESSION_NOT_IN_SCOPE", "No sessions are available in the current scope.");
    }
    if !allowed.iter().any(|s| s == session_id) {
        return scope_error(
            "SESSION_NOT_IN_SCOPE",
            &format!("Session \"{session_id}\" is not in the current scope."),
        );
    }
    json!({ "ok": true })
}

pub fn intersect_session_ids(primary: Option<&[String]>, secondary: Option<&[String]>) -> Option<Vec<String>> {
    match (primary, secondary) {
        (None, s) => s.map(<[String]>::to_vec),
        (Some(p), None) => Some(p.to_vec()),
        (Some(p), Some(s)) => Some(p.iter().filter(|id| s.contains(id)).cloned().collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_bindings() {
        assert_eq!(capability_by_rpc_method("netcatty/exec", SURFACE_BUILTIN).unwrap().id, "terminal.execute");
        assert_eq!(capability_by_mcp_tool("terminal_execute", SURFACE_BUILTIN).unwrap().id, "terminal.execute");
        assert_eq!(capability_by_rpc_method("public/terminalExecute", SURFACE_PUBLIC).unwrap().id, "terminal.execute");
        assert_eq!(capability_by_cli_command(&["exec".into()]).unwrap().id, "terminal.execute");
        assert_eq!(
            capability_by_cli_command(&["vault".into(), "host".into(), "get".into()]).unwrap().id,
            "vault.host.get"
        );
        assert!(capability_by_id("vault.host.get").unwrap().is_implemented());
        assert!(capability_by_id("portforward.rules.list").unwrap().is_implemented());
        assert_eq!(capability_by_catty_tool("tool_output_read").unwrap().id, "harness.tool_output.read");
    }

    #[test]
    fn timeouts() {
        assert!(is_long_running_rpc_method("netcatty/exec", SURFACE_BUILTIN));
        assert!(is_long_running_rpc_method("netcatty/sftp/home", SURFACE_BUILTIN));
        assert!(!is_long_running_rpc_method("netcatty/getContext", SURFACE_BUILTIN));
        assert!(is_approval_wait_rpc_method("netcatty/exec", SURFACE_BUILTIN, Some("confirm")));
        assert!(!is_approval_wait_rpc_method("netcatty/exec", SURFACE_BUILTIN, Some("auto")));
        assert!(!is_approval_wait_rpc_method("netcatty/jobStop", SURFACE_BUILTIN, Some("confirm")));
        let b = BridgeTimeouts {
            command_timeout_ms: Some(120_000),
            permission_mode: Some("confirm".into()),
            approval_timeout_ms: Some(110_000),
        };
        assert_eq!(resolve_rpc_timeout_ms("netcatty/exec", SURFACE_BUILTIN, &b), 235_000);
        let b = BridgeTimeouts { command_timeout_ms: Some(120_000), ..Default::default() };
        assert_eq!(resolve_rpc_timeout_ms("netcatty/exec", SURFACE_BUILTIN, &b), 125_000);
        assert_eq!(resolve_rpc_timeout_ms("netcatty/getContext", SURFACE_BUILTIN, &b), 30_000);
    }

    #[test]
    fn scope() {
        assert_eq!(validate_session_in_list("x", Some(&["a".into()]))["code"], "SESSION_NOT_IN_SCOPE");
        assert_eq!(validate_session_in_list("a", Some(&["a".into()]))["ok"], true);
        assert_eq!(
            intersect_session_ids(Some(&["a".into(), "b".into()]), Some(&["b".into()])),
            Some(vec!["b".to_string()])
        );
    }
}
