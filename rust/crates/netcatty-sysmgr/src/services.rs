//! systemd service management over the session exec channel — port of
//! `electron/bridges/systemManager/serviceOps.cjs` and the
//! `listSystemServices` / `systemServiceAction` wrappers in
//! `systemManagerBridge.cjs`.
//!
//! Listing runs `systemctl list-units` for the system and user managers;
//! actions run `systemctl [--user] <action> <unit>` and, for system units that
//! fail with a permission error, retry with passwordless `sudo` and then with
//! the session's sudo password on stdin (same order as Electron).

use crate::exec::{sh_quote, wrap_sh_json, ExecRequest, SessionExec};
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use std::cmp::Ordering;
use std::sync::OnceLock;

/// Remote collector body (Electron `LIST_UNITS_INNER`).
pub const LIST_UNITS_INNER: &str = concat!(
    r#"printf "%s\n" "__NC_SERVICES_BEGIN__"; "#,
    r#"if command -v systemctl >/dev/null 2>&1; then "#,
    r#"printf "%s\n" "__NC_SYSTEM__"; "#,
    // --plain needs systemd >= ~230; fall back for RHEL/CentOS 7-era hosts.
    r#"systemctl list-units --type=service --all --no-pager --no-legend --plain 2>/dev/null "#,
    r#"|| systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null "#,
    r#"|| true; "#,
    r#"printf "%s\n" "__NC_USER__"; "#,
    r#"systemctl --user list-units --type=service --all --no-pager --no-legend --plain 2>/dev/null "#,
    r#"|| systemctl --user list-units --type=service --all --no-pager --no-legend 2>/dev/null "#,
    r#"|| true; "#,
    r#"fi; "#,
    r#"printf "%s\n" "__NC_SERVICES_END__""#,
);

/// `exec sh -c <JSON.stringify(LIST_UNITS_INNER)>` (Electron `LIST_UNITS_SCRIPT`).
pub fn list_units_script() -> String {
    wrap_sh_json(LIST_UNITS_INNER)
}

const LIST_TIMEOUT_MS: u64 = 20_000;
const LIST_MAX_BUFFER: usize = 16 * 1024 * 1024;
const ACTION_TIMEOUT_MS: u64 = 30_000;
const ALLOWED_ACTIONS: [&str; 6] = ["start", "stop", "restart", "enable", "disable", "reload"];

/// One `systemctl list-units` row (`SystemdUnitInfo` in the renderer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemdUnit {
    pub name: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub description: String,
    pub scope: String,
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid regex"))
}

/// Electron `sanitizeUnitName`: trimmed, at most 256 chars, only
/// `A-Za-z0-9 : . _ @ \ -`.
pub fn sanitize_unit_name(name: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let trimmed: String = name.trim().chars().take(256).collect();
    if trimmed.is_empty() || !regex(&RE, r"^[A-Za-z0-9:._@\\-]+$").is_match(&trimmed) {
        return None;
    }
    Some(trimmed)
}

fn normalize_active_state(raw: &str) -> String {
    let text = raw.trim().to_lowercase();
    match text.as_str() {
        "active" | "inactive" | "failed" | "activating" | "deactivating" | "reloading" => text,
        _ => "unknown".into(),
    }
}

fn normalize_load_state(raw: &str) -> String {
    let text = raw.trim().to_lowercase();
    match text.as_str() {
        "loaded" | "not-found" | "bad-setting" | "error" | "masked" => text,
        _ => "unknown".into(),
    }
}

/// Electron `parseSystemctlListUnits`.
pub fn parse_systemctl_list_units(stdout: &str, scope: &str) -> Vec<SystemdUnit> {
    static BULLET: OnceLock<Regex> = OnceLock::new();
    static SKIP: OnceLock<Regex> = OnceLock::new();
    static ROW: OnceLock<Regex> = OnceLock::new();
    let bullet = regex(&BULLET, r"^●\s*");
    let skip = regex(
        &SKIP,
        r"(?i)^(?:UNIT\b|Legend:|\d+ loaded units listed|To show all)",
    );
    let row = regex(&ROW, r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$");
    let mut units = Vec::new();
    for line in stdout.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let cleaned = bullet.replace(trimmed, "");
        if cleaned.is_empty() || skip.is_match(&cleaned) {
            continue;
        }
        let Some(m) = row.captures(&cleaned) else {
            continue;
        };
        let name = m[1].to_string();
        if !name.contains('.') {
            continue;
        }
        units.push(SystemdUnit {
            name,
            load_state: normalize_load_state(&m[2]),
            active_state: normalize_active_state(&m[3]),
            sub_state: m[4].to_string(),
            description: m
                .get(5)
                .map(|d| d.as_str().trim())
                .unwrap_or("")
                .to_string(),
            scope: scope.to_string(),
        });
    }
    units
}

fn extract_between<'a>(text: &'a str, start_marker: &str, end_markers: &[&str]) -> &'a str {
    let Some(begin) = text.find(start_marker) else {
        return "";
    };
    let after = &text[begin + start_marker.len()..];
    let end = end_markers.iter().filter_map(|m| after.find(m)).min();
    match end {
        Some(end) => &after[..end],
        None => after,
    }
}

/// Approximation of `String.prototype.localeCompare` (ICU root collation)
/// for unit names: case-insensitive first, lowercase before uppercase on
/// ties. The renderer re-sorts with `localeCompare` anyway.
fn locale_compare(a: &str, b: &str) -> Ordering {
    a.to_lowercase()
        .cmp(&b.to_lowercase())
        .then_with(|| b.cmp(a))
}

/// Electron `parseServiceList`: system units first on name collisions,
/// failed units first, then by name.
pub fn parse_service_list(stdout: &str) -> Vec<SystemdUnit> {
    let system_part = extract_between(
        stdout,
        "__NC_SYSTEM__",
        &["__NC_USER__", "__NC_SERVICES_END__"],
    );
    let user_part = extract_between(stdout, "__NC_USER__", &["__NC_SERVICES_END__"]);
    let mut merged = parse_systemctl_list_units(system_part, "system");
    let mut seen: std::collections::HashSet<String> =
        merged.iter().map(|u| u.name.clone()).collect();
    for unit in parse_systemctl_list_units(user_part, "user") {
        if seen.insert(unit.name.clone()) {
            merged.push(unit);
        }
    }
    merged.sort_by(|a, b| {
        let af = a.active_state == "failed";
        let bf = b.active_state == "failed";
        match (af, bf) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => locale_compare(&a.name, &b.name),
        }
    });
    merged
}

/// JS `String(value || "")` for the string-ish payload fields.
fn js_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) if n.as_f64() != Some(0.0) => n.to_string(),
        Some(Value::Bool(true)) => "true".into(),
        _ => String::new(),
    }
}

fn session_id(payload: &Value) -> Option<&str> {
    payload
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// Electron `isPermissionDenied`.
fn is_permission_denied(result: &crate::exec::ExecResult) -> bool {
    let text = format!(
        "{}\n{}\n{}",
        result.stderr,
        result.stdout,
        result.error.as_deref().unwrap_or("")
    )
    .to_lowercase();
    [
        "permission denied",
        "access denied",
        "authentication is required",
        "interactive authentication required",
        "not authorized",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

/// `listSystemServices({ sessionId })`.
pub async fn list_services(exec: &dyn SessionExec, payload: &Value) -> Value {
    if session_id(payload).is_none() {
        return json!({ "success": false, "error": "Missing sessionId" });
    }
    let result = exec
        .exec(
            ExecRequest::new(list_units_script(), LIST_TIMEOUT_MS).with_max_buffer(LIST_MAX_BUFFER),
        )
        .await;
    if result.pending {
        return json!({ "success": false, "pending": true });
    }
    if !result.success {
        return json!({
            "success": false,
            "error": result.error.filter(|e| !e.is_empty()).unwrap_or_else(|| "Failed to list services".into()),
        });
    }
    json!({ "success": true, "units": parse_service_list(&result.stdout) })
}

/// `systemServiceAction({ sessionId, unitName, action, scope })`.
pub async fn service_action(exec: &dyn SessionExec, payload: &Value) -> Value {
    let unit_name = sanitize_unit_name(&js_string(payload.get("unitName")));
    let action = js_string(payload.get("action")).to_lowercase();
    let scope = if payload.get("scope").and_then(Value::as_str) == Some("user") {
        "user"
    } else {
        "system"
    };
    let (Some(_), Some(unit_name)) = (session_id(payload), unit_name) else {
        return json!({ "success": false, "error": "Missing sessionId or unitName" });
    };
    if !ALLOWED_ACTIONS.contains(&action.as_str()) {
        return json!({ "success": false, "error": "Invalid action" });
    }

    let user_flag = if scope == "user" { "--user " } else { "" };
    let quoted = sh_quote(&unit_name);
    let wrapped = wrap_sh_json(&format!("systemctl {user_flag}{action} {quoted}"));
    let pending = || json!({ "success": false, "pending": true });

    let result = exec
        .exec(ExecRequest::new(wrapped, ACTION_TIMEOUT_MS))
        .await;
    if result.pending {
        return pending();
    }
    if result.is_successful() {
        return json!({ "success": true });
    }

    // User-scope units should not escalate via sudo.
    if scope == "user" || !is_permission_denied(&result) {
        return json!({
            "success": false,
            "error": result.command_error(&format!("systemctl {action} failed")),
        });
    }

    let sudo_password = exec.sudo_password();
    let passwordless = wrap_sh_json(&format!("sudo systemctl {action} {quoted}"));
    let passwordless_result = exec
        .exec(ExecRequest::new(passwordless, ACTION_TIMEOUT_MS))
        .await;
    if passwordless_result.pending {
        return pending();
    }
    if passwordless_result.is_successful() {
        return json!({ "success": true });
    }

    if let Some(password) = sudo_password {
        let with_password = wrap_sh_json(&format!("sudo -S -p '' systemctl {action} {quoted}"));
        let sudo_result = exec
            .exec(
                ExecRequest::new(with_password, ACTION_TIMEOUT_MS)
                    .with_stdin(format!("{password}\n")),
            )
            .await;
        if sudo_result.pending {
            return pending();
        }
        if sudo_result.is_successful() {
            return json!({ "success": true });
        }
        return json!({
            "success": false,
            "error": sudo_result.command_error(&format!("sudo systemctl {action} failed")),
        });
    }

    let source = if !passwordless_result.success {
        &passwordless_result
    } else {
        &result
    };
    json!({
        "success": false,
        "error": source.command_error(&format!("systemctl {action} failed (sudo required)")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{ExecResult, FakeExec};

    #[test]
    fn sanitize_unit_name_rejects_shell_metacharacters() {
        assert_eq!(
            sanitize_unit_name("nginx.service").as_deref(),
            Some("nginx.service")
        );
        assert_eq!(
            sanitize_unit_name("user@1000.service").as_deref(),
            Some("user@1000.service")
        );
        assert_eq!(
            sanitize_unit_name(r"dev-disk-by\x2duuid.swap").as_deref(),
            Some(r"dev-disk-by\x2duuid.swap")
        );
        assert_eq!(sanitize_unit_name("evil;rm -rf /"), None);
        assert_eq!(sanitize_unit_name(""), None);
    }

    #[test]
    fn parses_plain_list_units_rows() {
        let sample = "\n  nginx.service                loaded active   running A high performance web server\n● broken.service               loaded failed   failed  Broken unit\n  cron.service                 loaded inactive dead    Regular background program processing daemon\n";
        let units = parse_systemctl_list_units(sample, "system");
        assert_eq!(units.len(), 3);
        assert_eq!(units[0].name, "nginx.service");
        assert_eq!(units[0].active_state, "active");
        assert_eq!(units[0].description, "A high performance web server");
        assert_eq!(units[1].name, "broken.service");
        assert_eq!(units[1].active_state, "failed");
        assert_eq!(units[2].active_state, "inactive");
    }

    #[test]
    fn keeps_units_with_empty_description() {
        let sample =
            "\n● broken.service loaded failed failed\n  quiet.service  loaded active  running\n";
        let units = parse_systemctl_list_units(sample, "system");
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].description, "");
        assert_eq!(units[1].name, "quiet.service");
        assert_eq!(units[1].active_state, "active");
    }

    #[test]
    fn skips_headers_and_legend() {
        let sample = "UNIT LOAD ACTIVE SUB DESCRIPTION\nfoo.service bogus weird x Foo\nLegend: LOAD ...\n12 loaded units listed.\nTo show all installed unit files use ...\nnodot loaded active running X\n";
        let units = parse_systemctl_list_units(sample, "user");
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].load_state, "unknown");
        assert_eq!(units[0].active_state, "unknown");
        assert_eq!(units[0].scope, "user");
    }

    #[test]
    fn merges_scopes_and_sorts_failed_first() {
        let stdout = "\n__NC_SERVICES_BEGIN__\n__NC_SYSTEM__\nbroken.service loaded failed failed Broken\nnginx.service loaded active running Nginx\n__NC_USER__\npodman.service loaded active running Podman\nnginx.service loaded active running User nginx\n__NC_SERVICES_END__\n";
        let units = parse_service_list(stdout);
        assert_eq!(units.len(), 3);
        assert_eq!(units[0].name, "broken.service");
        let nginx = units.iter().find(|u| u.name == "nginx.service").unwrap();
        assert_eq!(nginx.scope, "system");
        assert_eq!(nginx.description, "Nginx");
        let podman = units.iter().find(|u| u.name == "podman.service").unwrap();
        assert_eq!(podman.scope, "user");
        assert_eq!(units[1].name, "nginx.service");
    }

    #[test]
    fn list_script_wraps_inner_with_json() {
        let script = list_units_script();
        assert!(script
            .starts_with("exec sh -c \"printf \\\"%s\\\\n\\\" \\\"__NC_SERVICES_BEGIN__\\\"; "));
        assert!(script.ends_with("__NC_SERVICES_END__\\\"\""));
    }

    #[tokio::test]
    async fn list_services_reports_results_and_failures() {
        let fake = FakeExec::sequence(vec![
            ExecResult::ok(
                "__NC_SYSTEM__\na.service loaded active running A\n__NC_USER__\n__NC_SERVICES_END__\n",
                "",
                0,
            ),
            ExecResult::fail(""),
            ExecResult::pending("Mosh handshake in progress"),
        ]);
        let payload = json!({ "sessionId": "s1" });
        let ok = list_services(&fake, &payload).await;
        assert_eq!(ok["success"], true);
        assert_eq!(ok["units"][0]["name"], "a.service");
        assert_eq!(ok["units"][0]["activeState"], "active");
        assert_eq!(ok["units"][0]["scope"], "system");
        let failed = list_services(&fake, &payload).await;
        assert_eq!(
            failed,
            json!({ "success": false, "error": "Failed to list services" })
        );
        let pending = list_services(&fake, &payload).await;
        assert_eq!(pending, json!({ "success": false, "pending": true }));
        let req = &fake.requests()[0].0;
        assert_eq!(req.command, list_units_script());
        assert_eq!(req.timeout_ms, 20_000);
        assert_eq!(req.max_buffer, Some(16 * 1024 * 1024));
        assert_eq!(
            list_services(&fake, &json!({})).await,
            json!({ "success": false, "error": "Missing sessionId" })
        );
    }

    #[tokio::test]
    async fn service_action_validates_input() {
        let fake = FakeExec::sequence(vec![]);
        assert_eq!(
            service_action(
                &fake,
                &json!({ "sessionId": "s", "unitName": "a;b", "action": "start" })
            )
            .await,
            json!({ "success": false, "error": "Missing sessionId or unitName" })
        );
        assert_eq!(
            service_action(
                &fake,
                &json!({ "sessionId": "s", "unitName": "a.service", "action": "mask" })
            )
            .await,
            json!({ "success": false, "error": "Invalid action" })
        );
        assert!(fake.commands().is_empty());
    }

    #[tokio::test]
    async fn service_action_succeeds_without_sudo() {
        let fake = FakeExec::sequence(vec![ExecResult::ok("", "", 0)]);
        let reply = service_action(
            &fake,
            &json!({ "sessionId": "s", "unitName": "nginx.service", "action": "RESTART" }),
        )
        .await;
        assert_eq!(reply, json!({ "success": true }));
        assert_eq!(
            fake.commands(),
            vec!["exec sh -c \"systemctl restart 'nginx.service'\""]
        );
        assert_eq!(fake.requests()[0].0.timeout_ms, 30_000);
    }

    #[tokio::test]
    async fn user_scope_does_not_escalate() {
        let fake = FakeExec::sequence(vec![ExecResult {
            stderr: "Permission denied\n".into(),
            ..ExecResult::ok("", "", 1)
        }]);
        let reply = service_action(
            &fake,
            &json!({ "sessionId": "s", "unitName": "a.service", "action": "stop", "scope": "user" }),
        )
        .await;
        assert_eq!(
            reply,
            json!({ "success": false, "error": "Permission denied" })
        );
        assert_eq!(
            fake.commands(),
            vec!["exec sh -c \"systemctl --user stop 'a.service'\""]
        );
    }

    #[tokio::test]
    async fn non_permission_failure_is_reported() {
        let fake = FakeExec::sequence(vec![ExecResult::ok("", "", 5)]);
        let reply = service_action(
            &fake,
            &json!({ "sessionId": "s", "unitName": "a.service", "action": "start" }),
        )
        .await;
        assert_eq!(
            reply,
            json!({ "success": false, "error": "systemctl start failed" })
        );
    }

    fn denied() -> ExecResult {
        ExecResult {
            stderr: "Failed to start a.service: Access denied\n".into(),
            ..ExecResult::ok("", "", 1)
        }
    }

    #[tokio::test]
    async fn falls_back_to_passwordless_sudo() {
        let fake = FakeExec::sequence(vec![denied(), ExecResult::ok("", "", 0)]);
        let reply = service_action(
            &fake,
            &json!({ "sessionId": "s", "unitName": "a.service", "action": "start" }),
        )
        .await;
        assert_eq!(reply, json!({ "success": true }));
        assert_eq!(
            fake.commands()[1],
            "exec sh -c \"sudo systemctl start 'a.service'\""
        );
    }

    #[tokio::test]
    async fn uses_session_sudo_password_on_stdin() {
        let fake = FakeExec::sequence(vec![
            denied(),
            ExecResult {
                stderr: "sudo: a password is required\n".into(),
                ..ExecResult::ok("", "", 1)
            },
            ExecResult::ok("", "", 0),
        ])
        .with_sudo("hunter2");
        let reply = service_action(
            &fake,
            &json!({ "sessionId": "s", "unitName": "a.service", "action": "enable" }),
        )
        .await;
        assert_eq!(reply, json!({ "success": true }));
        let (req, _) = &fake.requests()[2];
        assert_eq!(
            req.command,
            "exec sh -c \"sudo -S -p '' systemctl enable 'a.service'\""
        );
        assert_eq!(req.stdin.as_deref(), Some("hunter2\n"));
    }

    #[tokio::test]
    async fn sudo_password_failure_and_missing_password() {
        let fake = FakeExec::sequence(vec![
            denied(),
            ExecResult::ok("", "", 1),
            ExecResult::ok("", "", 1),
        ])
        .with_sudo("pw");
        let reply = service_action(
            &fake,
            &json!({ "sessionId": "s", "unitName": "a.service", "action": "stop" }),
        )
        .await;
        assert_eq!(
            reply,
            json!({ "success": false, "error": "sudo systemctl stop failed" })
        );

        // No password: report the passwordless sudo failure when it ran,
        // else the original permission error.
        let fake = FakeExec::sequence(vec![denied(), ExecResult::ok("", "", 1)]);
        let reply = service_action(
            &fake,
            &json!({ "sessionId": "s", "unitName": "a.service", "action": "stop" }),
        )
        .await;
        assert_eq!(
            reply,
            json!({ "success": false, "error": "Failed to start a.service: Access denied" })
        );
        let fake = FakeExec::sequence(vec![denied(), ExecResult::fail("")]);
        let reply = service_action(
            &fake,
            &json!({ "sessionId": "s", "unitName": "a.service", "action": "stop" }),
        )
        .await;
        assert_eq!(
            reply,
            json!({ "success": false, "error": "systemctl stop failed (sudo required)" })
        );
    }
}
