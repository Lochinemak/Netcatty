//! Container runtime + kubectl helpers shared by [`crate::docker`] and
//! [`crate::kubectl`]: the backend half of Electron's
//! `domain/systemManager/containerRuntime.shared.cjs` (runtime probe,
//! runtime command builder, socket-permission / unreachable classifiers,
//! background kubectl command builders and the kubeconfig / namespace / pod
//! parsers). The interactive popup command builders stay in the renderer.

use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::LazyLock;

/// Container CLIs the system manager drives.
pub const CONTAINER_RUNTIMES: [&str; 3] = ["docker", "podman", "nerdctl"];

/// Which container sources a capability probe found (`parseRuntimeProbe`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeProbe {
    pub docker: bool,
    pub podman: bool,
    pub nerdctl: bool,
    pub kubernetes: bool,
}

/// Line-anchored `__NAME__=1` marker present in `text`.
pub(crate) fn has_probe_flag(text: &str, name: &str) -> bool {
    let pattern = format!(r"(?:^|\r?\n){}=1(?:\r?\n|$)", regex::escape(name));
    Regex::new(&pattern)
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

/// Electron `parseRuntimeProbe`: read the capability probe's runtime markers.
pub fn parse_runtime_probe(text: &str) -> RuntimeProbe {
    RuntimeProbe {
        docker: has_probe_flag(text, "__NC_DOCKER__"),
        podman: has_probe_flag(text, "__NC_PODMAN__"),
        nerdctl: has_probe_flag(text, "__NC_NERDCTL__"),
        kubernetes: has_probe_flag(text, "__NC_KUBECTL__"),
    }
}

/// `docker` unless `runtime` names a known container CLI.
pub fn normalize_container_runtime(runtime: Option<&Value>) -> &'static str {
    match runtime.and_then(Value::as_str) {
        Some("podman") => "podman",
        Some("nerdctl") => "nerdctl",
        _ => "docker",
    }
}

/// Electron `buildRuntimeCommand`: `<runtime> <args>` trimmed.
pub fn build_runtime_command(runtime: &str, args: &str) -> String {
    let bin = normalize_container_runtime(Some(&Value::String(runtime.to_string())));
    format!("{bin} {args}").trim().to_string()
}

fn socket_needles(runtime: &str) -> &'static [&'static str] {
    match runtime {
        "podman" => &["podman.sock", "/run/podman", "podman daemon"],
        "nerdctl" => &["containerd.sock", "/run/containerd"],
        _ => &[
            "docker daemon",
            "docker.sock",
            "/var/run/docker.sock",
            "connect to the docker daemon",
        ],
    }
}

/// Electron `isRuntimeSocketPermissionError`: a "permission denied" that is
/// about this runtime's daemon socket (worth a sudo retry).
pub fn is_runtime_socket_permission_error(
    runtime: &str,
    stderr: &str,
    stdout: &str,
    error: &str,
) -> bool {
    let text = format!("{stderr}\n{stdout}\n{error}").to_lowercase();
    if !text.contains("permission denied") {
        return false;
    }
    let runtime = normalize_container_runtime(Some(&Value::String(runtime.to_string())));
    socket_needles(runtime)
        .iter()
        .any(|needle| text.contains(needle))
}

static FORBIDDEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i-u:\bforbidden\b)").expect("valid regex"));
static UNREACHABLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)couldn'?t get current server api group list|could not get current server api group list|unable to connect to the server|connection refused|dial tcp|i/o timeout|no such host|network is unreachable|context deadline exceeded|tls handshake timeout",
    )
    .expect("valid regex")
});
static NERDCTL_UNREACHABLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"not running|connection refused|no such file|cannot connect|failed to connect|unavailable",
    )
    .expect("valid regex")
});

/// Electron `isKubectlForbiddenError`.
pub fn is_kubectl_forbidden_error(message: &str) -> bool {
    FORBIDDEN_RE.is_match(message)
}

/// Electron `isKubectlUnreachableError`: API discovery / dial failures (not
/// RBAC denials), reported to the renderer as `clusterUnreachable`.
pub fn is_kubectl_unreachable_error(message: &str) -> bool {
    if message.trim().is_empty() || is_kubectl_forbidden_error(message) {
        return false;
    }
    UNREACHABLE_RE.is_match(message)
}

/// Electron `isNerdctlUnreachableError`: containerd itself is not reachable.
pub fn is_nerdctl_unreachable_error(message: &str) -> bool {
    let text = message.to_lowercase();
    if text.trim().is_empty() {
        return false;
    }
    if text.contains("rootless containerd") || text.contains("xdg_runtime_dir") {
        return true;
    }
    if text.contains("cannot connect to the docker daemon") {
        return true;
    }
    if !text.contains("containerd") {
        return false;
    }
    NERDCTL_UNREACHABLE_RE.is_match(&text)
}

// ---------------------------------------------------------------------------
// kubectl command builders
// ---------------------------------------------------------------------------

/// Shell the background kubectl command is quoted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KubectlShell {
    Posix,
    PowerShell,
    Cmd,
}

fn has_control_char(text: &str) -> bool {
    text.encode_utf16().any(|c| c <= 31 || c == 127)
}

/// Electron `isSafeShellArg`.
fn is_safe_shell_arg(text: &str, shell: KubectlShell) -> bool {
    if text.is_empty() || text.encode_utf16().count() > 512 {
        return false;
    }
    if has_control_char(text) {
        return false;
    }
    if shell == KubectlShell::Cmd && (text.contains('%') || text.contains('!')) {
        return false;
    }
    true
}

fn quote_shell_arg(shell: KubectlShell, text: &str) -> String {
    match shell {
        KubectlShell::Cmd => format!("\"{}\"", text.replace('"', "\"\"")),
        KubectlShell::PowerShell => format!("'{}'", text.replace('\'', "''")),
        KubectlShell::Posix => crate::exec::sh_quote(text),
    }
}

fn kubectl_prefix(context: &str, namespace: Option<&str>, shell: KubectlShell) -> Option<String> {
    if !is_safe_shell_arg(context, shell) {
        return None;
    }
    let mut parts = vec![
        "kubectl".to_string(),
        "--context".to_string(),
        quote_shell_arg(shell, context),
    ];
    if let Some(ns) = namespace.filter(|ns| !ns.is_empty()) {
        if !is_safe_shell_arg(ns, shell) {
            return None;
        }
        parts.push("-n".to_string());
        parts.push(quote_shell_arg(shell, ns));
    }
    Some(parts.join(" "))
}

/// `kubectl config view -o json`.
pub fn build_kubectl_contexts_command() -> String {
    "kubectl config view -o json".to_string()
}

/// `kubectl --context <ctx> get namespaces -o json`; `None` for an unsafe context.
pub fn build_kubectl_namespaces_command(context: &str, shell: KubectlShell) -> Option<String> {
    if !is_safe_shell_arg(context, shell) {
        return None;
    }
    Some(format!(
        "kubectl --context {} get namespaces -o json",
        quote_shell_arg(shell, context)
    ))
}

/// `kubectl --context <ctx> [-n <ns>] get pods -o json`.
pub fn build_kubectl_pods_command(
    context: &str,
    namespace: Option<&str>,
    shell: KubectlShell,
) -> Option<String> {
    kubectl_prefix(context, namespace, shell).map(|p| format!("{p} get pods -o json"))
}

/// `kubectl --context <ctx> [-n <ns>] delete pod <pod> --wait=false`.
pub fn build_kubectl_delete_pod_command(
    context: &str,
    namespace: Option<&str>,
    pod: &str,
    shell: KubectlShell,
) -> Option<String> {
    let prefix = kubectl_prefix(context, namespace, shell)?;
    if !is_safe_shell_arg(pod, shell) {
        return None;
    }
    Some(format!(
        "{prefix} delete pod {} --wait=false",
        quote_shell_arg(shell, pod)
    ))
}

// ---------------------------------------------------------------------------
// kubectl output parsers
// ---------------------------------------------------------------------------

/// Electron `parseJsonValue`: the first `{` / `[` from which the rest of the
/// text parses as JSON (skips warnings and `[WARN]` banners).
pub fn parse_json_value(text: &str) -> Option<Value> {
    for (i, ch) in text.char_indices() {
        if ch != '{' && ch != '[' {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(&text[i..]) {
            return Some(value);
        }
    }
    None
}

/// One kubeconfig context (`KubeContextInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeContext {
    pub name: String,
    pub namespace: String,
    pub current: bool,
}

/// Electron `parseKubeconfigContexts`: names + default namespaces, never
/// user / credential material. `None` when the output is not JSON.
pub fn parse_kubeconfig_contexts(text: &str) -> Option<(Vec<KubeContext>, String)> {
    let parsed = parse_json_value(text)?;
    let current = parsed["current-context"].as_str().unwrap_or("").to_string();
    let mut contexts = Vec::new();
    for entry in parsed["contexts"].as_array().into_iter().flatten() {
        let name = entry["name"].as_str().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let namespace = entry["context"]["namespace"]
            .as_str()
            .filter(|ns| !ns.is_empty())
            .unwrap_or("default");
        contexts.push(KubeContext {
            name: name.to_string(),
            namespace: namespace.to_string(),
            current: name == current,
        });
    }
    Some((contexts, current))
}

/// Electron `parseNamespaceList`.
pub fn parse_namespace_list(text: &str) -> Option<Vec<String>> {
    let parsed = parse_json_value(text)?;
    Some(
        parsed["items"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| item["metadata"]["name"].as_str())
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

/// Electron `formatPodAge`: `50s` / `3m` / `2h` / `2d`, `""` when unparsable.
pub fn format_pod_age(iso: &str, now_ms: i64) -> String {
    let Some(timestamp) = parse_iso_ms(iso) else {
        return String::new();
    };
    let seconds = ((now_ms - timestamp) as f64 / 1000.0).floor().max(0.0) as i64;
    if seconds < 60 {
        return format!("{seconds}s");
    }
    let minutes = seconds / 60;
    if minutes < 60 {
        return format!("{minutes}m");
    }
    let hours = minutes / 60;
    if hours < 24 {
        return format!("{hours}h");
    }
    format!("{}d", hours / 24)
}

fn array_items(value: &Value) -> impl Iterator<Item = &Value> {
    value.as_array().into_iter().flatten()
}

fn pod_display_status(pod: &Value) -> String {
    if pod["metadata"]["deletionTimestamp"]
        .as_str()
        .is_some_and(|s| !s.is_empty())
    {
        return "Terminating".to_string();
    }
    let status = &pod["status"];
    let statuses: Vec<&Value> = array_items(&status["initContainerStatuses"])
        .chain(array_items(&status["containerStatuses"]))
        .collect();
    for s in &statuses {
        let reason = &s["state"]["waiting"]["reason"];
        if js_truthy(reason) {
            return js_string(reason);
        }
    }
    let pod_reason = status["reason"].as_str().map(str::trim).unwrap_or("");
    if !pod_reason.is_empty() {
        return pod_reason.to_string();
    }
    for s in &statuses {
        let reason = &s["state"]["terminated"]["reason"];
        if js_truthy(reason) && reason.as_str() != Some("Completed") {
            return js_string(reason);
        }
    }
    let phase = &status["phase"];
    let phase = if js_truthy(phase) {
        js_string(phase)
    } else {
        "Unknown".to_string()
    };
    if phase == "Succeeded" {
        "Completed".to_string()
    } else {
        phase
    }
}

fn pod_container_names(pod: &Value) -> Vec<String> {
    let spec = &pod["spec"];
    let mut names: Vec<String> = Vec::new();
    for container in array_items(&spec["containers"])
        .chain(array_items(&spec["initContainers"]))
        .chain(array_items(&spec["ephemeralContainers"]))
    {
        if let Some(name) = container["name"].as_str().filter(|n| !n.is_empty()) {
            if !names.iter().any(|n| n == name) {
                names.push(name.to_string());
            }
        }
    }
    names
}

fn pod_shell_container_names(pod: &Value) -> Vec<String> {
    let status = &pod["status"];
    let mut running: Vec<String> = Vec::new();
    for s in array_items(&status["containerStatuses"])
        .chain(array_items(&status["initContainerStatuses"]))
        .chain(array_items(&status["ephemeralContainerStatuses"]))
    {
        if !js_truthy(&s["state"]["running"]) {
            continue;
        }
        if let Some(name) = s["name"].as_str().filter(|n| !n.is_empty()) {
            if !running.iter().any(|n| n == name) {
                running.push(name.to_string());
            }
        }
    }
    let mut ordered: Vec<String> = pod_container_names(pod)
        .into_iter()
        .filter(|name| running.contains(name))
        .collect();
    for name in running {
        if !ordered.contains(&name) {
            ordered.push(name);
        }
    }
    ordered
}

fn pod_restart_count(pod: &Value) -> f64 {
    let status = &pod["status"];
    array_items(&status["containerStatuses"])
        .chain(array_items(&status["initContainerStatuses"]))
        .map(|s| {
            let raw = &s["restartCount"];
            if js_truthy(raw) {
                js_number(raw)
            } else {
                0.0
            }
        })
        .filter(|n| n.is_finite())
        .sum()
}

/// Electron `parseKubectlPodList` → `KubectlPodInfo[]` as JSON.
pub fn parse_kubectl_pod_list(text: &str, now_ms: i64) -> Option<Vec<Value>> {
    let parsed = parse_json_value(text)?;
    let mut pods = Vec::new();
    for pod in array_items(&parsed["items"]) {
        let name = pod["metadata"]["name"].as_str().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        pods.push(json!({
            "name": name,
            "namespace": pod["metadata"]["namespace"].as_str().unwrap_or(""),
            "status": pod_display_status(pod),
            "restarts": js_num(pod_restart_count(pod)),
            "age": format_pod_age(&js_string_or_empty(&pod["metadata"]["creationTimestamp"]), now_ms),
            "containers": pod_container_names(pod),
            "shellContainers": pod_shell_container_names(pod),
        }));
    }
    Some(pods)
}

// ---------------------------------------------------------------------------
// Small JS-semantics helpers (shared with docker.rs)
// ---------------------------------------------------------------------------

/// JavaScript truthiness of a JSON value.
pub(crate) fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `String(value)` for JSON values.
pub(crate) fn js_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.as_f64().map(js_num_str).unwrap_or_else(|| n.to_string()),
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(|v| {
                if v.is_null() {
                    String::new()
                } else {
                    js_string(v)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// `String(value || "")`.
pub(crate) fn js_string_or_empty(value: &Value) -> String {
    if js_truthy(value) {
        js_string(value)
    } else {
        String::new()
    }
}

/// `Number(value)`.
pub(crate) fn js_number(value: &Value) -> f64 {
    match value {
        Value::Null => 0.0,
        Value::Bool(b) => f64::from(u8::from(*b)),
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                i64::from_str_radix(hex, 16)
                    .map(|v| v as f64)
                    .unwrap_or(f64::NAN)
            } else if t.chars().all(|c| c.is_ascii_digit() || "+-.eE".contains(c))
                || t == "Infinity"
                || t == "-Infinity"
                || t == "+Infinity"
            {
                match t {
                    "Infinity" | "+Infinity" => f64::INFINITY,
                    "-Infinity" => f64::NEG_INFINITY,
                    _ => t.parse::<f64>().unwrap_or(f64::NAN),
                }
            } else {
                f64::NAN
            }
        }
        Value::Array(items) => match items.as_slice() {
            [] => 0.0,
            [one] => js_number(&Value::String(js_string(one))),
            _ => f64::NAN,
        },
        Value::Object(_) => f64::NAN,
    }
}

/// `parseFloat(text)`: longest numeric prefix after leading whitespace.
pub(crate) fn js_parse_float(text: &str) -> f64 {
    static PREFIX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[+-]?(?:Infinity|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)").expect("valid regex")
    });
    let t = text.trim_start();
    match PREFIX.find(t) {
        Some(m) => match m.as_str().trim_start_matches('+') {
            "Infinity" => f64::INFINITY,
            "-Infinity" => f64::NEG_INFINITY,
            s => s.parse::<f64>().unwrap_or(f64::NAN),
        },
        None => f64::NAN,
    }
}

/// JS number → string (`7`, `1.5`).
pub(crate) fn js_num_str(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_string()
    } else if value.is_infinite() {
        if value > 0.0 { "Infinity" } else { "-Infinity" }.to_string()
    } else if value.fract() == 0.0 && value.abs() < 1e21 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

/// JS number → JSON (integers stay integers; NaN/Infinity become `null`
/// like `JSON.stringify`).
pub(crate) fn js_num(value: f64) -> Value {
    if !value.is_finite() {
        Value::Null
    } else if value.fract() == 0.0 && value.abs() < 9.0e15 {
        json!(value as i64)
    } else {
        json!(value)
    }
}

/// First field (in `keys` order) whose value is truthy (`a || b || c`).
pub(crate) fn first_truthy<'a>(row: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .filter_map(|k| row.get(*k))
        .find(|v| js_truthy(v))
}

/// First field (in `keys` order) that is not null / missing (`a ?? b ?? c`).
pub(crate) fn first_present<'a>(row: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .filter_map(|k| row.get(*k))
        .find(|v| !v.is_null())
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `Date.parse` for ISO-8601 / RFC 3339 timestamps (a missing offset is
/// read as UTC).
pub(crate) fn parse_iso_ms(text: &str) -> Option<i64> {
    static ISO: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?)?\s*(Z|z|[+-]\d{2}:?\d{2})?$",
        )
        .expect("valid regex")
    });
    let caps = ISO.captures(text.trim())?;
    let num = |i: usize| -> i64 {
        caps.get(i)
            .and_then(|m| m.as_str().parse::<i64>().ok())
            .unwrap_or(0)
    };
    let (year, month, day) = (num(1), num(2), num(3));
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (hour, minute, second) = (num(4), num(5), num(6));
    if hour > 24 || minute > 59 || second > 59 {
        return None;
    }
    let millis = caps
        .get(7)
        .map(|m| {
            let digits: String = m.as_str().chars().chain("000".chars()).take(3).collect();
            digits.parse::<i64>().unwrap_or(0)
        })
        .unwrap_or(0);
    let offset_minutes = match caps.get(8).map(|m| m.as_str()) {
        None | Some("Z") | Some("z") => 0,
        Some(offset) => {
            let sign = if offset.starts_with('-') { -1 } else { 1 };
            let digits: String = offset[1..].chars().filter(char::is_ascii_digit).collect();
            let h: i64 = digits[..2].parse().ok()?;
            let m: i64 = digits[2..].parse().ok()?;
            sign * (h * 60 + m)
        }
    };
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_minutes * 60;
    Some(secs * 1000 + millis)
}

/// `new Date(ms).toISOString()`.
pub(crate) fn iso_string_from_ms(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (y, m, d) = civil_from_days(days);
    let (h, rem) = (rem / 3_600_000, rem % 3_600_000);
    let (min, rem) = (rem / 60_000, rem % 60_000);
    let (s, milli) = (rem / 1000, rem % 1000);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}.{milli:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_runtime_probe_reads_line_anchored_markers() {
        let probe = parse_runtime_probe(
            &[
                "command -v docker >/dev/null && printf __NC_DOCKER__=1",
                "__NC_OS__=Linux",
                "__NC_DOCKER__=1",
                "__NC_PODMAN__=1",
                "echo __NC_NERDCTL__=1 trailing",
                "__NC_KUBECTL__=1",
            ]
            .join("\n"),
        );
        assert_eq!(
            probe,
            RuntimeProbe {
                docker: true,
                podman: true,
                nerdctl: false,
                kubernetes: true
            }
        );
        assert!(parse_runtime_probe("__NC_NERDCTL__=1\r\n").nerdctl);
        assert_eq!(parse_runtime_probe(""), RuntimeProbe::default());
    }

    #[test]
    fn build_runtime_command_defaults_unknown_runtimes_to_docker() {
        assert_eq!(
            build_runtime_command("docker", "ps -a --format '{{json .}}'"),
            "docker ps -a --format '{{json .}}'"
        );
        assert_eq!(
            build_runtime_command("podman", "start abc123"),
            "podman start abc123"
        );
        assert_eq!(
            build_runtime_command("nerdctl", "logs -f --tail 200 abc123"),
            "nerdctl logs -f --tail 200 abc123"
        );
        assert_eq!(build_runtime_command("kubernetes", "ps"), "docker ps");
        assert_eq!(normalize_container_runtime(None), "docker");
    }

    #[test]
    fn socket_permission_fallback_is_specific_to_each_runtime() {
        let check = |rt: &str, stderr: &str| is_runtime_socket_permission_error(rt, stderr, "", "");
        assert!(check(
            "docker",
            "dial unix /var/run/docker.sock: connect: permission denied"
        ));
        assert!(!check("docker", "permission denied"));
        assert!(check(
            "podman",
            "dial unix /run/podman/podman.sock: connect: permission denied"
        ));
        assert!(check(
            "nerdctl",
            "dial unix /run/containerd/containerd.sock: connect: permission denied"
        ));
        assert!(!check(
            "podman",
            "dial unix /var/run/docker.sock: connect: permission denied"
        ));
    }

    #[test]
    fn kubeconfig_contexts_omit_user_material() {
        let text = json!({
            "current-context": "kind-kind",
            "contexts": [
                { "name": "kind-kind", "context": { "cluster": "kind-kind", "user": "kind-kind", "namespace": "app" } },
                { "name": "arn:aws:eks:us-west-2:123:cluster/prod", "context": { "cluster": "prod", "user": "admin" } }
            ],
            "users": [{ "name": "admin", "user": { "token": "secret-token" } }]
        })
        .to_string();
        let (contexts, current) = parse_kubeconfig_contexts(&text).unwrap();
        assert_eq!(current, "kind-kind");
        assert_eq!(
            contexts,
            vec![
                KubeContext {
                    name: "kind-kind".into(),
                    namespace: "app".into(),
                    current: true
                },
                KubeContext {
                    name: "arn:aws:eks:us-west-2:123:cluster/prod".into(),
                    namespace: "default".into(),
                    current: false
                },
            ]
        );
        assert!(parse_kubeconfig_contexts("not json").is_none());
    }

    #[test]
    fn namespace_list_skips_banners_and_warnings() {
        let names = parse_namespace_list(
            "[WARN] connection is using an insecure certificate\n{\"items\":[{\"metadata\":{\"name\":\"default\"}}]}",
        );
        assert_eq!(names.unwrap(), vec!["default"]);
        let stdout = format!(
            "Warning: old client\n{}",
            json!({ "items": [
                { "metadata": { "name": "default" } },
                { "metadata": { "name": "kube-system" } },
                { "metadata": {} }
            ]})
        );
        assert_eq!(
            parse_namespace_list(&stdout).unwrap(),
            vec!["default", "kube-system"]
        );
    }

    #[test]
    fn pod_list_reports_status_restarts_age_and_containers() {
        let now = parse_iso_ms("2026-10-20T00:10:00Z").unwrap();
        let pods = parse_kubectl_pod_list(
            &json!({ "items": [
                {
                    "metadata": { "name": "api", "namespace": "default", "creationTimestamp": "2026-10-20T00:08:30Z" },
                    "spec": { "containers": [{ "name": "app" }, { "name": "sidecar" }], "initContainers": [{ "name": "init" }] },
                    "status": {
                        "phase": "Running",
                        "initContainerStatuses": [
                            { "name": "init", "restartCount": 0, "state": { "terminated": { "reason": "Completed" } } }
                        ],
                        "containerStatuses": [
                            { "name": "app", "restartCount": 4, "state": { "waiting": { "reason": "CrashLoopBackOff" } } },
                            { "name": "sidecar", "restartCount": 1, "state": { "running": {} } }
                        ]
                    }
                },
                {
                    "metadata": { "name": "batch", "namespace": "jobs", "creationTimestamp": "2026-10-18T00:10:00Z" },
                    "spec": { "containers": [{ "name": "worker" }] },
                    "status": {
                        "phase": "Succeeded",
                        "containerStatuses": [
                            { "name": "worker", "restartCount": 0, "state": { "terminated": { "reason": "Completed" } } }
                        ]
                    }
                }
            ]})
            .to_string(),
            now,
        )
        .unwrap();
        assert_eq!(
            pods,
            vec![
                json!({
                    "name": "api", "namespace": "default", "status": "CrashLoopBackOff",
                    "restarts": 5, "age": "1m",
                    "containers": ["app", "sidecar", "init"], "shellContainers": ["sidecar"]
                }),
                json!({
                    "name": "batch", "namespace": "jobs", "status": "Completed",
                    "restarts": 0, "age": "2d",
                    "containers": ["worker"], "shellContainers": []
                }),
            ]
        );

        let terminating = parse_kubectl_pod_list(
            &json!({ "items": [{
                "metadata": {
                    "name": "api", "namespace": "default",
                    "creationTimestamp": "2026-10-20T00:08:30Z",
                    "deletionTimestamp": "2026-10-20T00:10:00Z"
                },
                "spec": {
                    "containers": [{ "name": "app" }],
                    "ephemeralContainers": [{ "name": "debugger" }, { "name": "old-debug" }]
                },
                "status": {
                    "phase": "Running",
                    "containerStatuses": [{ "name": "app", "restartCount": 0, "state": { "running": {} } }],
                    "ephemeralContainerStatuses": [
                        { "name": "debugger", "restartCount": 0, "state": { "running": {} } },
                        { "name": "old-debug", "restartCount": 0, "state": { "terminated": { "reason": "Completed" } } }
                    ]
                }
            }]})
            .to_string(),
            now,
        )
        .unwrap();
        assert_eq!(terminating[0]["status"], "Terminating");
        assert_eq!(
            terminating[0]["containers"],
            json!(["app", "debugger", "old-debug"])
        );
        assert_eq!(
            terminating[0]["shellContainers"],
            json!(["app", "debugger"])
        );

        let evicted = parse_kubectl_pod_list(
            &json!({ "items": [{
                "metadata": { "name": "api", "namespace": "default", "creationTimestamp": "2026-10-20T00:08:30Z" },
                "spec": { "containers": [{ "name": "app" }] },
                "status": {
                    "phase": "Failed", "reason": "Evicted",
                    "message": "The node was low on resource: memory.",
                    "containerStatuses": [
                        { "name": "app", "restartCount": 0, "state": { "terminated": { "reason": "Error", "exitCode": 137 } } }
                    ]
                }
            }]})
            .to_string(),
            now,
        )
        .unwrap();
        assert_eq!(evicted[0]["status"], "Evicted");

        assert_eq!(format_pod_age("2026-10-20T00:09:10Z", now), "50s");
        assert_eq!(format_pod_age("2026-10-20T00:07:00Z", now), "3m");
        assert_eq!(format_pod_age("2026-10-19T22:10:00Z", now), "2h");
        assert_eq!(format_pod_age("garbage", now), "");
    }

    #[test]
    fn kubectl_commands_quote_arguments_and_reject_control_characters() {
        use KubectlShell::*;
        assert_eq!(
            build_kubectl_pods_command("kind-kind", Some("default"), Posix).unwrap(),
            "kubectl --context 'kind-kind' -n 'default' get pods -o json"
        );
        assert_eq!(
            build_kubectl_namespaces_command("arn:aws:eks:us-west-2:123:cluster/prod", Posix)
                .unwrap(),
            "kubectl --context 'arn:aws:eks:us-west-2:123:cluster/prod' get namespaces -o json"
        );
        assert_eq!(
            build_kubectl_delete_pod_command("ctx", Some("kube-system"), "coredns-a", Posix)
                .unwrap(),
            "kubectl --context 'ctx' -n 'kube-system' delete pod 'coredns-a' --wait=false"
        );
        assert!(
            build_kubectl_delete_pod_command("ctx", Some("default"), "bad\nname", Posix).is_none()
        );
        assert!(build_kubectl_pods_command("ok", Some("bad\nns"), Posix).is_none());
        assert_eq!(
            build_kubectl_namespaces_command("o'brien", PowerShell).unwrap(),
            "kubectl --context 'o''brien' get namespaces -o json"
        );
        assert_eq!(
            build_kubectl_pods_command("o'brien", Some("default"), PowerShell).unwrap(),
            "kubectl --context 'o''brien' -n 'default' get pods -o json"
        );
        assert!(
            build_kubectl_delete_pod_command("o'brien", Some("default"), "web", Cmd)
                .unwrap()
                .contains("--context \"o'brien\"")
        );
        let quoted =
            build_kubectl_delete_pod_command("o'brien", Some("default"), "web", Posix).unwrap();
        assert!(quoted.contains("--context 'o'\"'\"'brien'"));
        assert!(build_kubectl_pods_command("", None, Posix).is_none());
        assert!(build_kubectl_namespaces_command("50%", Cmd).is_none());
    }

    #[test]
    fn error_classifiers() {
        assert!(is_kubectl_forbidden_error(
            "Error from server (Forbidden): namespaces is forbidden: User \"view\" cannot list resource \"namespaces\""
        ));
        assert!(!is_kubectl_forbidden_error(
            "Unable to connect to the server"
        ));

        let spam = "memcache.go:381] \"Couldn't get current server API group list\"\ndial tcp 127.0.0.1:6443: connect: connection refused";
        assert!(is_kubectl_unreachable_error(spam));
        assert!(is_kubectl_unreachable_error(
            "Unable to connect to the server: dial tcp 10.0.0.1:6443: i/o timeout"
        ));
        assert!(!is_kubectl_unreachable_error(
            "Error from server (Forbidden): pods is forbidden"
        ));
        assert!(!is_kubectl_unreachable_error(""));

        assert!(is_nerdctl_unreachable_error(
            "time=\"2026-10-20T18:31:27+08:00\" level=fatal msg=\"rootless containerd not running? (hint: use containerd-rootless-setuptool.sh install to start rootless containerd): environment variable XDG_RUNTIME_DIR is not set\""
        ));
        assert!(!is_nerdctl_unreachable_error(
            "permission denied while trying to connect to the containerd socket"
        ));
        assert!(!is_nerdctl_unreachable_error(
            "Error: no such container: abc"
        ));
    }

    #[test]
    fn js_helpers() {
        assert_eq!(js_parse_float("1.50%"), 1.5);
        assert_eq!(js_parse_float(" 0.25%"), 0.25);
        assert!(js_parse_float("abc").is_nan());
        assert_eq!(js_number(&json!("4")), 4.0);
        assert!(js_number(&json!("4x")).is_nan());
        assert_eq!(js_num_str(7.0), "7");
        assert_eq!(js_num_str(1.5), "1.5");
        assert_eq!(
            iso_string_from_ms(1_700_000_000_000),
            "2023-11-14T22:13:20.000Z"
        );
        assert_eq!(
            parse_iso_ms("2023-11-14T23:13:20.5+01:00"),
            Some(1_700_000_000_500)
        );
    }
}
