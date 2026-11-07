//! Container management for Docker, Podman and nerdctl (Electron
//! `systemManager/dockerOps.cjs` plus the reply mapping in
//! `systemManagerBridge.cjs`).
//!
//! Every runtime command is tried plainly first; a daemon-socket permission
//! denial retries with passwordless `sudo`, then with `sudo -S` fed the
//! host's saved sudo-autofill password through stdin (never argv).

use crate::container_runtime::{
    build_runtime_command, first_present, first_truthy, is_nerdctl_unreachable_error,
    is_runtime_socket_permission_error, iso_string_from_ms, js_num, js_num_str, js_number,
    js_parse_float, js_string, js_string_or_empty, js_truthy, normalize_container_runtime,
};
use crate::exec::{sh_quote, ExecRequest, ExecResult, SessionExec};
use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// Sanitizers
// ---------------------------------------------------------------------------

/// Electron `sanitizeDockerId`: alphanumerics only, max 64.
fn sanitize_docker_id(id: Option<&Value>) -> String {
    let raw = id.map(js_string_or_empty).unwrap_or_default();
    raw.chars()
        .filter(char::is_ascii_alphanumeric)
        .take(64)
        .collect()
}

fn js_slice(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// Electron `sanitizeContainerName`.
fn sanitize_container_name(name: Option<&Value>) -> Option<String> {
    let raw = name.map(js_string_or_empty).unwrap_or_default();
    let trimmed = js_slice(raw.trim(), 128);
    if trimmed.is_empty() {
        return None;
    }
    let cleaned: String = trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Electron `sanitizeImageRef`.
fn sanitize_image_ref(raw: &str) -> Option<String> {
    let trimmed = js_slice(raw.trim(), 256);
    (!trimmed.is_empty()).then_some(trimmed)
}

// ---------------------------------------------------------------------------
// runDocker
// ---------------------------------------------------------------------------

/// Electron `userFacingRuntimeFailure`.
fn user_facing_runtime_failure(runtime: &str, result: &ExecResult, fallback: &str) -> ExecResult {
    let raw = result.command_error(fallback);
    if runtime == "nerdctl" && is_nerdctl_unreachable_error(&raw) {
        return ExecResult {
            success: false,
            error_code: Some("nerdctlUnreachable".into()),
            ..Default::default()
        };
    }
    ExecResult {
        success: false,
        error: Some(raw),
        stderr: result.stderr.clone(),
        ..Default::default()
    }
}

fn code_label(code: Option<i32>) -> String {
    code.map(|c| c.to_string())
        .unwrap_or_else(|| "undefined".to_string())
}

/// Electron `runDocker`: run `<runtime> <args>`, retrying through sudo on a
/// daemon-socket permission denial.
async fn run_docker(
    exec: &dyn SessionExec,
    args: &str,
    timeout_ms: u64,
    runtime: Option<&Value>,
) -> ExecResult {
    let runtime = normalize_container_runtime(runtime);
    let bin = runtime;
    let cmd = build_runtime_command(runtime, args);
    let result = exec.exec(ExecRequest::new(cmd.clone(), timeout_ms)).await;
    if result.is_successful() {
        return result;
    }

    if is_runtime_socket_permission_error(
        runtime,
        &result.stderr,
        &result.stdout,
        result.error.as_deref().unwrap_or(""),
    ) {
        let sudo_password = exec.sudo_password();
        let nopasswd = exec
            .exec(ExecRequest::new(format!("sudo {cmd}"), timeout_ms))
            .await;
        if nopasswd.is_successful() {
            return nopasswd;
        }
        let mut last = nopasswd;
        if let Some(password) = sudo_password {
            let with_password = exec
                .exec(
                    ExecRequest::new(format!("sudo -S -p '' {cmd}"), timeout_ms)
                        .with_stdin(format!("{password}\n")),
                )
                .await;
            if with_password.is_successful() {
                return with_password;
            }
            last = with_password;
        }
        let fallback = format!("sudo {bin} exited with code {}", code_label(last.code));
        return user_facing_runtime_failure(runtime, &last, &fallback);
    }

    if !result.success {
        if runtime == "nerdctl" && is_nerdctl_unreachable_error(&result.command_error("")) {
            return user_facing_runtime_failure(runtime, &result, &format!("{bin} failed"));
        }
        return result;
    }
    if let Some(code) = result.code.filter(|c| *c != 0) {
        return user_facing_runtime_failure(
            runtime,
            &result,
            &format!("{bin} exited with code {code}"),
        );
    }
    result
}

/// Electron `failurePayload`.
fn failure_payload(result: &ExecResult) -> Value {
    let mut out = Map::new();
    out.insert("success".into(), json!(false));
    if let Some(error) = result.error.as_deref().filter(|e| !e.is_empty()) {
        out.insert("error".into(), json!(error));
    }
    if let Some(code) = result.error_code.as_deref().filter(|c| !c.is_empty()) {
        out.insert("errorCode".into(), json!(code));
    }
    if !out.contains_key("error") && !out.contains_key("errorCode") {
        out.insert("error".into(), json!("command failed"));
    }
    Value::Object(out)
}

/// Bridge mapping for mutating actions (`dockerAction` / `dockerImageAction`):
/// keep `nerdctlUnreachable`, otherwise `error || stderr || fallback`.
fn action_failure(result: &ExecResult) -> Value {
    if result.error_code.as_deref() == Some("nerdctlUnreachable") {
        return json!({ "success": false, "errorCode": "nerdctlUnreachable" });
    }
    let error = result
        .error
        .clone()
        .filter(|e| !e.is_empty())
        .or_else(|| Some(result.stderr.clone()).filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "docker command failed".to_string());
    json!({ "success": false, "error": error })
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/// Electron `parseJsonRecords`: a JSON array / object, or JSON lines.
pub fn parse_json_records(stdout: &str) -> Vec<Map<String, Value>> {
    let raw = stdout.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let objects = |value: Value| -> Vec<Map<String, Value>> {
        match value {
            Value::Array(items) => items
                .into_iter()
                .filter_map(|item| match item {
                    Value::Object(map) => Some(map),
                    _ => None,
                })
                .collect(),
            Value::Object(map) => vec![map],
            _ => Vec::new(),
        }
    };
    if raw.starts_with('[') || raw.starts_with('{') {
        if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
            if parsed.is_array() || parsed.is_object() {
                return objects(parsed);
            }
        }
    }
    let mut rows = Vec::new();
    for line in raw.split('\n') {
        let trimmed = line.trim();
        let trimmed = trimmed.strip_suffix(',').unwrap_or(trimmed);
        if trimmed.is_empty() || trimmed == "[" || trimmed == "]" {
            continue;
        }
        if let Ok(row) = serde_json::from_str::<Value>(trimmed) {
            rows.extend(objects(row));
        }
    }
    rows
}

/// Electron `portInRange`.
fn port_in_range(value: Option<&Value>) -> Option<i64> {
    let n = value.map(js_number).unwrap_or(f64::NAN);
    (n.fract() == 0.0 && (1.0..=65535.0).contains(&n)).then_some(n as i64)
}

fn format_host_bind(ip: &str, host_label: &str) -> String {
    let bind = if ip.is_empty() { "0.0.0.0" } else { ip };
    if bind.contains(':') && !bind.starts_with('[') {
        format!("[{bind}]:{host_label}")
    } else {
        format!("{bind}:{host_label}")
    }
}

struct FormattedPort {
    label: String,
    keys: Vec<String>,
}

/// Electron `formatPortMapping` (Podman's structured `Ports` entries).
fn format_port_mapping(mapping: &Value) -> Vec<FormattedPort> {
    let Some(mapping) = mapping.as_object() else {
        return Vec::new();
    };
    let Some(container_port) = port_in_range(first_present(
        mapping,
        &[
            "container_port",
            "containerPort",
            "ContainerPort",
            "PrivatePort",
        ],
    )) else {
        return Vec::new();
    };
    let host_port = port_in_range(first_present(
        mapping,
        &["host_port", "hostPort", "HostPort", "PublicPort"],
    ));
    let requested_range = first_present(mapping, &["range", "Range"])
        .map(js_number)
        .unwrap_or(f64::NAN);
    let range = if requested_range.fract() == 0.0 && requested_range > 1.0 {
        requested_range as i64
    } else {
        1
    };
    if container_port + range - 1 > 65535 {
        return Vec::new();
    }
    if host_port.is_some_and(|hp| hp + range - 1 > 65535) {
        return Vec::new();
    }
    let host_ip = first_present(mapping, &["host_ip", "hostIP", "HostIP", "HostIp", "IP"])
        .map(js_string)
        .unwrap_or_default()
        .trim()
        .to_string();
    let protocols_raw = first_present(mapping, &["protocol", "Protocol", "Type"])
        .map(js_string)
        .unwrap_or_else(|| "tcp".to_string());
    let mut protocols: Vec<String> = protocols_raw
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    if protocols.is_empty() {
        protocols.push("tcp".to_string());
    }
    let container_label = if range > 1 {
        format!("{container_port}-{}", container_port + range - 1)
    } else {
        container_port.to_string()
    };
    let host_label = match host_port {
        None => String::new(),
        Some(hp) if range > 1 => format!("{hp}-{}", hp + range - 1),
        Some(hp) => hp.to_string(),
    };
    protocols
        .into_iter()
        .map(|protocol| {
            let keys = (0..range)
                .map(|offset| format!("{}/{protocol}", container_port + offset))
                .collect();
            let label = if host_label.is_empty() {
                format!("{container_label}/{protocol}")
            } else {
                format!(
                    "{}->{container_label}/{protocol}",
                    format_host_bind(&host_ip, &host_label)
                )
            };
            FormattedPort { label, keys }
        })
        .collect()
}

/// Electron `formatExposedPorts`: exposed-but-unpublished ports.
fn format_exposed_ports(exposed: Option<&Value>, published: &[String]) -> Vec<String> {
    let Some(exposed) = exposed.and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut entries: Vec<(i64, String)> = Vec::new();
    for (key, value) in exposed {
        if let Some(slash) = key.find('/').filter(|s| *s > 0) {
            let port = port_in_range(Some(&Value::String(key[..slash].to_string())));
            let protocol = key[slash + 1..].trim();
            let protocol = if protocol.is_empty() { "tcp" } else { protocol };
            if let Some(port) = port {
                entries.push((port, protocol.to_string()));
            }
            continue;
        }
        let Some(port) = port_in_range(Some(&Value::String(key.clone()))) else {
            continue;
        };
        let protocols: Vec<Value> = match value.as_array() {
            Some(list) if !list.is_empty() => list.clone(),
            _ => vec![json!("tcp")],
        };
        for protocol in protocols {
            let name = if js_truthy(&protocol) {
                js_string(&protocol)
            } else {
                "tcp".to_string()
            };
            let name = name.trim();
            if !name.is_empty() {
                entries.push((port, name.to_string()));
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut labels: Vec<String> = Vec::new();
    for (port, protocol) in entries {
        let label = format!("{port}/{protocol}");
        if published.contains(&label) || labels.contains(&label) {
            continue;
        }
        labels.push(label);
    }
    labels
}

/// Electron `formatContainerPorts`.
fn format_container_ports(row: &Map<String, Value>) -> Value {
    let ports = first_present(row, &["Ports", "ports"]);
    if let Some(Value::String(text)) = ports {
        return json!(text);
    }
    let mut labels: Vec<String> = Vec::new();
    let mut published: Vec<String> = Vec::new();
    if let Some(Value::Array(mappings)) = ports {
        for mapping in mappings {
            for formatted in format_port_mapping(mapping) {
                if labels.contains(&formatted.label) {
                    continue;
                }
                labels.push(formatted.label);
                for key in formatted.keys {
                    if !published.contains(&key) {
                        published.push(key);
                    }
                }
            }
        }
    }
    labels.extend(format_exposed_ports(
        first_present(row, &["ExposedPorts", "exposedPorts"]),
        &published,
    ));
    json!(labels.join(", "))
}

fn truthy_or_empty(row: &Map<String, Value>, keys: &[&str]) -> Value {
    first_truthy(row, keys)
        .cloned()
        .unwrap_or_else(|| json!(""))
}

/// Electron `parseDockerContainers` → `DockerContainerInfo[]`.
pub fn parse_docker_containers(stdout: &str) -> Vec<Value> {
    parse_json_records(stdout)
        .into_iter()
        .map(|row| {
            let raw_name = match row.get("Names") {
                Some(Value::Array(names)) => {
                    names.first().map(js_string_or_empty).unwrap_or_default()
                }
                _ => first_truthy(&row, &["Names", "Name"])
                    .map(js_string)
                    .unwrap_or_default(),
            };
            let name = raw_name.strip_prefix('/').unwrap_or(&raw_name).to_string();
            json!({
                "id": truthy_or_empty(&row, &["ID", "Id"]),
                "name": name,
                "image": truthy_or_empty(&row, &["Image"]),
                "status": truthy_or_empty(&row, &["Status", "State"]),
                "state": truthy_or_empty(&row, &["State"]),
                "ports": format_container_ports(&row),
                "createdAt": truthy_or_empty(&row, &["CreatedAt", "Created"]),
            })
        })
        .filter(|c| js_truthy(&c["id"]) || js_truthy(&c["name"]))
        .collect()
}

/// Electron `parsePercent`.
fn parse_percent(value: Option<&Value>) -> f64 {
    if let Some(Value::Number(n)) = value {
        if let Some(f) = n.as_f64().filter(|f| f.is_finite()) {
            return f;
        }
    }
    let text = value
        .map(js_string_or_empty)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "0".to_string())
        .replacen('%', "", 1);
    let parsed = js_parse_float(&text);
    if parsed.is_nan() || parsed == 0.0 {
        0.0
    } else {
        parsed
    }
}

/// Electron `sumNetworkBytes`: Podman's per-interface `Network` counters.
fn sum_network_bytes(network: Option<&Value>) -> Option<(f64, f64)> {
    let network = network?.as_object()?;
    let (mut rx, mut tx, mut saw) = (0.0, 0.0, false);
    for stats in network.values() {
        let Some(stats) = stats.as_object() else {
            continue;
        };
        if let Some(v) = first_present(stats, &["RxBytes", "rx_bytes"]).and_then(Value::as_f64) {
            rx += v;
            saw = true;
        }
        if let Some(v) = first_present(stats, &["TxBytes", "tx_bytes"]).and_then(Value::as_f64) {
            tx += v;
            saw = true;
        }
    }
    saw.then_some((rx, tx))
}

fn number_field(row: &Map<String, Value>, key: &str) -> Option<f64> {
    row.get(key).and_then(Value::as_f64)
}

/// Electron `parseDockerStats` → `DockerStatInfo[]`.
pub fn parse_docker_stats(stdout: &str) -> Vec<Value> {
    parse_json_records(stdout)
        .into_iter()
        .map(|row| {
            let mem_usage = match (number_field(&row, "MemUsage"), number_field(&row, "MemLimit")) {
                (Some(used), Some(limit)) => {
                    format!("{} / {}", format_size_num(used), format_size_num(limit))
                }
                _ => first_truthy(&row, &["MemUsage", "mem_usage"])
                    .map(js_string)
                    .unwrap_or_default(),
            };
            let net_io = match first_truthy(&row, &["NetIO", "net_io", "netio"]) {
                Some(v) => js_string(v),
                None => match sum_network_bytes(first_truthy(&row, &["Network", "network"])) {
                    Some((rx, tx)) => format!("{} / {}", format_size_num(rx), format_size_num(tx)),
                    None => match (number_field(&row, "NetInput"), number_field(&row, "NetOutput")) {
                        (Some(i), Some(o)) => {
                            format!("{} / {}", format_size_num(i), format_size_num(o))
                        }
                        _ => String::new(),
                    },
                },
            };
            let block_io = match first_truthy(&row, &["BlockIO", "block_io"]) {
                Some(v) => js_string(v),
                None => match (
                    number_field(&row, "BlockInput"),
                    number_field(&row, "BlockOutput"),
                ) {
                    (Some(i), Some(o)) => {
                        format!("{} / {}", format_size_num(i), format_size_num(o))
                    }
                    _ => String::new(),
                },
            };
            let pids = first_truthy(&row, &["PIDs", "Pids", "pids"])
                .map(js_number)
                .unwrap_or(0.0);
            let pids = if pids.is_nan() { 0.0 } else { pids };
            json!({
                "id": first_truthy(&row, &["ID", "Id", "id", "ContainerID", "Container"])
                    .map(js_string)
                    .unwrap_or_default(),
                "name": first_truthy(&row, &["Name", "name"]).map(js_string).unwrap_or_default(),
                "cpuPercent": js_num(parse_percent(first_present(&row, &["CPUPerc", "cpu_percent", "CPU"]))),
                "memUsage": mem_usage,
                "memPercent": js_num(parse_percent(first_present(&row, &["MemPerc", "mem_percent"]))),
                "netIO": net_io,
                "blockIO": block_io,
                "pids": js_num(pids),
            })
        })
        .filter(|s| js_truthy(&s["id"]) || js_truthy(&s["name"]))
        .collect()
}

fn split_image_name(text: &str) -> (String, String) {
    let slash = text.rfind('/');
    let colon = text.rfind(':');
    match colon {
        Some(c) if slash.is_none_or(|s| c > s) => {
            (text[..c].to_string(), text[c + 1..].to_string())
        }
        _ => (text.to_string(), String::new()),
    }
}

fn image_aliases(row: &Map<String, Value>) -> Vec<(String, String)> {
    let repo = row.get("Repository").cloned().unwrap_or(Value::Null);
    let tag = row.get("Tag").cloned().unwrap_or(Value::Null);
    if js_truthy(&repo) || js_truthy(&tag) {
        return vec![(js_string_or_empty(&repo), js_string_or_empty(&tag))];
    }
    let names: Vec<Value> = match (row.get("Names"), row.get("RepoTags")) {
        (Some(Value::Array(names)), _) if !names.is_empty() => names.clone(),
        (_, Some(Value::Array(tags))) => tags.clone(),
        _ => Vec::new(),
    };
    let aliases: Vec<(String, String)> = names
        .iter()
        .filter(|n| js_truthy(n))
        .map(|n| split_image_name(&js_string(n)))
        .collect();
    if aliases.is_empty() {
        vec![(String::new(), String::new())]
    } else {
        aliases
    }
}

fn format_size_num(size: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = size;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let rounded = if unit == 0 || value >= 10.0 {
        (value + 0.5).floor()
    } else {
        (value * 10.0 + 0.5).floor() / 10.0
    };
    format!("{}{}", js_num_str(rounded), UNITS[unit])
}

/// Electron `formatImageSize`: numbers become `7MB` / `1.5KB`, anything else
/// is passed through as text.
fn format_image_size(size: Option<&Value>) -> String {
    match size {
        Some(Value::Number(n)) => match n.as_f64() {
            Some(f) if f.is_finite() => format_size_num(f),
            _ => js_string(&Value::Number(n.clone())),
        },
        Some(v) => js_string_or_empty(v),
        None => String::new(),
    }
}

fn format_image_created(row: &Map<String, Value>) -> String {
    if let Some(v) = row.get("CreatedAt").filter(|v| js_truthy(v)) {
        return js_string(v);
    }
    if let Some(v) = row.get("CreatedSince").filter(|v| js_truthy(v)) {
        return js_string(v);
    }
    match row.get("Created") {
        Some(Value::Number(n)) => match n.as_f64().filter(|f| f.is_finite()) {
            Some(created) => {
                let ms = if created > 1e12 {
                    created
                } else {
                    created * 1000.0
                };
                iso_string_from_ms(ms as i64)
            }
            None => String::new(),
        },
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

/// Electron `parseDockerImages` → `DockerImageInfo[]` (one entry per tag).
pub fn parse_docker_images(stdout: &str) -> Vec<Value> {
    let mut images = Vec::new();
    for row in parse_json_records(stdout) {
        let id = first_truthy(&row, &["ID", "Id"])
            .map(js_string)
            .unwrap_or_default();
        let size = format_image_size(row.get("Size"));
        let created_at = format_image_created(&row);
        let digest = match row.get("Digest").filter(|v| js_truthy(v)) {
            Some(v) => js_string(v),
            None => match row.get("RepoDigests") {
                Some(Value::Array(list)) => {
                    list.first().map(js_string_or_empty).unwrap_or_default()
                }
                _ => String::new(),
            },
        };
        for (repository, tag) in image_aliases(&row) {
            let name = if !repository.is_empty() && !tag.is_empty() {
                format!("{repository}:{tag}")
            } else if !repository.is_empty() {
                repository.clone()
            } else if !tag.is_empty() {
                tag.clone()
            } else {
                id.clone()
            };
            if id.is_empty() && name.is_empty() {
                continue;
            }
            images.push(json!({
                "id": id,
                "repository": repository,
                "tag": tag,
                "size": size,
                "createdAt": created_at,
                "digest": digest,
                "name": name,
            }));
        }
    }
    images
}

/// Insert `key` when the JS source value would not be `undefined`.
fn put(out: &mut Map<String, Value>, key: &str, value: Option<&Value>) {
    if let Some(v) = value {
        out.insert(key.to_string(), v.clone());
    }
}

fn summarize_image_inspect(info: &Value) -> Value {
    if !js_truthy(info) {
        return Value::Null;
    }
    let mut out = Map::new();
    put(&mut out, "id", info.get("Id"));
    put(&mut out, "repoTags", info.get("RepoTags"));
    put(&mut out, "repoDigests", info.get("RepoDigests"));
    put(&mut out, "created", info.get("Created"));
    put(&mut out, "size", info.get("Size"));
    put(&mut out, "architecture", info.get("Architecture"));
    put(&mut out, "os", info.get("Os"));
    let config_src = info.get("Config").filter(|c| !c.is_null());
    let field = |key: &str| config_src.and_then(|c| c.get(key));
    let mut config = Map::new();
    put(&mut config, "env", field("Env"));
    put(&mut config, "cmd", field("Cmd"));
    put(&mut config, "entrypoint", field("Entrypoint"));
    put(&mut config, "workingDir", field("WorkingDir"));
    put(&mut config, "exposedPorts", field("ExposedPorts"));
    put(&mut config, "labels", field("Labels"));
    out.insert("config".into(), Value::Object(config));
    put(&mut out, "rootfs", info.get("RootFS"));
    if let Some(Value::Array(history)) = info.get("History") {
        out.insert(
            "history".into(),
            Value::Array(history.iter().take(5).cloned().collect()),
        );
    }
    Value::Object(out)
}

fn summarize_container_inspect(info: &Value) -> Value {
    if !js_truthy(info) {
        return Value::Null;
    }
    let config = info.get("Config").filter(|c| !c.is_null());
    let host_config = info.get("HostConfig").filter(|c| !c.is_null());
    let mut out = Map::new();
    put(&mut out, "id", info.get("Id"));
    put(&mut out, "name", info.get("Name"));
    put(&mut out, "image", config.and_then(|c| c.get("Image")));
    put(&mut out, "state", info.get("State"));
    put(&mut out, "network", info.get("NetworkSettings"));
    put(&mut out, "mounts", info.get("Mounts"));
    put(&mut out, "env", config.and_then(|c| c.get("Env")));
    put(&mut out, "labels", config.and_then(|c| c.get("Labels")));
    put(&mut out, "created", info.get("Created"));
    put(&mut out, "path", info.get("Path"));
    put(&mut out, "args", info.get("Args"));
    put(
        &mut out,
        "restartPolicy",
        host_config.and_then(|c| c.get("RestartPolicy")),
    );
    Value::Object(out)
}

/// `JSON.parse(stdout || "[]")`, first element when it is an array.
fn parse_inspect(stdout: &str) -> Option<Value> {
    let text = if stdout.is_empty() { "[]" } else { stdout };
    let parsed: Value = serde_json::from_str(text).ok()?;
    Some(match parsed {
        Value::Array(mut items) => {
            if items.is_empty() {
                Value::Null
            } else {
                items.swap_remove(0)
            }
        }
        other => other,
    })
}

// ---------------------------------------------------------------------------
// Bridge operations
// ---------------------------------------------------------------------------

fn field<'a>(payload: &'a Value, key: &str) -> Option<&'a Value> {
    payload.get(key).filter(|v| js_truthy(v))
}

/// `listDockerContainers({ sessionId, runtime })`.
pub async fn list_containers(exec: &dyn SessionExec, payload: &Value) -> Value {
    if field(payload, "sessionId").is_none() {
        return json!({ "success": false, "error": "Missing sessionId" });
    }
    let result = run_docker(
        exec,
        "ps -a --format '{{json .}}'",
        12_000,
        payload.get("runtime"),
    )
    .await;
    if !result.success {
        return failure_payload(&result);
    }
    json!({ "success": true, "containers": parse_docker_containers(&result.stdout) })
}

/// `listDockerImages({ sessionId, runtime })`.
pub async fn list_images(exec: &dyn SessionExec, payload: &Value) -> Value {
    if field(payload, "sessionId").is_none() {
        return json!({ "success": false, "error": "Missing sessionId" });
    }
    let result = run_docker(
        exec,
        "images --format '{{json .}}'",
        12_000,
        payload.get("runtime"),
    )
    .await;
    if !result.success {
        return failure_payload(&result);
    }
    json!({ "success": true, "images": parse_docker_images(&result.stdout) })
}

/// `getDockerStats({ sessionId, ids?, runtime? })`.
pub async fn get_stats(exec: &dyn SessionExec, payload: &Value) -> Value {
    if field(payload, "sessionId").is_none() {
        return json!({ "success": false, "error": "Missing sessionId" });
    }
    let id_arg = payload
        .get("ids")
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter(|id| js_truthy(id))
                .map(|id| sanitize_docker_id(Some(id)))
                .filter(|id| !id.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let args = format!("stats --no-stream --format '{{{{json .}}}}' {id_arg}");
    let result = run_docker(exec, args.trim(), 15_000, payload.get("runtime")).await;
    if !result.success {
        return failure_payload(&result);
    }
    json!({ "success": true, "stats": parse_docker_stats(&result.stdout) })
}

/// `dockerInspect({ sessionId, containerId, runtime? })`.
pub async fn inspect_container(exec: &dyn SessionExec, payload: &Value) -> Value {
    let (Some(_), Some(container_id)) =
        (field(payload, "sessionId"), field(payload, "containerId"))
    else {
        return json!({ "success": false, "error": "Missing params" });
    };
    let safe_id = sanitize_docker_id(Some(container_id));
    let result = run_docker(
        exec,
        &format!("inspect {safe_id}"),
        10_000,
        payload.get("runtime"),
    )
    .await;
    if !result.success {
        return failure_payload(&result);
    }
    match parse_inspect(&result.stdout) {
        Some(info) => json!({ "success": true, "inspect": summarize_container_inspect(&info) }),
        None => json!({ "success": false, "error": "Failed to parse inspect output" }),
    }
}

/// `dockerImageInspect({ sessionId, imageId, runtime? })`.
pub async fn inspect_image(exec: &dyn SessionExec, payload: &Value) -> Value {
    let (Some(_), Some(image_id)) = (field(payload, "sessionId"), field(payload, "imageId")) else {
        return json!({ "success": false, "error": "Missing params" });
    };
    let safe_id = sanitize_docker_id(Some(image_id));
    let result = run_docker(
        exec,
        &format!("image inspect {safe_id}"),
        10_000,
        payload.get("runtime"),
    )
    .await;
    if !result.success {
        return failure_payload(&result);
    }
    match parse_inspect(&result.stdout) {
        Some(info) => json!({ "success": true, "inspect": summarize_image_inspect(&info) }),
        None => json!({ "success": false, "error": "Failed to parse image inspect output" }),
    }
}

async fn container_action_inner(exec: &dyn SessionExec, payload: &Value) -> ExecResult {
    let (Some(_), Some(container_id), Some(action)) = (
        field(payload, "sessionId"),
        field(payload, "containerId"),
        field(payload, "action"),
    ) else {
        return ExecResult::fail("Missing params");
    };
    let safe_id = sanitize_docker_id(Some(container_id));
    let runtime = payload.get("runtime");
    let action = js_string(action);
    let args = match action.as_str() {
        "start" => format!("start {safe_id}"),
        "stop" => format!("stop {safe_id}"),
        "restart" => format!("restart {safe_id}"),
        "rm" => format!("rm -f {safe_id}"),
        "pause" => format!("pause {safe_id}"),
        "unpause" => format!("unpause {safe_id}"),
        "kill" => format!("kill {safe_id}"),
        "rename" => match sanitize_container_name(payload.get("newName")) {
            Some(next) => format!("rename {safe_id} {}", sh_quote(&next)),
            None => return ExecResult::fail("Invalid container name"),
        },
        other => return ExecResult::fail(format!("Invalid container action: {other}")),
    };
    run_docker(exec, &args, 15_000, runtime).await
}

/// `dockerAction({ sessionId, containerId, action, newName?, runtime? })`.
pub async fn container_action(exec: &dyn SessionExec, payload: &Value) -> Value {
    let result = container_action_inner(exec, payload).await;
    if !result.success {
        return action_failure(&result);
    }
    json!({ "success": true })
}

async fn image_action_inner(exec: &dyn SessionExec, payload: &Value) -> ExecResult {
    let (Some(_), Some(action)) = (field(payload, "sessionId"), field(payload, "action")) else {
        return ExecResult::fail("Missing params");
    };
    let runtime = payload.get("runtime");
    let text = |key: &str| payload.get(key).map(js_string_or_empty).unwrap_or_default();
    match js_string(action).as_str() {
        "pull" => {
            let Some(reference) = sanitize_image_ref(&text("imageRef")) else {
                return ExecResult::fail("Missing image reference");
            };
            run_docker(
                exec,
                &format!("pull {}", sh_quote(&reference)),
                600_000,
                runtime,
            )
            .await
        }
        "rm" => {
            let repo = text("repository").trim().to_string();
            let tag = text("tag").trim().to_string();
            let tagged = !repo.is_empty() && !tag.is_empty() && repo != "<none>" && tag != "<none>";
            if tagged {
                let Some(reference) = sanitize_image_ref(&format!("{repo}:{tag}")) else {
                    return ExecResult::fail("Invalid image reference");
                };
                return run_docker(
                    exec,
                    &format!("rmi {}", sh_quote(&reference)),
                    15_000,
                    runtime,
                )
                .await;
            }
            let safe_id = sanitize_docker_id(payload.get("imageId"));
            if safe_id.is_empty() {
                return ExecResult::fail("Missing image id");
            }
            let force = if field(payload, "force").is_some() {
                " -f"
            } else {
                ""
            };
            run_docker(exec, &format!("rmi{force} {safe_id}"), 15_000, runtime).await
        }
        "prune" => {
            let all = if field(payload, "all").is_some() {
                " -a"
            } else {
                ""
            };
            run_docker(exec, &format!("image prune{all} -f"), 120_000, runtime).await
        }
        "tag" => {
            let safe_id = sanitize_docker_id(payload.get("imageId"));
            let repo = sanitize_image_ref(&text("repository"));
            let tag = js_slice(text("tag").trim(), 128);
            let tag = if tag.is_empty() {
                "latest".to_string()
            } else {
                tag
            };
            let (false, Some(repo)) = (safe_id.is_empty(), repo) else {
                return ExecResult::fail("Missing params");
            };
            run_docker(
                exec,
                &format!("tag {safe_id} {}", sh_quote(&format!("{repo}:{tag}"))),
                15_000,
                runtime,
            )
            .await
        }
        other => ExecResult::fail(format!("Invalid image action: {other}")),
    }
}

/// `dockerImageAction({ sessionId, action, imageRef?, imageId?, force?, all?,
/// repository?, tag?, runtime? })` → `{ success, output }` on success.
pub async fn image_action(exec: &dyn SessionExec, payload: &Value) -> Value {
    let result = image_action_inner(exec, payload).await;
    if !result.success {
        return action_failure(&result);
    }
    json!({ "success": true, "output": result.stdout })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::FakeExec;

    const ONE_CONTAINER: &str =
        "{\"ID\":\"abc123\",\"Names\":\"web\",\"Image\":\"nginx\",\"State\":\"running\"}\n";

    fn denied(stderr: &str) -> ExecResult {
        ExecResult::ok("", stderr, 1)
    }

    #[tokio::test]
    async fn plain_docker_first_even_with_saved_password() {
        let fake =
            FakeExec::new(|_, _| ExecResult::ok(ONE_CONTAINER, "", 0)).with_sudo("host-secret");
        let result = list_containers(&fake, &json!({ "sessionId": "s1" })).await;
        assert_eq!(result["success"], true);
        assert_eq!(result["containers"].as_array().unwrap().len(), 1);
        let requests = fake.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0.command, "docker ps -a --format '{{json .}}'");
        assert_eq!(requests[0].0.stdin, None);
        assert_eq!(requests[0].0.timeout_ms, 12_000);
    }

    #[tokio::test]
    async fn socket_denial_retries_sudo_then_password_via_stdin() {
        let fake = FakeExec::sequence(vec![
            denied("permission denied while trying to connect to the Docker daemon socket"),
            denied("sudo: a password is required"),
            ExecResult::ok(ONE_CONTAINER, "", 0),
        ])
        .with_sudo("host-secret");
        let result = list_containers(&fake, &json!({ "sessionId": "s1" })).await;
        assert_eq!(result["success"], true);
        assert_eq!(result["containers"].as_array().unwrap().len(), 1);
        let requests = fake.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].0.command, "docker ps -a --format '{{json .}}'");
        assert_eq!(
            requests[1].0.command,
            "sudo docker ps -a --format '{{json .}}'"
        );
        assert_eq!(requests[1].0.stdin, None);
        assert_eq!(
            requests[2].0.command,
            "sudo -S -p '' docker ps -a --format '{{json .}}'"
        );
        assert_eq!(requests[2].0.stdin.as_deref(), Some("host-secret\n"));
    }

    #[tokio::test]
    async fn passwordless_sudo_when_no_saved_password() {
        let fake = FakeExec::sequence(vec![
            denied("Got permission denied while trying to connect to the Docker daemon socket"),
            ExecResult::ok(ONE_CONTAINER, "", 0),
        ]);
        let result = list_containers(&fake, &json!({ "sessionId": "s1" })).await;
        assert_eq!(result["success"], true);
        let requests = fake.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].0.command,
            "sudo docker ps -a --format '{{json .}}'"
        );
        assert_eq!(requests[1].0.stdin, None);
    }

    #[tokio::test]
    async fn no_password_retry_without_saved_sudo_password() {
        let fake = FakeExec::new(|_, _| {
            denied("permission denied while trying to connect to the Docker daemon socket")
        });
        let result = list_containers(&fake, &json!({ "sessionId": "s1" })).await;
        assert_eq!(result["success"], false);
        assert!(result["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("permission denied"));
        assert!(result.get("errorCode").is_none());
        assert_eq!(fake.requests().len(), 2);
    }

    #[tokio::test]
    async fn image_rm_retries_with_sudo_password_on_stdin() {
        let fake = FakeExec::sequence(vec![
            denied("dial unix /var/run/docker.sock: connect: permission denied"),
            denied("sudo: a password is required"),
            ExecResult::ok("deleted\n", "", 0),
        ])
        .with_sudo("pa'ss");
        let result = image_action(
            &fake,
            &json!({ "sessionId": "s1", "action": "rm", "imageId": "sha256:abc123" }),
        )
        .await;
        assert_eq!(result, json!({ "success": true, "output": "deleted\n" }));
        let requests = fake.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[2].0.command,
            "sudo -S -p '' docker rmi sha256abc123"
        );
        assert_eq!(requests[2].0.stdin.as_deref(), Some("pa'ss\n"));
    }

    #[tokio::test]
    async fn podman_runtime_and_podman_socket_sudo() {
        let fake = FakeExec::sequence(vec![
            denied("dial unix /run/podman/podman.sock: connect: permission denied"),
            ExecResult::ok(
                "{\"ID\":\"abc123\",\"Names\":[\"web\"],\"Image\":\"nginx\",\"State\":\"running\"}\n",
                "",
                0,
            ),
        ])
        .with_sudo("host-secret");
        let result =
            list_containers(&fake, &json!({ "sessionId": "s1", "runtime": "podman" })).await;
        assert_eq!(result["success"], true);
        assert_eq!(result["containers"][0]["name"], "web");
        let commands = fake.commands();
        assert_eq!(commands[0], "podman ps -a --format '{{json .}}'");
        assert_eq!(commands[1], "sudo podman ps -a --format '{{json .}}'");
    }

    #[tokio::test]
    async fn list_images_reads_podman_array_and_docker_lines() {
        let podman = FakeExec::new(|_, _| {
            ExecResult::ok(
                r#"[
        {
          "Id": "abc123",
          "Names": ["docker.io/library/alpine:3.20", "localhost/alpine:dev"],
          "Size": 7340032,
          "Created": 1700000000,
          "Digest": "sha256:deadbeef"
        }
      ]"#,
                "",
                0,
            )
        });
        let result = list_images(&podman, &json!({ "sessionId": "s1", "runtime": "podman" })).await;
        assert_eq!(result["success"], true);
        let images = result["images"].as_array().unwrap();
        assert_eq!(images.len(), 2);
        assert_eq!(images[0]["repository"], "docker.io/library/alpine");
        assert_eq!(images[0]["tag"], "3.20");
        assert_eq!(images[0]["name"], "docker.io/library/alpine:3.20");
        assert_eq!(images[1]["name"], "localhost/alpine:dev");
        assert_eq!(images[1]["id"], "abc123");
        assert_eq!(images[0]["size"], "7MB");
        assert_eq!(images[0]["digest"], "sha256:deadbeef");
        assert_eq!(images[0]["createdAt"], "2023-11-14T22:13:20.000Z");
        assert_eq!(podman.commands()[0], "podman images --format '{{json .}}'");

        let docker = FakeExec::new(|_, _| {
            ExecResult::ok(
                "{\"ID\":\"fff\",\"Repository\":\"nginx\",\"Tag\":\"latest\",\"Size\":\"10MB\",\"CreatedAt\":\"2026-01-01\"}\n",
                "",
                0,
            )
        });
        let result = list_images(&docker, &json!({ "sessionId": "s1", "runtime": "docker" })).await;
        let images = result["images"].as_array().unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0]["name"], "nginx:latest");
        assert_eq!(images[0]["size"], "10MB");
    }

    #[tokio::test]
    async fn get_stats_reads_podman_array_and_docker_lines() {
        let podman = FakeExec::new(|_, _| {
            ExecResult::ok(
                json!([{
                    "id": "abc123def456", "name": "web", "cpu_percent": "1.50%",
                    "mem_usage": "2MB / 1GB", "mem_percent": "0.20%",
                    "net_io": "1kB / 2kB", "block_io": "3kB / 4kB", "pids": "4"
                }])
                .to_string(),
                "",
                0,
            )
        });
        let result = get_stats(
            &podman,
            &json!({ "sessionId": "s1", "ids": ["abc123def456"], "runtime": "podman" }),
        )
        .await;
        assert_eq!(result["success"], true);
        let stats = result["stats"].as_array().unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0]["id"], "abc123def456");
        assert_eq!(stats[0]["name"], "web");
        assert_eq!(stats[0]["cpuPercent"], 1.5);
        assert_eq!(stats[0]["memUsage"], "2MB / 1GB");
        assert_eq!(stats[0]["pids"], 4);
        assert_eq!(
            podman.commands()[0],
            "podman stats --no-stream --format '{{json .}}' abc123def456"
        );

        let docker = FakeExec::new(|_, _| {
            ExecResult::ok(
                "{\"ID\":\"fff111\",\"Name\":\"db\",\"CPUPerc\":\"0.25%\",\"MemUsage\":\"1MiB / 2GiB\",\"MemPerc\":\"0.01%\",\"NetIO\":\"0B / 0B\",\"BlockIO\":\"0B / 0B\",\"PIDs\":\"2\"}\n",
                "",
                0,
            )
        });
        let result = get_stats(&docker, &json!({ "sessionId": "s1", "runtime": "docker" })).await;
        assert_eq!(result["stats"][0]["id"], "fff111");
        assert_eq!(result["stats"][0]["cpuPercent"], 0.25);
        assert_eq!(result["stats"][0]["memUsage"], "1MiB / 2GiB");
        assert_eq!(
            docker.commands()[0],
            "docker stats --no-stream --format '{{json .}}'"
        );
    }

    #[tokio::test]
    async fn image_removal_targets_tag_or_dangling_id() {
        let fake = FakeExec::new(|_, _| ExecResult::ok("", "", 0));
        let tagged = image_action(
            &fake,
            &json!({
                "sessionId": "s1", "runtime": "podman", "action": "rm",
                "imageId": "abc123", "repository": "localhost/alpine", "tag": "dev"
            }),
        )
        .await;
        assert_eq!(tagged["success"], true);
        let dangling = image_action(
            &fake,
            &json!({
                "sessionId": "s1", "runtime": "podman", "action": "rm",
                "imageId": "abc123", "repository": "<none>", "tag": "<none>", "force": true
            }),
        )
        .await;
        assert_eq!(dangling["success"], true);
        let commands = fake.commands();
        assert_eq!(commands[0], "podman rmi 'localhost/alpine:dev'");
        assert_eq!(commands[1], "podman rmi -f abc123");
    }

    #[tokio::test]
    async fn get_stats_sums_podman_network_counters() {
        let fake = FakeExec::new(|_, _| {
            ExecResult::ok(
                json!([{
                    "ContainerID": "abc123def456", "Name": "web", "CPU": 1.5,
                    "MemUsage": 2097152, "MemLimit": 1073741824, "MemPerc": 0.2,
                    "Network": {
                        "eth0": { "RxBytes": 1000, "TxBytes": 2000 },
                        "eth1": { "RxBytes": 500, "TxBytes": 250 }
                    },
                    "PIDs": 4
                }])
                .to_string(),
                "",
                0,
            )
        });
        let result = get_stats(&fake, &json!({ "sessionId": "s1", "runtime": "podman" })).await;
        assert_eq!(result["success"], true);
        assert_eq!(result["stats"][0]["netIO"], "1.5KB / 2.2KB");
        assert_eq!(result["stats"][0]["memUsage"], "2MB / 1GB");
        assert_eq!(result["stats"][0]["cpuPercent"], 1.5);
        assert_eq!(result["stats"][0]["memPercent"], 0.2);
    }

    #[tokio::test]
    async fn nerdctl_containerd_failure_becomes_stable_code() {
        let fake = FakeExec::new(|_, _| {
            denied("time=\"2026-10-20T18:31:27+08:00\" level=fatal msg=\"rootless containerd not running? environment variable XDG_RUNTIME_DIR is not set\"")
        });
        let result =
            list_containers(&fake, &json!({ "sessionId": "s1", "runtime": "nerdctl" })).await;
        assert_eq!(
            result,
            json!({ "success": false, "errorCode": "nerdctlUnreachable" })
        );
        let action = container_action(
            &fake,
            &json!({ "sessionId": "s1", "runtime": "nerdctl", "containerId": "abc", "action": "start" }),
        )
        .await;
        assert_eq!(
            action,
            json!({ "success": false, "errorCode": "nerdctlUnreachable" })
        );
    }

    #[tokio::test]
    async fn specific_nerdctl_error_and_docker_stderr_are_kept() {
        let nerdctl = FakeExec::new(|_, _| denied("Error: no such container: abc"));
        let specific = list_containers(
            &nerdctl,
            &json!({ "sessionId": "s1", "runtime": "nerdctl" }),
        )
        .await;
        assert_eq!(specific["success"], false);
        assert!(specific.get("errorCode").is_none());
        assert!(specific["error"]
            .as_str()
            .unwrap()
            .contains("no such container"));

        let docker = FakeExec::new(|_, _| {
            denied("permission denied while trying to connect to the Docker daemon socket")
        });
        let result =
            list_containers(&docker, &json!({ "sessionId": "s1", "runtime": "docker" })).await;
        assert!(result["error"]
            .as_str()
            .unwrap()
            .contains("permission denied"));
        assert!(result.get("errorCode").is_none());
    }

    #[test]
    fn container_ports_format_podman_mappings_and_exposed_ports() {
        let docker = parse_docker_containers(
            "{\"ID\":\"abc\",\"Names\":\"web\",\"Ports\":\"0.0.0.0:8080->80/tcp\"}\n",
        );
        assert_eq!(docker[0]["ports"], "0.0.0.0:8080->80/tcp");

        let podman = parse_docker_containers(
            &json!({
                "Id": "def",
                "Names": ["api"],
                "Ports": [
                    { "host_ip": "127.0.0.1", "container_port": 80, "host_port": 8080, "range": 1, "protocol": "tcp" },
                    { "host_ip": "", "container_port": 53, "host_port": 5353, "range": 2, "protocol": "udp" },
                    { "host_ip": "::", "container_port": 443, "host_port": 8443, "protocol": "tcp,udp" }
                ],
                "ExposedPorts": { "80": ["tcp"], "443": ["tcp"], "90": ["tcp"] }
            })
            .to_string(),
        );
        assert_eq!(podman[0]["name"], "api");
        assert_eq!(
            podman[0]["ports"],
            "127.0.0.1:8080->80/tcp, 0.0.0.0:5353-5354->53-54/udp, [::]:8443->443/tcp, [::]:8443->443/udp, 90/tcp"
        );
    }

    #[tokio::test]
    async fn actions_validate_and_map_errors() {
        let fake = FakeExec::new(|_, _| ExecResult::ok("", "boom", 1));
        assert_eq!(
            container_action(&fake, &json!({ "sessionId": "s1", "containerId": "a" })).await,
            json!({ "success": false, "error": "Missing params" })
        );
        assert_eq!(
            container_action(
                &fake,
                &json!({ "sessionId": "s1", "containerId": "a", "action": "rename", "newName": "!!" })
            )
            .await,
            json!({ "success": false, "error": "Invalid container name" })
        );
        assert_eq!(
            container_action(
                &fake,
                &json!({ "sessionId": "s1", "containerId": "a", "action": "explode" })
            )
            .await,
            json!({ "success": false, "error": "Invalid container action: explode" })
        );
        assert_eq!(
            container_action(
                &fake,
                &json!({ "sessionId": "s1", "containerId": "a-b", "action": "stop" })
            )
            .await,
            json!({ "success": false, "error": "boom" })
        );
        assert_eq!(fake.commands().last().unwrap(), "docker stop ab");

        let ok = FakeExec::new(|_, _| ExecResult::ok("", "", 0));
        assert_eq!(
            container_action(
                &ok,
                &json!({ "sessionId": "s1", "containerId": "a", "action": "rename", "newName": "new name" })
            )
            .await,
            json!({ "success": true })
        );
        assert_eq!(ok.commands()[0], "docker rename a 'newname'");
        assert_eq!(
            image_action(&ok, &json!({ "sessionId": "s1", "action": "tag", "imageId": "abc", "repository": "repo" })).await,
            json!({ "success": true, "output": "" })
        );
        assert_eq!(ok.commands()[1], "docker tag abc 'repo:latest'");
        image_action(
            &ok,
            &json!({ "sessionId": "s1", "action": "prune", "all": true }),
        )
        .await;
        assert_eq!(ok.commands()[2], "docker image prune -a -f");
        assert_eq!(ok.requests()[2].0.timeout_ms, 120_000);
        image_action(
            &ok,
            &json!({ "sessionId": "s1", "action": "pull", "imageRef": " alpine:3 " }),
        )
        .await;
        assert_eq!(ok.commands()[3], "docker pull 'alpine:3'");
        assert_eq!(ok.requests()[3].0.timeout_ms, 600_000);
        assert_eq!(
            image_action(&ok, &json!({ "sessionId": "s1", "action": "pull" })).await,
            json!({ "success": false, "error": "Missing image reference" })
        );
        assert_eq!(
            image_action(&ok, &json!({ "sessionId": "s1", "action": "nope" })).await,
            json!({ "success": false, "error": "Invalid image action: nope" })
        );
        assert_eq!(
            list_images(&ok, &json!({})).await,
            json!({ "success": false, "error": "Missing sessionId" })
        );
        assert_eq!(
            get_stats(&ok, &json!({ "runtime": "docker" })).await,
            json!({ "success": false, "error": "Missing sessionId" })
        );
    }

    #[tokio::test]
    async fn transport_failure_is_passed_through() {
        let fake = FakeExec::new(|_, _| ExecResult::fail("Session not found or not connected"));
        assert_eq!(
            list_containers(&fake, &json!({ "sessionId": "s1" })).await,
            json!({ "success": false, "error": "Session not found or not connected" })
        );
        let empty = FakeExec::new(|_, _| ExecResult::ok("", "", 3));
        assert_eq!(
            list_containers(&empty, &json!({ "sessionId": "s1" })).await,
            json!({ "success": false, "error": "docker exited with code 3" })
        );
    }

    #[tokio::test]
    async fn inspect_summaries() {
        let fake = FakeExec::new(|req, _| {
            if req.command.starts_with("docker image inspect") {
                ExecResult::ok(
                    json!([{
                        "Id": "sha256:1", "RepoTags": ["a:b"], "Size": 10,
                        "Config": { "Env": ["A=1"], "Cmd": null },
                        "History": [1, 2, 3, 4, 5, 6]
                    }])
                    .to_string(),
                    "",
                    0,
                )
            } else {
                ExecResult::ok(
                    json!([{
                        "Id": "c1", "Name": "/web", "State": { "Status": "running" },
                        "Config": { "Image": "nginx", "Env": [] },
                        "HostConfig": { "RestartPolicy": { "Name": "always" } }
                    }])
                    .to_string(),
                    "",
                    0,
                )
            }
        });
        let image =
            inspect_image(&fake, &json!({ "sessionId": "s1", "imageId": "sha256:1" })).await;
        assert_eq!(
            image,
            json!({
                "success": true,
                "inspect": {
                    "id": "sha256:1", "repoTags": ["a:b"], "size": 10,
                    "config": { "env": ["A=1"], "cmd": null },
                    "history": [1, 2, 3, 4, 5]
                }
            })
        );
        assert_eq!(fake.commands()[0], "docker image inspect sha2561");
        let container =
            inspect_container(&fake, &json!({ "sessionId": "s1", "containerId": "c1" })).await;
        assert_eq!(
            container,
            json!({
                "success": true,
                "inspect": {
                    "id": "c1", "name": "/web", "image": "nginx",
                    "state": { "Status": "running" }, "env": [],
                    "restartPolicy": { "Name": "always" }
                }
            })
        );
        let bad = FakeExec::new(|_, _| ExecResult::ok("nope", "", 0));
        assert_eq!(
            inspect_container(&bad, &json!({ "sessionId": "s1", "containerId": "c1" })).await,
            json!({ "success": false, "error": "Failed to parse inspect output" })
        );
        assert_eq!(
            inspect_image(&bad, &json!({ "sessionId": "s1" })).await,
            json!({ "success": false, "error": "Missing params" })
        );
    }
}
