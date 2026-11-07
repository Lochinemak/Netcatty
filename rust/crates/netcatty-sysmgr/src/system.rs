//! Capability probe, process list, process signals and the OSC 7 setup
//! pass-through — port of `electron/bridges/systemManagerBridge.cjs`.

use crate::container_runtime::parse_runtime_probe;
use crate::exec::{now_ms, wrap_sh_json, ExecRequest, ExecResult, LocalPlatform, SessionExec};
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::OnceLock;

/// Electron `nerdctlUsableClause`.
fn nerdctl_usable_clause(mark_command: &str) -> String {
    [
        "if command -v nerdctl >/dev/null 2>&1; then ",
        "_nc_nerdctl_err=$( { if command -v timeout >/dev/null 2>&1; then timeout 3 nerdctl info; else nerdctl info; fi; } 2>&1 >/dev/null ); ",
        "_nc_nerdctl_code=$?; ",
        "if [ \"$_nc_nerdctl_code\" -eq 0 ] || printf \"%s\\n\" \"$_nc_nerdctl_err\" | grep -i \"permission denied\" >/dev/null 2>&1; then ",
        mark_command,
        "; fi; fi; ",
    ]
    .concat()
}

/// Body of Electron's `CAPABILITY_SCRIPT_POSIX` (inside `exec sh -c '...'`).
fn capability_script_inner() -> String {
    [
        "printf \"%s\\n\" \"__NC_OS__=$(uname -s)\"; ",
        "command -v tmux >/dev/null 2>&1 && printf \"%s\\n\" __NC_TMUX__=1; ",
        "command -v docker >/dev/null 2>&1 && printf \"%s\\n\" __NC_DOCKER__=1; ",
        "command -v podman >/dev/null 2>&1 && printf \"%s\\n\" __NC_PODMAN__=1; ",
        &nerdctl_usable_clause("printf \"%s\\n\" __NC_NERDCTL__=1"),
        "command -v kubectl >/dev/null 2>&1 && printf \"%s\\n\" __NC_KUBECTL__=1; ",
        "command -v nvidia-smi >/dev/null 2>&1 && printf \"%s\\n\" __NC_NVIDIA_SMI__=1; ",
        "command -v npu-smi >/dev/null 2>&1 && printf \"%s\\n\" __NC_NPU_SMI__=1; ",
        "command -v ss >/dev/null 2>&1 && printf \"%s\\n\" __NC_SS__=1; ",
        "command -v netstat >/dev/null 2>&1 && printf \"%s\\n\" __NC_NETSTAT__=1; ",
        "command -v lsof >/dev/null 2>&1 && printf \"%s\\n\" __NC_LSOF__=1; ",
        "command -v systemctl >/dev/null 2>&1 && printf \"%s\\n\" __NC_SYSTEMCTL__=1",
    ]
    .concat()
}

/// Electron `CAPABILITY_SCRIPT_POSIX`.
pub fn capability_script() -> String {
    format!("exec sh -c '{}'", capability_script_inner())
}

const CAPABILITY_SCRIPT_WINDOWS: &str = concat!(
    "Write-Output \"__NC_OS__=Windows\"; ",
    "if (Get-Command tmux -ErrorAction SilentlyContinue) { Write-Output '__NC_TMUX__=1' }; ",
    "docker info 2>$null; if ($LASTEXITCODE -eq 0) { Write-Output '__NC_DOCKER__=1' }; ",
    "if (Get-Command podman -ErrorAction SilentlyContinue) { Write-Output '__NC_PODMAN__=1' }; ",
    "if (Get-Command nerdctl -ErrorAction SilentlyContinue) { nerdctl info 2>$null; if ($LASTEXITCODE -eq 0) { Write-Output '__NC_NERDCTL__=1' } }; ",
    "if (Get-Command kubectl -ErrorAction SilentlyContinue) { Write-Output '__NC_KUBECTL__=1' }; ",
    "if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) { Write-Output '__NC_NVIDIA_SMI__=1' }; ",
    "if (Get-Command npu-smi -ErrorAction SilentlyContinue) { Write-Output '__NC_NPU_SMI__=1' }; ",
    "Write-Output '__NC_NETSTAT__=1'; ",
    "if (Get-Command ss -ErrorAction SilentlyContinue) { Write-Output '__NC_SS__=1' }; ",
    "if (Get-Command lsof -ErrorAction SilentlyContinue) { Write-Output '__NC_LSOF__=1' }; ",
    "if (Get-Command systemctl -ErrorAction SilentlyContinue) { Write-Output '__NC_SYSTEMCTL__=1' }",
);

/// Electron `PROCESS_LIST_SCRIPT_POSIX`.
pub const PROCESS_LIST_SCRIPT: &str = "exec sh -c 'ps -eo pid= -o ppid= -o user= -o stat= -o pcpu= -o pmem= -o rss= -o vsz= -o etime= -o args= 2>/dev/null || top -b -n 1 2>/dev/null || ps ww 2>/dev/null || ps 2>/dev/null'";
const PROCESS_LIST_WINDOWS: &str = "Get-CimInstance Win32_Process | Sort-Object KernelModeTime -Descending | Select-Object ProcessId,ParentProcessId,Name,WorkingSetSize | ConvertTo-Json -Compress";
/// Electron `PROCESS_LIST_MAX_BUFFER`.
pub const PROCESS_LIST_MAX_BUFFER: usize = 64 * 1024 * 1024;

/// `SessionCapabilities` (domain/systemManager/types.ts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub target_os: &'static str,
    pub has_tmux: bool,
    pub has_docker: bool,
    pub has_podman: bool,
    pub has_nerdctl: bool,
    pub has_kubectl: bool,
    pub has_nvidia_smi: bool,
    pub has_npu_smi: bool,
    pub has_ss: bool,
    pub has_netstat: bool,
    pub has_lsof: bool,
    pub has_systemctl: bool,
    pub probed_at: i64,
}

fn has_flag(text: &str, name: &str) -> bool {
    crate::container_runtime::has_probe_flag(text, name)
}

/// Electron `parseCapabilities`.
pub fn parse_capabilities(stdout: &str, local: Option<LocalPlatform>) -> Capabilities {
    let target_os = match local {
        Some(LocalPlatform::Linux) => "linux",
        Some(LocalPlatform::Darwin) => "darwin",
        Some(LocalPlatform::Win32) => "win32",
        Some(LocalPlatform::Other) => "unknown",
        None => {
            let uname = stdout
                .split(['\r', '\n'])
                .find_map(|line| {
                    line.find("__NC_OS__=")
                        .map(|at| line[at + "__NC_OS__=".len()..].to_string())
                })
                .unwrap_or_default()
                .trim()
                .to_lowercase();
            if uname.contains("linux") {
                "linux"
            } else if uname.contains("darwin") {
                "darwin"
            } else if uname.contains("windows") || uname.contains("mingw") {
                "win32"
            } else {
                "unknown"
            }
        }
    };
    let runtime = parse_runtime_probe(stdout);
    Capabilities {
        target_os,
        has_tmux: has_flag(stdout, "__NC_TMUX__"),
        has_docker: runtime.docker,
        has_podman: runtime.podman,
        has_nerdctl: runtime.nerdctl,
        has_kubectl: runtime.kubernetes,
        has_nvidia_smi: has_flag(stdout, "__NC_NVIDIA_SMI__"),
        has_npu_smi: has_flag(stdout, "__NC_NPU_SMI__"),
        has_ss: has_flag(stdout, "__NC_SS__"),
        has_netstat: has_flag(stdout, "__NC_NETSTAT__"),
        has_lsof: has_flag(stdout, "__NC_LSOF__"),
        has_systemctl: has_flag(stdout, "__NC_SYSTEMCTL__"),
        probed_at: now_ms(),
    }
}

/// `payload.sessionId` when it is a non-empty string (JS truthiness).
pub fn session_id_of(payload: &Value) -> Option<&str> {
    match payload {
        Value::String(s) if !s.is_empty() => Some(s.as_str()),
        _ => payload
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty()),
    }
}

fn fail(error: &str) -> Value {
    json!({ "success": false, "error": error })
}

/// `probeSystemCapabilities`.
pub async fn probe_capabilities(exec: &dyn SessionExec, payload: &Value) -> Value {
    if session_id_of(payload).is_none() {
        return fail("Missing sessionId");
    }
    if exec.is_local() {
        let platform = exec.local_platform();
        if platform == LocalPlatform::Win32 {
            let result = exec
                .exec_local(ExecRequest::new(CAPABILITY_SCRIPT_WINDOWS, 8000))
                .await;
            if !result.success {
                return fail(result.error.as_deref().unwrap_or("Probe failed"));
            }
            return json!({
                "success": true,
                "capabilities": parse_capabilities(&result.stdout, Some(platform)),
            });
        }
        let result = exec
            .exec_local(ExecRequest::new(capability_script_inner(), 8000))
            .await;
        if !result.success {
            let fallback_script = [
                "uname -s; ",
                "command -v tmux; ",
                "command -v docker >/dev/null 2>&1 && echo docker_ok; ",
                "command -v podman >/dev/null 2>&1 && echo podman_ok; ",
                &nerdctl_usable_clause("echo nerdctl_ok"),
                "command -v kubectl >/dev/null 2>&1 && echo kubectl_ok; ",
                "command -v nvidia-smi >/dev/null 2>&1 && echo nvidia_ok; ",
                "command -v npu-smi >/dev/null 2>&1 && echo npu_ok; ",
                "command -v ss >/dev/null 2>&1 && echo ss_ok; ",
                "command -v netstat >/dev/null 2>&1 && echo netstat_ok; ",
                "command -v lsof >/dev/null 2>&1 && echo lsof_ok; ",
                "command -v systemctl >/dev/null 2>&1 && echo systemctl_ok",
            ]
            .concat();
            let fallback = exec
                .exec_local(ExecRequest::new(fallback_script, 8000))
                .await;
            if !fallback.success {
                return fail(fallback.error.as_deref().unwrap_or("Probe failed"));
            }
            let text = fallback.stdout.as_str();
            let target_os = match platform {
                LocalPlatform::Linux => "linux",
                LocalPlatform::Darwin => "darwin",
                _ => "unknown",
            };
            return json!({
                "success": true,
                "capabilities": Capabilities {
                    target_os,
                    has_tmux: text.contains("tmux") && !text.contains("not found"),
                    has_docker: text.contains("docker_ok"),
                    has_podman: text.contains("podman_ok"),
                    has_nerdctl: text.contains("nerdctl_ok"),
                    has_kubectl: text.contains("kubectl_ok"),
                    has_nvidia_smi: text.contains("nvidia_ok"),
                    has_npu_smi: text.contains("npu_ok"),
                    has_ss: text.contains("ss_ok"),
                    has_netstat: text.contains("netstat_ok"),
                    has_lsof: text.contains("lsof_ok"),
                    has_systemctl: text.contains("systemctl_ok"),
                    probed_at: now_ms(),
                },
            });
        }
        return json!({
            "success": true,
            "capabilities": parse_capabilities(&result.stdout, Some(platform)),
        });
    }

    let result = exec.exec(ExecRequest::new(capability_script(), 8000)).await;
    if result.pending {
        return json!({ "success": false, "pending": true });
    }
    if !result.success {
        return fail(result.error.as_deref().unwrap_or("Probe failed"));
    }
    json!({ "success": true, "capabilities": parse_capabilities(&result.stdout, None) })
}

/// `SystemProcessInfo`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: f64,
    pub ppid: f64,
    pub user: String,
    pub stat: String,
    pub cpu_percent: f64,
    pub mem_percent: f64,
    pub rss_kb: f64,
    pub vsz_kb: f64,
    pub elapsed: String,
    pub command: String,
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

/// JS `Number(text)` for the numeric shapes these regexes accept.
fn num(text: &str) -> f64 {
    text.parse::<f64>().unwrap_or(f64::NAN)
}

/// JS `Number.parseFloat` on `\d+(\.\d+)?[suffix]`.
fn leading_float(text: &str) -> f64 {
    let end = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    text[..end].parse::<f64>().unwrap_or(f64::NAN)
}

fn size_multiplier(value: &str) -> f64 {
    match value
        .chars()
        .last()
        .map(|c| c.to_ascii_lowercase())
        .unwrap_or(' ')
    {
        'm' => 1024f64,
        'g' => 1024f64.powi(2),
        't' => 1024f64.powi(3),
        'p' => 1024f64.powi(4),
        'e' => 1024f64.powi(5),
        'z' => 1024f64.powi(6),
        'y' => 1024f64.powi(7),
        _ => 1.0,
    }
}

/// Electron `parseProcessLines`: procps `ps -eo`, BusyBox `top -b -n 1`
/// and plain BusyBox `ps` layouts.
pub fn parse_process_lines(stdout: &str) -> Vec<ProcessInfo> {
    static PS: OnceLock<Regex> = OnceLock::new();
    static TOP: OnceLock<Regex> = OnceLock::new();
    static BUSYBOX: OnceLock<Regex> = OnceLock::new();
    let ps = re(
        &PS,
        r"^(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+)$",
    );
    let top = re(
        &TOP,
        r"(?i)^(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+(?:\.\d+)?[mgtpezy]?)\s+([\d.]+)%?\s+(?:\d+\s+)?([\d.]+)%?\s+(.+)$",
    );
    let busybox = re(
        &BUSYBOX,
        r"(?i)^(\d+)\s+(\S+)\s+(\d+(?:\.\d+)?[mgtpezy]?)\s+(\S+)\s+(.+)$",
    );
    let mut out = Vec::new();
    for line in stdout.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(m) = ps.captures(trimmed) {
            out.push(ProcessInfo {
                pid: num(&m[1]),
                ppid: num(&m[2]),
                user: m[3].to_string(),
                stat: m[4].to_string(),
                cpu_percent: num(&m[5]),
                mem_percent: num(&m[6]),
                rss_kb: num(&m[7]),
                vsz_kb: num(&m[8]),
                elapsed: m[9].to_string(),
                command: m[10].to_string(),
            });
            continue;
        }
        if let Some(m) = top.captures(trimmed) {
            out.push(ProcessInfo {
                pid: num(&m[1]),
                ppid: num(&m[2]),
                user: m[3].to_string(),
                stat: m[4].to_string(),
                cpu_percent: num(&m[7]),
                mem_percent: num(&m[6]),
                rss_kb: 0.0,
                vsz_kb: (leading_float(&m[5]) * size_multiplier(&m[5])).round(),
                elapsed: String::new(),
                command: m[8].to_string(),
            });
            continue;
        }
        if let Some(m) = busybox.captures(trimmed) {
            out.push(ProcessInfo {
                pid: num(&m[1]),
                ppid: 0.0,
                user: m[2].to_string(),
                stat: m[4].to_string(),
                cpu_percent: 0.0,
                mem_percent: 0.0,
                rss_kb: 0.0,
                vsz_kb: (leading_float(&m[3]) * size_multiplier(&m[3])).round(),
                elapsed: String::new(),
                command: m[5].to_string(),
            });
        }
    }
    out
}

fn processes_json(list: &[ProcessInfo]) -> Value {
    // f64 fields serialize as `1.0`; JSON consumers (JS) read them as 1, but
    // keep integral values integral for readability and parity.
    Value::Array(
        list.iter()
            .map(|p| {
                let mut v = serde_json::to_value(p).unwrap_or(Value::Null);
                if let Value::Object(map) = &mut v {
                    for value in map.values_mut() {
                        *value = js_number_value(value);
                    }
                }
                v
            })
            .collect(),
    )
}

/// Integral finite floats → integers; NaN → null (as `JSON.stringify`).
pub(crate) fn js_number_value(value: &Value) -> Value {
    match value.as_f64() {
        Some(f) if value.is_f64() && f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 => {
            json!(f as i64)
        }
        _ => value.clone(),
    }
}

/// `listSystemProcesses`.
pub async fn list_processes(exec: &dyn SessionExec, payload: &Value) -> Value {
    if session_id_of(payload).is_none() {
        return fail("Missing sessionId");
    }
    if exec.is_local() && exec.local_platform() == LocalPlatform::Win32 {
        let result = exec
            .exec_local(
                ExecRequest::new(PROCESS_LIST_WINDOWS, 10000)
                    .with_max_buffer(PROCESS_LIST_MAX_BUFFER),
            )
            .await;
        if !result.success {
            return json!({ "success": false, "error": result.error });
        }
        let raw: Value = match serde_json::from_str(if result.stdout.trim().is_empty() {
            "[]"
        } else {
            result.stdout.as_str()
        }) {
            Ok(v) => v,
            Err(_) => return fail("Failed to parse process list"),
        };
        let list = match raw {
            Value::Array(items) => items,
            other => vec![other],
        };
        let processes: Vec<ProcessInfo> = list
            .iter()
            .map(|p| ProcessInfo {
                pid: p
                    .get("ProcessId")
                    .and_then(Value::as_f64)
                    .unwrap_or(f64::NAN),
                ppid: p
                    .get("ParentProcessId")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0),
                user: String::new(),
                stat: "R".into(),
                cpu_percent: 0.0,
                mem_percent: 0.0,
                rss_kb: (p
                    .get("WorkingSetSize")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0)
                    / 1024.0)
                    .round(),
                vsz_kb: 0.0,
                elapsed: String::new(),
                command: p
                    .get("Name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            })
            .collect();
        return json!({ "success": true, "processes": processes_json(&processes) });
    }
    let result = exec
        .exec(ExecRequest::new(PROCESS_LIST_SCRIPT, 12000).with_max_buffer(PROCESS_LIST_MAX_BUFFER))
        .await;
    if result.pending {
        return json!({ "success": false, "pending": true });
    }
    if !result.success {
        return fail(
            result
                .error
                .as_deref()
                .unwrap_or("Failed to list processes"),
        );
    }
    json!({ "success": true, "processes": processes_json(&parse_process_lines(&result.stdout)) })
}

const ALLOWED_SIGNALS: &[&str] = &[
    "TERM", "KILL", "STOP", "CONT", "HUP", "INT", "USR1", "USR2", "1", "2", "9", "15", "18", "19",
];

/// JS `Number(value)` for a JSON pid / nice value.
fn js_number(value: Option<&Value>) -> f64 {
    match value {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().unwrap_or(f64::NAN)
            }
        }
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Null) => 0.0,
        _ => f64::NAN,
    }
}

/// JS number → string.
fn js_num_str(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 9.0e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// Electron `buildProcessSignalCommand`: the shell command, or an error.
pub fn build_process_signal_command(
    pid: Option<&Value>,
    signal: Option<&str>,
    nice: Option<&Value>,
) -> Result<String, &'static str> {
    if let Some(nice) = nice.filter(|v| !v.is_null()) {
        let n = js_number(Some(nice));
        if !n.is_finite() || !(-20.0..=19.0).contains(&n) {
            return Err("Invalid nice value");
        }
        return Ok(format!(
            "renice {} -p {}",
            js_num_str(n.trunc()),
            js_num_str(js_number(pid))
        ));
    }
    let sig = signal
        .filter(|s| !s.is_empty())
        .unwrap_or("TERM")
        .to_uppercase();
    if !ALLOWED_SIGNALS.contains(&sig.as_str()) {
        return Err("Invalid signal");
    }
    let numeric_pid = js_number(pid);
    if !numeric_pid.is_finite() || numeric_pid <= 0.0 {
        return Err("Invalid pid");
    }
    let pid = js_num_str(numeric_pid);
    Ok(match sig.as_str() {
        "KILL" | "9" => format!("kill -9 {pid}"),
        "TERM" | "15" => format!("kill -15 {pid}"),
        s if s.chars().all(|c| c.is_ascii_digit()) => format!("kill -{s} {pid}"),
        s => format!("kill -s {s} {pid}"),
    })
}

fn js_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

fn signal_string(payload: &Value) -> Option<String> {
    match payload.get("signal") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    }
}

fn exit_failure(result: &ExecResult, what: &str) -> Value {
    let code = result.code.unwrap_or(0);
    let raw = if !result.stderr.is_empty() {
        result.stderr.clone()
    } else if let Some(e) = result.error.as_ref().filter(|e| !e.is_empty()) {
        e.clone()
    } else {
        format!("{what} exited with code {code}")
    };
    json!({ "success": false, "error": raw.trim(), "code": code })
}

/// `signalSystemProcess`.
pub async fn signal_process(exec: &dyn SessionExec, payload: &Value) -> Value {
    let session_ok = payload
        .get("sessionId")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    let pid = payload.get("pid");
    if !session_ok || !js_truthy(pid) {
        return fail("Missing sessionId or pid");
    }
    let numeric_pid = js_number(pid);
    if !numeric_pid.is_finite() || numeric_pid <= 0.0 {
        return fail("Invalid pid");
    }
    let signal = signal_string(payload);
    let nice = payload.get("nice").filter(|v| !v.is_null());

    if exec.is_local() && exec.local_platform() == LocalPlatform::Win32 {
        if nice.is_some() {
            return fail("renice is not supported on Windows");
        }
        let sig = signal
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "TERM".into())
            .to_uppercase();
        if !matches!(sig.as_str(), "TERM" | "15" | "KILL" | "9") {
            return fail(&format!("signal {sig} is not supported on Windows"));
        }
        let id = js_num_str(numeric_pid.trunc());
        let script = if sig == "KILL" || sig == "9" {
            format!("Stop-Process -Id {id} -Force -ErrorAction Stop")
        } else {
            format!("Stop-Process -Id {id} -ErrorAction Stop")
        };
        let result = exec.exec_local(ExecRequest::new(script, 5000)).await;
        if !result.success {
            return fail(result.error.as_deref().unwrap_or("Stop-Process failed"));
        }
        if matches!(result.code, Some(code) if code != 0) {
            return exit_failure(&result, "Stop-Process");
        }
        return json!({ "success": true, "code": result.code });
    }

    let command = match build_process_signal_command(pid, signal.as_deref(), nice) {
        Ok(command) => command,
        Err(error) => return fail(error),
    };
    let result = exec
        .exec(ExecRequest::new(wrap_sh_json(&command), 5000))
        .await;
    if result.pending {
        return json!({ "success": false, "pending": true, "error": result.error });
    }
    if !result.success {
        return json!({ "success": false, "error": result.error });
    }
    if matches!(result.code, Some(code) if code != 0) {
        return exit_failure(&result, "kill");
    }
    json!({ "success": true, "code": result.code })
}

/// `setupOsc7Tracking`: run the renderer-built shell-integration command.
pub async fn setup_osc7_tracking(exec: &dyn SessionExec, payload: &Value) -> Value {
    let command = payload.get("command").and_then(Value::as_str);
    let Some(command) = command.filter(|c| !c.trim().is_empty()) else {
        return fail("Missing sessionId or command");
    };
    if session_id_of(payload).is_none() {
        return fail("Missing sessionId or command");
    }
    let result = exec.exec(ExecRequest::new(command, 10000)).await;
    if result.pending {
        return json!({ "success": false, "pending": true, "error": result.error });
    }
    if !result.success {
        return fail(
            result
                .error
                .as_deref()
                .unwrap_or("Directory tracking setup failed"),
        );
    }
    if let Some(code) = result.code.filter(|c| *c != 0) {
        let raw = if !result.stderr.is_empty() {
            result.stderr.clone()
        } else if let Some(e) = result.error.as_ref().filter(|e| !e.is_empty()) {
            e.clone()
        } else {
            format!("Directory tracking setup failed with exit code {code}")
        };
        return json!({
            "success": false,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "code": code,
            "error": raw.trim(),
        });
    }
    json!({
        "success": true,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "code": result.code.unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::FakeExec;

    #[test]
    fn capability_flags_are_line_anchored() {
        let out =
            "__NC_OS__=Linux\n__NC_TMUX__=1\n__NC_DOCKER__=1\n__NC_SS__=1\necho __NC_LSOF__=1 x\n";
        let caps = parse_capabilities(out, None);
        assert_eq!(caps.target_os, "linux");
        assert!(caps.has_tmux && caps.has_docker && caps.has_ss);
        assert!(!caps.has_lsof && !caps.has_podman && !caps.has_systemctl);
        assert_eq!(
            parse_capabilities("__NC_OS__=Darwin\r\n", None).target_os,
            "darwin"
        );
        assert_eq!(
            parse_capabilities("__NC_OS__=Linux", Some(LocalPlatform::Win32)).target_os,
            "win32"
        );
    }

    #[test]
    fn capability_script_matches_electron_shape() {
        let script = capability_script();
        assert!(script.starts_with("exec sh -c '"));
        assert!(script.ends_with('\''));
        for needle in [
            "command -v docker",
            "command -v nvidia-smi",
            "command -v npu-smi",
            "command -v ss",
            "command -v systemctl",
            "timeout 3 nerdctl info",
        ] {
            assert!(script.contains(needle), "{needle}");
        }
        assert!(!script.contains("docker info"));
        assert!(!script.contains("docker.sock"));
    }

    #[tokio::test]
    async fn probe_reports_pending_and_errors() {
        let fake = FakeExec::sequence(vec![ExecResult::pending("Mosh handshake in progress")]);
        let r = probe_capabilities(&fake, &json!({"sessionId": "s"})).await;
        assert_eq!(r, json!({"success": false, "pending": true}));
        let fake = FakeExec::sequence(vec![ExecResult::fail("Session not found")]);
        let r = probe_capabilities(&fake, &json!({"sessionId": "s"})).await;
        assert_eq!(r, json!({"success": false, "error": "Session not found"}));
        let r = probe_capabilities(&fake, &json!({})).await;
        assert_eq!(r["error"], "Missing sessionId");
    }

    #[tokio::test]
    async fn probe_reports_docker_when_installed() {
        let fake = FakeExec::new(|req, _| {
            assert!(req.command.contains("command -v docker"));
            ExecResult::ok("__NC_OS__=Linux\n__NC_DOCKER__=1\n", "", 0)
        });
        let r = probe_capabilities(&fake, &json!({"sessionId": "s"})).await;
        assert_eq!(r["success"], true);
        assert_eq!(r["capabilities"]["hasDocker"], true);
        assert_eq!(r["capabilities"]["targetOs"], "linux");
        assert!(r["capabilities"]["probedAt"].as_i64().unwrap() > 0);
    }

    #[tokio::test]
    async fn local_probe_strips_the_exec_wrapper() {
        let fake = FakeExec::new(|req, local| {
            assert!(local);
            assert!(!req.command.starts_with("exec sh -c"));
            ExecResult::ok("__NC_OS__=Darwin\n__NC_TMUX__=1\n", "", 0)
        })
        .local(LocalPlatform::Darwin);
        let r = probe_capabilities(&fake, &json!({"sessionId": "s"})).await;
        assert_eq!(r["capabilities"]["targetOs"], "darwin");
        assert_eq!(r["capabilities"]["hasTmux"], true);
    }

    const BUSYBOX_PS: &str =
        "  PID USER       VSZ STAT COMMAND\n    1 root      1356 S    /sbin/procd\n  411 root     97.6m S    /sbin/ubusd\n";

    #[test]
    fn parses_procps_rows() {
        let out = "    1     0 root     Ss    0.0  0.1 12345 170000 10-02:03:04 /usr/lib/systemd/systemd --switched-root --system --deserialize 21\n";
        let list = parse_process_lines(out);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].pid, 1.0);
        assert_eq!(list[0].rss_kb, 12345.0);
        assert_eq!(list[0].elapsed, "10-02:03:04");
        assert_eq!(
            list[0].command,
            "/usr/lib/systemd/systemd --switched-root --system --deserialize 21"
        );
    }

    #[test]
    fn parses_busybox_top_with_and_without_cpu_column() {
        for top in [
            "Mem: 2059948K used\nCPU:   0% usr\n  PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND\n    1     0 root     S     1356   1%   2% /sbin/procd\n  411     1 root     R    97.6m  10%   7% /sbin/ubusd\n",
            "  PID  PPID USER     STAT   VSZ %VSZ CPU %CPU COMMAND\n    1     0 root     S     1356   1%   0   2% /sbin/procd\n  411     1 root     R    97.6m  10%   3   7% /sbin/ubusd\n",
            "  PID  PPID USER     STAT   VSZ %VSZ CPU %CPU COMMAND\n    1     0 root     S     1356   1.0   0   2.0 /sbin/procd\n  411     1 root     R    97.6m  10.0   3   7.0 /sbin/ubusd\n",
        ] {
            let list = parse_process_lines(top);
            assert_eq!(list.len(), 2, "{top}");
            assert_eq!(
                (list[0].pid, list[0].cpu_percent, list[0].mem_percent),
                (1.0, 2.0, 1.0)
            );
            assert_eq!(
                (list[1].pid, list[1].cpu_percent, list[1].mem_percent),
                (411.0, 7.0, 10.0)
            );
            assert_eq!(list[0].command, "/sbin/procd");
            assert_eq!(list[1].vsz_kb, 99942.0);
        }
    }

    #[test]
    fn parses_plain_busybox_ps() {
        let list = parse_process_lines(BUSYBOX_PS);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].user, "root");
        assert_eq!(list[0].vsz_kb, 1356.0);
        assert_eq!(list[1].vsz_kb, 99942.0);
        assert_eq!(list[1].command, "/sbin/ubusd");
    }

    #[cfg(unix)]
    #[test]
    fn process_script_falls_back_through_busybox_layouts() {
        // Same shell harness as systemManagerBridge.processes.test.cjs: fake
        // `ps` / `top` functions in front of the real script body.
        let inner = PROCESS_LIST_SCRIPT
            .strip_prefix("exec sh -c '")
            .and_then(|s| s.strip_suffix('\''))
            .unwrap();
        let harness = format!(
            "top() {{ printf '%s\\n' '  PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND'; printf '%s\\n' '    1     0 root     S     1356   1%   2% /sbin/procd'; }}\n\
             ps() {{ if [ \"$1\" = '-eo' ]; then return 1; fi; return 1; }}\n{inner}"
        );
        let out = std::process::Command::new("sh")
            .args(["-c", &harness])
            .output()
            .unwrap();
        let list = parse_process_lines(&String::from_utf8_lossy(&out.stdout));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].cpu_percent, 2.0);
        assert!(!PROCESS_LIST_SCRIPT.contains("head -n 2000"));
    }

    #[tokio::test]
    async fn list_processes_uses_large_buffer_and_integral_json() {
        let fake = FakeExec::new(|req, _| {
            assert!(req.max_buffer.unwrap() > 10 * 1024 * 1024);
            ExecResult::ok(BUSYBOX_PS, "", 0)
        });
        let r = list_processes(&fake, &json!({"sessionId": "s"})).await;
        assert_eq!(r["success"], true);
        assert_eq!(
            r["processes"][0],
            json!({"pid": 1, "ppid": 0, "user": "root", "stat": "S", "cpuPercent": 0,
                   "memPercent": 0, "rssKb": 0, "vszKb": 1356, "elapsed": "", "command": "/sbin/procd"})
        );
    }

    #[tokio::test]
    async fn windows_process_list() {
        let fake = FakeExec::new(|req, local| {
            assert!(local);
            assert!(req.command.contains("Get-CimInstance Win32_Process"));
            assert!(!req.command.contains("Select-Object -First 2000"));
            ExecResult::ok(
                r#"{"ProcessId":4,"ParentProcessId":0,"Name":"System","WorkingSetSize":2048}"#,
                "",
                0,
            )
        })
        .local(LocalPlatform::Win32);
        let r = list_processes(&fake, &json!({"sessionId": "s"})).await;
        assert_eq!(r["processes"][0]["pid"], 4);
        assert_eq!(r["processes"][0]["rssKb"], 2);
        assert_eq!(r["processes"][0]["stat"], "R");
    }

    #[test]
    fn signal_commands() {
        let pid = json!(42);
        assert_eq!(
            build_process_signal_command(Some(&pid), None, None).unwrap(),
            "kill -15 42"
        );
        assert_eq!(
            build_process_signal_command(Some(&pid), Some("kill"), None).unwrap(),
            "kill -9 42"
        );
        assert_eq!(
            build_process_signal_command(Some(&pid), Some("19"), None).unwrap(),
            "kill -19 42"
        );
        assert_eq!(
            build_process_signal_command(Some(&pid), Some("HUP"), None).unwrap(),
            "kill -s HUP 42"
        );
        assert_eq!(
            build_process_signal_command(Some(&pid), Some("SEGV"), None),
            Err("Invalid signal")
        );
        assert_eq!(
            build_process_signal_command(Some(&pid), None, Some(&json!(5.7))).unwrap(),
            "renice 5 -p 42"
        );
        assert_eq!(
            build_process_signal_command(Some(&pid), None, Some(&json!(30))),
            Err("Invalid nice value")
        );
    }

    #[tokio::test]
    async fn signal_process_flow() {
        let fake = FakeExec::sequence(vec![
            ExecResult::ok("", "", 0),
            ExecResult {
                stderr: "kill: (42) - Operation not permitted\n".into(),
                ..ExecResult::ok("", "", 1)
            },
        ]);
        let ok = signal_process(&fake, &json!({"sessionId": "s", "pid": 42})).await;
        assert_eq!(ok, json!({"success": true, "code": 0}));
        assert_eq!(fake.commands()[0], "exec sh -c \"kill -15 42\"");
        let denied = signal_process(&fake, &json!({"sessionId": "s", "pid": 42})).await;
        assert_eq!(
            denied,
            json!({"success": false, "error": "kill: (42) - Operation not permitted", "code": 1})
        );
        let missing = signal_process(&fake, &json!({"sessionId": "s"})).await;
        assert_eq!(missing["error"], "Missing sessionId or pid");
        let bad = signal_process(&fake, &json!({"sessionId": "s", "pid": "x"})).await;
        assert_eq!(bad["error"], "Invalid pid");
    }

    #[tokio::test]
    async fn windows_signals() {
        let fake = FakeExec::sequence(vec![ExecResult::ok("", "", 0)]).local(LocalPlatform::Win32);
        let r = signal_process(
            &fake,
            &json!({"sessionId": "s", "pid": 7, "signal": "KILL"}),
        )
        .await;
        assert_eq!(r["success"], true);
        assert_eq!(
            fake.commands()[0],
            "Stop-Process -Id 7 -Force -ErrorAction Stop"
        );
        let r = signal_process(&fake, &json!({"sessionId": "s", "pid": 7, "signal": "HUP"})).await;
        assert_eq!(r["error"], "signal HUP is not supported on Windows");
        let r = signal_process(&fake, &json!({"sessionId": "s", "pid": 7, "nice": 1})).await;
        assert_eq!(r["error"], "renice is not supported on Windows");
    }

    #[tokio::test]
    async fn osc7_setup_passes_results_through() {
        let fake = FakeExec::sequence(vec![
            ExecResult::ok("done", "", 0),
            ExecResult::ok("", "", 3),
        ]);
        let payload = json!({"sessionId": "s", "command": "echo hi"});
        assert_eq!(
            setup_osc7_tracking(&fake, &payload).await,
            json!({"success": true, "stdout": "done", "stderr": "", "code": 0})
        );
        let r = setup_osc7_tracking(&fake, &payload).await;
        assert_eq!(
            r["error"],
            "Directory tracking setup failed with exit code 3"
        );
        assert_eq!(r["code"], 3);
        let r = setup_osc7_tracking(&fake, &json!({"sessionId": "s", "command": " "})).await;
        assert_eq!(r["error"], "Missing sessionId or command");
    }
}
