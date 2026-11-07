//! Accelerator (NVIDIA GPU / Huawei Ascend NPU) inventory — port of
//! `electron/bridges/systemManager/gpuOps.cjs` and the `listAccelerators`
//! wrapper in `systemManagerBridge.cjs`.
//!
//! One collector script dumps `nvidia-smi` CSV queries and the various
//! `npu-smi` reports between `__NC_*__` markers; the parsers below turn that
//! into the renderer's `AcceleratorDeviceInfo` / `AcceleratorProcessInfo`.

use crate::exec::{now_ms, wrap_sh_json, ExecRequest, LocalPlatform, SessionExec};
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::OnceLock;

const NVIDIA_GPU_QUERY: &str = "nvidia-smi --query-gpu=index,uuid,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,power.limit,fan.speed,driver_version --format=csv,noheader,nounits";
const NVIDIA_PROCESS_QUERY: &str = "nvidia-smi --query-compute-apps=gpu_uuid,pid,process_name,used_gpu_memory --format=csv,noheader,nounits";

/// Local Windows collector — PowerShell (Electron
/// `ACCELERATOR_COLLECT_SCRIPT_WINDOWS`).
pub fn accelerator_collect_script_windows() -> String {
    [
        r#"Write-Output "__NC_ACCEL_BEGIN__"; "#,
        "if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) { ",
        r#"Write-Output "__NC_NVIDIA_DEVICES__"; "#,
        &format!("{NVIDIA_GPU_QUERY} 2>$null; "),
        r#"Write-Output "__NC_NVIDIA_PROCESSES__"; "#,
        &format!("{NVIDIA_PROCESS_QUERY} 2>$null; "),
        "}; ",
        "if (Get-Command npu-smi -ErrorAction SilentlyContinue) { ",
        r#"Write-Output "__NC_NPU_BEGIN__"; "#,
        r#"Write-Output "__NC_NPU_INFO__"; "#,
        "npu-smi info 2>$null; ",
        r#"Write-Output "__NC_NPU_PROCS__"; "#,
        "npu-smi info -t proc-mem 2>$null; ",
        r#"Write-Output "__NC_NPU_END__"; "#,
        "}; ",
        r#"Write-Output "__NC_ACCEL_END__""#,
    ]
    .concat()
}

/// Remote collector body (Electron `ACCELERATOR_COLLECT_INNER`).
pub fn accelerator_collect_inner() -> String {
    [
        r#"printf "%s\n" "__NC_ACCEL_BEGIN__"; "#,
        "if command -v nvidia-smi >/dev/null 2>&1; then ",
        r#"printf "%s\n" "__NC_NVIDIA_DEVICES__"; "#,
        &format!("{NVIDIA_GPU_QUERY} 2>/dev/null || true; "),
        r#"printf "%s\n" "__NC_NVIDIA_PROCESSES__"; "#,
        &format!("{NVIDIA_PROCESS_QUERY} 2>/dev/null || true; "),
        "fi; ",
        "if command -v npu-smi >/dev/null 2>&1; then ",
        r#"printf "%s\n" "__NC_NPU_BEGIN__"; "#,
        // Prefer info -l; fall back to info -m (SwanLab / Ascend mapping table).
        r"ids=$(npu-smi info -l 2>/dev/null | sed -n 's/^[[:space:]]*NPU ID[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p'); ",
        r#"if [ -z "$ids" ]; then "#,
        "ids=$(npu-smi info -m 2>/dev/null | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1}' | sort -nu); ",
        "fi; ",
        r#"if [ -n "$ids" ]; then "#,
        "for id in $ids; do ",
        r#"printf "%s\n" "__NC_NPU_DEVICE__=$id"; "#,
        r#"npu-smi info -t board -i "$id" 2>/dev/null || true; "#,
        r#"npu-smi info -t common -i "$id" 2>/dev/null || true; "#,
        r#"npu-smi info -t usages -i "$id" 2>/dev/null || true; "#,
        r#"npu-smi info -t memory -i "$id" 2>/dev/null || true; "#,
        "done; ",
        "fi; ",
        // Always keep the summary table; typed queries can be empty on
        // ModelArts / containers, and Windows collectors only emit this dump.
        r#"printf "%s\n" "__NC_NPU_INFO__"; "#,
        "npu-smi info 2>/dev/null || true; ",
        r#"printf "%s\n" "__NC_NPU_PROCS__"; "#,
        "npu-smi info -t proc-mem 2>/dev/null || true; ",
        r#"printf "%s\n" "__NC_NPU_END__"; "#,
        "fi; ",
        r#"printf "%s\n" "__NC_ACCEL_END__""#,
    ]
    .concat()
}

/// `exec sh -c <JSON.stringify(inner)>` (Electron `ACCELERATOR_COLLECT_SCRIPT`);
/// JSON quoting keeps the nested sed single quotes intact.
pub fn accelerator_collect_script() -> String {
    wrap_sh_json(&accelerator_collect_inner())
}

const COLLECT_TIMEOUT_MS: u64 = 15_000;

/// `AcceleratorDeviceInfo`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceleratorDevice {
    pub vendor: String,
    pub index: i64,
    pub uuid: String,
    pub name: String,
    pub utilization_percent: Option<f64>,
    pub memory_used_mb: Option<f64>,
    pub memory_total_mb: Option<f64>,
    pub temperature_c: Option<f64>,
    pub power_draw_w: Option<f64>,
    pub power_limit_w: Option<f64>,
    pub fan_percent: Option<f64>,
    pub driver_version: Option<String>,
    pub health: Option<String>,
    /// Chips folded into this NPU while parsing (Electron `_chipCount`,
    /// deleted before returning).
    #[serde(skip)]
    chip_count: u32,
}

/// `AcceleratorProcessInfo`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceleratorProcess {
    pub vendor: String,
    pub gpu_index: i64,
    pub pid: i64,
    pub process_name: String,
    pub memory_used_mb: Option<f64>,
}

/// Result of [`parse_accelerator_snapshot`] (without `success`).
#[derive(Debug, Clone, PartialEq)]
pub struct AcceleratorSnapshot {
    pub devices: Vec<AcceleratorDevice>,
    pub processes: Vec<AcceleratorProcess>,
    pub nvidia_driver_version: Option<String>,
    pub probed_at: i64,
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid regex"))
}

/// JS `Number.parseFloat`: longest numeric prefix, `None` when NaN/∞.
fn js_parse_float(text: &str) -> Option<f64> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let t = text.trim_start();
    let m = regex(&RE, r"^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?").find(t)?;
    m.as_str().parse::<f64>().ok().filter(|n| n.is_finite())
}

/// JS `Number.parseInt(text, 10)`.
fn js_parse_int(text: &str) -> Option<i64> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let t = text.trim_start();
    let m = regex(&RE, r"^[+-]?\d+").find(t)?;
    m.as_str().parse::<i64>().ok()
}

/// Electron `parseCsvNumber`: blank, `-`, `[N/A]`, `Not Supported` → `None`.
fn parse_csv_number(raw: Option<&str>) -> Option<f64> {
    static NA: OnceLock<Regex> = OnceLock::new();
    let text = raw.unwrap_or("").trim();
    if text.is_empty()
        || text == "-"
        || regex(&NA, r"(?i)^(?:\[?n/?a\]?|not\s+supported)$").is_match(text)
    {
        return None;
    }
    js_parse_float(&text.replace([',', '%'], ""))
}

/// Electron `extractAscendDriverVersion`: `| npu-smi X  Version: Y |`.
fn extract_ascend_driver_version(text: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let m = regex(&RE, r"(?i)\|\s*npu-smi\s+(\S+)\s+.*?Version:\s*(\S+)").captures(text)?;
    let raw = m
        .get(2)
        .map(|g| g.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| m.get(1).map(|g| g.as_str()))
        .unwrap_or("");
    let version = raw.replace('|', "").trim().to_string();
    (!version.is_empty()).then_some(version)
}

/// Electron `applyMemPair`.
fn apply_mem_pair(device: &mut AcceleratorDevice, used: &str, total: &str, aggregate: bool) {
    let used = parse_csv_number(Some(used));
    let total = parse_csv_number(Some(total));
    if used.is_none() && total.is_none() {
        return;
    }
    if aggregate {
        if let (Some(current), Some(used)) = (device.memory_used_mb, used) {
            device.memory_used_mb = Some(current + used);
            device.memory_total_mb =
                Some(device.memory_total_mb.unwrap_or(0.0) + total.unwrap_or(0.0));
            return;
        }
    }
    if used.is_some() {
        device.memory_used_mb = used;
    }
    if total.is_some() {
        device.memory_total_mb = total;
    }
}

/// Electron `maxFinite`.
fn max_finite(current: Option<f64>, next: Option<f64>) -> Option<f64> {
    match (current, next) {
        (_, None) => current,
        (None, next) => next,
        (Some(c), Some(n)) => Some(c.max(n)),
    }
}

fn parse_csv_fields(line: &str) -> Vec<&str> {
    line.split(',').map(str::trim).collect()
}

fn non_empty(text: Option<&&str>) -> Option<String> {
    text.filter(|s| !s.is_empty()).map(|s| s.to_string())
}

/// Electron `parseNvidiaDevices` (`--query-gpu` CSV).
pub fn parse_nvidia_devices(section: &str) -> Vec<AcceleratorDevice> {
    let mut devices = Vec::new();
    for line in section.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("__NC_") {
            continue;
        }
        let fields = parse_csv_fields(trimmed);
        if fields.len() < 3 {
            continue;
        }
        let Some(index) = js_parse_int(fields[0]) else {
            continue;
        };
        let num = |i: usize| parse_csv_number(fields.get(i).copied());
        devices.push(AcceleratorDevice {
            vendor: "nvidia".into(),
            index,
            uuid: fields[1].to_string(),
            name: non_empty(fields.get(2)).unwrap_or_else(|| format!("GPU {index}")),
            utilization_percent: num(3),
            memory_used_mb: num(4),
            memory_total_mb: num(5),
            temperature_c: num(6),
            power_draw_w: num(7),
            power_limit_w: num(8),
            fan_percent: num(9),
            driver_version: non_empty(fields.get(10)),
            health: None,
            chip_count: 0,
        });
    }
    devices
}

/// Electron `parseNvidiaProcesses` (`--query-compute-apps` CSV); GPU index
/// resolved through the device UUIDs, 0 when unknown.
pub fn parse_nvidia_processes(
    section: &str,
    devices: &[AcceleratorDevice],
) -> Vec<AcceleratorProcess> {
    let mut processes = Vec::new();
    for line in section.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("__NC_") {
            continue;
        }
        let fields = parse_csv_fields(trimmed);
        if fields.len() < 3 {
            continue;
        }
        let uuid = fields[0];
        let Some(pid) = js_parse_int(fields[1]).filter(|p| *p > 0) else {
            continue;
        };
        let gpu_index = devices
            .iter()
            .filter(|d| !d.uuid.is_empty())
            .rev()
            .find(|d| d.uuid == uuid)
            .map_or(0, |d| d.index);
        processes.push(AcceleratorProcess {
            vendor: "nvidia".into(),
            gpu_index,
            pid,
            process_name: fields[2].to_string(),
            memory_used_mb: parse_csv_number(fields.get(3).copied()),
        });
    }
    processes
}

/// Electron `extractKvNumber`: first `label [:=] number` match.
fn extract_kv_number(block: &str, labels: &[&str]) -> Option<f64> {
    for label in labels {
        let re = Regex::new(&format!(r"(?i){label}\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)"))
            .expect("valid label regex");
        if let Some(m) = re.captures(block) {
            if let Some(n) = js_parse_float(&m[1]) {
                return Some(n);
            }
        }
    }
    None
}

/// Electron `extractKvText`: first `label [:=] text`, cut at a double space.
fn extract_kv_text(block: &str, labels: &[&str]) -> Option<String> {
    static GAP: OnceLock<Regex> = OnceLock::new();
    for label in labels {
        let re = Regex::new(&format!(r"(?i){label}\s*[:=]\s*(.+)")).expect("valid label regex");
        if let Some(m) = re.captures(block) {
            let value = m[1].trim();
            let value = regex(&GAP, r"\s{2,}.*").replace(value, "");
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Electron `parseAscendDeviceBlock`: one `npu-smi info -t board|common|
/// usages|memory -i <id>` dump.
pub fn parse_ascend_device_block(index: i64, block: &str) -> AcceleratorDevice {
    static PAIR_A: OnceLock<Regex> = OnceLock::new();
    static PAIR_B: OnceLock<Regex> = OnceLock::new();
    let name = extract_kv_text(
        block,
        &[
            "Product Name",
            "NPU Name",
            "Chip Name",
            "Model",
            "Board Name",
        ],
    )
    .unwrap_or_else(|| format!("Ascend NPU {index}"));
    let utilization_percent = extract_kv_number(
        block,
        &[
            r"Aicore Usage Rate\(%\)",
            r"AICore Usage Rate\(%\)",
            "Aicore Usage Rate",
            "AI Core Usage",
        ],
    );
    // Absolute MB fields only — never treat "HBM Usage Rate(%)" as megabytes.
    let hbm_used = extract_kv_number(
        block,
        &[
            r"HBM Used Memory\(MB\)",
            r"HBM Memory Usage\(MB\)",
            r"Used HBM Memory\(MB\)",
            "Used HBM Memory",
        ],
    );
    let hbm_total = extract_kv_number(
        block,
        &[
            r"HBM Total Memory\(MB\)",
            r"HBM Capacity\(MB\)",
            r"Total HBM Memory\(MB\)",
            "Total HBM Memory",
        ],
    );
    let hbm_usage_rate = extract_kv_number(block, &[r"HBM Usage Rate\(%\)", "HBM Usage Rate"]);
    // memory command sometimes reports "Used / Total"
    let pair = regex(
        &PAIR_A,
        r"(?i)HBM[^\n]*?(?:Memory|Usage)\([^\n]*?(\d+(?:\.\d+)?)\s*/\s*(\d+(?:\.\d+)?)",
    )
    .captures(block)
    .or_else(|| {
        regex(
            &PAIR_B,
            r"(?i)HBM Used Memory[^\n]*?(\d+(?:\.\d+)?)\s*/\s*(\d+(?:\.\d+)?)",
        )
        .captures(block)
    });
    let (mut memory_used_mb, memory_total_mb) = match &pair {
        Some(m) => (js_parse_float(&m[1]), js_parse_float(&m[2])),
        None => (hbm_used, hbm_total),
    };
    // Derive used MB from rate only when total is known and used is missing.
    if memory_used_mb.is_none() {
        if let (Some(rate), Some(total)) = (hbm_usage_rate, memory_total_mb) {
            if total > 0.0 {
                memory_used_mb = Some(rate / 100.0 * total);
            }
        }
    }
    let temperature_c =
        extract_kv_number(block, &[r"Temperature\(C\)", r"Temp\(C\)", "Temperature"]);
    let power_draw_w = extract_kv_number(
        block,
        &[
            r"NPU Real-time Power\(W\)",
            r"Power Dissipation\(W\)",
            r"Power\(W\)",
            "Power",
        ],
    );
    let health = extract_kv_text(block, &["Health", "Health Status"]);
    AcceleratorDevice {
        vendor: "ascend".into(),
        index,
        uuid: String::new(),
        name,
        utilization_percent,
        memory_used_mb,
        memory_total_mb,
        temperature_c,
        power_draw_w,
        power_limit_w: None,
        fan_percent: None,
        driver_version: None,
        health,
        chip_count: 0,
    }
}

/// Last `used / total` pair of a chip row.
fn last_mem_pair(line: &str) -> Option<(String, String)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r"(\d+(?:\.\d+)?)\s*/\s*(\d+(?:\.\d+)?)")
        .captures_iter(line)
        .last()
        .map(|m| (m[1].to_string(), m[2].to_string()))
}

/// Electron `parseAscendInfoTable`: `npu-smi info` summary tables (legacy and
/// CANN 24.x Bus-Id layouts). Chip rows attach to the preceding NPU row;
/// multi-chip cards aggregate memory and keep the max utilization.
pub fn parse_ascend_info_table(section: &str) -> Vec<AcceleratorDevice> {
    static SUMMARY: OnceLock<Regex> = OnceLock::new();
    static BUS_CHIP: OnceLock<Regex> = OnceLock::new();
    static LEGACY_CHIP: OnceLock<Regex> = OnceLock::new();
    static HEADER_NAME: OnceLock<Regex> = OnceLock::new();
    static OK: OnceLock<Regex> = OnceLock::new();
    // Summary: NPU ID, Name, Health, Power, Temp; tolerate Hugepages column after Temp.
    let summary_re = regex(
        &SUMMARY,
        r"^\|\s*(\d+)\s+(\S+)\s+\|\s*(\S+)\s+\|\s*(\S+)\s+(\d+(?:\.\d+)?)\b",
    );
    // Bus-Id chip row (CANN 24.x): | ChipID [PhyID] | Bus-Id | AICore(%) ... mem pairs ... |
    let bus_chip_re = regex(
        &BUS_CHIP,
        r"^\|\s*(\d+)\s*(\d*)\s*\|\s*([0-9A-Fa-f:.]+|NA)\s*\|\s*(\d+(?:\.\d+)?)\b",
    );
    // Legacy whitespace chip row: | NPU Chip Logic AICore Mem/Tot HBM/Tot |
    let legacy_chip_re = regex(
        &LEGACY_CHIP,
        r"^\|\s*(\d+)\s+\d+\s+\d+\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s*/\s*(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s*/\s*(\d+(?:\.\d+)?)",
    );
    let header_name = regex(&HEADER_NAME, r"(?i)^(?:NPU|Chip|Name)$");
    let ok_re = regex(&OK, r"(?i)^ok$");

    let driver_version = extract_ascend_driver_version(section);
    let lines: Vec<&str> = section.split('\n').collect();
    let mut devices: Vec<AcceleratorDevice> = Vec::new();
    let mut last: Option<usize> = None;
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        i += 1;
        if !line.starts_with('|') {
            continue;
        }

        if let Some(summary) = summary_re.captures(line) {
            let Some(index) = js_parse_int(&summary[1]) else {
                continue;
            };
            let name = summary[2].trim().to_string();
            if name.is_empty() || header_name.is_match(&name) {
                continue;
            }
            let health = summary[3].trim().to_string();
            let power = parse_csv_number(Some(&summary[4]));
            let temperature = parse_csv_number(Some(&summary[5]));
            let (idx, is_new) = match devices.iter().position(|d| d.index == index) {
                Some(idx) => {
                    let device = &mut devices[idx];
                    if device.name.is_empty() {
                        device.name = name;
                    }
                    device.temperature_c = max_finite(device.temperature_c, temperature);
                    if device.power_draw_w.is_none() {
                        device.power_draw_w = power;
                    }
                    let keep = device.health.as_deref().unwrap_or("");
                    if (keep.is_empty() || ok_re.is_match(keep)) && !health.is_empty() {
                        device.health = Some(health);
                    }
                    if device.driver_version.is_none() && driver_version.is_some() {
                        device.driver_version = driver_version.clone();
                    }
                    (idx, false)
                }
                None => {
                    devices.push(AcceleratorDevice {
                        vendor: "ascend".into(),
                        index,
                        uuid: String::new(),
                        name,
                        utilization_percent: None,
                        memory_used_mb: None,
                        memory_total_mb: None,
                        temperature_c: temperature,
                        power_draw_w: power,
                        power_limit_w: None,
                        fan_percent: None,
                        driver_version: driver_version.clone(),
                        health: Some(health),
                        chip_count: 0,
                    });
                    (devices.len() - 1, true)
                }
            };
            last = Some(idx);
            let device = &mut devices[idx];

            let next = lines.get(i).map_or("", |l| l.trim());
            if let Some(bus_chip) = bus_chip_re.captures(next) {
                i += 1;
                device.utilization_percent = max_finite(
                    device.utilization_percent,
                    parse_csv_number(Some(&bus_chip[4])),
                );
                if let Some((used, total)) = last_mem_pair(next) {
                    let aggregate = !is_new && device.chip_count > 0;
                    apply_mem_pair(device, &used, &total, aggregate);
                }
                device.chip_count += 1;
                continue;
            }
            if let Some(legacy) = legacy_chip_re.captures(next) {
                i += 1;
                device.utilization_percent = max_finite(
                    device.utilization_percent,
                    parse_csv_number(Some(&legacy[2])),
                );
                let aggregate = !is_new && device.chip_count > 0;
                apply_mem_pair(device, &legacy[5], &legacy[6], aggregate);
                device.chip_count += 1;
            }
            continue;
        }

        if let Some(legacy) = legacy_chip_re.captures(line) {
            let index = js_parse_int(&legacy[1]);
            let Some(idx) = devices.iter().position(|d| Some(d.index) == index).or(last) else {
                continue;
            };
            let device = &mut devices[idx];
            device.utilization_percent = max_finite(
                device.utilization_percent,
                parse_csv_number(Some(&legacy[2])),
            );
            let aggregate = device.chip_count > 0;
            apply_mem_pair(device, &legacy[5], &legacy[6], aggregate);
            device.chip_count += 1;
            continue;
        }

        if let (Some(bus_chip), Some(idx)) = (bus_chip_re.captures(line), last) {
            let device = &mut devices[idx];
            device.utilization_percent = max_finite(
                device.utilization_percent,
                parse_csv_number(Some(&bus_chip[4])),
            );
            if let Some((used, total)) = last_mem_pair(line) {
                let aggregate = device.chip_count > 0;
                apply_mem_pair(device, &used, &total, aggregate);
            }
            device.chip_count += 1;
        }
    }
    for device in &mut devices {
        device.chip_count = 0;
    }
    devices
}

/// Electron `parseAscendTypedSections`: `__NC_NPU_DEVICE__=<id>` blocks.
fn parse_ascend_typed_sections(section: &str) -> Vec<AcceleratorDevice> {
    let mut devices = Vec::new();
    for chunk in section.split("__NC_NPU_DEVICE__=") {
        let trimmed = chunk.trim();
        if trimmed.is_empty() || trimmed.starts_with("__NC_") {
            continue;
        }
        let (id_part, body) = match trimmed.find('\n') {
            Some(nl) => (&trimmed[..nl], &trimmed[nl + 1..]),
            None => (trimmed, ""),
        };
        let Some(index) = js_parse_int(id_part) else {
            continue;
        };
        devices.push(parse_ascend_device_block(index, body));
    }
    devices
}

/// Electron `parseAscendProcesses`: `npu-smi info -t proc-mem` lines and the
/// process table of the `npu-smi info` dump.
pub fn parse_ascend_processes(section: &str) -> Vec<AcceleratorProcess> {
    static NONE: OnceLock<Regex> = OnceLock::new();
    static KV: OnceLock<Regex> = OnceLock::new();
    static INFO: OnceLock<Regex> = OnceLock::new();
    static PIPE: OnceLock<Regex> = OnceLock::new();
    static WS: OnceLock<Regex> = OnceLock::new();
    let none = regex(&NONE, r"(?i)no running processes");
    // Common proc-mem lines include NPU/Chip/Pid/Name/Memory.
    let kv = regex(
        &KV,
        r"(?i)(?:NPU|Device)?\s*I?D?\s*[:=]?\s*(\d+).*?\b(?:PID|Pid)\s*[:=]?\s*(\d+).*?\b(?:Name|Process)\s*[:=]?\s*(\S+).*?(?:Memory|Mem)\s*[:=]?\s*(\d+(?:\.\d+)?)",
    );
    // nputop / npu-smi info process table:
    // | 0       0                 | 124528        | python3.8                | 17400                   |
    let info = regex(
        &INFO,
        r"^\|\s*(\d+)\s+(\d+)\s+\|\s+(\d+)\s+\|\s*([^|]+?)\s*\|\s*(\d+(?:\.\d+)?)",
    );
    // Pipe-separated: | 0 | 0 | 12345 | python | 1024 |
    let pipe = regex(
        &PIPE,
        r"^\|\s*(\d+)\s*\|\s*\d+\s*\|\s*(\d+)\s*\|\s*([^|]+?)\s*\|\s*(\d+(?:\.\d+)?)",
    );
    // Whitespace-delimited inside one outer |: | 0 0 12345 python 1024 |
    let ws = regex(
        &WS,
        r"^\|\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\d+(?:\.\d+)?)\s*\|?\s*$",
    );
    let make = |gpu: &str, pid: &str, name: &str, mem: &str| AcceleratorProcess {
        vendor: "ascend".into(),
        gpu_index: js_parse_int(gpu).unwrap_or(0),
        pid: js_parse_int(pid).unwrap_or(0),
        process_name: name.to_string(),
        memory_used_mb: parse_csv_number(Some(mem)),
    };
    let mut processes = Vec::new();
    for line in section.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || none.is_match(trimmed) {
            continue;
        }
        if let Some(m) = kv.captures(trimmed) {
            processes.push(make(&m[1], &m[2], &m[3], &m[4]));
        } else if let Some(m) = info.captures(trimmed) {
            processes.push(make(&m[1], &m[3], m[4].trim(), &m[5]));
        } else if let Some(m) = pipe.captures(trimmed) {
            processes.push(make(&m[1], &m[2], m[3].trim(), &m[4]));
        } else if let Some(m) = ws.captures(trimmed) {
            processes.push(make(&m[1], &m[3], &m[4], &m[5]));
        }
    }
    processes.retain(|p| p.pid > 0);
    processes
}

/// Electron `dedupeAcceleratorProcesses`.
fn dedupe_processes(processes: Vec<AcceleratorProcess>) -> Vec<AcceleratorProcess> {
    let mut seen = std::collections::HashSet::new();
    processes
        .into_iter()
        .filter(|p| {
            seen.insert(format!(
                "{}:{}:{}:{}",
                p.vendor, p.gpu_index, p.pid, p.process_name
            ))
        })
        .collect()
}

/// Electron `sliceMarkedSection`.
fn slice_marked_section<'a>(text: &'a str, begin: &str, ends: &[&str]) -> &'a str {
    let Some(start) = text.find(begin) else {
        return "";
    };
    let from = start + begin.len();
    let rest = &text[from..];
    let end = ends
        .iter()
        .filter_map(|m| rest.find(m))
        .min()
        .unwrap_or(rest.len());
    &rest[..end]
}

/// Electron `parseAcceleratorSnapshot`.
pub fn parse_accelerator_snapshot(stdout: &str) -> AcceleratorSnapshot {
    let nvidia_devices_text = slice_marked_section(
        stdout,
        "__NC_NVIDIA_DEVICES__",
        &[
            "__NC_NVIDIA_PROCESSES__",
            "__NC_NPU_BEGIN__",
            "__NC_ACCEL_END__",
        ],
    );
    let nvidia_processes_text = slice_marked_section(
        stdout,
        "__NC_NVIDIA_PROCESSES__",
        &["__NC_NPU_BEGIN__", "__NC_ACCEL_END__"],
    );
    let npu_section = slice_marked_section(
        stdout,
        "__NC_NPU_BEGIN__",
        &["__NC_NPU_END__", "__NC_ACCEL_END__"],
    );

    let nvidia_devices = parse_nvidia_devices(nvidia_devices_text);
    let nvidia_processes = parse_nvidia_processes(nvidia_processes_text, &nvidia_devices);

    let mut ascend_devices = parse_ascend_typed_sections(npu_section);
    let info_dump = slice_marked_section(
        npu_section,
        "__NC_NPU_INFO__",
        &["__NC_NPU_PROCS__", "__NC_NPU_END__"],
    );
    let info_source = if info_dump.is_empty() {
        npu_section
    } else {
        info_dump
    };
    let table_devices = parse_ascend_info_table(info_source);
    if ascend_devices.is_empty() {
        ascend_devices = table_devices;
    } else {
        // Fill gaps when typed -t queries returned stubs but the summary
        // table is rich.
        static STUB: OnceLock<Regex> = OnceLock::new();
        let stub = regex(&STUB, r"(?i)^Ascend NPU\b");
        for table_device in table_devices {
            let Some(existing) = ascend_devices
                .iter_mut()
                .rev()
                .find(|d| d.index == table_device.index)
            else {
                ascend_devices.push(table_device);
                continue;
            };
            if existing.name.is_empty() || stub.is_match(&existing.name) {
                existing.name = table_device.name.clone();
            }
            let fill = |slot: &mut Option<f64>, value: Option<f64>| {
                if slot.is_none() {
                    *slot = value;
                }
            };
            fill(
                &mut existing.utilization_percent,
                table_device.utilization_percent,
            );
            fill(&mut existing.memory_used_mb, table_device.memory_used_mb);
            fill(&mut existing.memory_total_mb, table_device.memory_total_mb);
            fill(&mut existing.temperature_c, table_device.temperature_c);
            fill(&mut existing.power_draw_w, table_device.power_draw_w);
            if existing.health.is_none() {
                existing.health = table_device.health.clone();
            }
        }
    }
    let ascend_proc_text =
        slice_marked_section(npu_section, "__NC_NPU_PROCS__", &["__NC_NPU_END__"]);
    // Processes often live in the `npu-smi info` dump (nputop fixtures), not
    // only in `-t proc-mem`.
    let mut ascend_processes = parse_ascend_processes(ascend_proc_text);
    ascend_processes.extend(parse_ascend_processes(info_source));
    let ascend_processes = dedupe_processes(ascend_processes);

    if let Some(version) = extract_ascend_driver_version(info_source) {
        for device in &mut ascend_devices {
            if device.driver_version.is_none() {
                device.driver_version = Some(version.clone());
            }
        }
    }

    let nvidia_driver_version = nvidia_devices.iter().find_map(|d| d.driver_version.clone());
    let mut devices: Vec<AcceleratorDevice> =
        nvidia_devices.into_iter().chain(ascend_devices).collect();
    devices.sort_by(|a, b| a.vendor.cmp(&b.vendor).then(a.index.cmp(&b.index)));
    let mut processes = nvidia_processes;
    processes.extend(ascend_processes);

    AcceleratorSnapshot {
        devices,
        processes,
        nvidia_driver_version,
        probed_at: now_ms(),
    }
}

/// `listAccelerators({ sessionId })`.
pub async fn list_accelerators(exec: &dyn SessionExec, payload: &Value) -> Value {
    let has_session = payload
        .get("sessionId")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if !has_session {
        return json!({ "success": false, "error": "Missing sessionId" });
    }
    let result = if exec.is_local() && exec.local_platform() == LocalPlatform::Win32 {
        exec.exec_local(ExecRequest::new(
            accelerator_collect_script_windows(),
            COLLECT_TIMEOUT_MS,
        ))
        .await
    } else {
        exec.exec(ExecRequest::new(
            accelerator_collect_script(),
            COLLECT_TIMEOUT_MS,
        ))
        .await
    };
    if result.pending {
        return json!({ "success": false, "pending": true });
    }
    if !result.success {
        return json!({
            "success": false,
            "error": result.error.filter(|e| !e.is_empty()).unwrap_or_else(|| "Failed to query accelerators".into()),
        });
    }
    let snapshot = parse_accelerator_snapshot(&result.stdout);
    json!({
        "success": true,
        "devices": number_cleanup(json!(snapshot.devices)),
        "processes": number_cleanup(json!(snapshot.processes)),
        "nvidiaDriverVersion": snapshot.nvidia_driver_version,
        "probedAt": snapshot.probed_at,
    })
}

/// Serialize integral floats as integers (`1024` rather than `1024.0`) so the
/// JSON matches what Node's `JSON.stringify` produces.
fn number_cleanup(value: Value) -> Value {
    match value {
        Value::Number(n) => match n.as_f64() {
            Some(f) if n.is_f64() && f.fract() == 0.0 && f.abs() < 9.007_199_254_740_992e15 => {
                json!(f as i64)
            }
            _ => Value::Number(n),
        },
        Value::Array(items) => Value::Array(items.into_iter().map(number_cleanup).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, number_cleanup(v)))
                .collect(),
        ),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{ExecResult, FakeExec};

    #[test]
    fn nvidia_devices_read_csv_nounits_rows() {
        let devices = parse_nvidia_devices(
            "0, GPU-aaa, NVIDIA GeForce RTX 4090, 42, 1024, 24576, 61, 120.5, 450.0, 35, 550.54.15\n\
             1, GPU-bbb, NVIDIA A100-SXM4-80GB, [N/A], 0, 81920, 38, 70.0, 400.0, [N/A], 550.54.15\n",
        );
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].vendor, "nvidia");
        assert_eq!(devices[0].name, "NVIDIA GeForce RTX 4090");
        assert_eq!(devices[0].utilization_percent, Some(42.0));
        assert_eq!(devices[0].memory_used_mb, Some(1024.0));
        assert_eq!(devices[0].memory_total_mb, Some(24576.0));
        assert_eq!(devices[0].power_draw_w, Some(120.5));
        assert_eq!(devices[0].driver_version.as_deref(), Some("550.54.15"));
        assert_eq!(devices[1].utilization_percent, None);
        assert_eq!(devices[1].fan_percent, None);
    }

    #[test]
    fn nvidia_processes_map_uuid_to_gpu_index() {
        let devices = parse_nvidia_devices(
            "0, GPU-aaa, RTX, 10, 1, 2, 30, 40, 50, 20, 1.0\n3, GPU-ccc, RTX, 1, 1, 1, 1, 1, 1, 1, 1\n",
        );
        let processes = parse_nvidia_processes(
            "GPU-aaa, 1234, python, 2048\nGPU-ccc, 7, x, 1\nGPU-zzz, 8, y, 1\n",
            &devices,
        );
        assert_eq!(processes.len(), 3);
        assert_eq!(processes[0].gpu_index, 0);
        assert_eq!(processes[0].pid, 1234);
        assert_eq!(processes[0].process_name, "python");
        assert_eq!(processes[0].memory_used_mb, Some(2048.0));
        assert_eq!(processes[1].gpu_index, 3);
        assert_eq!(processes[2].gpu_index, 0);
    }

    #[test]
    fn ascend_device_block_extracts_usages_and_memory_pair() {
        let device = parse_ascend_device_block(
            0,
            "
NPU ID                         : 0
Chip ID                        : 0
Product Name                   : Ascend 910B
Aicore Usage Rate(%)           : 17
HBM Usage Rate(%)              : 6
HBM Capacity(MB)               : 32768
HBM Used Memory(MB)            : 2048 / 32768
Temperature(C)                 : 41
NPU Real-time Power(W)         : 71.7
Health                         : OK
",
        );
        assert_eq!(device.vendor, "ascend");
        assert_eq!(device.name, "Ascend 910B");
        assert_eq!(device.utilization_percent, Some(17.0));
        assert_eq!(device.memory_used_mb, Some(2048.0));
        assert_eq!(device.memory_total_mb, Some(32768.0));
        assert_eq!(device.temperature_c, Some(41.0));
        assert_eq!(device.power_draw_w, Some(71.7));
        assert_eq!(device.health.as_deref(), Some("OK"));
    }

    #[test]
    fn ascend_device_block_does_not_treat_usage_rate_as_megabytes() {
        let device = parse_ascend_device_block(
            2,
            "
Product Name                   : Ascend 910B
Aicore Usage Rate(%)           : 3
HBM Usage Rate(%)              : 25
HBM Capacity(MB)               : 32768
Temperature(C)                 : 40
",
        );
        assert_eq!(device.memory_total_mb, Some(32768.0));
        assert_eq!(device.memory_used_mb, Some(8192.0));
        assert_eq!(device.health, None);
    }

    #[test]
    fn ascend_processes_accept_whitespace_delimited_rows() {
        let processes = parse_ascend_processes(
            "
| NPU Chip PID Name Memory |
| 0 0 12345 python 1024 |
| 1 0 99 train.py 2048 |
",
        );
        assert_eq!(processes.len(), 2);
        assert_eq!(processes[0].gpu_index, 0);
        assert_eq!(processes[0].pid, 12345);
        assert_eq!(processes[0].process_name, "python");
        assert_eq!(processes[0].memory_used_mb, Some(1024.0));
        assert_eq!(processes[1].pid, 99);
    }

    #[test]
    fn posix_collector_keeps_sed_quotes_inside_json_wrapped_sh() {
        let script = accelerator_collect_script();
        assert!(script.starts_with("exec sh -c \""));
        assert!(script.contains("sed -n '"));
        assert!(!script.starts_with("exec sh -c '"));
        assert!(script.contains("__NC_NPU_INFO__"));
        assert!(script.contains("npu-smi info -m"));
        assert!(script.contains("npu-smi info 2>/dev/null"));
        // The sed back-references survive JSON quoting as `\\(` / `\\1`.
        assert!(script.contains(r"\\([0-9][0-9]*\\).*/\\1/p'"));
    }

    #[cfg(unix)]
    #[test]
    fn posix_collector_is_syntactically_valid_for_sh() {
        // Replace remote tools with no-ops so only the wrapper shell runs.
        let dry_run = accelerator_collect_script()
            .replace("nvidia-smi", "false")
            .replace("npu-smi", "false");
        let output = std::process::Command::new("sh")
            .args(["-c", &dry_run])
            .output()
            .expect("run sh");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "stderr={}\nstdout={stdout}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("__NC_ACCEL_BEGIN__"));
        assert!(stdout.contains("__NC_ACCEL_END__"));
    }

    #[tokio::test]
    async fn list_accelerators_uses_powershell_on_local_windows() {
        let fake = FakeExec::new(|_, local| {
            assert!(local, "POSIX collector should not run on local Windows");
            ExecResult::ok(
                "__NC_ACCEL_BEGIN__\n__NC_NVIDIA_DEVICES__\n0, GPU-w, RTX, 1, 2, 3, 4, 5, 6, 7, 8.0\n__NC_ACCEL_END__\n",
                "",
                0,
            )
        })
        .local(LocalPlatform::Win32);
        let result = list_accelerators(&fake, &json!({ "sessionId": "local-1" })).await;
        assert_eq!(result["success"], true);
        assert_eq!(fake.commands(), vec![accelerator_collect_script_windows()]);
        assert_eq!(fake.requests()[0].0.timeout_ms, 15_000);
        assert_eq!(result["devices"].as_array().unwrap().len(), 1);
        assert_eq!(result["devices"][0]["name"], "RTX");
        assert_eq!(result["devices"][0]["memoryUsedMb"], json!(2));
        assert_eq!(result["devices"][0]["driverVersion"], "8.0");
        assert_eq!(result["nvidiaDriverVersion"], "8.0");
        assert!(result["probedAt"].as_i64().unwrap() > 0);
    }

    #[tokio::test]
    async fn list_accelerators_remote_failures() {
        let fake = FakeExec::sequence(vec![
            ExecResult::fail(""),
            ExecResult::pending("Mosh handshake in progress"),
            ExecResult::ok("__NC_ACCEL_BEGIN__\n__NC_ACCEL_END__\n", "", 0),
        ]);
        let payload = json!({ "sessionId": "s" });
        assert_eq!(
            list_accelerators(&fake, &payload).await,
            json!({ "success": false, "error": "Failed to query accelerators" })
        );
        assert_eq!(
            list_accelerators(&fake, &payload).await,
            json!({ "success": false, "pending": true })
        );
        let empty = list_accelerators(&fake, &payload).await;
        assert_eq!(empty["devices"], json!([]));
        assert_eq!(empty["processes"], json!([]));
        assert_eq!(empty["nvidiaDriverVersion"], Value::Null);
        assert_eq!(fake.commands()[0], accelerator_collect_script());
        assert!(!fake.requests()[0].1);
        assert_eq!(
            list_accelerators(&fake, &json!({})).await,
            json!({ "success": false, "error": "Missing sessionId" })
        );
    }

    #[test]
    fn ascend_info_table_reads_summary_and_chip_rows() {
        let devices = parse_ascend_info_table(
            "
| NPU   Name                    | Health          | Power(W)   Temp(C)                        |
| 0     910B3                   | OK              | 71.8       42                             |
| Chip   Phy-ID   Chip-Logic-ID   AICore(%)   Memory-Usage(MB)   HBM-Usage(MB) |
| 0      0        0               12          100 / 32768         2048 / 32768  |
",
        );
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "910B3");
        assert_eq!(devices[0].utilization_percent, Some(12.0));
        assert_eq!(devices[0].memory_used_mb, Some(2048.0));
        assert_eq!(devices[0].memory_total_mb, Some(32768.0));
        assert_eq!(devices[0].temperature_c, Some(42.0));
    }

    const CANN24_TABLE: &str = "
+------------------------------------------------------------------------------------------------+
| npu-smi 24.1.rc2                       Version: 24.1.rc2                                       |
+---------------------------+---------------+----------------------------------------------------+
| NPU   Name                | Health          | Power(W)    Temp(C)           Hugepages-Usage(page)|
| Chip                      | Bus-Id          | AICore(%)   Memory-Usage(MB)  HBM-Usage(MB)        |
+===========================+===============+====================================================+
| 6     910B1               | OK            | 100.8       33                0    / 0             |
| 0                         | 0000:01:00.0  | 0           0    / 0          3384 / 65536         |
+===========================+===============+====================================================+
| No running processes found in NPU 6                                                            |
+===========================+===============+====================================================+
";

    #[test]
    fn ascend_info_table_reads_cann24_bus_id_table() {
        // Fixture from GitHub issue #2811 (ModelArts / Ascend 910B1).
        let devices = parse_ascend_info_table(CANN24_TABLE);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].index, 6);
        assert_eq!(devices[0].name, "910B1");
        assert_eq!(devices[0].health.as_deref(), Some("OK"));
        assert_eq!(devices[0].power_draw_w, Some(100.8));
        assert_eq!(devices[0].temperature_c, Some(33.0));
        assert_eq!(devices[0].utilization_percent, Some(0.0));
        assert_eq!(devices[0].memory_used_mb, Some(3384.0));
        assert_eq!(devices[0].memory_total_mb, Some(65536.0));
        assert_eq!(devices[0].driver_version.as_deref(), Some("24.1.rc2"));
    }

    const MODERN_INFO: &str = "
| NPU   Name                | Health          | Power(W)    Temp(C)           Hugepages-Usage(page)|
| Chip                      | Bus-Id          | AICore(%)   Memory-Usage(MB)  HBM-Usage(MB)        |
| 6     910B1               | OK            | 100.8       33                0    / 0             |
| 0                         | 0000:01:00.0  | 0           0    / 0          3384 / 65536         |
";

    #[test]
    fn snapshot_falls_back_to_modern_info_table() {
        let snapshot = parse_accelerator_snapshot(&format!(
            "\n__NC_ACCEL_BEGIN__\n__NC_NPU_BEGIN__\n__NC_NPU_INFO__{MODERN_INFO}__NC_NPU_PROCS__\n__NC_NPU_END__\n__NC_ACCEL_END__\n"
        ));
        assert_eq!(snapshot.devices.len(), 1);
        assert_eq!(snapshot.devices[0].vendor, "ascend");
        assert_eq!(snapshot.devices[0].index, 6);
        assert_eq!(snapshot.devices[0].memory_total_mb, Some(65536.0));
    }

    #[test]
    fn snapshot_merges_nvidia_and_ascend_sections() {
        let snapshot = parse_accelerator_snapshot(
            "
__NC_ACCEL_BEGIN__
__NC_NVIDIA_DEVICES__
0, GPU-aaa, RTX 4090, 55, 8192, 24576, 60, 200.0, 450.0, 40, 550.54
__NC_NVIDIA_PROCESSES__
GPU-aaa, 99, train.py, 4096
__NC_NPU_BEGIN__
__NC_NPU_DEVICE__=1
Product Name                   : Ascend 910B
Aicore Usage Rate(%)           : 8
HBM Used Memory(MB)            : 512 / 32768
Temperature(C)                 : 39
NPU Real-time Power(W)         : 66.0
Health                         : OK
__NC_NPU_PROCS__
__NC_NPU_END__
__NC_ACCEL_END__
",
        );
        assert_eq!(snapshot.devices.len(), 2);
        assert_eq!(snapshot.devices[0].vendor, "ascend");
        assert_eq!(snapshot.devices[0].memory_used_mb, Some(512.0));
        assert_eq!(snapshot.devices[1].vendor, "nvidia");
        assert_eq!(snapshot.processes.len(), 1);
        assert_eq!(snapshot.nvidia_driver_version.as_deref(), Some("550.54"));
    }

    #[test]
    fn snapshot_enriches_typed_ascend_stubs_from_info_table() {
        let snapshot = parse_accelerator_snapshot(&format!(
            "\n__NC_ACCEL_BEGIN__\n__NC_NPU_BEGIN__\n__NC_NPU_DEVICE__=6\n__NC_NPU_INFO__{MODERN_INFO}__NC_NPU_PROCS__\n__NC_NPU_END__\n__NC_ACCEL_END__\n"
        ));
        assert_eq!(snapshot.devices.len(), 1);
        let d = &snapshot.devices[0];
        assert_eq!(d.index, 6);
        assert_eq!(d.name, "910B1");
        assert_eq!(d.memory_used_mb, Some(3384.0));
        assert_eq!(d.memory_total_mb, Some(65536.0));
        assert_eq!(d.temperature_c, Some(33.0));
        assert_eq!(d.power_draw_w, Some(100.8));
        assert_eq!(d.health.as_deref(), Some("OK"));
    }

    // Fixtures adapted from youyve/nputop tests/test_libascend.py (Apache-2.0).

    #[test]
    fn ascend_info_table_reads_nputop_910b2c_dual_npu_fixture() {
        let devices = parse_ascend_info_table(
            "
+------------------------------------------------------------------------------------------------+
| npu-smi 23.0.2.1                 Version: 23.0.2.1                                             |
+---------------------------+---------------+----------------------------------------------------+
| NPU   Name                | Health        | Power(W)    Temp(C)           Hugepages-Usage(page)|
| Chip                      | Bus-Id        | AICore(%)   Memory-Usage(MB)  HBM-Usage(MB)        |
+===========================+===============+====================================================+
| 0     910B2C              | OK            | 88.6        51                0    / 0             |
| 0                         | 0000:5A:00.0  | 0           0    / 0          20701/ 65536         |
+===========================+===============+====================================================+
| 1     910B2C              | OK            | 99.6        50                0    / 0             |
| 0                         | 0000:19:00.0  | 0           0    / 0          20687/ 65536         |
+===========================+===============+====================================================+
",
        );
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].name, "910B2C");
        assert_eq!(devices[0].memory_used_mb, Some(20701.0));
        assert_eq!(devices[0].memory_total_mb, Some(65536.0));
        assert_eq!(devices[0].power_draw_w, Some(88.6));
        assert_eq!(devices[0].driver_version.as_deref(), Some("23.0.2.1"));
        assert_eq!(devices[1].memory_used_mb, Some(20687.0));
    }

    #[test]
    fn ascend_info_table_reads_nputop_310b4_no_hbm_fixture() {
        let devices = parse_ascend_info_table(
            "
| npu-smi 23.0.0                                   Version: 23.0.0                                       |
| NPU     Name                  | Health          | Power(W)     Temp(C)           Hugepages-Usage(page) |
| Chip    Device                | Bus-Id          | AICore(%)    Memory-Usage(MB)                        |
| 0       310B4                 | Alarm           | 0.0          65                15    / 15            |
| 0       0                     | NA              | 0            3628 / 15609                            |
",
        );
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "310B4");
        assert_eq!(devices[0].health.as_deref(), Some("Alarm"));
        assert_eq!(devices[0].memory_used_mb, Some(3628.0));
        assert_eq!(devices[0].memory_total_mb, Some(15609.0));
        assert_eq!(devices[0].temperature_c, Some(65.0));
    }

    #[test]
    fn ascend_info_table_aggregates_atlas_a3_multi_chip_rows() {
        let devices = parse_ascend_info_table(
            "
| npu-smi 25.2.0                   Version: 25.2.0                                               |
| NPU   Name                | Health        | Power(W)    Temp(C)           Hugepages-Usage(page)|
| Chip  Phy-ID              | Bus-Id        | AICore(%)   Memory-Usage(MB)  HBM-Usage(MB)        |
| 0     Ascend910           | OK            | 162.8       37                0    / 0             |
| 0     0                   | 0000:9C:00.0  | 0           0    / 0          3133 / 65536         |
| 0     Ascend910           | OK            | -           37                0    / 0             |
| 1     1                   | 0000:9E:00.0  | 0           0    / 0          2876 / 65536         |
| 1     Ascend910           | OK            | 167.1       38                0    / 0             |
| 0     2                   | 0000:37:00.0  | 0           0    / 0          3116 / 65536         |
| 1     Ascend910           | OK            | -           38                0    / 0             |
| 1     3                   | 0000:39:00.0  | 0           0    / 0          10568/ 65536         |
",
        );
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].name, "Ascend910");
        assert_eq!(devices[0].power_draw_w, Some(162.8));
        assert_eq!(devices[0].memory_used_mb, Some(3133.0 + 2876.0));
        assert_eq!(devices[0].memory_total_mb, Some(65536.0 + 65536.0));
        assert_eq!(devices[1].memory_used_mb, Some(3116.0 + 10568.0));
        assert_eq!(devices[1].power_draw_w, Some(167.1));
    }

    #[test]
    fn snapshot_reads_nputop_310p3_processes_from_info_dump() {
        let snapshot = parse_accelerator_snapshot(
            "
__NC_ACCEL_BEGIN__
__NC_NPU_BEGIN__
__NC_NPU_INFO__
| npu-smi 24.1.0.1                                 Version: 24.1.0.1                                     |
| NPU     Name                  | Health          | Power(W)     Temp(C)           Hugepages-Usage(page) |
| Chip    Device                | Bus-Id          | AICore(%)    Memory-Usage(MB)                        |
| 1       310P3                 | OK              | NA           62                7210  / 7210          |
| 0       0                     | 0000:01:00.0    | 0            16302/ 44280                            |
| 1       310P3                 | OK              | NA           62                7210  / 7210          |
| 1       1                     | 0000:01:00.0    | 0            15543/ 43693                            |
| 2       310P3                 | OK              | NA           61                17057 / 17057         |
| 0       2                     | 0000:02:00.0    | 0            35563/ 44280                            |
| 2       310P3                 | OK              | NA           61                16823 / 16823         |
| 1       3                     | 0000:02:00.0    | 0            35204/ 43693                            |
| NPU     Chip                  | Process id      | Process name             | Process memory(MB)        |
| 1       0                     | 3277562         | mindie_llm_back          | 14513                     |
| 1       1                     | 3277565         | mindie_llm_back          | 14513                     |
| 2       0                     | 3034986         | mindie_llm_back          | 34207                     |
| 2       1                     | 3034989         | mindie_llm_back          | 33740                     |
__NC_NPU_PROCS__
__NC_NPU_END__
__NC_ACCEL_END__
",
        );
        assert_eq!(snapshot.devices.len(), 2);
        assert_eq!(snapshot.devices[0].index, 1);
        assert_eq!(snapshot.devices[0].name, "310P3");
        assert_eq!(snapshot.devices[0].memory_used_mb, Some(16302.0 + 15543.0));
        assert_eq!(snapshot.devices[0].power_draw_w, None);
        assert_eq!(
            snapshot.devices[0].driver_version.as_deref(),
            Some("24.1.0.1")
        );
        assert_eq!(snapshot.processes.len(), 4);
        assert_eq!(snapshot.processes[0].pid, 3277562);
        assert_eq!(snapshot.processes[0].process_name, "mindie_llm_back");
        assert_eq!(snapshot.processes[0].memory_used_mb, Some(14513.0));
        assert_eq!(snapshot.processes[0].gpu_index, 1);
    }

    #[test]
    fn csv_number_and_parse_helpers_follow_js() {
        assert_eq!(parse_csv_number(Some("[N/A]")), None);
        assert_eq!(parse_csv_number(Some("N/A")), None);
        assert_eq!(parse_csv_number(Some("Not Supported")), None);
        assert_eq!(parse_csv_number(Some("-")), None);
        assert_eq!(parse_csv_number(Some("1,024")), Some(1024.0));
        assert_eq!(parse_csv_number(Some("45%")), Some(45.0));
        assert_eq!(parse_csv_number(Some("120.5W")), Some(120.5));
        assert_eq!(parse_csv_number(None), None);
        assert_eq!(js_parse_int(" 12abc"), Some(12));
        assert_eq!(js_parse_int("abc"), None);
    }
}
