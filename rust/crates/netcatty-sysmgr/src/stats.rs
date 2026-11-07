//! Server stats (`getServerStats`, the monitor sampler) and the distro
//! probe — port of `electron/bridges/sshBridge/sessionOps.cjs`
//! (`collectServerStats`), `monitorDiskIo.cjs`, `monitorGpuStats.cjs` and the
//! history bookkeeping of `sharedStats.cjs`.
//!
//! The remote scripts in [`scripts`] are byte-identical to Electron's (the
//! fixtures under `tests/fixtures/` were captured from the Electron code).

mod scripts;

pub use scripts::{
    LINUX_DISK_STATS, LINUX_STATS_FULL, LINUX_STATS_MONITOR, MACOS_STATS_FULL, MACOS_STATS_MONITOR,
    MONITOR_GPU_PROBE,
};

use async_trait::async_trait;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// Marker printed before any stats output.
pub const LATENCY_MARKER: &str = "NC_LATENCY_MARK";
/// Client-side bound shared by the stats and disk probes (and the remote
/// watchdog).
pub const STATS_RUN_TIMEOUT_MS: u64 = 10_000;
/// Dropbear closes the whole transport for exec requests above this size.
pub const DROPBEAR_MAX_COMMAND_BYTES: usize = 9000;
/// Max output of one stats probe.
pub const STATS_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Distro probe bound.
pub const DISTRO_TIMEOUT_MS: u64 = 5000;
/// Monitor GPU probe bound.
pub const GPU_PROBE_TIMEOUT_MS: u64 = 2500;

/// sshBridge `quoteShellArg`: `'...'` with `'` as `'\''`.
pub fn quote_shell_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

const DESCENDANT_TREE_AWK: &str = r#"{ pp[$1+0]=$2+0 } END { for (p in pp) { q=p+0; d=0; while (q>0 && d<4096) { if (q==root) { printf "%s ", p+0; break } if (q==self) break; q=pp[q]+0; d++ } } }"#;

/// Electron `withRemoteWatchdog`: SIGKILL the probe shell (and its
/// descendants) once the client-side timeout has elapsed, so an abandoned
/// probe never lingers on the host (#3187).
pub fn with_remote_watchdog(command: &str, timeout_ms: u64) -> String {
    let timeout_ms = if timeout_ms == 0 { 10_000 } else { timeout_ms };
    let seconds = timeout_ms.div_ceil(1000).max(1);
    let watchdog = [
        format!("( sleep {seconds}"),
        "&& nc_self=$(exec sh -c 'echo $PPID' 2>/dev/null)".to_string(),
        format!("&& nc_tree=$(ps -e -o pid= -o ppid= 2>/dev/null | awk -v root=\"$$\" -v self=\"$nc_self\" '{DESCENDANT_TREE_AWK}')"),
        "&& kill -9 $nc_tree \"$$\" 2>/dev/null ) </dev/null >/dev/null 2>&1 & nc_watchdog_pid=$!".to_string(),
    ]
    .join(" ");
    [
        watchdog,
        command.to_string(),
        "nc_status=$?".to_string(),
        format!("nc_kids=$(ps -e -o pid= -o ppid= 2>/dev/null | awk -v root=\"$nc_watchdog_pid\" -v self=\"-1\" '{DESCENDANT_TREE_AWK}')"),
        "kill -9 $nc_kids \"$nc_watchdog_pid\" 2>/dev/null".to_string(),
        "exit $nc_status".to_string(),
    ]
    .join("; ")
}

/// Electron `withPosixRemoteWatchdog`: the watchdog under `exec sh -c` so
/// fish / zsh login shells never parse it.
pub fn with_posix_remote_watchdog(command: &str, timeout_ms: u64) -> String {
    format!(
        "exec sh -c {}",
        quote_shell_arg(&with_remote_watchdog(command, timeout_ms))
    )
}

/// The primary stats probe. `monitor` drops the process list (and the GPU
/// query on Linux), as Electron does for `_monitorStats` samples.
pub fn stats_command(monitor: bool) -> String {
    let (mac, linux) = if monitor {
        (MACOS_STATS_MONITOR, LINUX_STATS_MONITOR)
    } else {
        (MACOS_STATS_FULL, LINUX_STATS_FULL)
    };
    with_posix_remote_watchdog(
        &format!(
            "printf \"{LATENCY_MARKER}|\"; ostype=$(uname -s 2>/dev/null || echo \"Unknown\"); if [ \"$ostype\" = \"Darwin\" ]; then {mac}; elif [ \"$ostype\" = \"Linux\" ]; then {linux}; else echo \"UNSUPPORTED_OS:$ostype\"; fi"
        ),
        STATS_RUN_TIMEOUT_MS,
    )
}

/// The Linux mounted-disk probe (second request).
pub fn linux_disk_stats_command() -> String {
    with_posix_remote_watchdog(LINUX_DISK_STATS, STATS_RUN_TIMEOUT_MS)
}

/// The monitor's optional GPU probe.
pub fn monitor_gpu_command() -> String {
    with_posix_remote_watchdog(MONITOR_GPU_PROBE, GPU_PROBE_TIMEOUT_MS)
}

/// `getSessionDistroInfo` probe.
pub fn distro_command() -> String {
    with_posix_remote_watchdog(
        "cat /etc/os-release 2>/dev/null || uname -a",
        DISTRO_TIMEOUT_MS,
    )
}

// ---------------------------------------------------------------- JS helpers

/// JS `Math.round`.
pub fn js_round(x: f64) -> f64 {
    (x + 0.5).floor()
}

/// JS `parseFloat`: longest leading decimal literal, else NaN.
pub fn js_parse_float(text: &str) -> f64 {
    let t = text.trim_start();
    let bytes = t.as_bytes();
    let mut end = 0;
    if end < bytes.len() && (bytes[end] == b'+' || bytes[end] == b'-') {
        end += 1;
    }
    let digits_start = end;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end < bytes.len() && bytes[end] == b'.' {
        end += 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
    }
    if end == digits_start || (end == digits_start + 1 && bytes[digits_start] == b'.') {
        return if t[digits_start..].starts_with("Infinity") {
            if t.starts_with('-') {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            }
        } else {
            f64::NAN
        };
    }
    // Optional exponent.
    let mut exp_end = end;
    if exp_end < bytes.len() && (bytes[exp_end] == b'e' || bytes[exp_end] == b'E') {
        let mut j = exp_end + 1;
        if j < bytes.len() && (bytes[j] == b'+' || bytes[j] == b'-') {
            j += 1;
        }
        let start = j;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j > start {
            exp_end = j;
        }
    }
    t[..exp_end].parse::<f64>().unwrap_or(f64::NAN)
}

/// JS `parseInt(text, 10)`; `None` for NaN.
pub fn js_parse_int(text: &str) -> Option<i64> {
    let t = text.trim_start();
    let (neg, rest) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    let value: i64 = rest[..end].parse().ok()?;
    Some(if neg { -value } else { value })
}

/// JS `Number(text)` for trimmed decimal text (`""` → 0).
fn js_number(text: &str) -> f64 {
    let t = text.trim();
    if t.is_empty() {
        return 0.0;
    }
    t.parse::<f64>().unwrap_or(f64::NAN)
}

/// Serialize an f64 the way `JSON.stringify` would (integral → integer,
/// non-finite → null).
pub fn js_num(x: f64) -> Value {
    if !x.is_finite() {
        Value::Null
    } else if x.fract() == 0.0 && x.abs() < 9.0e15 {
        json!(x as i64)
    } else {
        json!(x)
    }
}

fn opt_num(x: Option<f64>) -> Value {
    x.map(js_num).unwrap_or(Value::Null)
}

// ---------------------------------------------------------------- disk I/O

/// One `/proc` block-counter sample (`parseDiskIo`).
#[derive(Debug, Clone, PartialEq)]
pub struct DiskIoSample {
    /// Remote `/proc/uptime` seconds.
    pub timestamp: f64,
    /// device → (read sectors, write sectors)
    pub devices: BTreeMap<String, (u64, u64)>,
}

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Electron `parseDiskIo`.
pub fn parse_disk_io(text: &str) -> Option<DiskIoSample> {
    let trimmed = text.trim();
    let mut parts = trimmed.split(';');
    let time = parts.next().unwrap_or("");
    let counters = parts.next();
    if parts.next().is_some() {
        return None;
    }
    let timestamp = js_number(time);
    let counters = counters.filter(|c| !c.is_empty())?;
    if time.is_empty() || !timestamp.is_finite() || timestamp < 0.0 {
        return None;
    }
    let mut devices = BTreeMap::new();
    let counters = counters.strip_suffix(',').unwrap_or(counters);
    for entry in counters.split(',') {
        let fields: Vec<&str> = entry.split(':').collect();
        if fields.len() != 3 {
            return None;
        }
        let (name, read, write) = (fields[0], fields[1], fields[2]);
        let name_ok = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '!' | '-'));
        let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
        if !name_ok || devices.contains_key(name) || !digits(read) || !digits(write) {
            return None;
        }
        let read: u64 = read.parse().ok().filter(|v| *v <= MAX_SAFE_INTEGER)?;
        let write: u64 = write.parse().ok().filter(|v| *v <= MAX_SAFE_INTEGER)?;
        devices.insert(name.to_string(), (read, write));
    }
    Some(DiskIoSample { timestamp, devices })
}

/// Electron `diskIoRates`: bytes/s, `(None, None)` while unavailable.
pub fn disk_io_rates(
    current: Option<&DiskIoSample>,
    previous: Option<&DiskIoSample>,
) -> (Option<f64>, Option<f64>) {
    let (Some(current), Some(previous)) = (current, previous) else {
        return (None, None);
    };
    if current.devices.len() != previous.devices.len() {
        return (None, None);
    }
    let seconds = current.timestamp - previous.timestamp;
    if seconds.is_nan() || seconds <= 0.0 {
        return (None, None);
    }
    let mut read = 0f64;
    let mut write = 0f64;
    for (name, (r, w)) in &current.devices {
        let Some((pr, pw)) = previous.devices.get(name) else {
            return (None, None);
        };
        if r < pr || w < pw {
            return (None, None);
        }
        read += ((r - pr) * 512) as f64;
        write += ((w - pw) * 512) as f64;
    }
    (Some(read / seconds), Some(write / seconds))
}

/// Decode `\NNN` octal escapes of `/proc/self/mountinfo`.
fn unescape_octal(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 4 <= bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let code = u32::from_str_radix(&text[i + 1..i + 4], 8).unwrap_or(0);
            out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
            i += 4;
            continue;
        }
        let ch = text[i..].chars().next().unwrap_or('\u{FFFD}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Electron `withPartitionIo`: attach per-mount block rates.
pub fn with_partition_io(
    disks: Vec<DiskInfo>,
    mounts: &str,
    current: Option<&DiskIoSample>,
    previous: Option<&DiskIoSample>,
) -> Vec<DiskInfo> {
    let mut devices: BTreeMap<String, String> = BTreeMap::new();
    for entry in mounts.split(',') {
        let Some(sep) = entry.rfind(':') else {
            continue;
        };
        devices.insert(unescape_octal(&entry[..sep]), entry[sep + 1..].to_string());
    }
    let sample = |snapshot: Option<&DiskIoSample>, name: &str| -> Option<DiskIoSample> {
        let snapshot = snapshot?;
        let counters = snapshot.devices.get(name)?;
        Some(DiskIoSample {
            timestamp: snapshot.timestamp,
            devices: BTreeMap::from([(name.to_string(), *counters)]),
        })
    };
    disks
        .into_iter()
        .map(|mut disk| {
            let Some(name) = devices.get(&disk.mount_point) else {
                return disk;
            };
            let (read, write) = disk_io_rates(
                sample(current, name).as_ref(),
                sample(previous, name).as_ref(),
            );
            if read.is_some() {
                disk.disk_read_speed = read;
                disk.disk_write_speed = write;
            }
            disk
        })
        .collect()
}

// ---------------------------------------------------------------- GPU

/// One NVIDIA card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuCard {
    pub index: i64,
    pub name: String,
    pub utilization: Option<i64>,
    pub memory_used: Option<i64>,
    pub memory_total: Option<i64>,
}

/// GPU fields of a stats sample (`EMPTY_GPU` shape).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuStats {
    pub gpu: Option<i64>,
    pub gpu_name: Option<String>,
    pub gpu_mem_used: Option<i64>,
    pub gpu_mem_total: Option<i64>,
    pub gpus: Vec<GpuCard>,
}

const GPU_LIST_MARK: &str = " ;; ";

fn parse_gpu_number(value: Option<&str>) -> Option<i64> {
    let t = value?.trim();
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

fn parse_gpu_card(record: &str) -> Option<GpuCard> {
    let fields: Vec<&str> = record.split('\t').collect();
    if fields.len() < 5 {
        return None;
    }
    let n = fields.len();
    let index = parse_gpu_number(Some(fields[0]))?;
    Some(GpuCard {
        index,
        name: fields[1..n - 3].join("\t").trim().to_string(),
        utilization: parse_gpu_number(Some(fields[n - 3])).map(|u| u.clamp(0, 100)),
        memory_used: parse_gpu_number(Some(fields[n - 2])),
        memory_total: parse_gpu_number(Some(fields[n - 1])),
    })
}

/// Electron `parseGpuStats`: reads the `GPU:` part of a stats line.
pub fn parse_gpu_stats(output: &str) -> GpuStats {
    let payload = output
        .split('|')
        .find(|p| p.starts_with("GPU:"))
        .map(|p| p[4..].trim())
        .unwrap_or("");
    if payload.is_empty() {
        return GpuStats::default();
    }
    let (summary, list) = match payload.find(GPU_LIST_MARK) {
        Some(at) => (payload[..at].trim(), &payload[at + GPU_LIST_MARK.len()..]),
        None => (payload.trim(), ""),
    };
    let raw: Vec<&str> = summary.split_whitespace().collect();
    let Some(utilization) = parse_gpu_number(raw.first().copied()) else {
        return GpuStats::default();
    };
    let gpus = if list.is_empty() {
        Vec::new()
    } else {
        list.split(GPU_LIST_MARK)
            .filter_map(parse_gpu_card)
            .collect()
    };
    let name = raw.get(3..).map(|r| r.join(" ")).unwrap_or_default();
    GpuStats {
        gpu: Some(utilization.clamp(0, 100)),
        gpu_name: (!name.is_empty()).then_some(name),
        gpu_mem_used: parse_gpu_number(raw.get(1).copied()),
        gpu_mem_total: parse_gpu_number(raw.get(2).copied()),
        gpus,
    }
}

/// Per-connection cache of the monitor's optional GPU probe
/// (`monitorGpuStats.cjs` state).
#[derive(Debug, Clone, Default)]
pub struct GpuCache {
    pub stats: GpuStats,
    /// Earliest time (ms) of the next probe.
    pub next_at: i64,
    /// Strictly increasing publication time of `stats` changes.
    pub updated_at: i64,
    pub pending: bool,
    /// An open timeout permanently disables the probe on this transport.
    pub disabled: bool,
}

impl GpuCache {
    /// `updateGpuStats`.
    pub fn update(&mut self, next: GpuStats, now: i64) {
        if next != self.stats {
            self.updated_at = (now + 1).max(self.updated_at + 1);
        }
        self.stats = next;
    }

    /// `cacheFullGpuStats`: a full (terminal) sample already carries GPU data.
    pub fn cache_full(&mut self, stats: &Value, now: i64) {
        let next = GpuStats {
            gpu: stats.get("gpu").and_then(Value::as_i64),
            gpu_name: stats
                .get("gpuName")
                .and_then(Value::as_str)
                .map(str::to_string),
            gpu_mem_used: stats.get("gpuMemUsed").and_then(Value::as_i64),
            gpu_mem_total: stats.get("gpuMemTotal").and_then(Value::as_i64),
            gpus: stats
                .get("gpus")
                .and_then(|g| serde_json::from_value::<Vec<GpuCardIn>>(g.clone()).ok())
                .map(|cards| cards.into_iter().map(GpuCard::from).collect())
                .unwrap_or_default(),
        };
        self.update(next, now);
        self.next_at = now + 10_000;
    }

    /// Should a monitor sample start a GPU probe now?
    pub fn due(&self, now: i64) -> bool {
        !self.disabled && !self.pending && now >= self.next_at
    }

    /// Record a probe result (`None` = failed).
    pub fn finish_probe(&mut self, stdout: Option<&str>, open_timeout: bool, now: i64) {
        self.pending = false;
        match stdout {
            Some(out) => {
                self.update(parse_gpu_stats(out), now);
                self.next_at = now
                    + if self.stats.gpu.is_none() {
                        30_000
                    } else {
                        10_000
                    };
            }
            None => {
                if open_timeout {
                    self.disabled = true;
                }
                self.update(GpuStats::default(), now);
            }
        }
    }

    /// `withCachedMonitorGpu`: overlay cached GPU fields onto a stats object.
    pub fn overlay(&self, stats: &mut Value) {
        if let Value::Object(map) = stats {
            map.insert("gpu".into(), json!(self.stats.gpu));
            map.insert("gpuName".into(), json!(self.stats.gpu_name));
            map.insert("gpuMemUsed".into(), json!(self.stats.gpu_mem_used));
            map.insert("gpuMemTotal".into(), json!(self.stats.gpu_mem_total));
            map.insert("gpus".into(), json!(self.stats.gpus));
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct GpuCardIn {
    index: i64,
    name: String,
    utilization: Option<i64>,
    memory_used: Option<i64>,
    memory_total: Option<i64>,
}

impl From<GpuCardIn> for GpuCard {
    fn from(c: GpuCardIn) -> Self {
        Self {
            index: c.index,
            name: c.name,
            utilization: c.utilization,
            memory_used: c.memory_used,
            memory_total: c.memory_total,
        }
    }
}

// ---------------------------------------------------------------- parsing

/// One mounted filesystem.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskInfo {
    pub mount_point: String,
    pub used: f64,
    pub total: f64,
    pub percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_read_speed: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_write_speed: Option<f64>,
}

impl DiskInfo {
    fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("mountPoint".into(), json!(self.mount_point));
        map.insert("used".into(), js_num(self.used));
        map.insert("total".into(), js_num(self.total));
        map.insert("percent".into(), js_num(self.percent));
        if let Some(k) = &self.capacity_key {
            map.insert("capacityKey".into(), json!(k));
        }
        if let Some(t) = &self.filesystem_type {
            map.insert("filesystemType".into(), json!(t));
        }
        if let Some(r) = self.disk_read_speed {
            map.insert("diskReadSpeed".into(), js_num(r));
        }
        if let Some(w) = self.disk_write_speed {
            map.insert("diskWriteSpeed".into(), js_num(w));
        }
        Value::Object(map)
    }
}

/// One network interface counter reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetCounter {
    pub name: String,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

/// Everything one stats line carries, before deltas.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RawSample {
    pub cpu_direct: Option<f64>,
    pub cpu_raw: Option<(i64, i64)>,
    pub per_core_raw: Vec<(i64, i64)>,
    pub cpu_cores: Option<i64>,
    pub mem_total: Option<i64>,
    pub mem_free: Option<i64>,
    pub mem_buffers: Option<i64>,
    pub mem_cached: Option<i64>,
    pub mem_used: Option<i64>,
    pub swap_total: Option<i64>,
    pub swap_used: Option<i64>,
    /// (pid, memPercent, command)
    pub top_processes: Vec<(String, f64, String)>,
    pub disks: Vec<DiskInfo>,
    pub disk_io: Option<DiskIoSample>,
    pub partition_io: Option<DiskIoSample>,
    pub disk_mounts: String,
    pub net: Vec<NetCounter>,
    pub gpu: GpuStats,
    pub hostname: String,
    pub os_name: String,
    pub kernel_release: String,
    pub uptime_seconds: Option<f64>,
    pub load_average: Vec<f64>,
}

/// Result of parsing a combined stats line.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedStats {
    /// `UNSUPPORTED_OS:<uname>`.
    Unsupported(String),
    Sample(Box<RawSample>),
}

/// Strip the leading `NC_LATENCY_MARK|`.
pub fn strip_latency_marker(text: &str) -> &str {
    match text.strip_prefix(LATENCY_MARKER) {
        Some(rest) => rest.strip_prefix('|').unwrap_or(rest),
        None => text,
    }
}

/// Parse the `KEY:value|KEY:value` stats line.
pub fn parse_stats_output(combined: &str) -> ParsedStats {
    let output = strip_latency_marker(combined);
    if let Some(os) = output.strip_prefix("UNSUPPORTED_OS:") {
        return ParsedStats::Unsupported(os.to_string());
    }
    let mut s = RawSample::default();
    for part in output.split('|') {
        if let Some(v) = part.strip_prefix("CPU:") {
            let val = js_parse_float(v.trim());
            if !val.is_nan() {
                s.cpu_direct = Some(js_round(val).clamp(0.0, 100.0));
            }
        } else if let Some(v) = part.strip_prefix("PARTITIONIO:") {
            s.partition_io = parse_disk_io(v);
        } else if let Some(v) = part.strip_prefix("DISKMOUNTS:") {
            s.disk_mounts = v.to_string();
        } else if let Some(v) = part.strip_prefix("DISKIO:") {
            s.disk_io = parse_disk_io(v);
        } else if let Some(v) = part.strip_prefix("CPURAW:") {
            let raw: Vec<&str> = v.split_whitespace().collect();
            if raw.len() >= 2 {
                if let (Some(t), Some(i)) = (js_parse_int(raw[0]), js_parse_int(raw[1])) {
                    s.cpu_raw = Some((t, i));
                }
            }
        } else if let Some(v) = part.strip_prefix("CORES:") {
            if let Some(n) = js_parse_int(v.trim()).filter(|n| *n > 0) {
                s.cpu_cores = Some(n);
            }
        } else if let Some(v) = part.strip_prefix("PERCORERAW:") {
            let v = v.trim();
            if !v.is_empty() {
                s.per_core_raw = v
                    .split(',')
                    .filter_map(|entry| {
                        let mut it = entry.trim().split(':');
                        let total = js_parse_int(it.next()?)?;
                        let idle = js_parse_int(it.next()?)?;
                        Some((total, idle))
                    })
                    .collect();
            }
        } else if let Some(v) = part.strip_prefix("MEMINFO:") {
            let m: Vec<&str> = v.split_whitespace().collect();
            if m.len() >= 4 {
                s.mem_total = js_parse_int(m[0]).or(s.mem_total);
                s.mem_free = js_parse_int(m[1]).or(s.mem_free);
                s.mem_buffers = js_parse_int(m[2]).or(s.mem_buffers);
                s.mem_cached = js_parse_int(m[3]).or(s.mem_cached);
                if let (Some(t), Some(f), Some(b), Some(c)) =
                    (s.mem_total, s.mem_free, s.mem_buffers, s.mem_cached)
                {
                    s.mem_used = Some((t - f - b - c).max(0));
                }
                if m.len() >= 6 {
                    if let Some(st) = js_parse_int(m[4]) {
                        s.swap_total = Some(st);
                    }
                    if let Some(sf) = js_parse_int(m[5]) {
                        s.swap_used = s.swap_total.map(|t| (t - sf).max(0));
                    }
                }
            }
        } else if let Some(v) = part.strip_prefix("PROCS:") {
            let v = v.trim();
            if !v.is_empty() {
                for entry in v.split(',') {
                    let fields: Vec<&str> = entry.split(';').collect();
                    if fields.len() >= 3 {
                        let pct = js_parse_float(fields[1]);
                        if !pct.is_nan() {
                            s.top_processes.push((
                                fields[0].to_string(),
                                pct,
                                fields[2..].join(";"),
                            ));
                        }
                    }
                }
            }
        } else if let Some(v) = part.strip_prefix("DISKS:") {
            let v = v.trim();
            if !v.is_empty() {
                for entry in v.split(',') {
                    if let Some(disk) = parse_disk_entry(entry) {
                        s.disks.push(disk);
                    }
                }
            }
        } else if let Some(v) = part.strip_prefix("NET:") {
            let v = v.trim();
            if !v.is_empty() {
                for entry in v.split(',') {
                    let fields: Vec<&str> = entry.split(':').collect();
                    if fields.len() >= 3 {
                        if let (Some(rx), Some(tx)) =
                            (js_parse_int(fields[1]), js_parse_int(fields[2]))
                        {
                            s.net.push(NetCounter {
                                name: fields[0].to_string(),
                                rx_bytes: rx,
                                tx_bytes: tx,
                            });
                        }
                    }
                }
            }
        } else if part.starts_with("GPU:") {
            s.gpu = parse_gpu_stats(part);
        } else if let Some(v) = part.strip_prefix("HOST:") {
            s.hostname = v.trim().to_string();
        } else if let Some(v) = part.strip_prefix("OS:") {
            s.os_name = v.trim().to_string();
        } else if let Some(v) = part.strip_prefix("KERNEL:") {
            s.kernel_release = v.trim().to_string();
        } else if let Some(v) = part.strip_prefix("UPTIME:") {
            let v = v.trim();
            if !v.is_empty() {
                let up = js_number(v);
                if up.is_finite() && up >= 0.0 {
                    s.uptime_seconds = Some(up);
                }
            }
        } else if let Some(v) = part.strip_prefix("LOAD:") {
            let v = v.trim();
            if !v.is_empty() {
                s.load_average = v
                    .split_whitespace()
                    .map(js_number)
                    .filter(|x| x.is_finite() && *x >= 0.0)
                    .take(3)
                    .collect();
            }
        }
    }
    ParsedStats::Sample(Box::new(s))
}

fn parse_disk_entry(entry: &str) -> Option<DiskInfo> {
    let fields: Vec<&str> = entry.split(':').collect();
    if fields.len() < 4 {
        return None;
    }
    let used = js_parse_float(fields[1]);
    let total = js_parse_float(fields[2]);
    let mut percent = js_parse_int(fields[3])
        .map(|p| p as f64)
        .unwrap_or(f64::NAN);
    if percent.is_nan() && used.is_finite() && total.is_finite() && total > 0.0 {
        percent = js_round(used / total * 100.0);
    }
    if used.is_nan() || total.is_nan() || percent.is_nan() || total <= 0.0 {
        return None;
    }
    let metadata = fields[4..].join(":").trim().to_string();
    let mut capacity_key = metadata.clone();
    let mut filesystem_type = None;
    if metadata.starts_with("fs=") {
        if let Some(sep) = metadata.find(':').filter(|s| *s > 3) {
            filesystem_type = Some(metadata[3..sep].trim().to_string());
            capacity_key = metadata[sep + 1..].trim().to_string();
        }
    }
    Some(DiskInfo {
        mount_point: fields[0].to_string(),
        used,
        total,
        percent,
        capacity_key: (!capacity_key.is_empty()).then_some(capacity_key),
        filesystem_type: filesystem_type.filter(|t| !t.is_empty()),
        disk_read_speed: None,
        disk_write_speed: None,
    })
}

// ---------------------------------------------------------------- deltas

/// `(total, idle)` overall plus per core.
type CpuReading = ((i64, i64), Vec<(i64, i64)>);

/// Previous readings needed for rates (Electron keeps them on the session /
/// shared sampler context).
#[derive(Debug, Clone, Default)]
pub struct StatsBaseline {
    prev_net: Option<(Vec<NetCounter>, i64)>,
    prev_cpu: Option<CpuReading>,
    prev_disk_io: Option<DiskIoSample>,
    prev_partition_io: Option<DiskIoSample>,
}

/// Turn a parsed sample into the renderer's `stats` object, updating the
/// baseline. `Err` carries the user-visible error.
pub fn finalize_stats(
    parsed: ParsedStats,
    baseline: &mut StatsBaseline,
    now_ms: i64,
    latency_ms: Option<f64>,
    response_latency_ms: Option<f64>,
) -> Result<Value, String> {
    let s = match parsed {
        ParsedStats::Unsupported(os) => {
            return Err(format!("Server stats not supported on this OS ({os})"));
        }
        ParsedStats::Sample(s) => *s,
    };

    let (disk_read, disk_write) = disk_io_rates(s.disk_io.as_ref(), baseline.prev_disk_io.as_ref());
    let disks = with_partition_io(
        s.disks.clone(),
        &s.disk_mounts,
        s.partition_io.as_ref(),
        baseline.prev_partition_io.as_ref(),
    );
    baseline.prev_disk_io = s.disk_io.clone();
    baseline.prev_partition_io = s.partition_io.clone();

    // Network rates.
    let (prev_ifaces, prev_at) = baseline.prev_net.clone().unwrap_or((Vec::new(), 0));
    let time_delta = (now_ms - prev_at) as f64 / 1000.0;
    let mut net_rx = 0f64;
    let mut net_tx = 0f64;
    let mut net_interfaces = Vec::new();
    for iface in &s.net {
        let (mut rx_speed, mut tx_speed) = (0f64, 0f64);
        if time_delta > 0.0 && !prev_ifaces.is_empty() {
            if let Some(prev) = prev_ifaces.iter().find(|p| p.name == iface.name) {
                let rx_delta = iface.rx_bytes - prev.rx_bytes;
                let tx_delta = iface.tx_bytes - prev.tx_bytes;
                if rx_delta > 0 {
                    rx_speed = js_round(rx_delta as f64 / time_delta);
                }
                if tx_delta > 0 {
                    tx_speed = js_round(tx_delta as f64 / time_delta);
                }
                net_rx += rx_speed;
                net_tx += tx_speed;
            }
        }
        net_interfaces.push(json!({
            "name": iface.name,
            "rxBytes": iface.rx_bytes,
            "txBytes": iface.tx_bytes,
            "rxSpeed": js_num(rx_speed),
            "txSpeed": js_num(tx_speed),
        }));
    }
    let network_ready = prev_at > 0 && !prev_ifaces.is_empty();
    baseline.prev_net = Some((s.net.clone(), now_ms));

    // CPU.
    let usage = |total: i64, idle: i64, prev_total: i64, prev_idle: i64| -> Option<f64> {
        let total_delta = total - prev_total;
        let idle_delta = idle - prev_idle;
        (total_delta > 0).then(|| {
            js_round(100.0 - (idle_delta as f64 / total_delta as f64 * 100.0)).clamp(0.0, 100.0)
        })
    };
    let (prev_total, prev_idle, prev_cores) = match &baseline.prev_cpu {
        Some(((t, i), cores)) => (*t, *i, cores.clone()),
        None => (0, 0, Vec::new()),
    };
    let mut cpu = None;
    if let Some((t, i)) = s.cpu_raw {
        if prev_total > 0 {
            cpu = usage(t, i, prev_total, prev_idle);
        }
    }
    if cpu.is_none() {
        cpu = s.cpu_direct;
    }
    let cpu_per_core: Vec<f64> = if !s.per_core_raw.is_empty() && !prev_cores.is_empty() {
        s.per_core_raw
            .iter()
            .enumerate()
            .map(|(idx, (t, i))| {
                prev_cores
                    .get(idx)
                    .and_then(|(pt, pi)| usage(*t, *i, *pt, *pi))
                    .unwrap_or(0.0)
            })
            .collect()
    } else {
        vec![0.0; s.per_core_raw.len()]
    };
    baseline.prev_cpu = Some((s.cpu_raw.unwrap_or((0, 0)), s.per_core_raw.clone()));

    let root = disks.iter().find(|d| d.mount_point == "/");
    if cpu.is_none() && s.mem_total.is_none() && s.cpu_cores.is_none() {
        return Err("Unable to parse server stats (unsupported OS or shell)".to_string());
    }

    let mut stats = Map::new();
    stats.insert("cpu".into(), opt_num(cpu));
    stats.insert("cpuCores".into(), json!(s.cpu_cores));
    stats.insert(
        "cpuPerCore".into(),
        Value::Array(cpu_per_core.into_iter().map(js_num).collect()),
    );
    stats.insert("gpu".into(), json!(s.gpu.gpu));
    stats.insert("gpuName".into(), json!(s.gpu.gpu_name));
    stats.insert("gpuMemUsed".into(), json!(s.gpu.gpu_mem_used));
    stats.insert("gpuMemTotal".into(), json!(s.gpu.gpu_mem_total));
    stats.insert("gpus".into(), json!(s.gpu.gpus));
    stats.insert("memTotal".into(), json!(s.mem_total));
    stats.insert("memUsed".into(), json!(s.mem_used));
    stats.insert("memFree".into(), json!(s.mem_free));
    stats.insert("memBuffers".into(), json!(s.mem_buffers));
    stats.insert("memCached".into(), json!(s.mem_cached));
    stats.insert("swapTotal".into(), json!(s.swap_total));
    stats.insert("swapUsed".into(), json!(s.swap_used));
    stats.insert(
        "topProcesses".into(),
        Value::Array(
            s.top_processes
                .iter()
                .map(|(pid, pct, cmd)| json!({"pid": pid, "memPercent": js_num(*pct), "command": cmd}))
                .collect(),
        ),
    );
    stats.insert("diskPercent".into(), opt_num(root.map(|d| d.percent)));
    stats.insert("diskUsed".into(), opt_num(root.map(|d| d.used)));
    stats.insert("diskTotal".into(), opt_num(root.map(|d| d.total)));
    stats.insert(
        "disks".into(),
        Value::Array(disks.iter().map(DiskInfo::to_json).collect()),
    );
    stats.insert("diskReadSpeed".into(), opt_num(disk_read));
    stats.insert("diskWriteSpeed".into(), opt_num(disk_write));
    stats.insert("networkReady".into(), json!(network_ready));
    stats.insert("netRxSpeed".into(), js_num(net_rx));
    stats.insert("netTxSpeed".into(), js_num(net_tx));
    stats.insert("latencyMs".into(), opt_num(latency_ms));
    stats.insert("responseLatencyMs".into(), opt_num(response_latency_ms));
    stats.insert("netInterfaces".into(), Value::Array(net_interfaces));
    stats.insert("hostname".into(), json!(s.hostname));
    stats.insert("osName".into(), json!(s.os_name));
    stats.insert("kernelRelease".into(), json!(s.kernel_release));
    stats.insert("uptimeSeconds".into(), opt_num(s.uptime_seconds));
    stats.insert(
        "loadAverage".into(),
        Value::Array(s.load_average.into_iter().map(js_num).collect()),
    );
    Ok(Value::Object(stats))
}

// ---------------------------------------------------------------- collection

/// Failure of one stats probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsExecError {
    /// Channel open or run timed out.
    Timeout,
    /// Anything else (user-visible message).
    Other(String),
}

/// Output of one stats probe.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StatsExecOutput {
    pub stdout: String,
    /// Time from sending the request until the exec channel was confirmed.
    pub opened_after_ms: Option<f64>,
}

/// The connection a stats sample runs on.
#[async_trait]
pub trait StatsTransport: Send + Sync {
    /// Run one bounded probe (open + run bound = `timeout_ms`).
    async fn run(
        &self,
        command: &str,
        timeout_ms: u64,
        max_output_bytes: usize,
    ) -> Result<StatsExecOutput, StatsExecError>;
    /// Transport-level ping round trip (ms), `None` when unavailable.
    async fn ping_ms(&self) -> Option<f64>;
}

fn stats_error(err: StatsExecError) -> String {
    match err {
        StatsExecError::Timeout => "Timeout getting server stats".to_string(),
        StatsExecError::Other(message) => message,
    }
}

async fn run_limited(
    transport: &dyn StatsTransport,
    command: &str,
) -> Result<StatsExecOutput, String> {
    if command.len() > DROPBEAR_MAX_COMMAND_BYTES {
        return Err(format!(
            "Server stats command exceeds Dropbear limit ({} bytes)",
            command.len()
        ));
    }
    transport
        .run(command, STATS_RUN_TIMEOUT_MS, STATS_MAX_OUTPUT_BYTES)
        .await
        .map_err(stats_error)
}

/// Collect one sample: the primary probe (+ the Linux disk probe) and a
/// transport ping in parallel, then parse and apply deltas. Returns the
/// renderer reply `{ success, stats }` / `{ success: false, error }`.
pub async fn collect_stats(
    transport: &dyn StatsTransport,
    baseline: &mut StatsBaseline,
    monitor: bool,
    now_ms: impl Fn() -> i64,
) -> Value {
    let command = stats_command(monitor);
    let (primary, latency) = futures::join!(
        async {
            let first = run_limited(transport, &command).await?;
            let mut combined = first.stdout.trim().to_string();
            if strip_latency_marker(&combined).starts_with("CPURAW:") {
                let disk = run_limited(transport, &linux_disk_stats_command()).await?;
                let disk_out = disk.stdout.trim();
                if !disk_out.is_empty() {
                    if combined.is_empty() {
                        combined = disk_out.to_string();
                    } else {
                        combined = format!("{combined}|{disk_out}");
                    }
                }
            }
            Ok::<_, String>((combined, first.opened_after_ms))
        },
        transport.ping_ms()
    );
    let (combined, opened) = match primary {
        Ok(v) => v,
        Err(error) => return json!({ "success": false, "error": error }),
    };
    let latency = latency.filter(|l| l.is_finite());
    match finalize_stats(
        parse_stats_output(&combined),
        baseline,
        now_ms(),
        latency,
        opened.map(|o| js_round(o.max(0.0))),
    ) {
        Ok(stats) => json!({ "success": true, "stats": stats }),
        Err(error) => json!({ "success": false, "error": error }),
    }
}

// ---------------------------------------------------------------- history

/// One monitor history point.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MonitorPoint {
    pub at: i64,
    pub cpu: Option<f64>,
    pub memory: Option<f64>,
    pub disk: Option<f64>,
    pub rx: Option<f64>,
    pub tx: Option<f64>,
}

/// 30 minutes.
pub const HISTORY_WINDOW_MS: i64 = 30 * 60_000;
/// Max retained points.
pub const HISTORY_MAX_POINTS: usize = 1800;

/// Monitor history of one transport (`sharedStats.cjs` `history`).
#[derive(Debug, Clone, Default)]
pub struct StatsHistory {
    /// Last successful reply (`{ success, stats }`) and when it was taken.
    pub latest: Option<Value>,
    pub at: i64,
    /// Whether `latest` came from a full (terminal) sample.
    pub latest_full: bool,
    /// Last full reply and its time (terminal 4 s cache).
    pub full_result: Option<Value>,
    pub full_at: i64,
    pub points: Vec<MonitorPoint>,
}

impl StatsHistory {
    /// `appendPoint`: at most one point per second unless `fresh_after`
    /// (a panel restart) lies after the last point.
    pub fn append_point(&mut self, stats: &Value, now: i64, fresh_after: i64) {
        let last = self.points.last().map(|p| p.at).unwrap_or(0);
        if now - last < 1000 && last > fresh_after {
            return;
        }
        let f = |key: &str| stats.get(key).and_then(Value::as_f64);
        let mem_total = f("memTotal");
        let mem_used = f("memUsed");
        let ready = stats.get("networkReady").and_then(Value::as_bool) == Some(true);
        self.points.push(MonitorPoint {
            at: now,
            cpu: f("cpu"),
            memory: match (mem_total, mem_used) {
                (Some(t), Some(u)) if t > 0.0 && u.is_finite() => Some(u / t * 100.0),
                _ => None,
            },
            disk: f("diskPercent"),
            rx: if ready { f("netRxSpeed") } else { None },
            tx: if ready { f("netTxSpeed") } else { None },
        });
        self.prune(now);
    }

    /// Drop points older than the window and cap the count.
    pub fn prune(&mut self, now: i64) {
        self.points.retain(|p| now - p.at <= HISTORY_WINDOW_MS);
        if self.points.len() > HISTORY_MAX_POINTS {
            let excess = self.points.len() - HISTORY_MAX_POINTS;
            self.points.drain(..excess);
        }
    }

    /// Record a successful reply.
    pub fn record(&mut self, reply: &Value, full: bool, now: i64, fresh_after: i64) {
        if reply.get("success").and_then(Value::as_bool) != Some(true) {
            return;
        }
        self.latest = Some(reply.clone());
        self.latest_full = full;
        self.at = now;
        if full {
            self.full_result = Some(reply.clone());
            self.full_at = now;
        }
        if let Some(stats) = reply.get("stats") {
            self.append_point(stats, now, fresh_after);
        }
    }
}

#[cfg(test)]
mod tests;
