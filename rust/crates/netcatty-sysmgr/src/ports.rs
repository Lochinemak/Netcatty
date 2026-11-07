//! Listening-port collectors — port of
//! `electron/bridges/systemManager/portOps.cjs` and the `listListeningPorts`
//! wrapper in `systemManagerBridge.cjs`.
//!
//! One remote script runs every available collector (`ss`, `netstat`,
//! `lsof`); their outputs are parsed and merged so a PID-bearing row replaces
//! an anonymous one for the same socket. Local Windows sessions use
//! `Get-NetTCPConnection` / `Get-NetUDPEndpoint` instead.

use crate::exec::{wrap_sh_json, ExecRequest, LocalPlatform, SessionExec};
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::OnceLock;

/// Remote collector body (Electron `LISTEN_PORTS_INNER`).
pub const LISTEN_PORTS_INNER: &str = concat!(
    r#"printf "%s\n" "__NC_PORTS_BEGIN__"; "#,
    // Run every available collector. macOS often has netstat without useful
    // PID columns; lsof fills that gap. Prefer merging over elif exclusivity.
    r#"if command -v ss >/dev/null 2>&1; then "#,
    r#"printf "%s\n" "__NC_SS__"; "#,
    r#"ss -H -tulnp 2>/dev/null || ss -tulnp 2>/dev/null || true; "#,
    r#"fi; "#,
    r#"if command -v netstat >/dev/null 2>&1; then "#,
    r#"printf "%s\n" "__NC_NETSTAT__"; "#,
    // `-lntp` is TCP-only; prefer `-lntup`, else TCP+UDP separately. macOS uses `-anv -p`.
    r#"if netstat -lntup 2>/dev/null; then :; "#,
    r#"elif netstat -lntp 2>/dev/null; then "#,
    r#"netstat -lnup 2>/dev/null || true; "#,
    r#"elif netstat -anv -p tcp >/dev/null 2>&1; then "#,
    // Prefer LISTEN-only TCP to keep stdout under maxBuffer on busy hosts.
    r#"netstat -anv -p tcp 2>/dev/null | grep -i LISTEN || true; "#,
    r#"netstat -anv -p udp 2>/dev/null || true; "#,
    r#"else "#,
    r#"netstat -anp 2>/dev/null | grep -Ei 'LISTEN|^udp' || netstat -an 2>/dev/null | grep -Ei 'LISTEN|^udp' || true; "#,
    r#"fi; "#,
    r#"fi; "#,
    r#"if command -v lsof >/dev/null 2>&1; then "#,
    r#"printf "%s\n" "__NC_LSOF__"; "#,
    r#"lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null || true; "#,
    // Idle-only: Linux has no UDP state names, so this no-ops there (ss/netstat cover UDP).
    // Do not fall back to bare `-iUDP` — that dumps client binds as fake listeners.
    r#"lsof -nP -iUDP -sUDP:Idle 2>/dev/null || true; "#,
    r#"fi; "#,
    r#"printf "%s\n" "__NC_PORTS_END__""#,
);

/// `exec sh -c <JSON.stringify(LISTEN_PORTS_INNER)>` (Electron `LISTEN_PORTS_SCRIPT`).
pub fn listen_ports_script() -> String {
    wrap_sh_json(LISTEN_PORTS_INNER)
}

/// Local Windows collector (Electron `LISTEN_PORTS_WINDOWS`).
pub const LISTEN_PORTS_WINDOWS: &str = concat!(
    r#"Write-Output "__NC_PORTS_BEGIN__"; "#,
    r#"Write-Output "__NC_WIN__"; "#,
    r#"$rows = @(); "#,
    r#"$rows += @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "#,
    r#"Select-Object LocalAddress,LocalPort,OwningProcess,@{Name='Protocol';Expression={'tcp'}}); "#,
    // UDP has no listen state; drop high ephemeral ports on non-wildcard /
    // non-loopback addresses so client binds do not flood the Ports tab.
    r#"$rows += @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { "#,
    r#"$a = [string]$_.LocalAddress; "#,
    r#"$wildcard = ($a -eq '0.0.0.0' -or $a -eq '::' -or $a -eq '*'); "#,
    r#"$loopback = ($a -eq '127.0.0.1' -or $a -eq '::1'); "#,
    r#"if ($wildcard -or $loopback) { $true } else { $_.LocalPort -lt 49152 } "#,
    r#"} | Select-Object LocalAddress,LocalPort,OwningProcess,@{Name='Protocol';Expression={'udp'}}); "#,
    r#"if ($rows.Count -gt 0) { $rows | ConvertTo-Json -Compress } else { Write-Output '[]' }; "#,
    r#"Write-Output "__NC_PORTS_END__""#,
);

const LISTEN_PORTS_TIMEOUT_MS: u64 = 12_000;
const LISTEN_PORTS_MAX_BUFFER: usize = 16 * 1024 * 1024;

/// One listening socket (`ListeningPortInfo` in the renderer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListeningPort {
    pub id: String,
    pub protocol: String,
    pub address: String,
    pub port: u32,
    pub pid: Option<i64>,
    pub process_name: String,
}

/// A parsed row before normalization (Electron `pushPort` input).
struct Row<'a> {
    protocol: &'a str,
    address: &'a str,
    port: u32,
    pid: Option<i64>,
    process_name: &'a str,
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid regex"))
}

/// Electron `normalizeProtocol`.
fn normalize_protocol(raw: &str) -> &'static str {
    match raw.trim().to_lowercase().as_str() {
        "tcp" | "tcp4" => "tcp",
        // macOS dual-stack (tcp46/udp46) is an IPv6 socket with v6only off;
        // map to tcp6/udp6 so netstat rows merge with lsof IPv6 listeners.
        "tcp6" | "tcp46" => "tcp6",
        "udp" | "udp4" => "udp",
        "udp6" | "udp46" => "udp6",
        _ => "unknown",
    }
}

fn normalize_address(address: &str) -> String {
    let address = address.split('%').next().unwrap_or("");
    if address == "*" || address == "0.0.0.0" || address == "::" {
        "*".to_string()
    } else {
        address.to_string()
    }
}

/// Electron `parseListenAddress`: `host:port`, `[v6]:port`, or BSD dotted
/// `host.port`.
fn parse_listen_address(addr: &str) -> Option<(String, u32)> {
    static DOTTED: OnceLock<Regex> = OnceLock::new();
    let text = addr.trim();
    if text.is_empty() {
        return None;
    }
    // macOS / BSD netstat: "*.22", "127.0.0.1.53", "::1.631", "fe80::1%lo0.22"
    if let Some(m) = regex(&DOTTED, r"^(.*)\.(\d+)$").captures(text) {
        if let Ok(port) = m[2].parse::<u32>() {
            if port <= 65535 {
                let host = if m[1].is_empty() { "*" } else { &m[1] };
                return Some((normalize_address(host), port));
            }
        }
    }
    let last_colon = text.rfind(':')?;
    if last_colon == 0 {
        return None;
    }
    let port_text = &text[last_colon + 1..];
    if port_text.is_empty() || !port_text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port = port_text.parse::<u32>().ok().filter(|p| *p <= 65535)?;
    let mut address = &text[..last_colon];
    if address.starts_with('[') && address.ends_with(']') && address.len() >= 2 {
        address = &address[1..address.len() - 1];
    }
    Some((normalize_address(address), port))
}

/// Electron `parseSsProcesses`: `users:(("app",pid=11,fd=3),...)`.
fn parse_ss_processes(info: &str) -> Vec<(String, Option<i64>)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let entries: Vec<_> = regex(&RE, r#"\("([^"]+)",pid=(\d+)"#)
        .captures_iter(info)
        .map(|m| (m[1].to_string(), m[2].parse::<i64>().ok()))
        .collect();
    if entries.is_empty() {
        vec![(String::new(), None)]
    } else {
        entries
    }
}

fn pid_label(pid: Option<i64>) -> String {
    pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
}

/// Merged port list with Electron's `pushPort` de-duplication rules.
#[derive(Default)]
struct PortSet {
    entries: Vec<ListeningPort>,
}

impl PortSet {
    fn key_matches(
        entry: &ListeningPort,
        protocol: &str,
        address: &str,
        port: u32,
        pid: Option<i64>,
    ) -> bool {
        entry.protocol == protocol
            && entry.address == address
            && entry.port == port
            && entry.pid == pid
    }

    fn push(&mut self, row: Row<'_>) {
        let protocol = normalize_protocol(row.protocol);
        let address = if row.address.is_empty() {
            "*"
        } else {
            row.address
        };
        let port = row.port;
        let pid = row.pid.filter(|p| *p > 0);

        if pid.is_some() {
            // Drop the anonymous placeholder once a PID-bearing collector
            // reports the socket.
            if let Some(idx) = self
                .entries
                .iter()
                .position(|e| Self::key_matches(e, protocol, address, port, None))
            {
                self.entries.remove(idx);
            }
        } else if self.entries.iter().any(|e| {
            e.protocol == protocol && e.address == address && e.port == port && e.pid.is_some()
        }) {
            return;
        }

        // Pid is part of the key so SO_REUSEPORT / multi-process listeners
        // stay distinct.
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| Self::key_matches(e, protocol, address, port, pid))
        {
            if existing.process_name.is_empty() && !row.process_name.is_empty() {
                existing.process_name = row.process_name.to_string();
            }
            return;
        }
        self.entries.push(ListeningPort {
            id: format!("{protocol}|{address}|{port}|{}", pid_label(pid)),
            protocol: protocol.to_string(),
            address: address.to_string(),
            port,
            pid,
            process_name: row.process_name.to_string(),
        });
    }

    fn merge(&mut self, rows: Vec<ListeningPort>) {
        for row in &rows {
            self.push(Row {
                protocol: &row.protocol,
                address: &row.address,
                port: row.port,
                pid: row.pid,
                process_name: &row.process_name,
            });
        }
    }
}

/// Electron `isWildcardPeer`.
fn is_wildcard_peer(peer: &str) -> bool {
    matches!(
        peer.trim(),
        "*.*" | "*:*" | "0.0.0.0:*" | ":::*" | "[::]:*" | "*."
    )
}

fn starts_with_ci(text: &str, prefix: &str) -> bool {
    text.len() >= prefix.len()
        && text.is_char_boundary(prefix.len())
        && text[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Electron `parseSsOutput` (`ss -tulnp`).
pub fn parse_ss_output(stdout: &str) -> Vec<ListeningPort> {
    static HEADER: OnceLock<Regex> = OnceLock::new();
    let header = regex(&HEADER, r"(?i)^(?:Netid|State)\b");
    let mut set = PortSet::default();
    for line in stdout.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || header.is_match(trimmed) {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        // Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        if parts.len() < 5 {
            continue;
        }
        if !(starts_with_ci(parts[0], "tcp") || starts_with_ci(parts[0], "udp")) {
            continue;
        }
        let protocol = parts[0];
        let (state, local, peer, process_field) =
            if parts.len() >= 6 && (parts[4].contains(':') || parts[4].contains('.')) {
                (parts[1], parts[4], parts[5], parts[6..].join(" "))
            } else {
                ("", parts[3], parts[4], parts[5..].join(" "))
            };
        let is_udp = starts_with_ci(protocol, "udp");
        if !is_udp && !state.is_empty() && !state.eq_ignore_ascii_case("LISTEN") {
            continue;
        }
        if is_udp
            && !state.is_empty()
            && !["UNCONN", "IDLE", "LISTEN"]
                .iter()
                .any(|s| state.eq_ignore_ascii_case(s))
        {
            continue;
        }
        if is_udp && !peer.is_empty() && !is_wildcard_peer(peer) {
            continue;
        }
        let Some((address, port)) = parse_listen_address(local) else {
            continue;
        };
        for (name, pid) in parse_ss_processes(&process_field) {
            set.push(Row {
                protocol,
                address: &address,
                port,
                pid,
                process_name: &name,
            });
        }
    }
    set.entries
}

/// Electron `parseNetstatOutput` (Linux, BusyBox and macOS netstat).
pub fn parse_netstat_output(stdout: &str) -> Vec<ListeningPort> {
    static HEADER: OnceLock<Regex> = OnceLock::new();
    static ROW: OnceLock<Regex> = OnceLock::new();
    static PID: OnceLock<Regex> = OnceLock::new();
    let header = regex(&HEADER, r"(?i)^(?:Proto|Active)\b");
    let row_re = regex(
        &ROW,
        r"(?i)^(tcp46|udp46|tcp[46]?|udp[46]?)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+(.*))?$",
    );
    let pid_re = regex(&PID, r"^(\d+)/(.+)$");
    let mut set = PortSet::default();
    for line in stdout.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || header.is_match(trimmed) {
            continue;
        }
        // Linux: tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd
        // BusyBox UDP often omits state: udp 0 0 127.0.0.1:53 0.0.0.0:* 456/dnsmasq
        // macOS: tcp4 0 0 *.22 *.* LISTEN
        let Some(m) = row_re.captures(trimmed) else {
            continue;
        };
        let protocol = m.get(1).map_or("", |g| g.as_str());
        let local = m.get(2).map_or("", |g| g.as_str());
        let peer = m.get(3).map_or("", |g| g.as_str());
        let rest = m.get(4).map_or("", |g| g.as_str()).trim();
        let is_udp = starts_with_ci(protocol, "udp");
        let mut state = "";
        let mut pid_field = String::new();
        if !rest.is_empty() {
            let rest_parts: Vec<&str> = rest.split_whitespace().collect();
            let first = rest_parts.first().copied().unwrap_or("");
            if first.eq_ignore_ascii_case("LISTEN") {
                state = "LISTEN";
                pid_field = rest_parts[1..].join(" ");
            } else if is_udp && first_is_pid_token(first) {
                // No State column — remainder is pid/program (may contain spaces).
                pid_field = rest.to_string();
            } else if !is_udp {
                // TCP without LISTEN (ESTABLISHED, or a bare pid token) is not a listener.
                continue;
            }
        }
        if !is_udp {
            if state != "LISTEN" {
                continue;
            }
        } else if !is_wildcard_peer(peer) {
            continue;
        }
        let Some((address, port)) = parse_listen_address(local) else {
            continue;
        };
        let (pid, name) = match pid_re.captures(&pid_field) {
            Some(pm) => (pm[1].parse::<i64>().ok(), pm[2].to_string()),
            None => (None, String::new()),
        };
        set.push(Row {
            protocol,
            address: &address,
            port,
            pid,
            process_name: &name,
        });
    }
    set.entries
}

/// `/^\d+\//`.
fn first_is_pid_token(token: &str) -> bool {
    let digits = token.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0 && token.as_bytes().get(digits) == Some(&b'/')
}

/// Electron `parseLsofOutput` (`lsof -nP -iTCP -sTCP:LISTEN`, UDP Idle).
pub fn parse_lsof_output(stdout: &str) -> Vec<ListeningPort> {
    static HEADER: OnceLock<Regex> = OnceLock::new();
    static UDP_WORD: OnceLock<Regex> = OnceLock::new();
    static TCP_WORD: OnceLock<Regex> = OnceLock::new();
    static LISTEN: OnceLock<Regex> = OnceLock::new();
    static PREFIX: OnceLock<Regex> = OnceLock::new();
    static SUFFIX: OnceLock<Regex> = OnceLock::new();
    let header = regex(&HEADER, r"(?i)^COMMAND\b");
    let udp_word = regex(&UDP_WORD, r"\bUDP\b");
    let tcp_word = regex(&TCP_WORD, r"\bTCP\b");
    let listen = regex(&LISTEN, r"(?i)\(LISTEN\)");
    let prefix = regex(&PREFIX, r"(?i)^(?:TCP|UDP)\s+");
    let suffix = regex(&SUFFIX, r"(?i)\s+\((LISTEN|UDP)\)\s*$");
    let mut set = PortSet::default();
    for line in stdout.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || header.is_match(trimmed) {
            continue;
        }
        // COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 9 {
            continue;
        }
        let process_name = parts[0];
        let pid = parts[1].parse::<i64>().ok();
        let type_field = parts[4].to_uppercase();
        let node_field = parts[7].to_uppercase();
        let name_field = parts[8..].join(" ");
        if name_field.contains("->") {
            continue;
        }
        let is_udp_node = node_field == "UDP" || udp_word.is_match(&name_field);
        let is_tcp_node =
            node_field == "TCP" || tcp_word.is_match(&name_field) || listen.is_match(&name_field);
        if !is_udp_node && !is_tcp_node {
            continue;
        }
        if is_tcp_node && !listen.is_match(&name_field) {
            continue;
        }
        // NAME forms: "TCP *:80 (LISTEN)", "TCP [::1]:80 (LISTEN)", "*:22 (LISTEN)"
        let without_prefix = prefix.replace(&name_field, "");
        let cleaned = suffix.replace(&without_prefix, "");
        let Some((address, port)) = parse_listen_address(cleaned.trim()) else {
            continue;
        };
        let mut protocol = if is_udp_node { "udp" } else { "tcp" };
        if type_field.contains("IPV6") || address.contains(':') {
            protocol = if is_udp_node { "udp6" } else { "tcp6" };
        }
        set.push(Row {
            protocol,
            address: &address,
            port,
            pid,
            process_name,
        });
    }
    set.entries
}

/// JS `Number(value)` for the JSON fields PowerShell emits.
fn js_number(value: Option<&Value>) -> f64 {
    match value {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().unwrap_or(f64::NAN)
            }
        }
        Some(_) => f64::NAN,
    }
}

/// JS truthiness of a JSON value.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

fn js_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Electron `parseWindowsPortsJson` (`ConvertTo-Json -Compress` rows).
fn parse_windows_ports_json(stdout: &str) -> Vec<ListeningPort> {
    let mut set = PortSet::default();
    let text = stdout.trim();
    if text.is_empty() {
        return set.entries;
    }
    let Ok(raw) = serde_json::from_str::<Value>(text) else {
        return set.entries;
    };
    let list = match raw {
        Value::Array(items) => items,
        other => vec![other],
    };
    for row in &list {
        if !truthy(Some(row)) {
            continue;
        }
        let port = js_number(row.get("LocalPort"));
        if !port.is_finite() || !(0.0..=u32::MAX as f64).contains(&port) {
            continue;
        }
        let pid = js_number(row.get("OwningProcess"));
        let mut address = if truthy(row.get("LocalAddress")) {
            js_to_string(&row["LocalAddress"])
        } else {
            "*".to_string()
        };
        let is_v6 = address.contains(':');
        if address == "0.0.0.0" || address == "::" || address == "*" {
            address = "*".into();
        }
        let proto_raw = if truthy(row.get("Protocol")) {
            js_to_string(&row["Protocol"]).to_lowercase()
        } else {
            "tcp".into()
        };
        let is_udp = proto_raw.starts_with("udp");
        let protocol = match (is_udp, is_v6) {
            (true, true) => "udp6",
            (true, false) => "udp",
            (false, true) => "tcp6",
            (false, false) => "tcp",
        };
        set.push(Row {
            protocol,
            address: &address,
            port: port as u32,
            pid: (pid.is_finite() && pid > 0.0).then_some(pid as i64),
            process_name: "",
        });
    }
    set.entries
}

/// Electron `extractSection`: text after `begin_marker` up to the next
/// `\n__NC_(SS|NETSTAT|LSOF|WIN|PORTS_END)__`.
fn extract_section<'a>(stdout: &'a str, begin_marker: &str) -> &'a str {
    static END: OnceLock<Regex> = OnceLock::new();
    let Some(begin) = stdout.find(begin_marker) else {
        return "";
    };
    let after = &stdout[begin + begin_marker.len()..];
    match regex(&END, r"\n__NC_(SS|NETSTAT|LSOF|WIN|PORTS_END)__").find(after) {
        Some(m) => &after[..m.start()],
        None => after,
    }
}

fn sort_ports(mut entries: Vec<ListeningPort>) -> Vec<ListeningPort> {
    entries.sort_by(|a, b| {
        a.port
            .cmp(&b.port)
            .then_with(|| a.protocol.cmp(&b.protocol))
    });
    entries
}

/// Electron `parseListeningPorts`: merge every marked collector section, or
/// fall back to parsing unmarked output with each parser in turn.
pub fn parse_listening_ports(stdout: &str) -> Vec<ListeningPort> {
    let mut set = PortSet::default();
    if stdout.contains("__NC_SS__") {
        set.merge(parse_ss_output(extract_section(stdout, "__NC_SS__")));
    }
    if stdout.contains("__NC_NETSTAT__") {
        set.merge(parse_netstat_output(extract_section(
            stdout,
            "__NC_NETSTAT__",
        )));
    }
    if stdout.contains("__NC_LSOF__") {
        set.merge(parse_lsof_output(extract_section(stdout, "__NC_LSOF__")));
    }
    if stdout.contains("__NC_WIN__") {
        set.merge(parse_windows_ports_json(extract_section(
            stdout,
            "__NC_WIN__",
        )));
    }
    if !set.entries.is_empty() {
        return sort_ports(set.entries);
    }
    // Bare output without markers (fallback probes).
    set.merge(parse_ss_output(stdout));
    if !set.entries.is_empty() {
        return sort_ports(set.entries);
    }
    set.merge(parse_netstat_output(stdout));
    if !set.entries.is_empty() {
        return sort_ports(set.entries);
    }
    set.merge(parse_lsof_output(stdout));
    sort_ports(set.entries)
}

/// `listListeningPorts({ sessionId })`.
pub async fn list_listening_ports(exec: &dyn SessionExec, payload: &Value) -> Value {
    let has_session = payload
        .get("sessionId")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if !has_session {
        return json!({ "success": false, "error": "Missing sessionId" });
    }
    let failed = |error: Option<String>| {
        json!({
            "success": false,
            "error": error.filter(|e| !e.is_empty()).unwrap_or_else(|| "Failed to list ports".into()),
        })
    };

    if exec.is_local() && exec.local_platform() == LocalPlatform::Win32 {
        let result = exec
            .exec_local(
                ExecRequest::new(LISTEN_PORTS_WINDOWS, LISTEN_PORTS_TIMEOUT_MS)
                    .with_max_buffer(LISTEN_PORTS_MAX_BUFFER),
            )
            .await;
        if !result.success {
            return failed(result.error);
        }
        return json!({ "success": true, "ports": parse_listening_ports(&result.stdout) });
    }

    let result = exec
        .exec(
            ExecRequest::new(listen_ports_script(), LISTEN_PORTS_TIMEOUT_MS)
                .with_max_buffer(LISTEN_PORTS_MAX_BUFFER),
        )
        .await;
    if result.pending {
        return json!({ "success": false, "pending": true });
    }
    if !result.success {
        return failed(result.error);
    }
    json!({ "success": true, "ports": parse_listening_ports(&result.stdout) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{ExecResult, FakeExec};

    fn find(ports: &[ListeningPort], port: u32) -> &ListeningPort {
        ports.iter().find(|p| p.port == port).expect("port present")
    }

    #[test]
    fn ss_reads_tcp_udp_listeners_and_process_fields() {
        let sample = r#"
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=1234,fd=3))
tcp   LISTEN 0      511                *:80               *:*    users:(("nginx",pid=99,fd=6))
udp   UNCONN 0      0            127.0.0.1:53         0.0.0.0:*    users:(("systemd-resolve",pid=500,fd=12))
tcp6  LISTEN 0      128             [::]:443            [::]:*    users:(("nginx",pid=99,fd=7))
"#;
        let ports = parse_ss_output(sample);
        assert_eq!(ports.len(), 4);
        assert_eq!(
            find(&ports, 22),
            &ListeningPort {
                id: "tcp|*|22|1234".into(),
                protocol: "tcp".into(),
                address: "*".into(),
                port: 22,
                pid: Some(1234),
                process_name: "sshd".into(),
            }
        );
        assert_eq!(find(&ports, 80).process_name, "nginx");
        assert_eq!(find(&ports, 53).protocol, "udp");
        assert_eq!(find(&ports, 443).protocol, "tcp6");
    }

    #[test]
    fn netstat_maps_pid_program_and_busybox_udp() {
        let sample = "
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
tcp6       0      0 :::80                   :::*                    LISTEN      99/nginx
udp        0      0 127.0.0.1:53            0.0.0.0:*
udp        0      0 0.0.0.0:5353            0.0.0.0:*               456/dnsmasq
";
        let ports = parse_netstat_output(sample);
        assert_eq!(ports.len(), 4);
        assert_eq!(find(&ports, 22).process_name, "sshd");
        assert_eq!(find(&ports, 80).address, "*");
        assert_eq!(find(&ports, 53).protocol, "udp");
        assert_eq!(find(&ports, 53).pid, None);
        assert_eq!(find(&ports, 5353).pid, Some(456));
        assert_eq!(find(&ports, 5353).process_name, "dnsmasq");
    }

    #[test]
    fn netstat_keeps_spaced_udp_program_names() {
        let sample = "
udp        0      0 0.0.0.0:5353            0.0.0.0:*               882/avahi-daemon: r
udp        0      0 0.0.0.0:53              0.0.0.0:*               100/named -u bind
";
        let ports = parse_netstat_output(sample);
        assert_eq!(find(&ports, 5353).pid, Some(882));
        assert_eq!(find(&ports, 5353).process_name, "avahi-daemon: r");
        assert_eq!(find(&ports, 53).pid, Some(100));
        assert_eq!(find(&ports, 53).process_name, "named -u bind");
    }

    #[test]
    fn netstat_understands_macos_dotted_addresses() {
        let sample = "
Active Internet connections
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.631          *.*                    LISTEN
";
        let ports = parse_netstat_output(sample);
        assert_eq!(ports.len(), 2);
        assert_eq!(find(&ports, 22).address, "*");
        assert_eq!(find(&ports, 631).address, "127.0.0.1");
    }

    #[test]
    fn merges_collectors_and_prefers_process_aware_rows() {
        let stdout = "
__NC_PORTS_BEGIN__
__NC_NETSTAT__
tcp4       0      0  *.22                   *.*                    LISTEN
__NC_LSOF__
sshd    1234 root  3u  IPv4 0x1      0t0  TCP *:22 (LISTEN)
__NC_PORTS_END__
";
        let ports = parse_listening_ports(stdout);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 22);
        assert_eq!(ports[0].pid, Some(1234));
        assert_eq!(ports[0].process_name, "sshd");
    }

    #[test]
    fn lsof_reads_tcp_listen_rows() {
        let sample = "
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
nginx      99 root    6u  IPv4 0xabc      0t0  TCP *:80 (LISTEN)
";
        let ports = parse_lsof_output(sample);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 80);
        assert_eq!(ports[0].process_name, "nginx");
    }

    #[test]
    fn netstat_rejects_established_tcp_and_connected_udp() {
        let sample = "
tcp        0      0 10.0.0.1:22            10.0.0.2:40000         ESTABLISHED 1234/sshd
tcp        0      0 10.0.0.1:22            10.0.0.2:40000         1234/sshd
udp        0      0 10.0.0.5:68            10.0.0.1:67
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      9/sshd
";
        let ports = parse_netstat_output(sample);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 22);
        assert_eq!(ports[0].process_name, "sshd");
    }

    #[test]
    fn lsof_ignores_connected_udp_and_non_listen_tcp() {
        let sample = "
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
chrome   1000 user   10u  IPv4 0x1      0t0  UDP 10.0.0.1:53122->8.8.8.8:53
nginx      99 root    6u  IPv4 0xabc      0t0  TCP 10.0.0.1:80->10.0.0.2:12345 (ESTABLISHED)
sshd     1234 root    3u  IPv4 0x2      0t0  TCP *:22 (LISTEN)
";
        let ports = parse_lsof_output(sample);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 22);
    }

    #[test]
    fn lsof_keeps_bracketed_ipv6_listeners_as_tcp6() {
        let sample = "
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
nginx      99 root    7u  IPv6 0xabc      0t0  TCP [::1]:80 (LISTEN)
";
        let ports = parse_lsof_output(sample);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].protocol, "tcp6");
        assert_eq!(ports[0].address, "::1");
        assert_eq!(ports[0].port, 80);
    }

    #[test]
    fn netstat_keeps_macos_ipv6_dotted_ports() {
        let sample = "
tcp6       0      0  ::1.631                *.*                    LISTEN
tcp6       0      0  fe80::1%lo0.22         *.*                    LISTEN
";
        let ports = parse_netstat_output(sample);
        assert_eq!(ports.len(), 2);
        assert_eq!(find(&ports, 631).address, "::1");
        assert_eq!(find(&ports, 22).address, "fe80::1");
    }

    #[test]
    fn ss_rejects_udp_with_non_wildcard_peers() {
        let sample = r#"
udp   UNCONN 0      0            10.0.0.5:68         10.0.0.1:67    users:(("dhclient",pid=7,fd=1))
udp   UNCONN 0      0            0.0.0.0:5353            0.0.0.0:*    users:(("avahi",pid=8,fd=1))
"#;
        let ports = parse_ss_output(sample);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 5353);
    }

    #[test]
    fn merges_ss_tcp6_with_lsof_ipv6_without_duplicating() {
        let stdout = r#"
__NC_PORTS_BEGIN__
__NC_SS__
tcp6  LISTEN 0      128             [::]:80             [::]:*    users:(("nginx",pid=99,fd=7))
__NC_LSOF__
nginx      99 root    7u  IPv6 0xabc      0t0  TCP *:80 (LISTEN)
__NC_PORTS_END__
"#;
        let ports = parse_listening_ports(stdout);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].protocol, "tcp6");
        assert_eq!(ports[0].pid, Some(99));
    }

    #[test]
    fn keeps_so_reuseport_listeners_as_separate_pid_rows() {
        let sample = r#"
tcp   LISTEN 0      128          0.0.0.0:8080         0.0.0.0:*    users:(("app",pid=11,fd=3))
tcp   LISTEN 0      128          0.0.0.0:8080         0.0.0.0:*    users:(("app",pid=12,fd=3))
"#;
        let ports = parse_ss_output(sample);
        let mut pids: Vec<_> = ports.iter().map(|p| p.pid.unwrap()).collect();
        pids.sort();
        assert_eq!(pids, vec![11, 12]);
    }

    #[test]
    fn reads_windows_udp_endpoints_from_protocol_field() {
        let stdout = r#"
__NC_PORTS_BEGIN__
__NC_WIN__
[{"LocalAddress":"0.0.0.0","LocalPort":53,"OwningProcess":500,"Protocol":"udp"},{"LocalAddress":"::","LocalPort":22,"OwningProcess":1234,"Protocol":"tcp"}]
__NC_PORTS_END__
"#;
        let ports = parse_listening_ports(stdout);
        assert_eq!(ports.len(), 2);
        assert_eq!(find(&ports, 53).protocol, "udp");
        assert_eq!(find(&ports, 22).protocol, "tcp6");
        assert_eq!(find(&ports, 22).address, "*");
        // A single object (one row) is accepted too.
        let single = parse_listening_ports(
            "__NC_WIN__\n{\"LocalAddress\":\"127.0.0.1\",\"LocalPort\":8080,\"OwningProcess\":0}\n__NC_PORTS_END__",
        );
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].protocol, "tcp");
        assert_eq!(single[0].pid, None);
        assert_eq!(single[0].id, "tcp|127.0.0.1|8080|-");
    }

    #[test]
    fn lsof_keeps_idle_udp_listeners() {
        let sample = "
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
mdnsd     200 root   12u  IPv4 0x1      0t0  UDP *:5353
";
        let ports = parse_lsof_output(sample);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].protocol, "udp");
        assert_eq!(ports[0].port, 5353);
    }

    #[test]
    fn netstat_accepts_macos_dual_stack_rows() {
        let sample = "
tcp46      0      0  *.80                   *.*                    LISTEN
udp46      0      0  *.5353                 *.*
";
        let ports = parse_netstat_output(sample);
        assert_eq!(ports.len(), 2);
        assert_eq!(find(&ports, 80).protocol, "tcp6");
        assert_eq!(find(&ports, 5353).protocol, "udp6");
    }

    #[test]
    fn merges_macos_tcp46_netstat_with_lsof_ipv6() {
        let stdout = "
__NC_PORTS_BEGIN__
__NC_NETSTAT__
tcp46      0      0  *.80                   *.*                    LISTEN
__NC_LSOF__
nginx      99 root    7u  IPv6 0xabc      0t0  TCP *:80 (LISTEN)
__NC_PORTS_END__
";
        let ports = parse_listening_ports(stdout);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].protocol, "tcp6");
        assert_eq!(ports[0].pid, Some(99));
    }

    #[test]
    fn ss_expands_multi_pid_users_tuples() {
        let sample = r#"
tcp   LISTEN 0      128          0.0.0.0:8080         0.0.0.0:*    users:(("app",pid=11,fd=3),("app",pid=12,fd=4))
"#;
        let ports = parse_ss_output(sample);
        let mut pids: Vec<_> = ports.iter().map(|p| p.pid.unwrap()).collect();
        pids.sort();
        assert_eq!(pids, vec![11, 12]);
    }

    #[test]
    fn unmarked_output_falls_back_and_sorts() {
        let stdout = "
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      1/a
udp        0      0 0.0.0.0:22              0.0.0.0:*               2/b
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      3/c
";
        let ports = parse_listening_ports(stdout);
        let order: Vec<_> = ports
            .iter()
            .map(|p| (p.port, p.protocol.as_str()))
            .collect();
        assert_eq!(order, vec![(22, "tcp"), (22, "udp"), (443, "tcp")]);
    }

    #[test]
    fn script_matches_electron_shape() {
        let script = listen_ports_script();
        assert!(
            script.starts_with("exec sh -c \"printf \\\"%s\\\\n\\\" \\\"__NC_PORTS_BEGIN__\\\"; ")
        );
        assert!(script.contains("grep -Ei 'LISTEN|^udp'"));
        assert!(script.ends_with("__NC_PORTS_END__\\\"\""));
    }

    #[tokio::test]
    async fn list_listening_ports_uses_remote_script() {
        let fake = FakeExec::sequence(vec![
            ExecResult::ok(
                "__NC_SS__\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n__NC_PORTS_END__\n",
                "",
                0,
            ),
            ExecResult::fail(""),
            ExecResult::pending("Mosh handshake in progress"),
        ]);
        let payload = json!({ "sessionId": "s" });
        let ok = list_listening_ports(&fake, &payload).await;
        assert_eq!(ok["success"], true);
        assert_eq!(
            ok["ports"][0],
            json!({ "id": "tcp|*|22|1", "protocol": "tcp", "address": "*", "port": 22, "pid": 1, "processName": "sshd" })
        );
        assert_eq!(
            list_listening_ports(&fake, &payload).await,
            json!({ "success": false, "error": "Failed to list ports" })
        );
        assert_eq!(
            list_listening_ports(&fake, &payload).await,
            json!({ "success": false, "pending": true })
        );
        let (req, local) = &fake.requests()[0];
        assert!(!local);
        assert_eq!(req.command, listen_ports_script());
        assert_eq!(req.timeout_ms, 12_000);
        assert_eq!(req.max_buffer, Some(16 * 1024 * 1024));
        assert_eq!(
            list_listening_ports(&fake, &json!({})).await,
            json!({ "success": false, "error": "Missing sessionId" })
        );
    }

    #[tokio::test]
    async fn list_listening_ports_uses_powershell_on_local_windows() {
        let fake = FakeExec::sequence(vec![ExecResult::ok(
            "__NC_WIN__\n[]\n__NC_PORTS_END__\n",
            "",
            0,
        )])
        .local(LocalPlatform::Win32);
        let reply = list_listening_ports(&fake, &json!({ "sessionId": "local-1" })).await;
        assert_eq!(reply, json!({ "success": true, "ports": [] }));
        let (req, local) = &fake.requests()[0];
        assert!(local);
        assert_eq!(req.command, LISTEN_PORTS_WINDOWS);
    }
}
