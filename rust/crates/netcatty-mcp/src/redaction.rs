//! Reversible, session-local redaction for External MCP clients (Electron
//! `electron/mcp/externalMcpRedaction.cjs` + `externalMcpPrivacyBoundary.cjs`).
//!
//! Public IPs, hostnames in host-like fields, credentials (secret-named
//! fields, `Bearer`, URL userinfo, `key=value`, `--password` flags, PEM
//! keys, GitHub / OpenAI style tokens) and custom RE2 patterns are replaced
//! by `[NC_<nonce>_<IP|HOST|SECRET>_<n>]` tokens; requests are restored
//! before dispatch. No reverse map leaves the session. Custom patterns use
//! the `regex` crate, which has RE2 semantics (linear time, no lookaround /
//! backreferences), exactly like the `re2js` engine Electron uses.

use fancy_regex::Regex as FRegex;
use ipnet::IpNet;
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::LazyLock;

pub const CONFIG_ERROR: &str = "Invalid External MCP redaction configuration";
pub const VALUE_ERROR: &str = "External MCP redaction could not safely process this value";
pub const TOKEN_ERROR: &str = "Unknown External MCP redaction token; reconnect the client";
pub const LIMIT_ERROR: &str = "External MCP redaction session limit reached; reconnect the client";
pub const RECONNECT_MESSAGE: &str = "External MCP privacy settings changed. Reconnect the MCP client before continuing.";
const MAX_ENTRIES: usize = 10_000;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_NODES: usize = 100_000;
const MAX_DEPTH: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedactionConfig {
    pub enabled: bool,
    pub redact_private_ips: bool,
    pub cidrs: Vec<String>,
    pub patterns: Vec<String>,
}

impl RedactionConfig {
    pub fn to_value(&self) -> Value {
        json!({ "enabled": self.enabled, "redactPrivateIps": self.redact_private_ips, "cidrs": self.cidrs, "patterns": self.patterns })
    }
}

fn parse_cidr(value: &str) -> Option<IpNet> {
    let (addr, prefix) = value.split_once('/')?;
    if addr.is_empty() || addr.contains(['%', ' ']) || prefix.is_empty() || (prefix.len() > 1 && prefix.starts_with('0')) || !prefix.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let ip: IpAddr = addr.parse().ok()?;
    let p: u8 = prefix.parse().ok()?;
    IpNet::new(ip, p).ok()
}

/// Strict normalisation; malformed policy never silently disables protection.
pub fn normalize_redaction_config(input: Option<&Value>) -> Result<RedactionConfig, String> {
    let empty = json!({});
    let input = match input {
        None => &empty,
        Some(v) => v,
    };
    let obj = input.as_object().ok_or(CONFIG_ERROR)?;
    if obj.keys().any(|k| !matches!(k.as_str(), "enabled" | "redactPrivateIps" | "cidrs" | "patterns")) {
        return Err(CONFIG_ERROR.into());
    }
    let flag = |k: &str| match obj.get(k) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(CONFIG_ERROR.to_string()),
    };
    let list = |k: &str| -> Result<Vec<String>, String> {
        match obj.get(k) {
            None => Ok(Vec::new()),
            Some(Value::Array(a)) if a.len() <= 100 => a
                .iter()
                .map(|v| v.as_str().filter(|s| !s.is_empty() && s.encode_utf16().count() <= 1024).map(str::to_string).ok_or(CONFIG_ERROR.to_string()))
                .collect(),
            _ => Err(CONFIG_ERROR.into()),
        }
    };
    let config = RedactionConfig { enabled: flag("enabled")?, redact_private_ips: flag("redactPrivateIps")?, cidrs: list("cidrs")?, patterns: list("patterns")? };
    for c in &config.cidrs {
        parse_cidr(c).ok_or(CONFIG_ERROR)?;
    }
    for p in &config.patterns {
        let re = regex::Regex::new(p).map_err(|_| CONFIG_ERROR)?;
        if re.is_match("") {
            return Err(CONFIG_ERROR.into());
        }
    }
    Ok(config)
}

fn normalized_key(key: &str) -> String {
    key.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase()
}

static SECRET_KEY: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?:password|passwd|passphrase|pwd|token|secret|apikey|accesskey|secretkey|privatekey|credentials?)$").unwrap()
});
static HOST_KEY: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^(?:host|hostname|address|ip|ipaddress|server|serveraddress|endpoint|remotehost|targethost|bindaddress|localaddress|remoteaddress)$").unwrap()
});

pub fn secret_key(key: &str) -> bool {
    SECRET_KEY.is_match(&normalized_key(key))
}

pub fn host_key(key: &str) -> bool {
    HOST_KEY.is_match(&normalized_key(key))
}

fn is_hostname(v: &str) -> bool {
    let label = regex::Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$").unwrap();
    v.len() <= 253 && v.chars().any(|c| c.is_ascii_alphabetic()) && v.trim_end_matches('.').split('.').all(|l| label.is_match(l))
}

static PRIVATE_NETS: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
        "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    ]
    .iter()
    .map(|c| c.parse().unwrap())
    .collect()
});
static RESERVED_TOKEN: LazyLock<FRegex> = LazyLock::new(|| FRegex::new(r"\[NC_[^\]\r\n]*(?:\]|(?=[\r\n]|$))").unwrap());
static PEM: LazyLock<FRegex> = LazyLock::new(|| FRegex::new(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----").unwrap());
static BEARER: LazyLock<FRegex> = LazyLock::new(|| FRegex::new(r"(?i)\bBearer(\s+)([A-Za-z0-9._~+/=-]{8,})").unwrap());
static URL_USERINFO: LazyLock<FRegex> = LazyLock::new(|| FRegex::new(r"(?i)(?<![a-z0-9+.-])([a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@]+)(@)").unwrap());
static QUOTED_KV: LazyLock<FRegex> = LazyLock::new(|| FRegex::new(r#"(?<![A-Za-z0-9_.-])(["']?)([A-Za-z0-9_.-]+)\1(\s*[:=]\s*)(["'])"#).unwrap());
static PLAIN_KV: LazyLock<FRegex> = LazyLock::new(|| FRegex::new(r#"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+)(\s*[:=]\s*)([^\s"',;{}\[\]]+)"#).unwrap());
static FLAG_SECRET: LazyLock<FRegex> = LazyLock::new(|| {
    FRegex::new(r#"(?i)--(?:password|passwd|passphrase|pwd|token|secret|api-key|access-key|secret-key|private-key)(?:\s+|=)(?:"((?:\\[\s\S]|[^"\\])*)"|'((?:\\[\s\S]|[^'\\])*)'|([^\s]+))"#).unwrap()
});
static VENDOR_TOKEN: LazyLock<FRegex> = LazyLock::new(|| FRegex::new(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b").unwrap());
static IPV4: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
static IPV6ISH: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"[A-Fa-f0-9:.]+(?:%[A-Za-z0-9_.-]+)?").unwrap());
static HOST_KV: LazyLock<FRegex> = LazyLock::new(|| FRegex::new(r#"(?<![A-Za-z0-9_.-])(["']?)([A-Za-z0-9_.-]+)\1\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|([^\s,;{}]+))"#).unwrap());
static AUTHORITY: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?i)^(?:[a-z][a-z0-9+.-]*://)?([^/?#:\s]+)(?::\d+)?(?:[/?#].*)?$").unwrap());

fn parse_ip(s: &str) -> Option<IpAddr> {
    let base = s.split('%').next()?;
    base.parse::<IpAddr>().ok()
}

#[derive(Clone)]
struct Range {
    start: usize,
    end: usize,
    namespace: &'static str,
    token: Option<String>,
}

struct Inner {
    nonce: String,
    originals: HashMap<String, Value>,
    tokens: HashMap<String, String>,
    known_secrets: HashSet<String>,
    known_hosts: HashSet<String>,
    counters: HashMap<&'static str, u64>,
    stored_bytes: usize,
    exhausted: bool,
}

/// One redaction namespace (one stdio process or one HTTP MCP session).
pub struct RedactionSession {
    config: RedactionConfig,
    custom: Vec<IpNet>,
    patterns: Vec<regex::Regex>,
    inner: Mutex<Inner>,
}

struct WalkState {
    nodes: usize,
    bytes: usize,
    depth: usize,
    preserve_root_keys: bool,
}

fn identity(v: &Value) -> String {
    match v {
        Value::String(s) => format!("string\0{s}"),
        Value::Number(n) => format!("number\0{n}"),
        Value::Bool(b) => format!("boolean\0{b}"),
        other => format!("object\0{other}"),
    }
}

impl RedactionSession {
    pub fn new(config: RedactionConfig) -> Self {
        let custom = config.cidrs.iter().filter_map(|c| parse_cidr(c)).collect();
        let patterns = config.patterns.iter().filter_map(|p| regex::Regex::new(p).ok()).collect();
        let nonce: [u8; 6] = rand::random();
        Self {
            config,
            custom,
            patterns,
            inner: Mutex::new(Inner {
                nonce: hex::encode(nonce),
                originals: HashMap::new(),
                tokens: HashMap::new(),
                known_secrets: HashSet::new(),
                known_hosts: HashSet::new(),
                counters: HashMap::new(),
                stored_bytes: 0,
                exhausted: false,
            }),
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    fn issue(inner: &mut Inner, value: Value, namespace: &'static str) -> Result<String, String> {
        let id = identity(&value);
        if let Some(t) = inner.tokens.get(&id) {
            return Ok(t.clone());
        }
        if inner.originals.len() >= MAX_ENTRIES || inner.stored_bytes + id.len() > MAX_BYTES {
            inner.exhausted = true;
            return Err(LIMIT_ERROR.into());
        }
        let n = inner.counters.entry(namespace).or_insert(0);
        *n += 1;
        let token = format!("[NC_{}_{namespace}_{n}]", inner.nonce);
        inner.stored_bytes += id.len();
        inner.tokens.insert(id, token.clone());
        inner.originals.insert(token.clone(), value);
        Ok(token)
    }

    fn should_mask_ip(&self, addr: &IpAddr) -> bool {
        let v4 = match addr {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4),
            _ => None,
        };
        let check = v4.as_ref().unwrap_or(addr);
        let in_any = |nets: &[IpNet]| nets.iter().any(|n| n.contains(check) || n.contains(addr));
        self.config.redact_private_ips || in_any(&self.custom) || !in_any(&PRIVATE_NETS)
    }

    fn inspect_string(&self, inner: &mut Inner, source: &str, key: &str, inherited_secret: bool, budget: &mut usize, accept_tokens: bool) -> Result<Vec<Range>, String> {
        let mut value = source.to_string();
        let mut aliases: Vec<Range> = Vec::new();
        if accept_tokens {
            let mut masked = String::new();
            let mut last = 0;
            for m in RESERVED_TOKEN.find_iter(source).flatten() {
                if !inner.originals.contains_key(m.as_str()) {
                    return Err(TOKEN_ERROR.into());
                }
                *budget += 1;
                if *budget > MAX_NODES {
                    return Err(VALUE_ERROR.into());
                }
                aliases.push(Range { start: m.start(), end: m.end(), namespace: "SECRET", token: Some(m.as_str().to_string()) });
                masked.push_str(&source[last..m.start()]);
                masked.push_str(&"x".repeat(m.end() - m.start()));
                last = m.end();
            }
            masked.push_str(&source[last..]);
            value = masked;
        }
        let mut ranges = aliases.clone();
        let add = |inner: &mut Inner, ranges: &mut Vec<Range>, budget: &mut usize, start: usize, end: usize, ns: &'static str, remember: bool| -> Result<(), String> {
            let mut cursor = start;
            let mut pieces = Vec::new();
            for a in aliases.iter().filter(|a| a.end > start && a.start < end) {
                pieces.push((cursor, a.start.min(end)));
                cursor = cursor.max(a.end);
            }
            pieces.push((cursor, end));
            for (s, e) in pieces {
                if e <= s {
                    continue;
                }
                *budget += 1;
                if *budget > MAX_NODES {
                    return Err(VALUE_ERROR.into());
                }
                ranges.push(Range { start: s, end: e, namespace: ns, token: None });
                let text = source[s..e].to_string();
                if ns == "SECRET" && remember && !text.is_empty() {
                    Self::issue(inner, Value::String(text.clone()), "SECRET")?;
                    inner.known_secrets.insert(text);
                } else if ns == "HOST" {
                    Self::issue(inner, Value::String(text.clone()), "HOST")?;
                    inner.known_hosts.insert(text);
                }
            }
            Ok(())
        };
        for m in RESERVED_TOKEN.find_iter(&value).flatten() {
            add(inner, &mut ranges, budget, m.start(), m.end(), "SECRET", false)?;
        }
        if !value.is_empty() && (inherited_secret || secret_key(key)) {
            add(inner, &mut ranges, budget, 0, value.len(), "SECRET", true)?;
        }
        let groups: Vec<(&FRegex, Box<dyn Fn(&fancy_regex::Captures) -> Option<usize>>)> = vec![
            (&PEM, Box::new(|_| Some(0))),
            (&BEARER, Box::new(|_| Some(2))),
            (&URL_USERINFO, Box::new(|_| Some(2))),
            (&PLAIN_KV, Box::new(|c| (secret_key(&c[1]) && &c[3] != "null").then_some(3))),
            (&FLAG_SECRET, Box::new(|c| Some(if c.get(1).is_some() { 1 } else if c.get(2).is_some() { 2 } else { 3 }))),
            (&VENDOR_TOKEN, Box::new(|_| Some(0))),
        ];
        for (re, select) in groups.iter().take(3) {
            for c in re.captures_iter(&value).flatten() {
                if let Some(g) = select(&c).and_then(|g| c.get(g)) {
                    add(inner, &mut ranges, budget, g.start(), g.end(), "SECRET", true)?;
                }
            }
        }
        for c in QUOTED_KV.captures_iter(&value).flatten() {
            if !secret_key(&c[2]) {
                continue;
            }
            let quote = c[4].chars().next().unwrap();
            let start = c.get(0).unwrap().end();
            let bytes: Vec<(usize, char)> = value[start..].char_indices().collect();
            let mut end = value.len();
            let mut i = 0;
            while i < bytes.len() {
                let (off, ch) = bytes[i];
                if ch == '\\' {
                    i += 2;
                    continue;
                }
                if ch == quote {
                    end = start + off;
                    break;
                }
                i += 1;
            }
            add(inner, &mut ranges, budget, start, end, "SECRET", true)?;
        }
        for (re, select) in groups.iter().skip(3) {
            for c in re.captures_iter(&value).flatten() {
                if let Some(g) = select(&c).and_then(|g| c.get(g)) {
                    add(inner, &mut ranges, budget, g.start(), g.end(), "SECRET", true)?;
                }
            }
        }
        for p in &self.patterns {
            for m in p.find_iter(&value) {
                add(inner, &mut ranges, budget, m.start(), m.end(), "SECRET", true)?;
            }
        }
        let boundary = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
        for m in IPV4.find_iter(&value) {
            let before = value[..m.start()].chars().last();
            let after = value[m.end()..].chars().next();
            if !boundary(before) && !boundary(after) {
                if let Some(ip) = parse_ip(m.as_str()).filter(|ip| ip.is_ipv4()) {
                    if self.should_mask_ip(&ip) {
                        add(inner, &mut ranges, budget, m.start(), m.end(), "IP", true)?;
                    }
                }
            }
        }
        for m in IPV6ISH.find_iter(&value) {
            let mut addr = m.as_str();
            if !addr.contains(':') {
                continue;
            }
            while !addr.is_empty() && parse_ip(addr).is_none() && (addr.ends_with('.') || addr.ends_with(':')) {
                addr = &addr[..addr.len() - 1];
            }
            if let Some(ip) = parse_ip(addr).filter(|ip| ip.is_ipv6()) {
                if self.should_mask_ip(&ip) {
                    add(inner, &mut ranges, budget, m.start(), m.start() + addr.len(), "IP", true)?;
                }
            }
        }
        let inspect_host = |inner: &mut Inner, ranges: &mut Vec<Range>, budget: &mut usize, start: usize, end: usize| -> Result<(), String> {
            let raw = &value[start..end];
            let trimmed = raw.trim();
            if trimmed.is_empty() || parse_ip(trimmed).is_some() {
                return Ok(());
            }
            let offset = start + raw.find(trimmed).unwrap_or(0);
            if let Some(c) = AUTHORITY.captures(trimmed) {
                let a = c.get(1).unwrap();
                if parse_ip(a.as_str()).is_none() && is_hostname(a.as_str()) {
                    add(inner, ranges, budget, offset + a.start(), offset + a.end(), "HOST", true)?;
                }
            }
            Ok(())
        };
        if host_key(key) {
            inspect_host(inner, &mut ranges, budget, 0, value.len())?;
        }
        let host_matches: Vec<(usize, usize)> = HOST_KV
            .captures_iter(&value)
            .flatten()
            .filter(|c| host_key(&c[2]))
            .filter_map(|c| c.get(3).or(c.get(4)).or(c.get(5)).map(|g| (g.start(), g.end())))
            .collect();
        for (s, e) in host_matches {
            inspect_host(inner, &mut ranges, budget, s, e)?;
        }
        Ok(ranges)
    }

    fn walk(&self, value: &Value, key: &str, inherited_secret: bool, state: &mut WalkState, f: &mut dyn FnMut(WalkItem<'_>) -> Result<Value, String>) -> Result<Value, String> {
        state.nodes += 1;
        if state.nodes > MAX_NODES || state.depth > MAX_DEPTH {
            return Err(VALUE_ERROR.into());
        }
        match value {
            Value::String(s) => {
                if s.contains('\0') {
                    return Err(VALUE_ERROR.into());
                }
                state.bytes += s.len();
                if state.bytes > MAX_BYTES {
                    return Err(VALUE_ERROR.into());
                }
                f(WalkItem::Str(s, key, inherited_secret))
            }
            Value::Array(items) => {
                state.depth += 1;
                let out = items.iter().map(|v| self.walk(v, key, inherited_secret, state, f)).collect::<Result<Vec<_>, _>>()?;
                state.depth -= 1;
                Ok(Value::Array(out))
            }
            Value::Object(map) => {
                reject_binary(map)?;
                state.depth += 1;
                let mut out = Map::new();
                let child_secret = inherited_secret || secret_key(key);
                for (k, v) in map {
                    let nk = if state.preserve_root_keys && state.depth == 1 {
                        k.clone()
                    } else {
                        match self.walk(&Value::String(k.clone()), "", false, state, f)? {
                            Value::String(s) => s,
                            other => other.to_string(),
                        }
                    };
                    let nv = self.walk(v, k, child_secret, state, f)?;
                    if out.insert(nk, nv).is_some() {
                        return Err(VALUE_ERROR.into());
                    }
                }
                state.depth -= 1;
                Ok(Value::Object(out))
            }
            other => f(WalkItem::Prim(other, key, inherited_secret)),
        }
    }

    /// Mask a value (results / errors going to the client).
    pub fn redact(&self, value: &Value, preserve_root_keys: bool) -> Result<Value, String> {
        if !self.config.enabled {
            return Ok(value.clone());
        }
        self.safe(|| self.redact_inner(value, preserve_root_keys, false))
    }

    /// Restore tokens in a client request before dispatch.
    pub fn restore(&self, value: &Value) -> Result<Value, String> {
        if !self.config.enabled {
            return Ok(value.clone());
        }
        self.safe(|| {
            let mut state = WalkState { nodes: 0, bytes: 0, depth: 0, preserve_root_keys: false };
            let inner = self.inner.lock();
            if inner.exhausted {
                return Err(LIMIT_ERROR.into());
            }
            self.walk(value, "", false, &mut state, &mut |item| match item {
                WalkItem::Str(s, _, _) => {
                    if let Some(orig) = inner.originals.get(s) {
                        return Ok(orig.clone());
                    }
                    let mut out = String::new();
                    let mut last = 0;
                    for m in RESERVED_TOKEN.find_iter(s).flatten() {
                        let Some(orig) = inner.originals.get(m.as_str()) else {
                            return Err(TOKEN_ERROR.to_string());
                        };
                        out.push_str(&s[last..m.start()]);
                        out.push_str(&match orig {
                            Value::String(t) => t.clone(),
                            other => other.to_string(),
                        });
                        last = m.end();
                    }
                    out.push_str(&s[last..]);
                    Ok(Value::String(out))
                }
                WalkItem::Prim(v, _, _) => Ok(v.clone()),
            })
        })
    }

    fn safe(&self, f: impl FnOnce() -> Result<Value, String>) -> Result<Value, String> {
        f().map_err(|e| if [VALUE_ERROR, TOKEN_ERROR, LIMIT_ERROR].contains(&e.as_str()) { e } else { VALUE_ERROR.to_string() })
    }

    fn redact_inner(&self, value: &Value, preserve_root_keys: bool, accept_tokens: bool) -> Result<Value, String> {
        let mut inner = self.inner.lock();
        if inner.exhausted {
            return Err(LIMIT_ERROR.into());
        }
        let mut plans: Vec<(String, Vec<Range>)> = Vec::new();
        let mut budget = 0usize;
        let mut state = WalkState { nodes: 0, bytes: 0, depth: 0, preserve_root_keys };
        self.walk(value, "", false, &mut state, &mut |item| match item {
            WalkItem::Str(s, key, secret) => {
                let ranges = self.inspect_string(&mut inner, s, key, secret, &mut budget, accept_tokens)?;
                plans.push((s.to_string(), ranges));
                // Keep keys distinct in this planning pass (duplicate-key check).
                Ok(Value::String(s.to_string()))
            }
            WalkItem::Prim(..) => Ok(Value::Null),
        })?;
        let escape = |s: &String| regex::escape(s);
        let mut secrets: Vec<&String> = inner.known_secrets.iter().collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        let known = (!secrets.is_empty()).then(|| regex::Regex::new(&secrets.iter().map(|s| escape(s)).collect::<Vec<_>>().join("|")).ok()).flatten();
        let mut hosts: Vec<&String> = inner.known_hosts.iter().collect();
        hosts.sort_by_key(|s| std::cmp::Reverse(s.len()));
        let known_hosts = (!hosts.is_empty())
            .then(|| FRegex::new(&format!("(?<![A-Za-z0-9_.-])(?:{})(?![A-Za-z0-9_.-])", hosts.iter().map(|s| escape(s)).collect::<Vec<_>>().join("|"))).ok())
            .flatten();
        let mut cursor = 0usize;
        let mut state = WalkState { nodes: 0, bytes: 0, depth: 0, preserve_root_keys };
        let inner_ref = &mut *inner;
        self.walk(value, "", false, &mut state, &mut |item| match item {
            WalkItem::Str(_, _, _) => {
                let (text, mut ranges) = plans[cursor].clone();
                cursor += 1;
                let alias: Vec<(usize, usize)> = ranges.iter().filter(|r| r.token.is_some()).map(|r| (r.start, r.end)).collect();
                let overlaps_alias = |s: usize, e: usize| alias.iter().any(|(a, b)| *a < e && *b > s);
                if let Some(re) = &known {
                    for m in re.find_iter(&text) {
                        if !overlaps_alias(m.start(), m.end()) {
                            ranges.push(Range { start: m.start(), end: m.end(), namespace: "SECRET", token: None });
                        }
                    }
                }
                if let Some(re) = &known_hosts {
                    for m in re.find_iter(&text).flatten() {
                        if !overlaps_alias(m.start(), m.end()) {
                            ranges.push(Range { start: m.start(), end: m.end(), namespace: "HOST", token: None });
                        }
                    }
                }
                ranges.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
                let mut merged: Vec<Range> = Vec::new();
                for r in ranges {
                    if let Some(prev) = merged.last_mut() {
                        if r.start < prev.end {
                            prev.end = prev.end.max(r.end);
                            if r.namespace == "SECRET" {
                                prev.namespace = "SECRET";
                            }
                            continue;
                        }
                    }
                    merged.push(r);
                }
                let mut out = String::new();
                let mut pos = 0;
                for r in merged {
                    out.push_str(&text[pos..r.start]);
                    match r.token {
                        Some(t) => out.push_str(&t),
                        None => out.push_str(&Self::issue(inner_ref, Value::String(text[r.start..r.end].to_string()), r.namespace)?),
                    }
                    pos = r.end;
                }
                out.push_str(&text[pos..]);
                Ok(Value::String(out))
            }
            WalkItem::Prim(v, key, secret) => {
                if !v.is_null() && (secret || secret_key(key)) {
                    Ok(Value::String(Self::issue(inner_ref, v.clone(), "SECRET")?))
                } else {
                    Ok(v.clone())
                }
            }
        })
    }
}

enum WalkItem<'a> {
    Str(&'a str, &'a str, bool),
    Prim(&'a Value, &'a str, bool),
}

fn reject_binary(map: &Map<String, Value>) -> Result<(), String> {
    let t = map.get("type").and_then(Value::as_str).unwrap_or("").to_lowercase();
    if t == "image" || t == "audio" {
        return Err(VALUE_ERROR.into());
    }
    for (k, v) in map {
        if matches!(normalized_key(k).as_str(), "base64data" | "base64" | "blob") && !(v.is_null() || v == "") {
            return Err(VALUE_ERROR.into());
        }
    }
    let mime = map.get("mimeType").or(map.get("mime_type")).and_then(Value::as_str);
    if let Some(m) = mime {
        let textual = regex::Regex::new(r"(?i)^(?:text/|application/(?:json|xml|javascript)(?:;|$))").unwrap().is_match(m);
        if !textual && map.get("data").is_some_and(|d| !(d.is_null() || d == "")) {
            return Err(VALUE_ERROR.into());
        }
    }
    Ok(())
}

/// One boundary per stdio process / HTTP session (`createPrivacyBoundary`):
/// the configuration fingerprint is pinned at first use; any change asks
/// the client to reconnect.
pub struct PrivacyBoundary {
    get_config: Box<dyn Fn() -> Option<Value> + Send + Sync>,
    state: Mutex<Option<(String, Option<std::sync::Arc<RedactionSession>>)>>,
}

impl PrivacyBoundary {
    pub fn new(get_config: impl Fn() -> Option<Value> + Send + Sync + 'static) -> Self {
        Self { get_config: Box::new(get_config), state: Mutex::new(None) }
    }

    fn check(&self) -> Result<Option<std::sync::Arc<RedactionSession>>, String> {
        let config = normalize_redaction_config((self.get_config)().as_ref())
            .map_err(|_| "External MCP privacy configuration is unavailable or invalid. Check Settings and reconnect.".to_string())?;
        let fingerprint = config.to_value().to_string();
        let mut state = self.state.lock();
        match &*state {
            Some((fp, _)) if *fp != fingerprint => Err(RECONNECT_MESSAGE.into()),
            Some((_, s)) => Ok(s.clone()),
            None => {
                let session = config.enabled.then(|| std::sync::Arc::new(RedactionSession::new(config)));
                *state = Some((fingerprint, session.clone()));
                Ok(session)
            }
        }
    }

    pub fn restore(&self, params: Value) -> Result<(Value, Option<std::sync::Arc<RedactionSession>>), String> {
        let protection = self.check()?;
        let restored = match &protection {
            Some(p) => p.restore(&params)?,
            None => params,
        };
        Ok((restored, protection))
    }

    /// Mask a result (or error message) after dispatch.
    pub fn finish(&self, method: &str, outcome: Result<Value, String>, protection: Option<std::sync::Arc<RedactionSession>>) -> Result<Value, String> {
        self.check()?;
        let Some(p) = protection else {
            return outcome;
        };
        match outcome {
            Err(e) => Err(match p.redact(&Value::String(e), false)? {
                Value::String(s) => s,
                other => other.to_string(),
            }),
            Ok(mut v) => {
                if method == "netcatty/readAttachment" && v.get("text").is_some_and(Value::is_string) {
                    v.as_object_mut().map(|m| m.remove("base64Data"));
                }
                p.redact(&v, true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> RedactionSession {
        RedactionSession::new(normalize_redaction_config(Some(&json!({ "enabled": true }))).unwrap())
    }

    fn is_token(s: &str) -> bool {
        regex::Regex::new(r"^\[NC_[a-f0-9]{12}_(?:IP|HOST|SECRET)_\d+\]$").unwrap().is_match(s)
    }

    #[test]
    fn config_normalization_is_strict() {
        assert_eq!(normalize_redaction_config(None).unwrap(), RedactionConfig::default());
        for bad in [
            json!(null), json!([]), json!({ "enabled": "true" }), json!({ "surprise": 1 }), json!({ "cidrs": ["1.2.3.4/33"] }),
            json!({ "cidrs": ["::1%eth0/64"] }), json!({ "cidrs": ["10.0.0.0/08"] }), json!({ "patterns": ["(?=x)"] }),
            json!({ "patterns": ["a*"] }), json!({ "patterns": [""] }),
        ] {
            assert_eq!(normalize_redaction_config(Some(&bad)).unwrap_err(), CONFIG_ERROR, "{bad}");
        }
    }

    #[test]
    fn disabled_is_identity() {
        let s = RedactionSession::new(RedactionConfig::default());
        let v = json!({ "password": "x", "content": "8.8.8.8" });
        assert_eq!(s.redact(&v, false).unwrap(), v);
    }

    #[test]
    fn masks_public_ips_secrets_hosts_and_round_trips() {
        let s = session();
        let src = json!({
            "8.8.8.8": [{ "host": "build.example.test", "password": "synthetic-pass" }, null, 42, false],
            "note": "connect 10.0.0.1 and 203.0.113.14 with token=abc123def",
            "tokenCount": 123,
        });
        let r = s.redact(&src, false).unwrap();
        let text = r.to_string();
        assert!(!text.contains("synthetic-pass") && !text.contains("8.8.8.8") && !text.contains("203.0.113.14") && !text.contains("abc123def"));
        assert!(text.contains("10.0.0.1"), "private IPs kept by default");
        assert!(!text.contains("build.example.test"));
        assert_eq!(r["tokenCount"], 123);
        assert_eq!(s.restore(&r).unwrap(), src);
        let a = s.redact(&json!("8.8.8.8"), false).unwrap();
        assert!(is_token(a.as_str().unwrap()));
        assert_eq!(s.redact(&json!("8.8.8.8"), false).unwrap(), a);
        assert!(session().restore(&a).is_err(), "cross-session tokens fail closed");
        let mapped = s.redact(&json!("::ffff:8.8.8.8"), false).unwrap();
        assert!(is_token(mapped.as_str().unwrap()));
        assert_eq!(s.redact(&json!("::ffff:10.0.0.1"), false).unwrap(), json!("::ffff:10.0.0.1"));
    }

    #[test]
    fn root_keys_preserved_and_binary_fails_closed() {
        let s = session();
        let src = json!({ "stdout": "password=stdout\nimportant output", "exitCode": 0 });
        let r = s.redact(&src, true).unwrap();
        assert!(r["stdout"].as_str().unwrap().starts_with("password=[NC_"));
        assert!(r["stdout"].as_str().unwrap().ends_with("\nimportant output"));
        assert!(s.redact(&json!({ "type": "image", "data": "x" }), false).is_err());
        assert!(s.redact(&json!({ "base64Data": "aGk=" }), false).is_err());
        assert!(s.restore(&json!("[NC_000000000000_IP_9]")).is_err());
    }

    #[test]
    fn pem_bearer_and_custom_patterns() {
        let s = RedactionSession::new(normalize_redaction_config(Some(&json!({ "enabled": true, "patterns": ["synthetic-[0-9]+"] }))).unwrap());
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----";
        let r = s.redact(&json!(format!("key:\n{pem}\nAuthorization: Bearer abcdefgh123 id synthetic-42")), false).unwrap();
        let t = r.as_str().unwrap();
        assert!(!t.contains("BEGIN") && !t.contains("abcdefgh123") && !t.contains("synthetic-42"));
        assert!(t.contains("Bearer "));
    }

    #[test]
    fn boundary_requires_reconnect_on_change() {
        let cfg = std::sync::Arc::new(Mutex::new(json!({ "enabled": true })));
        let c = cfg.clone();
        let b = PrivacyBoundary::new(move || Some(c.lock().clone()));
        let (p, prot) = b.restore(json!({ "a": 1 })).unwrap();
        assert_eq!(p, json!({ "a": 1 }));
        let r = b.finish("x", Ok(json!({ "ip": "8.8.8.8" })), prot).unwrap();
        assert!(is_token(r["ip"].as_str().unwrap()));
        *cfg.lock() = json!({ "enabled": false });
        assert_eq!(b.restore(json!({})).err().unwrap(), RECONNECT_MESSAGE);
        let bad = PrivacyBoundary::new(|| Some(json!({ "bad": 1 })));
        assert!(bad.restore(json!({})).err().unwrap().contains("unavailable or invalid"));
    }
}
