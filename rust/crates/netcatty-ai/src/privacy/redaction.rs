//! Reversible redaction sessions (Electron: `electron/mcp/externalMcpRedaction.cjs`).
//!
//! A session issues stable pseudonyms (`[NC_<nonce>_<IP|HOST|SECRET>_<n>]`)
//! for secrets, host names and public IP addresses found in parsed JSON
//! values and restores them later. No reverse map ever leaves the session.
//! Error messages never include source text.
//!
//! Detectors are a faithful port of the Electron regular expressions: the
//! ones with lookbehind / backreferences use `fancy-regex`, user patterns
//! use the `regex` crate (RE2 semantics: no lookaround / backreferences,
//! bounded execution time).

use fancy_regex::Regex as FancyRegex;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

pub const CONFIG_ERROR: &str = "Invalid External MCP redaction configuration";
pub const VALUE_ERROR: &str = "External MCP redaction could not safely process this value";
pub const TOKEN_ERROR: &str = "Unknown External MCP redaction token; reconnect the client";
pub const LIMIT_ERROR: &str = "External MCP redaction session limit reached; reconnect the client";
const MAX_ENTRIES: usize = 10_000;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_NODES: usize = 100_000;
const MAX_DEPTH: usize = 100;
const CONFIG_KEYS: &[&str] = &["enabled", "redactPrivateIps", "cidrs", "patterns"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionError {
    Config,
    Value,
    Token,
    Limit,
}

impl RedactionError {
    pub fn message(self) -> &'static str {
        match self {
            RedactionError::Config => CONFIG_ERROR,
            RedactionError::Value => VALUE_ERROR,
            RedactionError::Token => TOKEN_ERROR,
            RedactionError::Limit => LIMIT_ERROR,
        }
    }
}

impl fmt::Display for RedactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for RedactionError {}

type Result<T> = std::result::Result<T, RedactionError>;

/// Validated policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
pub struct RedactionConfig {
    pub enabled: bool,
    pub redact_private_ips: bool,
    pub cidrs: Vec<String>,
    pub patterns: Vec<String>,
}


// ---------------------------------------------------------------------------
// Regular expressions
// ---------------------------------------------------------------------------

macro_rules! re {
    ($name:ident, $pattern:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).expect(stringify!($name)));
    };
}
macro_rules! fre {
    ($name:ident, $pattern:expr) => {
        static $name: LazyLock<FancyRegex> =
            LazyLock::new(|| FancyRegex::new($pattern).expect(stringify!($name)));
    };
}

// `\[NC_[^\]\r\n]*(?:\]|(?=[\r\n]|$))`: the greedy run stops at `]`, a line
// break or the end, so an optional `]` is equivalent to the lookahead form.
re!(RESERVED_TOKEN, r"\[NC_[^\]\r\n]*\]?");
re!(CIDR, r"^([^/%\s]+)/(0|[1-9][0-9]*)$");
re!(NON_ALNUM, r"[^A-Za-z0-9]");
re!(SECRET_KEY, r"(?:password|passwd|passphrase|pwd|token|secret|apikey|accesskey|secretkey|privatekey|credentials?)$");
re!(HOST_KEY, r"^(?:host|hostname|address|ip|ipaddress|server|serveraddress|endpoint|remotehost|targethost|bindaddress|localaddress|remoteaddress)$");
re!(HOST_LABEL, r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$");
re!(HAS_LETTER, r"[A-Za-z]");
fre!(PEM_BLOCK, r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----");
re!(BEARER, r"(?i)(?-u:\b)Bearer(\s+)([A-Za-z0-9._~+/=-]{8,})");
fre!(URL_CREDENTIALS, r"(?i)(?<![a-z0-9+.-])([a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@]+)(@)");
fre!(QUOTED_ASSIGNMENT, r#"(?<![A-Za-z0-9_.-])(["']?)([A-Za-z0-9_.-]+)\1(\s*[:=]\s*)(["'])"#);
fre!(BARE_ASSIGNMENT, r#"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+)(\s*[:=]\s*)([^\s"',;{}\[\]]+)"#);
re!(
    CLI_FLAG,
    r#"(?i)--(?:password|passwd|passphrase|pwd|token|secret|api-key|access-key|secret-key|private-key)(?:\s+|=)(?:"((?:\\[\s\S]|[^"\\])*)"|'((?:\\[\s\S]|[^'\\])*)'|([^\s]+))"#
);
re!(WELL_KNOWN_TOKENS, r"(?-u:\b)(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})(?-u:\b)");
re!(IPV4_CANDIDATE, r"(?-u:\b)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?-u:\b)");
re!(IPV6_CANDIDATE, r"[A-Fa-f0-9:.]+(?:%[A-Za-z0-9_.-]+)?");
re!(AUTHORITY, r"(?i)^(?:[a-z][a-z0-9+.-]*://)?([^/?#:\s]+)(?::[0-9]+)?(?:[/?#].*)?$");
fre!(
    HOST_ASSIGNMENT,
    r#"(?<![A-Za-z0-9_.-])(["']?)([A-Za-z0-9_.-]+)\1\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|([^\s,;{}]+))"#
);
re!(BINARY_KEY, r"^(?:base64data|base64|blob)$");
re!(TEXT_MIME, r"(?i)^(?:text/|application/(?:json|xml|javascript)(?:;|$))");

static PRIVATE_V4: LazyLock<Vec<Ipv4Net>> = LazyLock::new(|| {
    [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    ]
    .iter()
    .map(|c| c.parse().expect("private v4 cidr"))
    .collect()
});
static PRIVATE_V6: LazyLock<Vec<Ipv6Net>> = LazyLock::new(|| {
    ["::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"]
        .iter()
        .map(|c| c.parse().expect("private v6 cidr"))
        .collect()
});

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Node `net.isIP`: 4, 6 or 0. IPv6 zone identifiers (`%eth0`) are accepted.
fn is_ip(value: &str) -> u8 {
    if value.parse::<Ipv4Addr>().is_ok() {
        return 4;
    }
    let bare = match value.find('%') {
        Some(i) if value.contains(':') && i + 1 < value.len() => &value[..i],
        Some(_) => return 0,
        None => value,
    };
    if bare.parse::<Ipv6Addr>().is_ok() {
        6
    } else {
        0
    }
}

fn parse_ip(value: &str) -> Option<IpAddr> {
    match is_ip(value) {
        4 => value.parse::<Ipv4Addr>().ok().map(IpAddr::V4),
        6 => {
            let bare = value.split('%').next().unwrap_or(value);
            bare.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
        }
        _ => None,
    }
}

/// Node `BlockList.check`: IPv4-mapped IPv6 addresses are checked against
/// the IPv4 rules.
fn in_ranges(ranges: &[IpNet], address: IpAddr) -> bool {
    let effective = match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
        v4 => v4,
    };
    ranges.iter().any(|net| net.contains(&effective))
}

fn is_private(address: IpAddr) -> bool {
    let effective = match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
        v4 => v4,
    };
    match effective {
        IpAddr::V4(v4) => PRIVATE_V4.iter().any(|net| net.contains(&v4)),
        IpAddr::V6(v6) => PRIVATE_V6.iter().any(|net| net.contains(&v6)),
    }
}

fn parse_cidr(value: &str) -> Result<IpNet> {
    let captures = CIDR.captures(value).ok_or(RedactionError::Config)?;
    let address = parse_ip(&captures[1]).ok_or(RedactionError::Config)?;
    if captures[1].contains('%') {
        return Err(RedactionError::Config);
    }
    let prefix: u8 = captures[2].parse().map_err(|_| RedactionError::Config)?;
    let net = match address {
        IpAddr::V4(v4) => Ipv4Net::new(v4, prefix).map(IpNet::V4),
        IpAddr::V6(v6) => Ipv6Net::new(v6, prefix).map(IpNet::V6),
    };
    net.map_err(|_| RedactionError::Config)
}

fn plain_object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

/// Reject malformed policy rather than silently disabling a requested protection.
pub fn normalize_redaction_config(input: Option<&Value>) -> Result<RedactionConfig> {
    let empty = Map::new();
    let object = match input {
        None => &empty,
        Some(value) => plain_object(value).ok_or(RedactionError::Config)?,
    };
    if object.keys().any(|key| !CONFIG_KEYS.contains(&key.as_str())) {
        return Err(RedactionError::Config);
    }
    let flag = |name: &str| -> Result<bool> {
        match object.get(name) {
            None => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(RedactionError::Config),
        }
    };
    let list = |name: &str| -> Result<Vec<String>> {
        match object.get(name) {
            None => Ok(Vec::new()),
            Some(Value::Array(items)) => {
                if items.len() > 100 {
                    return Err(RedactionError::Config);
                }
                items
                    .iter()
                    .map(|item| match item {
                        Value::String(s) if !s.is_empty() && s.encode_utf16().count() <= 1024 => Ok(s.clone()),
                        _ => Err(RedactionError::Config),
                    })
                    .collect()
            }
            Some(_) => Err(RedactionError::Config),
        }
    };
    let config = RedactionConfig {
        enabled: flag("enabled")?,
        redact_private_ips: flag("redactPrivateIps")?,
        cidrs: list("cidrs")?,
        patterns: list("patterns")?,
    };
    for cidr in &config.cidrs {
        parse_cidr(cidr)?;
    }
    // RE2 semantics: no backreferences / lookaround, bounded execution time.
    for pattern in &config.patterns {
        let compiled = Regex::new(pattern).map_err(|_| RedactionError::Config)?;
        if compiled.is_match("") {
            return Err(RedactionError::Config);
        }
    }
    Ok(config)
}

fn normalized_key(key: &str) -> String {
    NON_ALNUM.replace_all(key, "").to_ascii_lowercase()
}

fn secret_key(key: &str) -> bool {
    SECRET_KEY.is_match(&normalized_key(key))
}

fn host_key(key: &str) -> bool {
    HOST_KEY.is_match(&normalized_key(key))
}

fn hostname(value: &str) -> bool {
    value.len() <= 253
        && HAS_LETTER.is_match(value)
        && value.strip_suffix('.').unwrap_or(value).split('.').all(|label| HOST_LABEL.is_match(label))
}

/// JS `String(value)` for the primitives a token may stand for.
fn js_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// JS `typeof value`.
fn js_type(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        Value::Null => "object",
        Value::Array(_) | Value::Object(_) => "object",
    }
}

fn is_word_byte(byte: Option<u8>) -> bool {
    matches!(byte, Some(b) if b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Namespace {
    Ip,
    Host,
    Secret,
}

impl Namespace {
    fn label(self) -> &'static str {
        match self {
            Namespace::Ip => "IP",
            Namespace::Host => "HOST",
            Namespace::Secret => "SECRET",
        }
    }
    fn index(self) -> usize {
        match self {
            Namespace::Ip => 0,
            Namespace::Host => 1,
            Namespace::Secret => 2,
        }
    }
}

#[derive(Debug, Clone)]
struct Range {
    start: usize,
    end: usize,
    namespace: Namespace,
    /// An already-issued alias found in the source (`acceptExistingTokens`).
    token: Option<String>,
}

struct Plan {
    ranges: Vec<Range>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RedactOptions {
    /// Keep the root object's keys (RPC control fields) intact.
    pub preserve_root_keys: bool,
    /// Accept aliases this session issued earlier and keep them as they are.
    pub accept_existing_tokens: bool,
}

struct WalkState {
    nodes: usize,
    bytes: usize,
    depth: usize,
    preserve_root_keys: bool,
}

/// Session-local reversible pseudonyms.
#[derive(Debug)]
pub struct RedactionSession {
    enabled: bool,
    redact_private_ips: bool,
    nonce: String,
    /// token → original value
    originals: HashMap<String, Value>,
    /// `${typeof value}\0${String(value)}` → token
    tokens: HashMap<String, String>,
    known_secrets: Vec<String>,
    known_secret_set: HashSet<String>,
    known_hosts: Vec<String>,
    known_host_set: HashSet<String>,
    counters: [u64; 3],
    stored_bytes: usize,
    exhausted: bool,
    custom_ranges: Vec<IpNet>,
    patterns: Vec<Regex>,
}

/// Collects detected ranges for one string, splitting around aliases.
struct Adder<'a> {
    session: &'a mut RedactionSession,
    source: &'a str,
    aliases: &'a [Range],
    ranges: &'a mut Vec<Range>,
    budget: &'a mut usize,
}

impl Adder<'_> {
    fn append_range(&mut self, start: usize, end: usize, namespace: Namespace, remember: bool) -> Result<()> {
        if end <= start {
            return Ok(());
        }
        *self.budget += 1;
        if *self.budget > MAX_NODES {
            return Err(RedactionError::Value);
        }
        self.ranges.push(Range { start, end, namespace, token: None });
        let slice = &self.source[start..end];
        if namespace == Namespace::Secret && remember {
            self.session.remember_secret(slice)?;
        }
        if namespace == Namespace::Host {
            self.session.issue(&Value::String(slice.to_owned()), Namespace::Host)?;
            if self.session.known_host_set.insert(slice.to_owned()) {
                self.session.known_hosts.push(slice.to_owned());
            }
        }
        Ok(())
    }

    fn add(&mut self, start: usize, end: usize, namespace: Namespace, remember: bool) -> Result<()> {
        // First alias whose end is after `start` (binary search by alias end).
        let mut low = 0;
        let mut high = self.aliases.len();
        while low < high {
            let mid = (low + high) / 2;
            if self.aliases[mid].end <= start {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        let mut cursor = start;
        let mut index = low;
        while index < self.aliases.len() && self.aliases[index].start < end {
            let alias = &self.aliases[index];
            let (alias_start, alias_end) = (alias.start, alias.end);
            self.append_range(cursor, end.min(alias_start), namespace, remember)?;
            cursor = cursor.max(alias_end);
            index += 1;
        }
        self.append_range(cursor, end, namespace, remember)
    }
}

impl RedactionSession {
    /// Create a session for a (validated) policy. A disabled policy yields
    /// a pass-through session.
    pub fn new(config: &RedactionConfig) -> Result<Self> {
        let config = normalize_redaction_config(Some(&serde_json::to_value(config).map_err(|_| RedactionError::Config)?))?;
        let nonce: [u8; 6] = rand::random();
        Ok(Self {
            enabled: config.enabled,
            redact_private_ips: config.redact_private_ips,
            nonce: hex::encode(nonce),
            originals: HashMap::new(),
            tokens: HashMap::new(),
            known_secrets: Vec::new(),
            known_secret_set: HashSet::new(),
            known_hosts: Vec::new(),
            known_host_set: HashSet::new(),
            counters: [0; 3],
            stored_bytes: 0,
            exhausted: false,
            custom_ranges: config.cidrs.iter().map(|c| parse_cidr(c)).collect::<Result<_>>()?,
            patterns: config
                .patterns
                .iter()
                .map(|p| Regex::new(p).map_err(|_| RedactionError::Config))
                .collect::<Result<_>>()?,
        })
    }

    /// Create from untyped renderer input (`createRedactionSession(input)`).
    pub fn from_value(input: Option<&Value>) -> Result<Self> {
        Self::new(&normalize_redaction_config(input)?)
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    fn issue(&mut self, value: &Value, namespace: Namespace) -> Result<String> {
        // The first classification names a value; later contexts reuse its token.
        let identity = format!("{}\0{}", js_type(value), js_string(value));
        if let Some(prior) = self.tokens.get(&identity) {
            return Ok(prior.clone());
        }
        let bytes = identity.len();
        if self.originals.len() >= MAX_ENTRIES || self.stored_bytes + bytes > MAX_BYTES {
            self.exhausted = true;
            return Err(RedactionError::Limit);
        }
        self.counters[namespace.index()] += 1;
        let token = format!("[NC_{}_{}_{}]", self.nonce, namespace.label(), self.counters[namespace.index()]);
        self.tokens.insert(identity, token.clone());
        self.originals.insert(token.clone(), value.clone());
        self.stored_bytes += bytes;
        Ok(token)
    }

    fn remember_secret(&mut self, value: &str) -> Result<()> {
        if value.is_empty() {
            return Ok(());
        }
        self.issue(&Value::String(value.to_owned()), Namespace::Secret)?;
        if self.known_secret_set.insert(value.to_owned()) {
            self.known_secrets.push(value.to_owned());
        }
        Ok(())
    }

    fn should_mask_ip(&self, address: &str) -> bool {
        let Some(ip) = parse_ip(address) else { return false };
        self.redact_private_ips || in_ranges(&self.custom_ranges, ip) || !is_private(ip)
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_string(
        &mut self,
        source: &str,
        key: &str,
        inherited_secret: bool,
        budget: &mut usize,
        accept_existing_tokens: bool,
    ) -> Result<Plan> {
        let mut aliases: Vec<Range> = Vec::new();
        let value: String = if accept_existing_tokens {
            let mut masked = String::with_capacity(source.len());
            let mut last = 0;
            for m in RESERVED_TOKEN.find_iter(source) {
                let token = m.as_str();
                if !self.originals.contains_key(token) {
                    return Err(RedactionError::Token);
                }
                *budget += 1;
                if *budget > MAX_NODES {
                    return Err(RedactionError::Value);
                }
                aliases.push(Range { start: m.start(), end: m.end(), namespace: Namespace::Secret, token: Some(token.to_owned()) });
                masked.push_str(&source[last..m.start()]);
                // Keep offsets and credential context around aliases. In particular,
                // password=prefix<alias>suffix must mask both unaliased fragments.
                masked.push_str(&"x".repeat(token.len()));
                last = m.end();
            }
            masked.push_str(&source[last..]);
            masked
        } else {
            source.to_owned()
        };
        let mut ranges: Vec<Range> = aliases.clone();
        let mut adder = Adder { session: self, source, aliases: &aliases, ranges: &mut ranges, budget };

        // Source text that resembles a token must survive a one-pass round trip.
        // Do not remember these literals as credentials or scan replacement tokens.
        for m in RESERVED_TOKEN.find_iter(&value) {
            adder.add(m.start(), m.end(), Namespace::Secret, false)?;
        }
        if !value.is_empty() && (inherited_secret || secret_key(key)) {
            adder.add(0, value.len(), Namespace::Secret, true)?;
        }
        for m in PEM_BLOCK.find_iter(&value) {
            let m = m.map_err(|_| RedactionError::Value)?;
            adder.add(m.start(), m.end(), Namespace::Secret, true)?;
        }
        for caps in BEARER.captures_iter(&value) {
            if let Some(g) = caps.get(2) {
                adder.add(g.start(), g.end(), Namespace::Secret, true)?;
            }
        }
        for caps in URL_CREDENTIALS.captures_iter(&value) {
            let caps = caps.map_err(|_| RedactionError::Value)?;
            if let Some(g) = caps.get(2) {
                adder.add(g.start(), g.end(), Namespace::Secret, true)?;
            }
        }
        // Keep the original separators, whitespace, quotes, and escaped contents.
        for caps in QUOTED_ASSIGNMENT.captures_iter(&value) {
            let caps = caps.map_err(|_| RedactionError::Value)?;
            let (Some(whole), Some(name), Some(quote)) = (caps.get(0), caps.get(2), caps.get(4)) else { continue };
            if !secret_key(name.as_str()) {
                continue;
            }
            let quote = quote.as_str().as_bytes()[0];
            let bytes = value.as_bytes();
            let start = whole.end();
            let mut end = start;
            while end < bytes.len() {
                if bytes[end] == b'\\' {
                    end += 1;
                } else if bytes[end] == quote {
                    break;
                }
                end += 1;
            }
            let end = end.min(bytes.len());
            // `end` may sit one past a trailing backslash; clamp to a char boundary.
            let end = (end..=bytes.len()).find(|&i| value.is_char_boundary(i)).unwrap_or(bytes.len());
            adder.add(start, end, Namespace::Secret, true)?;
        }
        for caps in BARE_ASSIGNMENT.captures_iter(&value) {
            let caps = caps.map_err(|_| RedactionError::Value)?;
            let (Some(name), Some(assigned)) = (caps.get(1), caps.get(3)) else { continue };
            if secret_key(name.as_str()) && assigned.as_str() != "null" {
                adder.add(assigned.start(), assigned.end(), Namespace::Secret, true)?;
            }
        }
        for caps in CLI_FLAG.captures_iter(&value) {
            if let Some(g) = caps.get(1).or_else(|| caps.get(2)).or_else(|| caps.get(3)) {
                adder.add(g.start(), g.end(), Namespace::Secret, true)?;
            }
        }
        for m in WELL_KNOWN_TOKENS.find_iter(&value) {
            adder.add(m.start(), m.end(), Namespace::Secret, true)?;
        }

        let patterns = adder.session.patterns.clone();
        for pattern in &patterns {
            for m in pattern.find_iter(&value) {
                adder.add(m.start(), m.end(), Namespace::Secret, true)?;
            }
        }

        let bytes = value.as_bytes();
        for m in IPV4_CANDIDATE.find_iter(&value) {
            let (start, end) = (m.start(), m.end());
            let before = start.checked_sub(1).map(|i| bytes[i]);
            let after = bytes.get(end).copied();
            if !is_word_byte(before) && !is_word_byte(after) && adder.session.should_mask_ip(m.as_str()) {
                adder.add(start, end, Namespace::Ip, true)?;
            }
        }
        for m in IPV6_CANDIDATE.find_iter(&value) {
            let mut address = m.as_str();
            if !address.contains(':') {
                continue;
            }
            // Full stops/colons can be sentence punctuation following an address.
            while !address.is_empty() && is_ip(address) == 0 && (address.ends_with('.') || address.ends_with(':')) {
                address = &address[..address.len() - 1];
            }
            if is_ip(address) == 6 && adder.session.should_mask_ip(address) {
                adder.add(m.start(), m.start() + address.len(), Namespace::Ip, true)?;
            }
        }

        let inspect_host = |adder: &mut Adder<'_>, start: usize, end: usize| -> Result<()> {
            let raw = &value[start..end];
            let trimmed = raw.trim();
            if trimmed.is_empty() || is_ip(trimmed) != 0 {
                return Ok(());
            }
            let offset = start + raw.find(trimmed).unwrap_or(0);
            // In a structured address, only the authority is a hostname, not a path.
            let Some(caps) = AUTHORITY.captures(trimmed) else { return Ok(()) };
            let authority = &caps[1];
            if is_ip(authority) == 0 && hostname(authority) {
                let host_start = offset + trimmed.find(authority).unwrap_or(0);
                adder.add(host_start, host_start + authority.len(), Namespace::Host, true)?;
            }
            Ok(())
        };
        if host_key(key) {
            inspect_host(&mut adder, 0, value.len())?;
        }
        for caps in HOST_ASSIGNMENT.captures_iter(&value) {
            let caps = caps.map_err(|_| RedactionError::Value)?;
            let Some(name) = caps.get(2) else { continue };
            if !host_key(name.as_str()) {
                continue;
            }
            if let Some(g) = caps.get(3).or_else(|| caps.get(4)).or_else(|| caps.get(5)) {
                inspect_host(&mut adder, g.start(), g.end())?;
            }
        }
        Ok(Plan { ranges })
    }

    fn reject_binary(value: &Map<String, Value>) -> Result<()> {
        let kind = value.get("type").and_then(Value::as_str).map(str::to_ascii_lowercase).unwrap_or_default();
        if kind == "image" || kind == "audio" {
            return Err(RedactionError::Value);
        }
        for (key, entry) in value {
            if BINARY_KEY.is_match(&normalized_key(key)) && !entry.is_null() && entry.as_str() != Some("") {
                return Err(RedactionError::Value);
            }
        }
        let mime = match value.get("mimeType") {
            Some(Value::String(s)) => Some(s.as_str()),
            _ => value.get("mime_type").and_then(Value::as_str),
        };
        if let Some(mime) = mime {
            let data = value.get("data");
            if !TEXT_MIME.is_match(mime) && data.is_some_and(|d| !d.is_null() && d.as_str() != Some("")) {
                return Err(RedactionError::Value);
            }
        }
        Ok(())
    }

    fn walk(
        value: &Value,
        visitor: &mut dyn Visitor,
        key: &str,
        inherited_secret: bool,
        state: &mut WalkState,
    ) -> Result<Value> {
        state.nodes += 1;
        if state.nodes > MAX_NODES || state.depth > MAX_DEPTH {
            return Err(RedactionError::Value);
        }
        match value {
            Value::String(text) => {
                if text.contains('\0') {
                    return Err(RedactionError::Value);
                }
                state.bytes += text.len();
                if state.bytes > MAX_BYTES {
                    return Err(RedactionError::Value);
                }
                visitor.string(text, key, inherited_secret)
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => visitor.primitive(value, key, inherited_secret),
            Value::Array(items) => {
                state.depth += 1;
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(Self::walk(item, visitor, key, inherited_secret, state)?);
                }
                state.depth -= 1;
                Ok(Value::Array(out))
            }
            Value::Object(object) => {
                state.depth += 1;
                Self::reject_binary(object)?;
                let mut out = Map::new();
                for (entry_key, entry) in object {
                    let transformed_key = if state.preserve_root_keys && state.depth == 1 {
                        entry_key.clone()
                    } else {
                        js_string(&Self::walk(&Value::String(entry_key.clone()), visitor, "", false, state)?)
                    };
                    let transformed = Self::walk(entry, visitor, entry_key, inherited_secret || secret_key(key), state)?;
                    if out.insert(transformed_key, transformed).is_some() {
                        return Err(RedactionError::Value);
                    }
                }
                state.depth -= 1;
                Ok(Value::Object(out))
            }
        }
    }

    fn state(&self, preserve_root_keys: bool) -> Result<WalkState> {
        if self.exhausted {
            return Err(RedactionError::Limit);
        }
        Ok(WalkState { nodes: 0, bytes: 0, depth: 0, preserve_root_keys })
    }

    fn literal_alternation(literals: &[String]) -> String {
        let mut sorted = literals.to_vec();
        sorted.sort_by_key(|l| std::cmp::Reverse(l.len()));
        sorted.iter().map(|l| regex::escape(l)).collect::<Vec<_>>().join("|")
    }

    fn redact_inner(&mut self, value: &Value, options: RedactOptions) -> Result<Value> {
        // Inspect the entire value first: repeats appearing before a credential's
        // defining field in this response must be masked too.
        let mut state = self.state(options.preserve_root_keys)?;
        let mut inspect = InspectVisitor { session: self, plans: Vec::new(), budget: 0, options };
        Self::walk(value, &mut inspect, "", false, &mut state)?;
        let InspectVisitor { plans, budget, .. } = inspect;
        let known_pattern = if self.known_secrets.is_empty() {
            None
        } else {
            Some(Regex::new(&Self::literal_alternation(&self.known_secrets)).map_err(|_| RedactionError::Value)?)
        };
        let known_host_pattern = if self.known_hosts.is_empty() {
            None
        } else {
            let alternation = Self::literal_alternation(&self.known_hosts);
            Some(
                FancyRegex::new(&format!("(?<![A-Za-z0-9_.-])(?:{alternation})(?![A-Za-z0-9_.-])"))
                    .map_err(|_| RedactionError::Value)?,
            )
        };
        let mut state = self.state(options.preserve_root_keys)?;
        let mut rewrite = RewriteVisitor { session: self, plans, cursor: 0, budget, known_pattern, known_host_pattern };
        Self::walk(value, &mut rewrite, "", false, &mut state)
    }

    fn restore_inner(&mut self, value: &Value) -> Result<Value> {
        let mut state = self.state(false)?;
        let mut restore = RestoreVisitor { originals: &self.originals };
        Self::walk(value, &mut restore, "", false, &mut state)
    }

    /// Replace secrets, hosts and public IPs with session tokens.
    pub fn redact(&mut self, value: &Value, options: RedactOptions) -> Result<Value> {
        if !self.enabled {
            return Ok(value.clone());
        }
        self.redact_inner(value, options)
    }

    /// Put the original values back; unknown tokens fail closed.
    pub fn restore(&mut self, value: &Value) -> Result<Value> {
        if !self.enabled {
            return Ok(value.clone());
        }
        self.restore_inner(value)
    }
}

/// Per-node callbacks of [`RedactionSession::walk`].
trait Visitor {
    fn string(&mut self, text: &str, key: &str, inherited_secret: bool) -> Result<Value>;
    fn primitive(&mut self, value: &Value, key: &str, inherited_secret: bool) -> Result<Value>;
}

/// First redaction pass: detect ranges in every string (keys included).
struct InspectVisitor<'a> {
    session: &'a mut RedactionSession,
    plans: Vec<Plan>,
    budget: usize,
    options: RedactOptions,
}

impl Visitor for InspectVisitor<'_> {
    fn string(&mut self, text: &str, key: &str, inherited_secret: bool) -> Result<Value> {
        let accept = self.options.accept_existing_tokens;
        let plan = self.session.inspect_string(text, key, inherited_secret, &mut self.budget, accept)?;
        self.plans.push(plan);
        Ok(Value::String(text.to_owned()))
    }

    fn primitive(&mut self, value: &Value, _: &str, _: bool) -> Result<Value> {
        Ok(value.clone())
    }
}

/// Second redaction pass: add repeats of known secrets / hosts, merge the
/// ranges and replace them with tokens.
struct RewriteVisitor<'a> {
    session: &'a mut RedactionSession,
    plans: Vec<Plan>,
    cursor: usize,
    budget: usize,
    known_pattern: Option<Regex>,
    known_host_pattern: Option<FancyRegex>,
}

impl Visitor for RewriteVisitor<'_> {
    fn string(&mut self, text: &str, _: &str, _: bool) -> Result<Value> {
        let Plan { mut ranges } = std::mem::replace(&mut self.plans[self.cursor], Plan { ranges: Vec::new() });
        self.cursor += 1;
        let alias_ranges: Vec<Range> = ranges.iter().filter(|r| r.token.is_some()).cloned().collect();
        let mut known_matches: Vec<(usize, usize, Namespace)> = Vec::new();
        if let Some(pattern) = &self.known_pattern {
            for m in pattern.find_iter(text) {
                known_matches.push((m.start(), m.end(), Namespace::Secret));
            }
        }
        let mut host_matches: Vec<(usize, usize, Namespace)> = Vec::new();
        if let Some(pattern) = &self.known_host_pattern {
            for m in pattern.find_iter(text) {
                let m = m.map_err(|_| RedactionError::Value)?;
                host_matches.push((m.start(), m.end(), Namespace::Host));
            }
        }
        for matches in [known_matches, host_matches] {
            let mut alias_index = 0;
            for (start, end, namespace) in matches {
                // Previously issued aliases are protocol data, never source secrets.
                while alias_index < alias_ranges.len() && alias_ranges[alias_index].end <= start {
                    alias_index += 1;
                }
                if alias_index < alias_ranges.len() && alias_ranges[alias_index].start < end {
                    continue;
                }
                self.budget += 1;
                if self.budget > MAX_NODES {
                    return Err(RedactionError::Value);
                }
                ranges.push(Range { start, end, namespace, token: None });
            }
        }
        ranges.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        let mut merged: Vec<Range> = Vec::new();
        for range in ranges {
            match merged.last_mut() {
                Some(previous) if range.start < previous.end => {
                    previous.end = previous.end.max(range.end);
                    if range.namespace == Namespace::Secret {
                        previous.namespace = Namespace::Secret;
                    }
                }
                _ => merged.push(range),
            }
        }
        let mut result = String::with_capacity(text.len());
        let mut position = 0;
        for range in merged {
            result.push_str(&text[position..range.start]);
            let replacement = match range.token {
                Some(token) => token,
                None => self.session.issue(&Value::String(text[range.start..range.end].to_owned()), range.namespace)?,
            };
            result.push_str(&replacement);
            position = range.end;
        }
        result.push_str(&text[position..]);
        Ok(Value::String(result))
    }

    fn primitive(&mut self, value: &Value, key: &str, inherited_secret: bool) -> Result<Value> {
        if !value.is_null() && (inherited_secret || secret_key(key)) {
            Ok(Value::String(self.session.issue(value, Namespace::Secret)?))
        } else {
            Ok(value.clone())
        }
    }
}

/// Restore pass: whole-string tokens give back the original value (type
/// included); embedded tokens are replaced textually.
struct RestoreVisitor<'a> {
    originals: &'a HashMap<String, Value>,
}

impl Visitor for RestoreVisitor<'_> {
    fn string(&mut self, text: &str, _: &str, _: bool) -> Result<Value> {
        if let Some(original) = self.originals.get(text) {
            return Ok(original.clone());
        }
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for m in RESERVED_TOKEN.find_iter(text) {
            let Some(original) = self.originals.get(m.as_str()) else {
                return Err(RedactionError::Token);
            };
            out.push_str(&text[last..m.start()]);
            // A replacement is not scanned again, including a source token literal.
            out.push_str(&js_string(original));
            last = m.end();
        }
        out.push_str(&text[last..]);
        Ok(Value::String(out))
    }

    fn primitive(&mut self, value: &Value, _: &str, _: bool) -> Result<Value> {
        Ok(value.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn token_like(value: &str) -> bool {
        static TOKEN: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^\[NC_[a-f0-9]{12}_(?:IP|HOST|SECRET)_[0-9]+\]$").unwrap());
        TOKEN.is_match(value)
    }

    fn enabled(config: Value) -> RedactionSession {
        let mut object = json!({ "enabled": true });
        for (k, v) in config.as_object().unwrap() {
            object[k] = v.clone();
        }
        RedactionSession::from_value(Some(&object)).unwrap()
    }

    fn s(value: &Value) -> &str {
        value.as_str().unwrap()
    }

    #[test]
    fn policy_defaults_are_disabled_strict_and_copied() {
        assert_eq!(normalize_redaction_config(None).unwrap(), RedactionConfig::default());
        let config = normalize_redaction_config(Some(&json!({
            "enabled": true, "patterns": ["synthetic-[0-9]+"], "cidrs": ["10.0.0.0/8", "fc00::/7"]
        })))
        .unwrap();
        assert_eq!(config.patterns, vec!["synthetic-[0-9]+"]);
        for invalid in [
            json!(null), json!([]), json!(true), json!("sensitive-invalid-config"), json!({ "enabled": "true" }),
            json!({ "redactPrivateIps": 1 }), json!({ "surprise": "sensitive-invalid-config" }),
            json!({ "cidrs": "10.0.0.0/8" }), json!({ "cidrs": ["1.2.3.4/33"] }), json!({ "cidrs": ["::1/129"] }),
            json!({ "cidrs": ["::1%eth0/64"] }), json!({ "cidrs": ["10.0.0.0/08"] }),
            json!({ "cidrs": ["not-an-address/8"] }), json!({ "patterns": [""] }), json!({ "patterns": [1] }),
            json!({ "patterns": ["(?=unsupported)"] }), json!({ "patterns": ["(secret)\\1"] }),
            json!({ "patterns": ["("] }), json!({ "patterns": ["a*"] }), json!({ "patterns": ["^"] }),
            json!({ "patterns": vec!["value"; 101] }),
        ] {
            assert_eq!(normalize_redaction_config(Some(&invalid)), Err(RedactionError::Config), "{invalid}");
        }
    }

    #[test]
    fn disabled_policy_leaves_inputs_and_reserved_text_alone() {
        let mut session = RedactionSession::from_value(None).unwrap();
        let value = json!({ "password": "synthetic-password", "content": "[NC_other_SECRET_1] 8.8.8.8" });
        assert_eq!(session.redact(&value, RedactOptions::default()).unwrap(), value);
        assert_eq!(session.restore(&value).unwrap(), value);
    }

    #[test]
    fn recursive_transforms_include_keys_preserve_types_and_round_trip() {
        let mut session = enabled(json!({}));
        let source = json!({
            "8.8.8.8": [{ "host": "build.example.test", "password": "synthetic-pass" }, null, 42, false],
            "empty": "", "password": "", "apiKey": null, "tokenCount": 123
        });
        let redacted = session.redact(&source, RedactOptions::default()).unwrap();
        assert_ne!(redacted, source);
        assert!(!redacted.as_object().unwrap().contains_key("8.8.8.8"));
        assert!(!redacted.to_string().contains("synthetic-pass"));
        assert_eq!(redacted["tokenCount"], 123);
        assert_eq!(redacted["empty"], "");
        assert_eq!(redacted["password"], "");
        assert_eq!(redacted["apiKey"], Value::Null);
        assert_eq!(session.restore(&redacted).unwrap(), source);
    }

    #[test]
    fn root_keys_can_be_preserved_without_exempting_nested_keys_or_secret_values() {
        let mut session = enabled(json!({}));
        let source = json!({
            "stdout": "password=stdout\nimportant output", "stderr": "", "exitCode": 0,
            "password": "synthetic-root-secret", "details": { "stdout": "nested user key", "8.8.8.8": "address key" }
        });
        let result = session.redact(&source, RedactOptions { preserve_root_keys: true, ..Default::default() }).unwrap();
        let keys: Vec<&String> = result.as_object().unwrap().keys().collect();
        assert_eq!(keys, source.as_object().unwrap().keys().collect::<Vec<_>>());
        let stdout = s(&result["stdout"]);
        assert!(stdout.starts_with("password=[NC_") && stdout.ends_with("]\nimportant output"), "{stdout}");
        assert!(token_like(s(&result["password"])));
        assert!(!result["details"].as_object().unwrap().contains_key("stdout"));
        assert!(!result["details"].as_object().unwrap().contains_key("8.8.8.8"));
        assert_eq!(session.restore(&result).unwrap(), source);
        assert!(!session.redact(&source, RedactOptions::default()).unwrap().as_object().unwrap().contains_key("stdout"));
    }

    #[test]
    fn same_session_values_are_stable_and_sessions_are_isolated() {
        let mut one = enabled(json!({}));
        let mut two = enabled(json!({}));
        let a = one.redact(&json!("8.8.8.8"), RedactOptions::default()).unwrap();
        assert!(token_like(s(&a)));
        assert_eq!(one.redact(&json!("8.8.8.8"), RedactOptions::default()).unwrap(), a);
        assert_ne!(two.redact(&json!("8.8.8.8"), RedactOptions::default()).unwrap(), a);
        assert_eq!(two.restore(&a), Err(RedactionError::Token));
    }

    #[test]
    fn public_ipv4_and_ipv6_are_hidden() {
        let mut session = enabled(json!({}));
        for address in ["8.8.8.8", "203.0.113.14", "2001:4860:4860::8888", "2001:DB8::AbCd", "::ffff:8.8.8.8", "::ffff:808:808"] {
            let masked = session.redact(&json!(address), RedactOptions::default()).unwrap();
            assert!(token_like(s(&masked)), "{address} → {masked}");
            assert!(s(&masked).contains("_IP_"));
            assert_eq!(session.restore(&masked).unwrap(), json!(address));
        }
        let url = "https://[2001:db8::1234]:443/path";
        let masked = session.redact(&json!(url), RedactOptions::default()).unwrap();
        let text = s(&masked);
        assert!(text.starts_with("https://[[NC_") && text.contains("_IP_") && text.ends_with("]]:443/path"), "{text}");
        assert_eq!(session.restore(&masked).unwrap(), json!(url));
        let invalid = "invalid 999.999.999.999 and 1.2.3.4.5";
        assert_eq!(session.redact(&json!(invalid), RedactOptions::default()).unwrap(), json!(invalid));
    }

    #[test]
    fn private_addresses_are_preserved_by_default() {
        let mut session = enabled(json!({}));
        for address in [
            "10.2.3.4", "172.16.0.1", "172.31.255.255", "192.168.1.1", "127.0.0.1", "169.254.12.9", "100.64.0.1",
            "100.127.255.254", "::", "::1", "fd12:3456::1", "fc00::5", "fe80::cafe%eth0", "::ffff:10.0.0.1", "::ffff:7f00:1",
        ] {
            assert_eq!(session.redact(&json!(address), RedactOptions::default()).unwrap(), json!(address));
            assert_eq!(session.redact(&json!({ "host": address }), RedactOptions::default()).unwrap(), json!({ "host": address }));
        }
        assert!(token_like(s(&session.redact(&json!("100.128.0.1"), RedactOptions::default()).unwrap())));
        assert!(token_like(s(&session.redact(&json!("172.32.0.1"), RedactOptions::default()).unwrap())));
    }

    #[test]
    fn private_switch_and_cidr_opt_ins() {
        let mut all = enabled(json!({ "redactPrivateIps": true }));
        for address in ["10.0.0.1", "::1", "fe80::1%eth0", "::ffff:10.0.0.1"] {
            let token = all.redact(&json!(address), RedactOptions::default()).unwrap();
            assert!(token_like(s(&token)), "{address}");
            assert_eq!(all.restore(&token).unwrap(), json!(address));
        }
        let mut scoped = enabled(json!({ "cidrs": ["10.4.0.0/16", "fd12:3456::/32"] }));
        assert!(token_like(s(&scoped.redact(&json!("10.4.1.8"), RedactOptions::default()).unwrap())));
        assert_eq!(scoped.redact(&json!("10.5.1.8"), RedactOptions::default()).unwrap(), json!("10.5.1.8"));
        assert!(token_like(s(&scoped.redact(&json!("fd12:3456:abcd::8"), RedactOptions::default()).unwrap())));
        assert_eq!(scoped.redact(&json!("fd12:3457::8"), RedactOptions::default()).unwrap(), json!("fd12:3457::8"));
    }

    #[test]
    fn hostnames_require_structured_context() {
        let mut session = enabled(json!({}));
        let source = json!({
            "hostname": "build.internal.test", "address": "ssh.example.test:2222", "remoteHost": "ubuntu",
            "endpoint": "https://api.example.test/path?q=1",
            "description": "README.md and foo.example.test are ordinary prose"
        });
        let masked = session.redact(&source, RedactOptions::default()).unwrap();
        assert!(s(&masked["hostname"]).contains("_HOST_"));
        assert!(s(&masked["address"]).contains("_HOST_") && s(&masked["address"]).ends_with("]:2222"));
        assert!(s(&masked["remoteHost"]).contains("_HOST_"));
        let endpoint = s(&masked["endpoint"]);
        assert!(endpoint.starts_with("https://[NC_") && endpoint.contains("_HOST_") && endpoint.ends_with("]/path?q=1"), "{endpoint}");
        assert_eq!(masked["description"], source["description"]);
        assert_eq!(session.restore(&masked).unwrap(), source);
        let quoted = session.redact(&json!("hostname = \"build.internal.test\""), RedactOptions::default()).unwrap();
        assert!(s(&quoted).starts_with("hostname = \"[NC_"), "{quoted}");
        assert_eq!(session.redact(&json!({ "host": "not a hostname" }), RedactOptions::default()).unwrap()["host"], "not a hostname");
    }

    #[test]
    fn credential_recognizers_round_trip() {
        let mut session = enabled(json!({}));
        for value in [
            "PASSWORD \t= \t\"synthetic pass\\\"with quote\"; unchanged",
            "api_key: 'synthetic\\\\escaped-value'",
            "{\"password\" : \"synthetic\\nline\\tvalue\", \"ok\": true}",
            "message = \"password = 'synthetic-inner-quoted-value'\"",
            "token = synthetic_assignment_value; tokenCount=91",
            "curl --password  'synthetic cli pass' --api-key=synthetic_cli_key",
            "Authorization: Bearer \t SYNTHETIC_bearer_12345678",
            "https://alice:synthetic-url-password@service.example.test/path",
            "ghp_SYNTHETIC0000000000000000000001",
            "sk-SYNTHETIC0000000000000000000002",
        ] {
            let masked = session.redact(&json!(value), RedactOptions::default()).unwrap();
            assert_ne!(masked, json!(value), "{value}");
            assert_eq!(session.restore(&masked).unwrap(), json!(value), "{value}");
        }
        for untouched in ["password = \"\"", "password = null", "tokenCount = 91; authType = bearer"] {
            assert_eq!(session.redact(&json!(untouched), RedactOptions::default()).unwrap(), json!(untouched));
        }
    }

    #[test]
    fn pem_blocks_are_a_single_secret() {
        let mut session = enabled(json!({}));
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-ONLY-NOT-A-KEY\n-----END OPENSSH PRIVATE KEY-----";
        let source = format!("before\n{key}\nafter");
        let result = session.redact(&json!(source), RedactOptions::default()).unwrap();
        let text = s(&result);
        assert!(text.starts_with("before\n[NC_") && text.contains("_SECRET_") && text.ends_with("]\nafter"), "{text}");
        assert_eq!(session.restore(&result).unwrap(), json!(source));
    }

    #[test]
    fn repeated_credentials_are_masked_everywhere() {
        let mut session = enabled(json!({}));
        let source = json!({ "echo": "synthetic-repeat", "password": "synthetic-repeat", "nested": ["synthetic-repeat"] });
        let masked = session.redact(&source, RedactOptions::default()).unwrap();
        assert!(token_like(s(&masked["password"])));
        assert_eq!(masked["echo"], masked["password"]);
        assert_eq!(masked["nested"][0], masked["password"]);
        assert_eq!(
            session.redact(&json!("echo synthetic-repeat"), RedactOptions::default()).unwrap(),
            json!(format!("echo {}", s(&masked["password"])))
        );
        assert_eq!(session.restore(&masked).unwrap(), source);
    }

    #[test]
    fn known_hosts_repeat_without_matching_substrings() {
        let mut session = enabled(json!({}));
        let source = json!({ "before": "connect to db or build.example.test", "hostname": "db", "nested": { "host": "build.example.test" } });
        let masked = session.redact(&source, RedactOptions::default()).unwrap();
        assert_eq!(masked["before"], json!(format!("connect to {} or {}", s(&masked["hostname"]), s(&masked["nested"]["host"]))));
        assert_eq!(
            session.redact(&json!("ssh db; ping build.example.test"), RedactOptions::default()).unwrap(),
            json!(format!("ssh {}; ping {}", s(&masked["hostname"]), s(&masked["nested"]["host"])))
        );
        let prose = "dbx adb db.internal build.example.test.other";
        assert_eq!(session.redact(&json!(prose), RedactOptions::default()).unwrap(), json!(prose));
        assert_eq!(session.restore(&masked).unwrap(), source);
    }

    #[test]
    fn managed_boundaries_preserve_known_aliases() {
        let accept = RedactOptions { accept_existing_tokens: true, ..Default::default() };
        let mut session = enabled(json!({}));
        let source = json!({ "host": "db", "password": 123456, "secret": false, "text": "8.8.8.8" });
        let aliases = session.redact(&source, RedactOptions::default()).unwrap();
        assert_eq!(session.redact(&aliases, accept).unwrap(), aliases);
        let repeated = json!({ "text": format!("{} {} {} {}", s(&aliases["host"]), s(&aliases["password"]), s(&aliases["secret"]), s(&aliases["text"])) });
        assert_eq!(session.redact(&repeated, accept).unwrap(), repeated);
        assert_eq!(session.redact(&aliases["password"], accept).unwrap(), aliases["password"]);
        assert_eq!(session.restore(&aliases["password"]).unwrap(), json!(123456));
        assert_eq!(session.restore(&aliases["secret"]).unwrap(), json!(false));
        assert_ne!(session.redact(&aliases["host"], RedactOptions::default()).unwrap(), aliases["host"]);
        assert_eq!(session.redact(&json!("[NC_unknown_HOST_1]"), accept), Err(RedactionError::Token));
        assert_eq!(session.redact(&json!("[NC_unclosed"), accept), Err(RedactionError::Token));
    }

    #[test]
    fn managed_aliases_stay_intact_alongside_new_secrets() {
        let accept = RedactOptions { accept_existing_tokens: true, ..Default::default() };
        let mut session = enabled(json!({}));
        let token = session.redact(&json!("8.8.8.8"), RedactOptions::default()).unwrap();
        let token = s(&token).to_owned();
        let mixed = session
            .redact(&json!({ "password": format!("fresh-secret {token} another-secret"), "text": token }), accept)
            .unwrap();
        assert_eq!(mixed["text"], json!(token));
        assert!(s(&mixed["password"]).contains(&token));
        assert!(!s(&mixed["password"]).contains("fresh-secret"));
        assert_eq!(
            session.restore(&mixed).unwrap(),
            json!({ "password": "fresh-secret 8.8.8.8 another-secret", "text": "8.8.8.8" })
        );
        assert_eq!(session.redact(&json!(token), accept).unwrap(), json!(token));
    }

    #[test]
    fn managed_aliases_keep_context_around_raw_fragments() {
        let accept = RedactOptions { accept_existing_tokens: true, ..Default::default() };
        let mut session = enabled(json!({ "patterns": ["SENSITIVE-BEGIN[\\s\\S]*?SENSITIVE-END"] }));
        let token = session.redact(&json!("8.8.8.8"), RedactOptions::default()).unwrap();
        let token = s(&token).to_owned();
        for source in [
            format!("password=raw-prefix{token}raw-suffix"),
            format!("--password 'quoted-prefix{token}quoted-suffix'"),
            format!("SENSITIVE-BEGIN{token}SENSITIVE-END"),
        ] {
            let masked = session.redact(&json!(source), accept).unwrap();
            let text = s(&masked);
            assert!(text.contains(&token), "{text}");
            for fragment in ["raw-prefix", "raw-suffix", "quoted-prefix", "quoted-suffix", "SENSITIVE-BEGIN", "SENSITIVE-END"] {
                assert!(!text.contains(fragment), "{text} contains {fragment}");
            }
            assert_eq!(session.restore(&masked).unwrap(), json!(source.replacen(&token, "8.8.8.8", 1)));
        }
    }

    #[test]
    fn a_value_keeps_its_first_token_across_namespaces() {
        let mut session = enabled(json!({}));
        let ip = session.redact(&json!("8.8.8.8"), RedactOptions::default()).unwrap();
        assert_eq!(session.redact(&json!({ "password": "8.8.8.8" }), RedactOptions::default()).unwrap()["password"], ip);
        let host = session.redact(&json!({ "host": "synthetic.example.test" }), RedactOptions::default()).unwrap()["host"].clone();
        assert_eq!(session.redact(&json!({ "secret": "synthetic.example.test" }), RedactOptions::default()).unwrap()["secret"], host);
    }

    #[test]
    fn structured_numeric_and_nested_credentials_restore_types() {
        let mut session = enabled(json!({}));
        let source = json!({ "token": 123456, "credentials": { "password": "synthetic-nested", "values": ["synthetic-value"] }, "tokenCount": 123456 });
        let result = session.redact(&source, RedactOptions::default()).unwrap();
        assert!(token_like(s(&result["token"])));
        assert_eq!(result["tokenCount"], 123456);
        assert!(token_like(s(&result["credentials"]["values"][0])));
        assert_eq!(session.restore(&result).unwrap(), source);
    }

    #[test]
    fn custom_patterns_redact_whole_matches() {
        let mut session = enabled(json!({ "patterns": ["ACCOUNT-[0-9]+", "BEGIN[\\s\\S]*?END", "address=8\\.8\\.8\\.8"] }));
        let source = "ACCOUNT-123 and ACCOUNT-123; BEGIN\nsynthetic\nEND; address=8.8.8.8";
        let result = session.redact(&json!(source), RedactOptions::default()).unwrap();
        let text = s(&result);
        assert!(!text.contains("ACCOUNT-123") && !text.contains("BEGIN") && !text.contains("address="), "{text}");
        assert_eq!(session.restore(&result).unwrap(), json!(source));
        assert_eq!(session.redact(&json!(""), RedactOptions::default()).unwrap(), json!(""));
    }

    #[test]
    fn literal_reserved_tokens_are_escaped_and_restoration_never_rescans() {
        let mut session = enabled(json!({}));
        let issued = session.redact(&json!("8.8.8.8"), RedactOptions::default()).unwrap();
        let issued = s(&issued).to_owned();
        for literal in ["[NC_deadbeef0000_IP_1]", "[NC_other_SECRET_123]", "[NC_invalid]", "[NC_unclosed", issued.as_str()] {
            let escaped = session.redact(&json!(format!("literal={literal}")), RedactOptions::default()).unwrap();
            assert!(!s(&escaped).contains(literal), "{literal}");
            assert_eq!(session.restore(&escaped).unwrap(), json!(format!("literal={literal}")));
        }
        let escaped_actual = session.redact(&json!(issued), RedactOptions::default()).unwrap();
        assert_ne!(escaped_actual, json!(issued));
        assert_eq!(session.restore(&escaped_actual).unwrap(), json!(issued));
        assert_eq!(session.restore(&json!(issued)).unwrap(), json!("8.8.8.8"));
    }

    #[test]
    fn unknown_modified_and_key_tokens_fail_closed() {
        let mut session = enabled(json!({}));
        let issued = session.redact(&json!("8.8.8.8"), RedactOptions::default()).unwrap();
        let issued = s(&issued).to_owned();
        let mut truncated = issued.clone();
        truncated.pop();
        truncated.push_str("0]");
        for unknown in ["[NC_unknown_IP_1]".to_owned(), "[NC_unclosed".to_owned(), issued.replace("_IP_", "_HOST_"), truncated] {
            assert_eq!(session.restore(&json!(format!("ping {unknown}"))), Err(RedactionError::Token));
            assert_eq!(session.restore(&json!({ unknown: "test" })), Err(RedactionError::Token));
        }
    }

    #[test]
    fn restored_key_collisions_fail_closed() {
        let mut session = enabled(json!({}));
        let token = session.redact(&json!("8.8.8.8"), RedactOptions::default()).unwrap();
        let token = s(&token).to_owned();
        assert_eq!(session.restore(&json!({ token: 1, "8.8.8.8": 2 })), Err(RedactionError::Value));
        let source = json!({ "__proto__": "8.8.8.8", "constructor": "normal" });
        let redacted = session.redact(&source, RedactOptions::default()).unwrap();
        assert_eq!(session.restore(&redacted).unwrap(), source);
    }

    #[test]
    fn nontext_attachments_fail_closed_and_text_attachments_work() {
        let mut session = enabled(json!({}));
        for source in [
            json!({ "base64Data": "U1lOVEhFVElD" }),
            json!({ "content": [{ "type": "image", "data": "U1lOVEhFVElD", "mimeType": "image/png" }] }),
            json!({ "content": [{ "type": "audio", "data": "U1lOVEhFVElD", "mimeType": "audio/wav" }] }),
            json!({ "resource": { "blob": "U1lOVEhFVElD", "mimeType": "application/octet-stream" } }),
            json!({ "data": "U1lOVEhFVElD", "mimeType": "application/pdf" }),
            json!("binary\0text"),
        ] {
            assert_eq!(session.redact(&source, RedactOptions::default()), Err(RedactionError::Value), "{source}");
        }
        let text = json!({ "content": [{ "type": "text", "text": "8.8.8.8" }], "mimeType": "text/plain" });
        let masked = session.redact(&text, RedactOptions::default()).unwrap();
        assert_eq!(session.restore(&masked).unwrap(), text);
    }

    #[test]
    fn session_growth_fails_closed() {
        let mut session = enabled(json!({}));
        let first = session.redact(&json!("8.8.8.8"), RedactOptions::default()).unwrap();
        let many: Vec<Value> = (0..10_001).map(|i| json!({ "hostname": format!("host-{i}.example.test") })).collect();
        assert_eq!(session.redact(&Value::Array(many), RedactOptions::default()), Err(RedactionError::Limit));
        assert_eq!(session.redact(&json!("8.8.8.8"), RedactOptions::default()), Err(RedactionError::Limit));
        assert_eq!(session.restore(&first), Err(RedactionError::Limit));
    }

    #[test]
    fn large_strings_and_nested_quantifiers_do_not_backtrack() {
        let mut session = enabled(json!({ "patterns": ["(a+)+$"] }));
        let source = format!("{}!", "a".repeat(50_000));
        assert_eq!(session.redact(&json!(source), RedactOptions::default()).unwrap(), json!(source));
        assert_eq!(session.restore(&json!(source)).unwrap(), json!(source));
    }

    #[test]
    fn deep_nesting_is_rejected() {
        let mut session = enabled(json!({}));
        let mut value = json!("leaf");
        for _ in 0..101 {
            value = json!([value]);
        }
        assert_eq!(session.redact(&value, RedactOptions::default()), Err(RedactionError::Value));
    }
}
