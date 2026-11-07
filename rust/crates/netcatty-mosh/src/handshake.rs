//! Mosh bootstrap: what the upstream `mosh` Perl wrapper does, without Perl.
//!
//! Port of `electron/bridges/moshHandshake.cjs`:
//!
//! 1. run `ssh -n -tt [-p port] [user@]host -- sh -c '<report MOSH IP; exec
//!    mosh-server new ...>'` in a PTY so password / 2FA prompts render;
//! 2. forward the PTY output to the renderer through [`MoshConnectSniffer`],
//!    which hides the `MOSH IP` / `MOSH CONNECT <port> <key>` protocol lines
//!    and captures the port, key and server address;
//! 3. once ssh exits, start `mosh-client <ip> <port>` with `MOSH_KEY` set.

use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;

/// Default remote command. `-c 256` makes mosh-server export
/// `TERM=xterm-256color` (it uses `xterm` for the default 8 colors).
pub const DEFAULT_MOSH_SERVER: &str = "mosh-server new -s -c 256";
pub const DEFAULT_LANG: &str = "en_US.UTF-8";

/// Locale variables offered to mosh-server (`-l NAME=value`), in the stock
/// wrapper's order.
pub const MOSH_LOCALE_NAMES: &[&str] = &[
    "LANG",
    "LANGUAGE",
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_MESSAGES",
    "LC_PAPER",
    "LC_NAME",
    "LC_ADDRESS",
    "LC_TELEPHONE",
    "LC_MEASUREMENT",
    "LC_IDENTIFICATION",
    "LC_ALL",
];

/// Restores terminal modes a full-screen remote program can leak when
/// mosh-client exits (Netcatty keeps the primary screen).
pub const MOSH_PRIMARY_SCREEN_RESET: &str = "\x1b[?1l\x1b[0m\x1b[?25h\x1b[?1003l\x1b[?1002l\x1b[?1001l\x1b[?1000l\x1b[?1015l\x1b[?1006l\x1b[?1005l";

/// Clears the viewport (not scrollback) at the hand-off so bootstrap text
/// does not linger around the first reconstructed Mosh frame.
pub const MOSH_HANDSHAKE_VIEWPORT_RESET: &str = "\x1b[2J\x1b[H";

/// Shown when ssh exits without a valid `MOSH CONNECT` line.
pub const MOSH_HANDSHAKE_FAILED_HINT: &str = "\r\n[Mosh handshake failed during SSH startup: did not receive a valid MOSH CONNECT line from mosh-server. The UDP client was not started. Confirm the SSH login succeeded and mosh-server started correctly on the remote host.]\r\n";

/// `netcatty:exit` error for a failed handshake.
pub const MOSH_HANDSHAKE_FAILED_ERROR: &str =
    "Mosh SSH startup failed: no MOSH CONNECT from mosh-server (UDP client not started)";

const PROTOCOL_MARKERS: [&str; 2] = ["MOSH CONNECT", "MOSH IP"];
const RING_SIZE: usize = 4096;
const MAX_PROTOCOL_LINE: usize = 512;

fn ansi_escape_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[PX^_][^\x1b]*\x1b\\|[^\n\r\x{2028}\x{2029}])",
        )
        .expect("valid ansi regex")
    })
}

fn connect_prefix_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"MOSH CONNECT[ \t]+(\d{1,5})[ \t]+").expect("valid regex"))
}

fn mosh_ip_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"MOSH IP[ \t]+(\S+)").expect("valid regex"))
}

/// POSIX single-quote a value for `sh`.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn valid_mosh_key(key: &str) -> bool {
    key.len() == 22 || (key.len() == 24 && key.ends_with("=="))
}

fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

fn is_base64_or_pad(b: Option<u8>) -> bool {
    matches!(b, Some(c) if is_base64_char(c) || c == b'=')
}

/// End of the escape sequence starting at `pos`, if one starts there.
fn escape_at(text: &str, pos: usize) -> Option<usize> {
    if text.as_bytes().get(pos) != Some(&0x1b) {
        return None;
    }
    ansi_escape_re()
        .find_at(text, pos)
        .filter(|m| m.start() == pos)
        .map(|m| m.end())
}

fn skip_ansi_escapes(text: &str, offset: usize) -> usize {
    let mut pos = offset;
    while let Some(end) = escape_at(text, pos) {
        pos = end;
    }
    pos
}

/// Strip escapes, keeping a map from cleaned byte offsets to original ones.
fn strip_ansi_with_map(source: &str) -> (String, Vec<usize>) {
    let mut cleaned = String::with_capacity(source.len());
    let mut map = Vec::with_capacity(source.len() + 1);
    let mut index = 0;
    while index < source.len() {
        if let Some(end) = escape_at(source, index) {
            index = end;
            continue;
        }
        let ch = source[index..].chars().next().expect("char at boundary");
        for offset in 0..ch.len_utf8() {
            map.push(index + offset);
        }
        cleaned.push(ch);
        index += ch.len_utf8();
    }
    map.push(source.len());
    (cleaned, map)
}

fn strip_ansi(text: &str) -> String {
    ansi_escape_re().replace_all(text, "").into_owned()
}

/// A parsed `MOSH CONNECT` line (offsets into the original line).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectLine {
    port: u16,
    key: String,
    match_start: usize,
    match_end: usize,
}

fn parse_connect_line(line: &str) -> Option<ConnectLine> {
    let (cleaned, map) = strip_ansi_with_map(line);
    let caps = connect_prefix_re().captures(&cleaned)?;
    let whole = caps.get(0)?;
    let port: u32 = caps.get(1)?.as_str().parse().ok()?;
    if port == 0 || port > 65_535 {
        return None;
    }
    let connect_idx = *map.get(whole.start())?;
    let key_start = *map.get(whole.end())?;
    let bytes = line.as_bytes();

    let mut key = String::new();
    let mut pos = key_start;
    while pos < bytes.len() && key.len() < 22 {
        if let Some(end) = escape_at(line, pos) {
            pos = end;
            continue;
        }
        let b = bytes[pos];
        if !is_base64_char(b) {
            return None;
        }
        key.push(b as char);
        pos += 1;
    }
    if key.len() != 22 {
        return None;
    }

    let padding = skip_ansi_escapes(line, pos);
    if line[padding..].starts_with("==") {
        key.push_str("==");
        pos = padding + 2;
    } else if bytes.get(padding) == Some(&b'=') {
        let second = skip_ansi_escapes(line, padding + 1);
        if bytes.get(second) == Some(&b'=') {
            key.push_str("==");
            pos = second + 1;
        } else if padding == pos {
            return None;
        }
    } else if padding == pos && is_base64_or_pad(bytes.get(pos).copied()) {
        return None;
    }
    if is_base64_or_pad(bytes.get(pos).copied()) {
        return None;
    }
    if !valid_mosh_key(&key) {
        return None;
    }

    // Extend the redaction over trailing escapes / blanks.
    let mut match_end = pos;
    while match_end < bytes.len() {
        if let Some(end) = escape_at(line, match_end) {
            match_end = end;
            continue;
        }
        if bytes[match_end] == b' ' || bytes[match_end] == b'\t' {
            match_end += 1;
            continue;
        }
        break;
    }
    Some(ConnectLine {
        port: port as u16,
        key,
        match_start: connect_idx,
        match_end,
    })
}

fn parse_mosh_ip_line(line: &str) -> Option<String> {
    let cleaned = strip_ansi(line);
    let caps = mosh_ip_re().captures(&cleaned)?;
    let host = caps.get(1)?.as_str();
    host.parse::<IpAddr>().ok().map(|_| host.to_string())
}

struct Line<'a> {
    text: &'a str,
    newline: &'a str,
    start: usize,
    end: usize,
}

/// Complete lines (`([^\r\n]*)(\r\n|\r|\n)`) of `text`.
fn complete_lines(text: &str) -> Vec<Line<'_>> {
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' | b'\n' => {
                let nl_len = if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                lines.push(Line {
                    text: &text[start..i],
                    newline: &text[i..i + nl_len],
                    start,
                    end: i + nl_len,
                });
                i += nl_len;
                start = i;
            }
            _ => i += 1,
        }
    }
    lines
}

/// Earliest offset where a protocol marker (or a prefix of one at the end)
/// starts; `None` when the text cannot contain one.
fn potential_protocol_start(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut best: Option<usize> = None;
    let mut consider = |pos: usize| {
        best = Some(best.map_or(pos, |b| b.min(pos)));
    };
    for marker in PROTOCOL_MARKERS {
        if let Some(full) = text.find(marker) {
            consider(full);
        }
        let max = (marker.len() - 1).min(bytes.len());
        for len in (1..=max).rev() {
            if marker.as_bytes().starts_with(&bytes[bytes.len() - len..]) {
                consider(bytes.len() - len);
                break;
            }
        }
    }
    best
}

/// Largest char boundary `<= index`.
fn floor_boundary(text: &str, mut index: usize) -> usize {
    if index >= text.len() {
        return text.len();
    }
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// `MOSH CONNECT` details captured by the sniffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoshConnect {
    pub port: u16,
    pub key: String,
    /// Server address from the `MOSH IP` line (SSH_CONNECTION's server IP).
    pub host: Option<String>,
}

/// Parse a buffer for a complete `MOSH CONNECT` line (stateless helper).
pub fn parse_mosh_connect(text: &str) -> Option<(u16, String)> {
    for line in complete_lines(text) {
        if let Some(parsed) = parse_connect_line(line.text) {
            return Some((parsed.port, parsed.key));
        }
    }
    None
}

/// Result of one [`MoshConnectSniffer::feed`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SnifferOutput {
    /// Text safe to show (protocol lines removed).
    pub visible: String,
    /// Set once, when the `MOSH CONNECT` line completes.
    pub parsed: Option<MoshConnect>,
}

/// Streaming filter over the ssh PTY output (`createMoshConnectSniffer`).
///
/// Holds back a possible protocol line until it completes (at most
/// [`MAX_PROTOCOL_LINE`] bytes), so a key split across chunks is neither
/// leaked nor truncated. After a parse, everything passes through.
#[derive(Debug, Default)]
pub struct MoshConnectSniffer {
    pending: String,
    parsed: bool,
    mosh_host: Option<String>,
}

impl MoshConnectSniffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_parsed(&self) -> bool {
        self.parsed
    }

    fn make_parsed(&mut self, line: ConnectLine) -> MoshConnect {
        self.parsed = true;
        MoshConnect {
            port: line.port,
            key: line.key,
            host: self.mosh_host.clone(),
        }
    }

    pub fn feed(&mut self, chunk: &str) -> SnifferOutput {
        if self.parsed {
            return SnifferOutput {
                visible: chunk.to_string(),
                parsed: None,
            };
        }
        self.pending.push_str(chunk);
        let pending = std::mem::take(&mut self.pending);
        let mut visible = String::new();
        let mut consumed = 0;
        let mut parsed = None;

        for line in complete_lines(&pending) {
            if line.start > consumed {
                visible.push_str(&pending[consumed..line.start]);
            }
            if let Some(ip) = parse_mosh_ip_line(line.text) {
                self.mosh_host = Some(ip);
                consumed = line.end;
                continue;
            }
            if let Some(connect) = parse_connect_line(line.text) {
                visible.push_str(&line.text[..connect.match_start]);
                let suffix = &line.text[connect.match_end..];
                if !suffix.is_empty() {
                    visible.push_str(suffix);
                    visible.push_str(line.newline);
                }
                consumed = line.end;
                parsed = Some(self.make_parsed(connect));
                break;
            }
            visible.push_str(line.text);
            visible.push_str(line.newline);
            consumed = line.end;
        }

        if parsed.is_some() {
            visible.push_str(&pending[consumed..]);
            return SnifferOutput { visible, parsed };
        }

        // Never parse an unterminated CONNECT here: a 22-char key prefix can
        // still receive "==" in the next chunk. `flush` handles EOF.
        let mut rest = pending[consumed..].to_string();
        match potential_protocol_start(&rest) {
            None => {
                visible.push_str(&rest);
                rest.clear();
            }
            Some(hold) => {
                visible.push_str(&rest[..hold]);
                rest = rest[hold..].to_string();
                if rest.len() > MAX_PROTOCOL_LINE {
                    visible.push_str(&rest);
                    rest.clear();
                }
            }
        }
        if rest.len() > RING_SIZE {
            let overflow = floor_boundary(&rest, rest.len() - RING_SIZE);
            visible.push_str(&rest[..overflow]);
            rest = rest[overflow..].to_string();
        }
        self.pending = rest;
        SnifferOutput {
            visible,
            parsed: None,
        }
    }

    /// Drain a trailing unterminated protocol line when ssh exits (ssh /
    /// ConPTY often end the stream on the CONNECT line without a newline).
    pub fn flush(&mut self) -> SnifferOutput {
        if self.parsed || self.pending.is_empty() {
            return SnifferOutput::default();
        }
        let pending = std::mem::take(&mut self.pending);
        if let Some(ip) = parse_mosh_ip_line(&pending) {
            self.mosh_host = Some(ip);
        }
        if let Some(connect) = parse_connect_line(&pending) {
            let visible = format!(
                "{}{}",
                &pending[..connect.match_start],
                &pending[connect.match_end..]
            );
            let parsed = self.make_parsed(connect);
            return SnifferOutput {
                visible,
                parsed: Some(parsed),
            };
        }
        SnifferOutput {
            visible: pending,
            parsed: None,
        }
    }
}

/// `mosh-server new -s -c 256`, or a custom server path (quoted as a path).
pub fn build_mosh_server_command(mosh_server_path: Option<&str>) -> String {
    match mosh_server_path.map(str::trim).filter(|p| !p.is_empty()) {
        None => DEFAULT_MOSH_SERVER.to_string(),
        Some(path) => format!("{} new -s -c 256", shell_quote(path)),
    }
}

/// Inputs of [`build_ssh_handshake_args`].
#[derive(Debug, Clone, Default)]
pub struct SshHandshakeOptions<'a> {
    pub host: &'a str,
    pub port: Option<u16>,
    pub username: Option<&'a str>,
    /// UTF-8 locale offered when no locale variable is configured.
    pub lang: Option<&'a str>,
    /// Client environment; its locale variables are offered in stock order.
    pub locales: Option<&'a HashMap<String, String>>,
    /// Remote server command (default [`DEFAULT_MOSH_SERVER`]).
    pub mosh_server: Option<&'a str>,
    /// Extra ssh arguments (auth / host key options).
    pub ssh_args: &'a [String],
}

/// argv (after the `ssh` executable) of the bootstrap command.
pub fn build_ssh_handshake_args(opts: &SshHandshakeOptions<'_>) -> Result<Vec<String>, String> {
    if opts.host.trim().is_empty() {
        return Err("buildSshHandshakeCommand: host is required".into());
    }
    let mut args = vec!["-n".to_string(), "-tt".to_string()];
    if let Some(port) = opts.port.filter(|p| *p != 22 && *p != 0) {
        args.push("-p".into());
        args.push(port.to_string());
    }
    args.extend(opts.ssh_args.iter().cloned());
    args.push(match opts.username.filter(|u| !u.is_empty()) {
        Some(user) => format!("{user}@{}", opts.host),
        None => opts.host.to_string(),
    });
    args.push("--".into());

    let lang = opts.lang.filter(|l| !l.is_empty()).unwrap_or(DEFAULT_LANG);
    let mosh_server = opts
        .mosh_server
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_MOSH_SERVER);
    let mut assignments: Vec<String> = MOSH_LOCALE_NAMES
        .iter()
        .filter_map(|name| {
            opts.locales
                .and_then(|l| l.get(*name))
                .map(|value| format!("{name}={value}"))
        })
        .collect();
    if assignments.is_empty() {
        assignments.push(format!("LANG={lang}"));
    }
    let locale_args: String = assignments
        .iter()
        .map(|a| format!(" -l {}", shell_quote(a)))
        .collect();
    // SSH_CONNECTION's third field is the server address of this exact SSH
    // connection; resolving the hostname again for UDP could pick another.
    let remote_script = format!(
        "if [ -n \"$SSH_CONNECTION\" ]; then set -- $SSH_CONNECTION; printf '\\nMOSH IP %s\\n' \"$3\"; fi; exec {mosh_server}{locale_args}"
    );
    args.push(format!("sh -c {}", shell_quote(&remote_script)));
    Ok(args)
}

/// argv of `mosh-client <host> <port>`.
pub fn build_mosh_client_args(
    mosh_client_path: &str,
    host: &str,
    port: u16,
) -> Result<(String, Vec<String>), String> {
    if mosh_client_path.is_empty() {
        return Err("buildMoshClientCommand: moshClientPath is required".into());
    }
    if host.is_empty() {
        return Err("buildMoshClientCommand: host is required".into());
    }
    if port == 0 {
        return Err("buildMoshClientCommand: port must be > 0".into());
    }
    Ok((
        mosh_client_path.to_string(),
        vec![host.to_string(), port.to_string()],
    ))
}

/// Environment of `mosh-client`: `MOSH_KEY`, `MOSH_FALLBACK_HOST` (only for
/// this handshake), `LANG` / `TERM` defaults.
pub fn build_mosh_client_env(
    base_env: &HashMap<String, String>,
    key: &str,
    lang: Option<&str>,
    fallback_host: Option<&str>,
) -> HashMap<String, String> {
    let mut env = base_env.clone();
    env.insert("MOSH_KEY".into(), key.to_string());
    env.remove("MOSH_FALLBACK_HOST");
    if let Some(host) = fallback_host.filter(|h| !h.is_empty()) {
        env.insert("MOSH_FALLBACK_HOST".into(), host.to_string());
    }
    if let Some(lang) = lang.filter(|l| !l.is_empty()) {
        env.entry("LANG".into()).or_insert_with(|| lang.to_string());
    }
    env.entry("TERM".into())
        .or_insert_with(|| "xterm-256color".to_string());
    env
}

/// `resolveLangFromCharsetForMosh`.
pub fn resolve_lang_from_charset(charset: Option<&str>) -> String {
    match charset.map(str::trim).filter(|c| !c.is_empty()) {
        None => DEFAULT_LANG.to_string(),
        Some(c) if c.eq_ignore_ascii_case("utf-8") || c.eq_ignore_ascii_case("utf8") => {
            DEFAULT_LANG.to_string()
        }
        Some(c) => c.to_string(),
    }
}

/// Remove locale variables from the ssh environment: the handshake offers
/// them through mosh-server's `-l` fallback instead of `SendEnv`.
pub fn strip_locale_env(env: &mut HashMap<String, String>) {
    env.retain(|key, _| key != "LANG" && key != "LANGUAGE" && !key.starts_with("LC_"));
}

#[cfg(test)]
mod tests {
    //! Ported from `electron/bridges/moshHandshake.test.cjs`.
    use super::*;

    const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUV==";

    fn connect(port: u16, key: &str, host: Option<&str>) -> Option<MoshConnect> {
        Some(MoshConnect {
            port,
            key: key.into(),
            host: host.map(str::to_string),
        })
    }

    #[test]
    fn parse_typical_line() {
        assert_eq!(
            parse_mosh_connect("Welcome\r\nMOSH CONNECT 60001 ABCDEFGHIJKLMNOPQRSTUV==\r\n"),
            Some((60001, KEY.into()))
        );
        let (port, key) = parse_mosh_connect("MOSH CONNECT 60005 abcdefghijklmnopqrstuv\n").unwrap();
        assert_eq!(port, 60005);
        assert_eq!(key.len(), 22);
        assert_eq!(
            parse_mosh_connect("garbage MOSH CONNECT 60010 ABCDEFGHIJKLMNOPQRSTUV==\n")
                .unwrap()
                .0,
            60010
        );
    }

    #[test]
    fn parse_rejects_bad_ports_and_keys() {
        assert!(parse_mosh_connect("MOSH CONNECT 99999 ABCDEFGHIJKLMNOPQRSTUV==\n").is_none());
        assert!(parse_mosh_connect("MOSH CONNECT 0 ABCDEFGHIJKLMNOPQRSTUV==\n").is_none());
        assert!(parse_mosh_connect("MOSH CONNECT 60000 abc\n").is_none());
    }

    #[test]
    fn parse_tolerates_conpty_controls() {
        assert_eq!(
            parse_mosh_connect("MOSH CONNECT 60001 ABCDEFGHIJKLMNOPQRSTUV==\x1b[?25h\r\n"),
            Some((60001, KEY.into()))
        );
        assert_eq!(
            parse_mosh_connect("MOSH CONNECT 60030 nDMmYnfKIKn2yAXiK/\x1b[?25h34eg\r\n"),
            Some((60030, "nDMmYnfKIKn2yAXiK/34eg".into()))
        );
        assert_eq!(
            parse_mosh_connect("MOSH CONNECT 60031 ABCDEFGHIJKLMNOPQRSTUV=\x1b[?25h=\r\n"),
            Some((60031, KEY.into()))
        );
        assert_eq!(
            parse_mosh_connect(
                "MOSH CONNECT 60033 ABCDEFGHIJKLMNOPQRSTUV\x1b[?25h=\x1b[?25h=\r\n"
            ),
            Some((60033, KEY.into()))
        );
        assert_eq!(
            parse_mosh_connect("MOSH CONNECT 60032 ABCDEFGHIJKLMNOPQRSTUV\x1b[8;1H= banner\r\n"),
            Some((60032, "ABCDEFGHIJKLMNOPQRSTUV".into()))
        );
    }

    #[test]
    fn sniffer_handles_conpty_mangled_lines() {
        let mut s = MoshConnectSniffer::new();
        let r = s.feed(
            "mosh-server (mosh 1.4.0)\r\nMOSH CONNECT 60002 ABCDEFGHIJKLMNOPQRSTUV==\x1b[?25h\r\n[mosh-server detached, pid = 908918]\r\n",
        );
        assert_eq!(r.parsed, connect(60002, KEY, None));
        assert!(!r.visible.contains("MOSH CONNECT"));
        assert!(r.visible.contains("mosh-server detached"));

        for (line, port, key) in [
            (
                "MOSH CONNECT 60030 nDMmYnfKIKn2yAXiK/\x1b[?25h34eg\r\n",
                60030,
                "nDMmYnfKIKn2yAXiK/34eg",
            ),
            (
                "MOSH CONNECT 60031 ABCDEFGHIJKLMNOPQRSTUV=\x1b[?25h=\r\n",
                60031,
                KEY,
            ),
            (
                "MOSH CONNECT 60033 ABCDEFGHIJKLMNOPQRSTUV\x1b[?25h=\x1b[?25h=\r\n",
                60033,
                KEY,
            ),
        ] {
            let mut s = MoshConnectSniffer::new();
            let r = s.feed(line);
            assert_eq!(r.parsed, connect(port, key, None), "{line:?}");
            assert!(!r.visible.contains("MOSH CONNECT"));
            assert!(!r.visible.contains("34eg"));
            assert!(!r.visible.contains("ABCDEFGHIJKLMNOPQRSTUV"));
        }

        let mut s = MoshConnectSniffer::new();
        let r = s.feed("MOSH CONNECT 60032 ABCDEFGHIJKLMNOPQRSTUV\x1b[8;1H= banner\r\n");
        assert_eq!(r.parsed, connect(60032, "ABCDEFGHIJKLMNOPQRSTUV", None));
        assert!(!r.visible.contains("MOSH CONNECT"));
        assert!(r.visible.contains("= banner"));
    }

    #[test]
    fn sniffer_stops_key_at_cursor_move() {
        let mut s = MoshConnectSniffer::new();
        let r = s.feed(
            "MOSH IP 207.58.174.82\r\n\x1b[?25l\x1b[6;1HMOSH CONNECT 60030 BArYj8zs1avy+l7+GaHoTg\x1b[8;1Hmosh-server (mosh 1.4.0)\r\n",
        );
        assert_eq!(
            r.parsed,
            connect(60030, "BArYj8zs1avy+l7+GaHoTg", Some("207.58.174.82"))
        );
        assert!(!r.visible.contains("MOSH CONNECT"));
        assert!(r.visible.contains("mosh-server (mosh 1.4.0)"));
    }

    #[test]
    fn sniffer_flush_recovers_unterminated_connect() {
        let mut s = MoshConnectSniffer::new();
        assert!(s.feed("MOSH CONNECT 60003 ABCDEFGHIJKLMNOPQRSTUV==").parsed.is_none());
        let r = s.flush();
        assert_eq!(r.parsed, connect(60003, KEY, None));
        assert!(!r.visible.contains("MOSH CONNECT"));

        let mut s = MoshConnectSniffer::new();
        assert!(s
            .feed("MOSH CONNECT 60005 ABCDEFGHIJKLMNOPQRSTUV==\x1b[?25h")
            .parsed
            .is_none());
        assert_eq!(s.flush().parsed, connect(60005, KEY, None));
    }

    #[test]
    fn sniffer_waits_for_padding() {
        let mut s = MoshConnectSniffer::new();
        let r1 = s.feed("MOSH CONNECT 60004 ABCDEFGHIJKLMNOPQRSTUV");
        assert!(r1.parsed.is_none());
        assert!(!r1.visible.contains("MOSH CONNECT"));
        let r2 = s.feed("==\r\n");
        assert_eq!(r2.parsed, connect(60004, KEY, None));
        assert!(!r2.visible.contains("=="));
    }

    #[test]
    fn sniffer_split_markers_and_keys() {
        let mut s = MoshConnectSniffer::new();
        let r1 = s.feed("login as: alice\r\nlast login: yesterday\r\nMOSH CONNE");
        assert!(r1.parsed.is_none());
        assert!(!r1.visible.contains("MOSH CONNE"));
        let r2 = s.feed("CT 60002 ABCDEFGHIJKLMNOPQRSTUV==\r\n");
        assert_eq!(r2.parsed, connect(60002, KEY, None));
        assert!(!r2.visible.contains("MOSH CONNECT"));
        assert!(!r2.visible.contains(KEY));

        let mut s = MoshConnectSniffer::new();
        let r1 = s.feed("intro\r\nMOSH CONNECT 60002 ABCDEFGHIJ");
        assert!(r1.parsed.is_none());
        assert_eq!(r1.visible, "intro\r\n");
        let r2 = s.feed("KLMNOPQRSTUV==\r\n");
        assert_eq!(r2.parsed, connect(60002, KEY, None));
        assert_eq!(r2.visible, "");
    }

    #[test]
    fn sniffer_passes_prompts_through() {
        let mut s = MoshConnectSniffer::new();
        let r = s.feed("password:");
        assert!(r.parsed.is_none());
        assert_eq!(r.visible, "password:");
        let r = s.feed("中文 prompt ");
        assert_eq!(r.visible, "中文 prompt ");
    }

    #[test]
    fn sniffer_ignores_invalid_lines() {
        for line in [
            "MOSH CONNECT 99999 ABCDEFGHIJKLMNOPQRSTUV==\r\n",
            "MOSH CONNECT 0 ABCDEFGHIJKLMNOPQRSTUV==\r\n",
            "MOSH CONNECT 60000 short\r\n",
            "MOSH CONNECT 60000 ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\n",
            "MOSH CONNECT 60000 ABCDEFGHIJKLMNOPQRSTUV==oops\r\n",
        ] {
            let mut s = MoshConnectSniffer::new();
            assert!(s.feed(line).parsed.is_none(), "{line:?}");
        }
    }

    #[test]
    fn sniffer_captures_mosh_ip() {
        let mut s = MoshConnectSniffer::new();
        let r = s.feed(
            "welcome\r\nMOSH IP 203.0.113.8\r\nMOSH CONNECT 60002 ABCDEFGHIJKLMNOPQRSTUV==\r\n",
        );
        assert_eq!(r.parsed, connect(60002, KEY, Some("203.0.113.8")));
        assert_eq!(r.visible, "welcome\r\n");

        let mut s = MoshConnectSniffer::new();
        let r = s.feed("MOSH IP --help\r\nMOSH CONNECT 60002 ABCDEFGHIJKLMNOPQRSTUV==\r\n");
        assert_eq!(r.parsed, connect(60002, KEY, None));
    }

    #[test]
    fn sniffer_strips_marker_and_is_idempotent() {
        let mut s = MoshConnectSniffer::new();
        let r = s.feed("shell prompt $ \r\nMOSH CONNECT 60003 ABCDEFGHIJKLMNOPQRSTUV==\r\nbye\r\n");
        assert_eq!(r.parsed, connect(60003, KEY, None));
        assert!(!r.visible.contains("MOSH CONNECT"));
        assert!(r.visible.contains("bye"));
        let r2 = s.feed("trailing bytes after handshake\r\n");
        assert!(r2.parsed.is_none());
        assert_eq!(r2.visible, "trailing bytes after handshake\r\n");
        assert!(s.is_parsed());
    }

    #[test]
    fn sniffer_ring_buffer() {
        let mut s = MoshConnectSniffer::new();
        for _ in 0..10 {
            assert!(s.feed(&"x".repeat(1024)).parsed.is_none());
        }
        let r = s.feed("MOSH CONNECT 60020 ABCDEFGHIJKLMNOPQRSTUV==\r\n");
        assert_eq!(r.parsed.unwrap().port, 60020);
    }

    #[test]
    fn handshake_command_shape() {
        let args = build_ssh_handshake_args(&SshHandshakeOptions {
            host: "example.com",
            username: Some("alice"),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(&args[..4], &["-n", "-tt", "alice@example.com", "--"]);
        let remote = args.last().unwrap();
        assert!(remote.starts_with("sh -c "));
        assert!(!remote.contains("env LC_ALL="));
        assert!(remote.contains("exec mosh-server new -s -c 256 -l "));
        assert!(remote.contains("LANG=en_US.UTF-8"));
        assert!(remote.contains("SSH_CONNECTION"));
        assert!(remote.contains("MOSH IP"));
        assert!(remote.contains("$3"));

        let args = build_ssh_handshake_args(&SshHandshakeOptions {
            host: "example.com",
            port: Some(2222),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(&args[..4], &["-n", "-tt", "-p", "2222"]);
        assert!(build_ssh_handshake_args(&SshHandshakeOptions::default()).is_err());
    }

    #[test]
    fn handshake_lang_and_server_overrides() {
        let args = build_ssh_handshake_args(&SshHandshakeOptions {
            host: "h",
            lang: Some("zh_CN.UTF-8"),
            mosh_server: Some("/opt/mosh/bin/mosh-server new -s -c 256"),
            ..Default::default()
        })
        .unwrap();
        let remote = args.last().unwrap();
        assert!(remote.contains("zh_CN.UTF-8"));
        assert!(remote.contains("/opt/mosh/bin/mosh-server new -s -c 256"));

        let args = build_ssh_handshake_args(&SshHandshakeOptions {
            host: "h",
            lang: Some("C; touch /tmp/netcatty-owned"),
            ..Default::default()
        })
        .unwrap();
        assert!(args
            .last()
            .unwrap()
            .contains(r"-l '\''LANG=C; touch /tmp/netcatty-owned'\''"));
    }

    #[test]
    fn handshake_locale_order() {
        let mut locales = HashMap::new();
        locales.insert("LC_ALL".to_string(), "zh_CN.UTF-8".to_string());
        locales.insert("LC_CTYPE".to_string(), "ja_JP.UTF-8".to_string());
        locales.insert("LANG".to_string(), "C".to_string());
        locales.insert("PATH".to_string(), "/tmp/ignored".to_string());
        let args = build_ssh_handshake_args(&SshHandshakeOptions {
            host: "example.com",
            lang: Some("en_US.UTF-8"),
            locales: Some(&locales),
            ..Default::default()
        })
        .unwrap();
        let remote = args.last().unwrap();
        let lang = remote.find("LANG=C").unwrap();
        let ctype = remote.find("LC_CTYPE=ja_JP.UTF-8").unwrap();
        let all = remote.find("LC_ALL=zh_CN.UTF-8").unwrap();
        assert!(lang < ctype && ctype < all);
        assert_eq!(remote.matches(" -l ").count(), 3);
        assert!(!remote.contains("PATH="));
    }

    #[test]
    fn server_command() {
        assert_eq!(build_mosh_server_command(None), DEFAULT_MOSH_SERVER);
        assert_eq!(build_mosh_server_command(Some("")), DEFAULT_MOSH_SERVER);
        assert_eq!(build_mosh_server_command(Some("   ")), DEFAULT_MOSH_SERVER);
        assert_eq!(
            build_mosh_server_command(Some("/opt/Mosh Tools/mosh-server; touch /tmp/nope")),
            "'/opt/Mosh Tools/mosh-server; touch /tmp/nope' new -s -c 256"
        );
    }

    #[test]
    fn client_command_and_env() {
        let (cmd, args) =
            build_mosh_client_args("/usr/local/bin/mosh-client", "10.0.0.1", 60001).unwrap();
        assert_eq!(cmd, "/usr/local/bin/mosh-client");
        assert_eq!(args, vec!["10.0.0.1", "60001"]);
        assert!(build_mosh_client_args("", "h", 1)
            .unwrap_err()
            .contains("moshClientPath"));
        assert!(build_mosh_client_args("x", "", 1).unwrap_err().contains("host"));
        assert!(build_mosh_client_args("x", "h", 0).unwrap_err().contains("port"));

        let mut base = HashMap::new();
        base.insert("LANG".to_string(), "C".to_string());
        base.insert("PATH".to_string(), "/x".to_string());
        let env = build_mosh_client_env(&base, "deadbeef", Some("C"), Some("public.example"));
        assert_eq!(env["MOSH_KEY"], "deadbeef");
        assert_eq!(env["MOSH_FALLBACK_HOST"], "public.example");
        assert_eq!(env["PATH"], "/x");
        assert!(!base.contains_key("MOSH_KEY"));
        let env = build_mosh_client_env(&HashMap::new(), "k", Some("C"), None);
        assert_eq!(env["TERM"], "xterm-256color");
        let mut stale = HashMap::new();
        stale.insert("MOSH_FALLBACK_HOST".to_string(), "stale.example".to_string());
        let env = build_mosh_client_env(&stale, "k", Some("C"), None);
        assert!(!env.contains_key("MOSH_FALLBACK_HOST"));
    }

    #[test]
    fn lang_and_locale_helpers() {
        assert_eq!(resolve_lang_from_charset(None), "en_US.UTF-8");
        assert_eq!(resolve_lang_from_charset(Some("UTF-8")), "en_US.UTF-8");
        assert_eq!(resolve_lang_from_charset(Some("utf8")), "en_US.UTF-8");
        assert_eq!(resolve_lang_from_charset(Some("zh_CN.GB18030")), "zh_CN.GB18030");
        let mut env = HashMap::new();
        for k in ["LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "PATH"] {
            env.insert(k.to_string(), "x".to_string());
        }
        strip_locale_env(&mut env);
        assert_eq!(env.len(), 1);
        assert!(env.contains_key("PATH"));
    }
}
