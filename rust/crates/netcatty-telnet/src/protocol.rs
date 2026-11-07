//! Telnet protocol — RFC 854 framing + RFC 858/1091/1073 options.
//!
//! Port of `electron/bridges/telnetProtocol.cjs`. The parser and the
//! negotiation policy are separate, socket-free state machines; the
//! [`TelnetCodec`] wires them together the way `terminalBridge`'s telnet
//! session does (lazy activation on the first IAC from the peer).

use std::collections::BTreeSet;

// Command bytes (RFC 854 / RFC 855).
pub const IAC: u8 = 255;
pub const SE: u8 = 240;
pub const NOP: u8 = 241;
pub const DM: u8 = 242;
pub const BRK: u8 = 243;
pub const IP: u8 = 244;
pub const AO: u8 = 245;
pub const AYT: u8 = 246;
pub const EC: u8 = 247;
pub const EL: u8 = 248;
pub const GA: u8 = 249;
pub const SB: u8 = 250;
pub const WILL: u8 = 251;
pub const WONT: u8 = 252;
pub const DO: u8 = 253;
pub const DONT: u8 = 254;

/// Options the policy layer cares about. Everything else is refused with
/// DONT / WONT so the conversation terminates cleanly.
pub mod opt {
    /// RFC 857.
    pub const ECHO: u8 = 1;
    /// RFC 858.
    pub const SUPPRESS_GO_AHEAD: u8 = 3;
    pub const STATUS: u8 = 5;
    /// RFC 1091.
    pub const TERMINAL_TYPE: u8 = 24;
    /// RFC 1073 — window size.
    pub const NAWS: u8 = 31;
    pub const TERMINAL_SPEED: u8 = 32;
    pub const LINEMODE: u8 = 34;
    pub const NEW_ENVIRON: u8 = 39;
}

pub const SUBOPTION_IS: u8 = 0;
pub const SUBOPTION_SEND: u8 = 1;

/// Terminal type advertised for TERMINAL-TYPE subnegotiation.
pub const DEFAULT_TERM_TYPE: &str = "XTERM-256COLOR";

fn is_option_command(cmd: u8) -> bool {
    matches!(cmd, WILL | WONT | DO | DONT)
}

/// Escape data for the wire: every literal 0xFF becomes 0xFF 0xFF so the peer
/// does not read it as IAC.
pub fn escape_iac(data: &[u8]) -> Vec<u8> {
    if !data.contains(&IAC) {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len() + 4);
    for &b in data {
        out.push(b);
        if b == IAC {
            out.push(IAC);
        }
    }
    out
}

/// Normalize text input to Telnet NVT newline rules (RFC 854): newline is
/// CR LF, a literal carriage return is CR NUL. Existing CR LF / CR NUL pairs
/// are kept as they are.
pub fn normalize_nvt_newlines(data: &str) -> String {
    let mut out = String::with_capacity(data.len() + 4);
    let mut chars = data.chars().peekable();
    let mut prev: Option<char> = None;
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                out.push('\r');
                match chars.peek() {
                    Some('\n') | Some('\0') => {}
                    _ => out.push('\n'),
                }
            }
            '\n' => {
                if prev != Some('\r') {
                    out.push('\r');
                }
                out.push('\n');
            }
            other => out.push(other),
        }
        prev = Some(c);
    }
    out
}

fn unescape_iac_payload(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == IAC && i + 1 < buf.len() && buf[i + 1] == IAC {
            out.push(IAC);
            i += 2;
            continue;
        }
        out.push(buf[i]);
        i += 1;
    }
    out
}

/// One parsed element of the incoming stream, in wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParserEvent {
    /// Clean stream bytes (IAC IAC already unescaped). Never empty.
    Data(Vec<u8>),
    /// WILL / WONT / DO / DONT for `opt`.
    Command { cmd: u8, opt: u8 },
    /// `IAC SB <opt> ... IAC SE`; `payload` has IAC IAC unescaped.
    Subnegotiation { opt: u8, payload: Vec<u8> },
}

/// Stateful Telnet parser. A partial command (lone IAC, IAC + verb without
/// option, unterminated subnegotiation) is kept until the next feed so a
/// sequence split across TCP frames is reassembled before being acted on.
#[derive(Debug, Default)]
pub struct Parser {
    pending: Vec<u8>,
}

impl Parser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes held back waiting for the rest of a command.
    pub fn pending_byte_count(&self) -> usize {
        self.pending.len()
    }

    /// Drop any partial command.
    pub fn reset(&mut self) {
        self.pending.clear();
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Vec<ParserEvent> {
        let mut events = Vec::new();
        if chunk.is_empty() {
            return events;
        }
        let buf: Vec<u8> = if self.pending.is_empty() {
            chunk.to_vec()
        } else {
            let mut joined = std::mem::take(&mut self.pending);
            joined.extend_from_slice(chunk);
            joined
        };

        let mut out: Vec<u8> = Vec::new();
        let flush = |out: &mut Vec<u8>, events: &mut Vec<ParserEvent>| {
            if !out.is_empty() {
                events.push(ParserEvent::Data(std::mem::take(out)));
            }
        };

        let mut i = 0;
        while i < buf.len() {
            let byte = buf[i];
            if byte != IAC {
                out.push(byte);
                i += 1;
                continue;
            }
            // At an IAC: the verb is needed to know what follows.
            if i + 1 >= buf.len() {
                self.pending = buf[i..].to_vec();
                break;
            }
            let cmd = buf[i + 1];
            if cmd == IAC {
                out.push(IAC);
                i += 2;
                continue;
            }
            if is_option_command(cmd) {
                if i + 2 >= buf.len() {
                    self.pending = buf[i..].to_vec();
                    break;
                }
                let opt = buf[i + 2];
                flush(&mut out, &mut events);
                events.push(ParserEvent::Command { cmd, opt });
                i += 3;
                continue;
            }
            if cmd == SB {
                // Find the terminating IAC SE, skipping escaped IAC IAC.
                let mut j = i + 3;
                let mut se_found = false;
                while j + 1 < buf.len() {
                    if buf[j] == IAC {
                        if buf[j + 1] == SE {
                            se_found = true;
                            break;
                        }
                        j += 2;
                        continue;
                    }
                    j += 1;
                }
                if !se_found || i + 2 >= buf.len() {
                    // Subnegotiation continues into the next frame.
                    self.pending = buf[i..].to_vec();
                    break;
                }
                let opt = buf[i + 2];
                let payload = unescape_iac_payload(&buf[i + 3..j]);
                flush(&mut out, &mut events);
                events.push(ParserEvent::Subnegotiation { opt, payload });
                i = j + 2;
                continue;
            }
            // Other two-byte commands (NOP, AYT, IP, ...): consume them so
            // they do not leak into the data stream.
            flush(&mut out, &mut events);
            i += 2;
        }
        flush(&mut out, &mut events);
        events
    }
}

/// What the negotiator wants done, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiatorOutput {
    /// Send `IAC <cmd> <opt>`.
    Command { cmd: u8, opt: u8 },
    /// Send `IAC SB <opt> <payload> IAC SE` (payload already escaped).
    Subnegotiation { opt: u8, payload: Vec<u8> },
    /// The peer enabled (`true`) / disabled remote echo.
    RemoteEcho(bool),
    /// Our local echo was enabled / disabled by the peer.
    LocalEcho(bool),
}

impl NegotiatorOutput {
    /// Wire bytes of a send action; `None` for the echo notifications.
    pub fn wire_bytes(&self) -> Option<Vec<u8>> {
        match self {
            NegotiatorOutput::Command { cmd, opt } => Some(vec![IAC, *cmd, *opt]),
            NegotiatorOutput::Subnegotiation { opt, payload } => {
                let mut out = Vec::with_capacity(payload.len() + 5);
                out.extend_from_slice(&[IAC, SB, *opt]);
                out.extend_from_slice(payload);
                out.extend_from_slice(&[IAC, SE]);
                Some(out)
            }
            NegotiatorOutput::RemoteEcho(_) | NegotiatorOutput::LocalEcho(_) => None,
        }
    }
}

/// Telnet negotiation policy: which options we accept, direction-aware
/// acknowledgement tracking and the replies to peer commands.
#[derive(Debug)]
pub struct Negotiator {
    pending_do: BTreeSet<u8>,
    pending_will: BTreeSet<u8>,
    enabled_remote: BTreeSet<u8>,
    enabled_local: BTreeSet<u8>,
    term_type: String,
    cols: u16,
    rows: u16,
}

impl Default for Negotiator {
    fn default() -> Self {
        Self::new(DEFAULT_TERM_TYPE)
    }
}

impl Negotiator {
    pub fn new(term_type: &str) -> Self {
        Self {
            pending_do: BTreeSet::new(),
            pending_will: BTreeSet::new(),
            enabled_remote: BTreeSet::new(),
            enabled_local: BTreeSet::new(),
            term_type: term_type.to_string(),
            cols: 80,
            rows: 24,
        }
    }

    /// Terminal size reported through NAWS (0 → 80x24 fallback).
    pub fn set_window_size(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
    }

    pub fn pending_do_count(&self) -> usize {
        self.pending_do.len()
    }

    pub fn pending_will_count(&self) -> usize {
        self.pending_will.len()
    }

    fn naws(&self, out: &mut Vec<NegotiatorOutput>) -> bool {
        if !self.enabled_local.contains(&opt::NAWS) {
            return false;
        }
        let cols = if self.cols > 0 { self.cols } else { 80 };
        let rows = if self.rows > 0 { self.rows } else { 24 };
        let payload = [
            (cols >> 8) as u8,
            (cols & 0xff) as u8,
            (rows >> 8) as u8,
            (rows & 0xff) as u8,
        ];
        out.push(NegotiatorOutput::Subnegotiation {
            opt: opt::NAWS,
            payload: escape_iac(&payload),
        });
        true
    }

    fn request(&mut self, cmd: u8, option: u8, out: &mut Vec<NegotiatorOutput>) {
        if cmd == DO {
            self.pending_do.insert(option);
        } else if cmd == WILL {
            self.pending_will.insert(option);
        }
        out.push(NegotiatorOutput::Command { cmd, opt: option });
    }

    /// Drive the negotiation rather than waiting for the peer: many legacy
    /// servers do not advance past their banner until the client commits to
    /// a basic option set.
    pub fn start(&mut self) -> Vec<NegotiatorOutput> {
        let mut out = Vec::new();
        self.request(DO, opt::SUPPRESS_GO_AHEAD, &mut out);
        self.request(WILL, opt::TERMINAL_TYPE, &mut out);
        self.request(WILL, opt::NAWS, &mut out);
        out
    }

    /// Send the current window size if the peer enabled NAWS.
    pub fn send_window_size(&self) -> Option<NegotiatorOutput> {
        let mut out = Vec::new();
        if self.naws(&mut out) {
            out.pop()
        } else {
            None
        }
    }

    pub fn handle_command(&mut self, cmd: u8, option: u8) -> Vec<NegotiatorOutput> {
        let mut out = Vec::new();
        let send = |out: &mut Vec<NegotiatorOutput>, cmd: u8| {
            out.push(NegotiatorOutput::Command { cmd, opt: option });
        };
        let mut acknowledges_our_request = false;
        if (cmd == WILL || cmd == WONT) && self.pending_do.contains(&option) {
            self.pending_do.remove(&option);
            acknowledges_our_request = true;
        } else if (cmd == DO || cmd == DONT) && self.pending_will.contains(&option) {
            self.pending_will.remove(&option);
            acknowledges_our_request = true;
        }

        match cmd {
            WILL => {
                let supported = option == opt::SUPPRESS_GO_AHEAD || option == opt::ECHO;
                let was_enabled = self.enabled_remote.contains(&option);
                if supported {
                    self.enabled_remote.insert(option);
                }
                if option == opt::ECHO {
                    out.push(NegotiatorOutput::RemoteEcho(true));
                    if self.enabled_local.remove(&option) {
                        out.push(NegotiatorOutput::LocalEcho(false));
                        send(&mut out, WONT);
                    }
                }
                if !acknowledges_our_request {
                    if supported && !was_enabled {
                        send(&mut out, DO);
                    } else if !supported {
                        send(&mut out, DONT);
                    }
                }
            }
            DO => {
                let was_enabled = self.enabled_local.contains(&option);
                if option == opt::NAWS {
                    self.enabled_local.insert(option);
                    if !acknowledges_our_request && !was_enabled {
                        send(&mut out, WILL);
                    }
                    // Follow through with the size when NAWS first becomes
                    // active, whether this DO acknowledges our WILL or not.
                    if !was_enabled {
                        self.naws(&mut out);
                    }
                } else if option == opt::ECHO {
                    self.enabled_local.insert(option);
                    if !acknowledges_our_request && !was_enabled {
                        send(&mut out, WILL);
                    }
                    if !was_enabled {
                        out.push(NegotiatorOutput::LocalEcho(true));
                    }
                } else if option == opt::TERMINAL_TYPE || option == opt::SUPPRESS_GO_AHEAD {
                    self.enabled_local.insert(option);
                    if !acknowledges_our_request && !was_enabled {
                        send(&mut out, WILL);
                    }
                } else if !acknowledges_our_request {
                    send(&mut out, WONT);
                }
            }
            DONT => {
                let was_enabled = self.enabled_local.remove(&option);
                if option == opt::ECHO && was_enabled {
                    out.push(NegotiatorOutput::LocalEcho(false));
                }
                if !acknowledges_our_request && (was_enabled || self.pending_will.contains(&option))
                {
                    send(&mut out, WONT);
                }
            }
            WONT => {
                let was_enabled = self.enabled_remote.remove(&option);
                if option == opt::ECHO {
                    out.push(NegotiatorOutput::RemoteEcho(false));
                }
                if !acknowledges_our_request && was_enabled {
                    send(&mut out, DONT);
                }
            }
            _ => {}
        }
        out
    }

    pub fn handle_subnegotiation(&mut self, option: u8, payload: &[u8]) -> Vec<NegotiatorOutput> {
        let mut out = Vec::new();
        if option == opt::TERMINAL_TYPE && payload.first() == Some(&SUBOPTION_SEND) {
            let mut reply = vec![SUBOPTION_IS];
            reply.extend(self.term_type.bytes().filter(u8::is_ascii));
            out.push(NegotiatorOutput::Subnegotiation {
                opt: opt::TERMINAL_TYPE,
                payload: reply,
            });
        }
        out
    }
}

/// Echo state published to the renderer (`netcatty:telnet:echo-mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoMode {
    pub remote_echo: bool,
    pub local_echo: bool,
}

impl Default for EchoMode {
    fn default() -> Self {
        Self {
            remote_echo: true,
            local_echo: false,
        }
    }
}

/// Result of feeding peer bytes through the [`TelnetCodec`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Incoming {
    /// Clean terminal bytes for the decoder.
    pub data: Vec<u8>,
    /// Negotiation replies to write back to the peer (already framed).
    pub reply: Vec<u8>,
    /// One snapshot per echo notification, in order (Electron publishes the
    /// full mode on every change notification, repeats included).
    pub echo_updates: Vec<EchoMode>,
}

/// A telnet session's protocol state.
///
/// Negotiation only activates once the peer sends an IAC byte: legacy
/// raw-TCP services on port 23 never speak the protocol, and treating their
/// stray 0xFF bytes as IAC would corrupt the stream.
#[derive(Debug, Default)]
pub struct TelnetCodec {
    active: bool,
    parser: Parser,
    negotiator: Negotiator,
    echo: EchoMode,
}

impl TelnetCodec {
    pub fn new(cols: u16, rows: u16) -> Self {
        let mut negotiator = Negotiator::default();
        negotiator.set_window_size(cols, rows);
        Self {
            active: false,
            parser: Parser::new(),
            negotiator,
            echo: EchoMode::default(),
        }
    }

    /// Has the peer spoken the telnet protocol yet?
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn echo_mode(&self) -> EchoMode {
        self.echo
    }

    fn apply(&mut self, outputs: Vec<NegotiatorOutput>, incoming: &mut Incoming) {
        for output in outputs {
            match output {
                NegotiatorOutput::RemoteEcho(on) => {
                    self.echo.remote_echo = on;
                    incoming.echo_updates.push(self.echo);
                }
                NegotiatorOutput::LocalEcho(on) => {
                    self.echo.local_echo = on;
                    incoming.echo_updates.push(self.echo);
                }
                other => {
                    if let Some(bytes) = other.wire_bytes() {
                        incoming.reply.extend_from_slice(&bytes);
                    }
                }
            }
        }
    }

    /// Process bytes received from the peer.
    pub fn incoming(&mut self, data: &[u8]) -> Incoming {
        let mut result = Incoming::default();
        if !self.active {
            if !data.contains(&IAC) {
                result.data = data.to_vec();
                return result;
            }
            self.active = true;
            let start = self.negotiator.start();
            self.apply(start, &mut result);
        }
        for event in self.parser.feed(data) {
            match event {
                ParserEvent::Data(bytes) => result.data.extend_from_slice(&bytes),
                ParserEvent::Command { cmd, opt } => {
                    let outputs = self.negotiator.handle_command(cmd, opt);
                    self.apply(outputs, &mut result);
                }
                ParserEvent::Subnegotiation { opt, payload } => {
                    let outputs = self.negotiator.handle_subnegotiation(opt, &payload);
                    self.apply(outputs, &mut result);
                }
            }
        }
        result
    }

    /// Frame outgoing terminal bytes: 0xFF is doubled once the protocol is
    /// active (raw-TCP peers get the bytes unchanged).
    pub fn outgoing(&self, data: &[u8]) -> Vec<u8> {
        if self.active {
            escape_iac(data)
        } else {
            data.to_vec()
        }
    }

    /// Record a new terminal size; returns the NAWS frame to send when the
    /// protocol is active and the peer enabled NAWS.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Option<Vec<u8>> {
        self.negotiator.set_window_size(cols, rows);
        if !self.active {
            return None;
        }
        self.negotiator
            .send_window_size()
            .and_then(|o| o.wire_bytes())
    }
}

#[cfg(test)]
mod tests {
    //! Ported from `electron/bridges/telnetProtocol.test.cjs`.
    use super::*;

    fn data_of(events: &[ParserEvent]) -> Vec<u8> {
        events
            .iter()
            .filter_map(|e| match e {
                ParserEvent::Data(d) => Some(d.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn commands_of(events: &[ParserEvent]) -> Vec<(u8, u8)> {
        events
            .iter()
            .filter_map(|e| match e {
                ParserEvent::Command { cmd, opt } => Some((*cmd, *opt)),
                _ => None,
            })
            .collect()
    }

    fn subnegs_of(events: &[ParserEvent]) -> Vec<(u8, Vec<u8>)> {
        events
            .iter()
            .filter_map(|e| match e {
                ParserEvent::Subnegotiation { opt, payload } => Some((*opt, payload.clone())),
                _ => None,
            })
            .collect()
    }

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn escape_iac_passthrough_and_doubling() {
        assert_eq!(escape_iac(b"abc"), b"abc");
        assert_eq!(
            escape_iac(&[0xff, 0x61, 0xff, 0xff, 0x62]),
            vec![0xff, 0xff, 0x61, 0xff, 0xff, 0xff, 0xff, 0x62]
        );
    }

    #[test]
    fn nvt_newlines() {
        assert_eq!(normalize_nvt_newlines("ps\r"), "ps\r\n");
        assert_eq!(normalize_nvt_newlines("ps\n"), "ps\r\n");
        assert_eq!(normalize_nvt_newlines("ps\r\n"), "ps\r\n");
        assert_eq!(normalize_nvt_newlines("red\r\0raw"), "red\r\0raw");
        assert_eq!(normalize_nvt_newlines("a\n\nb\r\r"), "a\r\n\r\nb\r\n\r\n");
        assert_eq!(normalize_nvt_newlines(""), "");
    }

    #[test]
    fn parser_clean_data() {
        let mut p = Parser::new();
        let ev = p.feed(b"hello world");
        assert_eq!(data_of(&ev), b"hello world");
        assert!(commands_of(&ev).is_empty());
        assert!(subnegs_of(&ev).is_empty());
    }

    #[test]
    fn parser_complete_do() {
        let mut p = Parser::new();
        let ev = p.feed(&[IAC, DO, opt::SUPPRESS_GO_AHEAD]);
        assert!(data_of(&ev).is_empty());
        assert_eq!(commands_of(&ev), vec![(DO, opt::SUPPRESS_GO_AHEAD)]);
    }

    #[test]
    fn parser_splits_data_around_command() {
        let mut p = Parser::new();
        let ev = p.feed(&cat(&[b"login: ", &[IAC, WILL, opt::ECHO], b"admin"]));
        assert_eq!(data_of(&ev), b"login: admin");
        assert_eq!(commands_of(&ev), vec![(WILL, opt::ECHO)]);
    }

    #[test]
    fn parser_unescapes_iac_iac() {
        let mut p = Parser::new();
        assert_eq!(
            data_of(&p.feed(&[0x61, IAC, IAC, 0x62])),
            vec![0x61, 0xff, 0x62]
        );
    }

    #[test]
    fn parser_ignores_nop() {
        let mut p = Parser::new();
        let ev = p.feed(&[0x61, IAC, NOP, 0x62]);
        assert_eq!(data_of(&ev), vec![0x61, 0x62]);
        assert!(commands_of(&ev).is_empty());
    }

    #[test]
    fn parser_complete_subnegotiation() {
        let mut p = Parser::new();
        let ev = p.feed(&cat(&[
            &[IAC, SB, opt::TERMINAL_TYPE, 0],
            b"XTERM",
            &[IAC, SE],
        ]));
        assert!(data_of(&ev).is_empty());
        assert_eq!(
            subnegs_of(&ev),
            vec![(opt::TERMINAL_TYPE, vec![0, 0x58, 0x54, 0x45, 0x52, 0x4d])]
        );
    }

    #[test]
    fn parser_iac_iac_inside_subnegotiation() {
        let mut p = Parser::new();
        let ev = p.feed(&[IAC, SB, opt::STATUS, IAC, IAC, 0x01, IAC, SE]);
        assert_eq!(subnegs_of(&ev), vec![(opt::STATUS, vec![0xff, 0x01])]);
    }

    #[test]
    fn parser_keeps_lone_iac() {
        let mut p = Parser::new();
        let mut events = p.feed(&cat(&[b"hi", &[IAC]]));
        assert_eq!(data_of(&events), b"hi");
        assert_eq!(p.pending_byte_count(), 1);
        events.extend(p.feed(&[DO, opt::NAWS, 0x61]));
        assert_eq!(p.pending_byte_count(), 0);
        assert_eq!(commands_of(&events), vec![(DO, opt::NAWS)]);
        assert_eq!(data_of(&events), b"hia");
    }

    #[test]
    fn parser_keeps_half_command() {
        let mut p = Parser::new();
        let mut events = p.feed(&[0x61, IAC, DO]);
        assert_eq!(data_of(&events), b"a");
        assert_eq!(p.pending_byte_count(), 2);
        events.extend(p.feed(&[opt::TERMINAL_TYPE, 0x62]));
        assert_eq!(commands_of(&events), vec![(DO, opt::TERMINAL_TYPE)]);
        assert_eq!(data_of(&events), b"ab");
    }

    #[test]
    fn parser_keeps_unterminated_subnegotiation() {
        let mut p = Parser::new();
        let mut events = p.feed(&cat(&[
            b"prefix",
            &[IAC, SB, opt::TERMINAL_TYPE, 0],
            b"XTE",
        ]));
        assert_eq!(data_of(&events), b"prefix");
        assert!(subnegs_of(&events).is_empty());
        events.extend(p.feed(&cat(&[b"RM-256COLOR", &[IAC, SE], b" tail"])));
        assert_eq!(
            subnegs_of(&events),
            vec![(opt::TERMINAL_TYPE, b"\x00XTERM-256COLOR".to_vec())]
        );
        assert_eq!(data_of(&events), b"prefix tail");
    }

    #[test]
    fn parser_does_not_leak_unterminated_sb() {
        let mut p = Parser::new();
        let ev = p.feed(&cat(&[&[IAC, SB, opt::TERMINAL_TYPE, 0], b"XTERM-PARTIAL"]));
        assert!(data_of(&ev).is_empty());
        assert!(subnegs_of(&ev).is_empty());
        assert!(p.pending_byte_count() > 0);
    }

    #[test]
    fn parser_two_consecutive_commands() {
        let mut p = Parser::new();
        let ev = p.feed(&[IAC, WILL, opt::ECHO, IAC, DO, opt::SUPPRESS_GO_AHEAD]);
        assert_eq!(
            commands_of(&ev),
            vec![(WILL, opt::ECHO), (DO, opt::SUPPRESS_GO_AHEAD)]
        );
    }

    #[test]
    fn parser_empty_feed_and_reset() {
        let mut p = Parser::new();
        assert!(p.feed(&[]).is_empty());
        p.feed(&[IAC]);
        assert_eq!(p.pending_byte_count(), 1);
        p.reset();
        assert_eq!(p.pending_byte_count(), 0);
    }

    #[test]
    fn parser_preserves_order() {
        let mut p = Parser::new();
        let ev = p.feed(&cat(&[b"hi", &[IAC, WONT, opt::LINEMODE], b"bye"]));
        assert_eq!(
            ev,
            vec![
                ParserEvent::Data(b"hi".to_vec()),
                ParserEvent::Command {
                    cmd: WONT,
                    opt: opt::LINEMODE
                },
                ParserEvent::Data(b"bye".to_vec()),
            ]
        );
    }

    fn sized() -> Negotiator {
        let mut n = Negotiator::default();
        n.set_window_size(120, 40);
        n
    }

    fn cmds(out: &[NegotiatorOutput]) -> Vec<(u8, u8)> {
        out.iter()
            .filter_map(|o| match o {
                NegotiatorOutput::Command { cmd, opt } => Some((*cmd, *opt)),
                _ => None,
            })
            .collect()
    }

    fn subs(out: &[NegotiatorOutput]) -> Vec<(u8, Vec<u8>)> {
        out.iter()
            .filter_map(|o| match o {
                NegotiatorOutput::Subnegotiation { opt, payload } => Some((*opt, payload.clone())),
                _ => None,
            })
            .collect()
    }

    fn local_echo(out: &[NegotiatorOutput]) -> Vec<bool> {
        out.iter()
            .filter_map(|o| match o {
                NegotiatorOutput::LocalEcho(v) => Some(*v),
                _ => None,
            })
            .collect()
    }

    fn remote_echo(out: &[NegotiatorOutput]) -> Vec<bool> {
        out.iter()
            .filter_map(|o| match o {
                NegotiatorOutput::RemoteEcho(v) => Some(*v),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn start_drives_canonical_handshake() {
        let mut n = sized();
        assert_eq!(
            cmds(&n.start()),
            vec![
                (DO, opt::SUPPRESS_GO_AHEAD),
                (WILL, opt::TERMINAL_TYPE),
                (WILL, opt::NAWS)
            ]
        );
        assert_eq!(n.pending_do_count(), 1);
        assert_eq!(n.pending_will_count(), 2);
    }

    #[test]
    fn will_on_pending_do_is_swallowed() {
        let mut n = sized();
        n.start();
        assert!(cmds(&n.handle_command(WILL, opt::SUPPRESS_GO_AHEAD)).is_empty());
        assert_eq!(n.pending_do_count(), 0);
    }

    #[test]
    fn independent_do_sga_with_pending_do_replies_will() {
        let mut n = sized();
        n.start();
        assert_eq!(
            cmds(&n.handle_command(DO, opt::SUPPRESS_GO_AHEAD)),
            vec![(WILL, opt::SUPPRESS_GO_AHEAD)]
        );
        assert_eq!(n.pending_do_count(), 1);
    }

    #[test]
    fn do_naws_ack_still_sends_size() {
        let mut n = sized();
        n.start();
        let out = n.handle_command(DO, opt::NAWS);
        assert!(cmds(&out).is_empty());
        assert_eq!(subs(&out), vec![(opt::NAWS, vec![0, 120, 0, 40])]);
        assert_eq!(n.pending_will_count(), 1);
    }

    #[test]
    fn independent_do_naws_replies_will_and_size() {
        let mut n = sized();
        let out = n.handle_command(DO, opt::NAWS);
        assert_eq!(cmds(&out), vec![(WILL, opt::NAWS)]);
        assert_eq!(subs(&out).len(), 1);
    }

    #[test]
    fn send_window_size_silent_until_naws_enabled() {
        let mut n = sized();
        n.start();
        assert!(n.send_window_size().is_none());
    }

    #[test]
    fn repeated_do_is_ignored() {
        let mut n = sized();
        let mut out = n.handle_command(DO, opt::NAWS);
        out.extend(n.handle_command(DO, opt::NAWS));
        out.extend(n.handle_command(DO, opt::SUPPRESS_GO_AHEAD));
        out.extend(n.handle_command(DO, opt::SUPPRESS_GO_AHEAD));
        assert_eq!(
            cmds(&out),
            vec![(WILL, opt::NAWS), (WILL, opt::SUPPRESS_GO_AHEAD)]
        );
        assert_eq!(subs(&out).len(), 1);
    }

    #[test]
    fn do_dont_echo_controls_local_echo() {
        let mut n = sized();
        let mut out = n.handle_command(DO, opt::ECHO);
        out.extend(n.handle_command(DO, opt::ECHO));
        out.extend(n.handle_command(DONT, opt::ECHO));
        out.extend(n.handle_command(DONT, opt::ECHO));
        assert_eq!(local_echo(&out), vec![true, false]);
        assert_eq!(cmds(&out), vec![(WILL, opt::ECHO), (WONT, opt::ECHO)]);
    }

    #[test]
    fn will_echo_triggers_do_once() {
        let mut n = sized();
        let mut out = n.handle_command(WILL, opt::ECHO);
        out.extend(n.handle_command(WILL, opt::ECHO));
        assert_eq!(cmds(&out), vec![(DO, opt::ECHO)]);
    }

    #[test]
    fn will_echo_disables_local_echo() {
        let mut n = sized();
        let first = n.handle_command(DO, opt::ECHO);
        let out = n.handle_command(WILL, opt::ECHO);
        let mut all = first.clone();
        all.extend(out.clone());
        assert_eq!(local_echo(&all), vec![true, false]);
        assert_eq!(cmds(&out), vec![(WONT, opt::ECHO), (DO, opt::ECHO)]);
    }

    #[test]
    fn echo_negotiation_publishes_remote_echo() {
        let mut n = sized();
        let mut out = n.handle_command(WILL, opt::ECHO);
        out.extend(n.handle_command(WONT, opt::ECHO));
        assert_eq!(remote_echo(&out), vec![true, false]);
    }

    #[test]
    fn wont_on_pending_do_is_swallowed() {
        let mut n = sized();
        n.start();
        assert!(cmds(&n.handle_command(WONT, opt::SUPPRESS_GO_AHEAD)).is_empty());
        assert_eq!(n.pending_do_count(), 0);
    }

    #[test]
    fn repeated_wont_echo_not_looped() {
        let mut n = sized();
        n.handle_command(WILL, opt::ECHO);
        let mut out = n.handle_command(WONT, opt::ECHO);
        out.extend(n.handle_command(WONT, opt::ECHO));
        assert_eq!(cmds(&out), vec![(DONT, opt::ECHO)]);
    }

    #[test]
    fn dont_on_pending_will_is_swallowed() {
        let mut n = sized();
        n.start();
        assert!(cmds(&n.handle_command(DONT, opt::TERMINAL_TYPE)).is_empty());
        assert_eq!(n.pending_will_count(), 1);
    }

    #[test]
    fn repeated_dont_not_looped() {
        let mut n = sized();
        n.handle_command(DO, opt::SUPPRESS_GO_AHEAD);
        let mut out = n.handle_command(DONT, opt::SUPPRESS_GO_AHEAD);
        out.extend(n.handle_command(DONT, opt::SUPPRESS_GO_AHEAD));
        assert_eq!(cmds(&out), vec![(WONT, opt::SUPPRESS_GO_AHEAD)]);
    }

    #[test]
    fn unsupported_options_are_refused() {
        let mut n = sized();
        assert_eq!(
            cmds(&n.handle_command(DO, opt::LINEMODE)),
            vec![(WONT, opt::LINEMODE)]
        );
        assert_eq!(
            cmds(&n.handle_command(WILL, opt::NEW_ENVIRON)),
            vec![(DONT, opt::NEW_ENVIRON)]
        );
    }

    #[test]
    fn terminal_type_send_replies_is() {
        let mut n = sized();
        let out = n.handle_subnegotiation(opt::TERMINAL_TYPE, &[SUBOPTION_SEND]);
        assert_eq!(
            subs(&out),
            vec![(opt::TERMINAL_TYPE, b"\x00XTERM-256COLOR".to_vec())]
        );
        let mut custom = Negotiator::new("VT100");
        let out = custom.handle_subnegotiation(opt::TERMINAL_TYPE, &[SUBOPTION_SEND]);
        assert_eq!(subs(&out)[0].1, b"\x00VT100".to_vec());
    }

    #[test]
    fn window_size_falls_back_to_80x24() {
        let mut n = Negotiator::default();
        n.set_window_size(0, 0);
        n.handle_command(DO, opt::NAWS);
        let sent = n.send_window_size().expect("naws enabled");
        assert_eq!(
            sent,
            NegotiatorOutput::Subnegotiation {
                opt: opt::NAWS,
                payload: vec![0, 80, 0, 24]
            }
        );
        assert_eq!(
            sent.wire_bytes().unwrap(),
            vec![IAC, SB, opt::NAWS, 0, 80, 0, 24, IAC, SE]
        );
    }

    #[test]
    fn naws_payload_escapes_255() {
        let mut n = Negotiator::default();
        n.set_window_size(255, 24);
        let out = n.handle_command(DO, opt::NAWS);
        assert_eq!(subs(&out)[0].1, vec![0, 0xff, 0xff, 0, 24]);
    }

    // --- codec (mirrors terminalBridge.telnet*.test.cjs behaviour) ---------

    #[test]
    fn codec_passes_raw_tcp_through_until_first_iac() {
        let mut c = TelnetCodec::new(80, 24);
        let r = c.incoming(b"plain banner\r\n");
        assert_eq!(r.data, b"plain banner\r\n");
        assert!(r.reply.is_empty());
        assert!(!c.is_active());
        // Outgoing 0xFF is not escaped for raw peers, and resize is silent.
        assert_eq!(c.outgoing(&[0xff]), vec![0xff]);
        assert!(c.resize(100, 30).is_none());
    }

    #[test]
    fn codec_activates_and_negotiates() {
        let mut c = TelnetCodec::new(100, 30);
        let r = c.incoming(&cat(&[b"hi", &[IAC, DO, opt::NAWS], b"!"]));
        assert!(c.is_active());
        assert_eq!(r.data, b"hi!");
        // start(): DO SGA, WILL TT, WILL NAWS; then the NAWS size (the DO
        // acknowledges our WILL so no second WILL).
        assert_eq!(
            r.reply,
            cat(&[
                &[IAC, DO, opt::SUPPRESS_GO_AHEAD],
                &[IAC, WILL, opt::TERMINAL_TYPE],
                &[IAC, WILL, opt::NAWS],
                &[IAC, SB, opt::NAWS, 0, 100, 0, 30, IAC, SE],
            ])
        );
        assert_eq!(c.outgoing(&[0x61, 0xff]), vec![0x61, 0xff, 0xff]);
        assert_eq!(
            c.resize(132, 43).unwrap(),
            vec![IAC, SB, opt::NAWS, 0, 132, 0, 43, IAC, SE]
        );
    }

    #[test]
    fn codec_tracks_echo_mode() {
        let mut c = TelnetCodec::new(80, 24);
        assert_eq!(c.echo_mode(), EchoMode::default());
        let r = c.incoming(&[IAC, WILL, opt::ECHO]);
        assert_eq!(
            r.echo_updates,
            vec![EchoMode {
                remote_echo: true,
                local_echo: false
            }]
        );
        let r = c.incoming(&[IAC, WONT, opt::ECHO, IAC, DO, opt::ECHO]);
        assert_eq!(
            r.echo_updates,
            vec![
                EchoMode {
                    remote_echo: false,
                    local_echo: false
                },
                EchoMode {
                    remote_echo: false,
                    local_echo: true
                },
            ]
        );
        assert_eq!(
            c.echo_mode(),
            EchoMode {
                remote_echo: false,
                local_echo: true
            }
        );
    }
}
