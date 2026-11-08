//! ZMODEM sentry: sits between a terminal transport and the display.
//!
//! Port of `createZmodemSentry` (`electron/bridges/zmodemHelper.cjs`) and
//! `Zmodem.Sentry` (`zmodem.js`). Every raw output chunk of a session goes
//! through [`Sentry::consume`]:
//!
//! * without a transfer, the chunk is scanned for the `sz` (ZRQINIT) /
//!   `rz` (ZRINIT) start header; the bytes that may be displayed are
//!   returned after the Netcatty sanitising stages (command-echo
//!   suppression, visible hex-header stripping, withholding a hex header
//!   split across chunks);
//! * during a transfer the bytes feed the protocol session and nothing (but
//!   pre-header garbage) reaches the terminal;
//! * after an abort, output is swallowed for a short cooldown while the
//!   remote drains its buffers.
//!
//! Time is passed in explicitly so the behaviour is testable.

use crate::header::{self, FrameType, Header, HEX_HEADER_PREFIX};
use crate::session::{FileInfo, ReceiveEvent, ReceiveSession, SendEvent, SendSession};
use crate::{ZResult, ZmodemError, EXTRA_ABORT_BYTES, XON, ZDLE};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Transfer direction from Netcatty's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Remote `sz`: Netcatty receives (download).
    Receive,
    /// Remote `rz`: Netcatty sends (upload).
    Send,
}

impl Role {
    /// `transferType` of the renderer events.
    pub fn transfer_type(self) -> &'static str {
        match self {
            Role::Receive => "download",
            Role::Send => "upload",
        }
    }
}

/// Timing knobs (defaults are the Electron constants).
#[derive(Debug, Clone)]
pub struct SentryConfig {
    /// Output swallowed after an abort.
    pub cooldown: Duration,
    /// How long an echo of our own protocol bytes may be stripped.
    pub echo_ttl: Duration,
    /// How long a drag-drop command echo suppression stays armed.
    pub suppression_ttl: Duration,
    /// How long a withheld partial hex header may wait for completion.
    pub fragment_ttl: Duration,
    /// Same for a fragment made only of `*` (could be shell echo).
    pub printable_prefix_ttl: Duration,
}

impl Default for SentryConfig {
    fn default() -> Self {
        Self {
            cooldown: Duration::from_millis(2000),
            echo_ttl: Duration::from_millis(1500),
            suppression_ttl: Duration::from_millis(5000),
            fragment_ttl: Duration::from_millis(1000),
            printable_prefix_ttl: Duration::from_millis(16),
        }
    }
}

const ECHO_MAX_BYTES: usize = 256;
/// `**` ZDLE `B` `0`: what every ZRQINIT / ZRINIT hex header starts with.
const COMMON_ZM_HEX_START: [u8; 5] = [b'*', b'*', ZDLE, b'B', b'0'];
/// Longest partial hex header (prefix + 14 digits + CR) before its LF.
const HEX_HEADER_MAX_PARTIAL: usize = 19;
/// Detection cache kept between chunks.
const DETECTION_CACHE: usize = 24;

#[derive(Debug)]
pub enum Active {
    Receive(ReceiveSession),
    Send(SendSession),
}

/// Result of one [`Sentry::consume`].
#[derive(Debug, Default)]
pub struct ConsumeResult {
    /// Bytes to decode and show in the terminal.
    pub terminal: Vec<u8>,
    /// A transfer started with this chunk.
    pub detected: Option<Role>,
    pub rx_events: Vec<ReceiveEvent>,
    pub tx_events: Vec<SendEvent>,
    /// The transfer ended normally with this chunk.
    pub ended: bool,
    /// The transfer failed with this chunk (already aborted).
    pub error: Option<String>,
    /// Send Ctrl+C to the remote shortly (stuck `rz` / `sz` after CAN).
    pub interrupt: bool,
}

#[derive(Debug)]
pub struct Sentry {
    config: SentryConfig,
    cache: Vec<u8>,
    active: Option<Active>,
    out: Vec<Vec<u8>>,
    echoes: VecDeque<(Vec<u8>, Instant)>,
    suppression: Option<(Vec<u8>, Instant)>,
    fragment: Option<Vec<u8>>,
    fragment_deadline: Option<Instant>,
    emitted_prefix: usize,
    suppress_next_xon: bool,
    cooldown_until: Option<Instant>,
    last_cooldown_abort: Option<Instant>,
    ignore_detection_until: Option<Instant>,
    /// "OO" bytes may still follow a finished receive session.
    expect_oo_until: Option<Instant>,
}

impl Default for Sentry {
    fn default() -> Self {
        Self::new(SentryConfig::default())
    }
}

impl Sentry {
    pub fn new(config: SentryConfig) -> Self {
        Self {
            config,
            cache: Vec::new(),
            active: None,
            out: Vec::new(),
            echoes: VecDeque::new(),
            suppression: None,
            fragment: None,
            fragment_deadline: None,
            emitted_prefix: 0,
            suppress_next_xon: false,
            cooldown_until: None,
            last_cooldown_abort: None,
            ignore_detection_until: None,
            expect_oo_until: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.is_some()
    }

    pub fn role(&self) -> Option<Role> {
        match self.active {
            Some(Active::Receive(_)) => Some(Role::Receive),
            Some(Active::Send(_)) => Some(Role::Send),
            None => None,
        }
    }

    /// Wire writes queued since the last call, in order.
    pub fn take_outgoing(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.out)
    }

    /// Earliest time [`Sentry::flush_expired`] has something to release.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.fragment_deadline
    }

    /// Whether this sentry holds any state worth keeping between chunks
    /// (callers may drop an idle sentry to skip the scan).
    pub fn is_idle(&self, now: Instant) -> bool {
        self.active.is_none()
            && self.cache.is_empty()
            && self.fragment.is_none()
            && self.suppression.is_none()
            && self.echoes.is_empty()
            && self.cooldown_until.is_none_or(|t| now >= t)
            && self.ignore_detection_until.is_none_or(|t| now >= t)
            && self.expect_oo_until.is_none_or(|t| now >= t)
    }

    fn push_out(&mut self, bytes: Vec<u8>, now: Instant) {
        if bytes.is_empty() {
            return;
        }
        if bytes.len() <= ECHO_MAX_BYTES {
            self.prune_echoes(now);
            self.echoes.push_back((bytes.clone(), now + self.config.echo_ttl));
        }
        self.out.push(bytes);
    }

    fn drain_session_out(&mut self, now: Instant) {
        let bytes = match &mut self.active {
            Some(Active::Receive(s)) => s.take_outgoing(),
            Some(Active::Send(s)) => s.take_outgoing(),
            None => return,
        };
        self.push_out(bytes, now);
    }

    fn prune_echoes(&mut self, now: Instant) {
        while self.echoes.front().is_some_and(|(_, exp)| *exp <= now) {
            self.echoes.pop_front();
        }
    }

    fn strip_echoes<'a>(&mut self, data: &'a [u8], now: Instant) -> &'a [u8] {
        if self.echoes.is_empty() {
            return data;
        }
        self.prune_echoes(now);
        let mut buf = data;
        while let Some((echo, _)) = self.echoes.front() {
            if buf.is_empty() || buf.len() < echo.len() || &buf[..echo.len()] != echo.as_slice() {
                break;
            }
            buf = &buf[echo.len()..];
            self.echoes.pop_front();
        }
        buf
    }

    // -- renderer-driven actions --------------------------------------------

    /// Remember a command Netcatty types (drag-drop `rz -y\r`) so its echo
    /// is hidden. The caller writes the command itself.
    pub fn arm_command_echo(&mut self, command: &[u8], now: Instant) {
        if command.len() <= ECHO_MAX_BYTES {
            self.prune_echoes(now);
            self.echoes.push_back((command.to_vec(), now + self.config.echo_ttl));
        }
        let visible = command.strip_suffix(b"\r").unwrap_or(command);
        self.suppression = Some((visible.to_vec(), now));
    }

    /// Drop a pending command-echo suppression (the drag-drop upload never
    /// started, so it must not eat the user's next command).
    pub fn clear_suppression(&mut self) {
        self.suppression = None;
    }

    /// Ignore new transfer starts until `now + duration`.
    pub fn ignore_detection_for(&mut self, duration: Duration, now: Instant) {
        self.ignore_detection_until = Some(now + duration);
    }

    /// Queue the extra CANs that stop a streaming sender.
    pub fn send_extra_abort(&mut self) {
        self.out.push(EXTRA_ABORT_BYTES.to_vec());
    }

    /// Cancel the active transfer (user request): abort the session, send
    /// extra CANs and start the cooldown. Returns the cancelled role.
    pub fn cancel(&mut self, now: Instant) -> Option<Role> {
        let role = self.role()?;
        match &mut self.active {
            Some(Active::Receive(s)) => s.abort(),
            Some(Active::Send(s)) => s.abort(),
            None => {}
        }
        self.drain_session_out(now);
        self.active = None;
        self.send_extra_abort();
        self.start_cooldown(now);
        Some(role)
    }

    fn start_cooldown(&mut self, now: Instant) {
        self.cooldown_until = Some(now + self.config.cooldown);
        self.last_cooldown_abort = Some(now);
    }

    /// Accept the pending download offer.
    pub fn rx_accept(&mut self, offset: u32, now: Instant) -> ZResult<()> {
        match &mut self.active {
            Some(Active::Receive(s)) => s.accept(offset)?,
            _ => return Err(ZmodemError::protocol("No active download")),
        }
        self.drain_session_out(now);
        Ok(())
    }

    /// Skip the pending download offer.
    pub fn rx_skip(&mut self, now: Instant) -> ZResult<()> {
        match &mut self.active {
            Some(Active::Receive(s)) => s.skip()?,
            _ => return Err(ZmodemError::protocol("No active download")),
        }
        self.drain_session_out(now);
        Ok(())
    }

    fn with_send<T>(
        &mut self,
        now: Instant,
        f: impl FnOnce(&mut SendSession) -> ZResult<T>,
    ) -> ZResult<T> {
        let result = match &mut self.active {
            Some(Active::Send(s)) => f(s),
            _ => Err(ZmodemError::protocol("No active upload")),
        };
        self.drain_session_out(now);
        result
    }

    pub fn tx_offer(&mut self, info: &FileInfo, now: Instant) -> ZResult<()> {
        self.with_send(now, |s| s.offer(info))
    }

    pub fn tx_send_data(&mut self, data: &[u8], last: bool, now: Instant) -> ZResult<()> {
        self.with_send(now, |s| s.send_data(data, last))
    }

    pub fn tx_reposition(&mut self, offset: u32, now: Instant) -> ZResult<()> {
        self.with_send(now, |s| {
            s.reposition(offset);
            Ok(())
        })
    }

    pub fn tx_close(&mut self, now: Instant) -> ZResult<()> {
        self.with_send(now, |s| s.close())
    }

    pub fn tx_keepalive(&mut self, now: Instant) -> ZResult<()> {
        self.with_send(now, |s| {
            s.keepalive();
            Ok(())
        })
    }

    /// Abort the active session without the cooldown (dialog cancel paths
    /// abort through the session, then send CAN + Ctrl+C).
    pub fn abort_session(&mut self, now: Instant) -> Option<Role> {
        self.cancel(now)
    }

    // -- output path ----------------------------------------------------------

    /// Feed a raw output chunk.
    pub fn consume(&mut self, data: &[u8], now: Instant) -> ConsumeResult {
        let mut result = ConsumeResult::default();

        // During the post-abort cooldown everything is dropped: `sz` may
        // still stream arbitrary file bytes from SSH/TCP buffers. Keep
        // sending CAN in case earlier ones were lost in the flood.
        if let Some(until) = self.cooldown_until {
            if now < until {
                if self
                    .last_cooldown_abort
                    .is_none_or(|t| now.duration_since(t) > Duration::from_millis(200))
                {
                    self.send_extra_abort();
                    self.last_cooldown_abort = Some(now);
                }
                return result;
            }
            self.cooldown_until = None;
            self.last_cooldown_abort = None;
        }

        let data = self.strip_echoes(data, now);
        if data.is_empty() {
            return result;
        }
        let mut input: Vec<u8> = data.to_vec();

        if self.active.is_some() {
            let outcome = match self.active.as_mut() {
                Some(Active::Receive(s)) => s.consume(&input).map(|(events, garbage)| {
                    let ended = s.has_ended();
                    result.rx_events = events;
                    (garbage, ended, if ended { s.take_trailing() } else { Vec::new() })
                }),
                Some(Active::Send(s)) => s.consume(&input).map(|(events, garbage)| {
                    let ended = s.has_ended();
                    result.tx_events = events;
                    (garbage, ended, Vec::new())
                }),
                None => unreachable!(),
            };
            self.drain_session_out(now);
            match outcome {
                Ok((garbage, ended, trailing)) => {
                    if !garbage.is_empty() {
                        result.terminal.extend(self.to_terminal(&garbage, now));
                    }
                    if !ended {
                        return result;
                    }
                    let was_receive = matches!(self.active, Some(Active::Receive(_)));
                    self.active = None;
                    result.ended = true;
                    input = trailing;
                    if was_receive {
                        input = self.trim_over_and_out(input, now);
                    }
                }
                Err(err) => {
                    // Abort and make sure the remote rz/sz stops: CANs now,
                    // Ctrl+C shortly, and swallow its residue for a while.
                    match &mut self.active {
                        Some(Active::Receive(s)) => s.abort(),
                        Some(Active::Send(s)) => s.abort(),
                        None => {}
                    }
                    self.drain_session_out(now);
                    self.active = None;
                    self.send_extra_abort();
                    self.start_cooldown(now);
                    result.interrupt = true;
                    result.error = Some(err.to_string());
                    return result;
                }
            }
        } else if self.expect_oo_until.is_some() {
            input = self.trim_over_and_out(input, now);
        }

        if input.is_empty() {
            return result;
        }

        if let Some(header) = self.detect(&input) {
            let ignored = self
                .ignore_detection_until
                .is_some_and(|until| now < until);
            if ignored {
                // Deny: tell the stray sender to stop.
                self.out.push(crate::ABORT_SEQUENCE.to_vec());
            } else {
                match header.frame {
                    FrameType::ZRQINIT => {
                        let mut session = ReceiveSession::new();
                        session.start();
                        self.active = Some(Active::Receive(session));
                        self.suppression = Some((header.to_hex(), now));
                        result.detected = Some(Role::Receive);
                    }
                    FrameType::ZRINIT => match SendSession::new(header) {
                        Ok(session) => {
                            self.suppression = Some((session.last_zrinit().to_hex(), now));
                            self.active = Some(Active::Send(session));
                            result.detected = Some(Role::Send);
                        }
                        Err(err) => {
                            self.out.push(crate::ABORT_SEQUENCE.to_vec());
                            result.error = Some(err.to_string());
                        }
                    },
                    _ => {}
                }
                self.drain_session_out(now);
            }
        }

        result.terminal.extend(self.to_terminal(&input, now));
        result
    }

    /// Strip the "OO" that ends a receive session (it may arrive in the
    /// next chunk, see `expect_oo_until`).
    fn trim_over_and_out(&mut self, mut input: Vec<u8>, now: Instant) -> Vec<u8> {
        if self.expect_oo_until.is_some_and(|until| now >= until) {
            self.expect_oo_until = None;
            return input;
        }
        if input.is_empty() {
            self.expect_oo_until = Some(now + Duration::from_millis(1000));
            return input;
        }
        if input.starts_with(b"OO") {
            input.drain(..2);
        } else if input[0] == b'O' {
            input.drain(..1);
        }
        self.expect_oo_until = None;
        input
    }

    /// Look for a complete ZRQINIT / ZRINIT hex header ending the input
    /// (`Zmodem.Sentry._parse`).
    fn detect(&mut self, input: &[u8]) -> Option<Header> {
        self.cache.extend_from_slice(input);
        let mut found = None;
        if let Some(at) = find(&self.cache, &COMMON_ZM_HEX_START) {
            self.cache.drain(..at);
            if let Ok(Some((header, used))) = header::parse_hex(&self.cache) {
                self.cache.drain(..used);
                if self.cache == [XON] {
                    self.cache.clear();
                }
                if self.cache.is_empty()
                    && matches!(header.frame, FrameType::ZRQINIT | FrameType::ZRINIT)
                {
                    found = Some(header);
                }
            }
        }
        // Keep only a tail that can still begin a header split across chunks.
        if self.cache.len() > DETECTION_CACHE {
            let cut = self.cache.len() - DETECTION_CACHE;
            self.cache.drain(..cut);
        }
        match self.cache.iter().position(|&b| b == b'*') {
            Some(star) => {
                self.cache.drain(..star);
            }
            None => self.cache.clear(),
        }
        found
    }

    // -- terminal sanitising --------------------------------------------------

    fn to_terminal(&mut self, octets: &[u8], now: Instant) -> Vec<u8> {
        let mut buf = self.assemble(octets);
        if self.suppress_next_xon {
            self.suppress_next_xon = false;
            if buf.first() == Some(&XON) {
                buf.remove(0);
            }
        }
        let buf = self.strip_suppression(buf, now);
        let buf = self.strip_visible_headers(buf);
        self.defer_incomplete_header(buf, now)
    }

    /// Prepend a withheld partial header so it can complete.
    fn assemble(&mut self, octets: &[u8]) -> Vec<u8> {
        match self.fragment.take() {
            Some(mut frag) => {
                self.fragment_deadline = None;
                frag.extend_from_slice(octets);
                frag
            }
            None => octets.to_vec(),
        }
    }

    fn strip_suppression(&mut self, mut buf: Vec<u8>, now: Instant) -> Vec<u8> {
        let Some((pattern, armed_at)) = self.suppression.take() else {
            return buf;
        };
        if now.duration_since(armed_at) > self.config.suppression_ttl {
            return buf;
        }
        if pattern.is_empty() {
            return buf;
        }
        if let Some(at) = find(&buf, &pattern) {
            buf.drain(at..at + pattern.len());
            return buf;
        }
        let matched = buf
            .iter()
            .zip(pattern.iter())
            .take_while(|(a, b)| a == b)
            .count();
        if matched == 0 {
            self.suppression = Some((pattern, armed_at));
            return buf;
        }
        buf.drain(..matched);
        if matched < pattern.len() {
            self.suppression = Some((pattern[matched..].to_vec(), armed_at));
        }
        buf
    }

    fn strip_visible_headers(&mut self, mut buf: Vec<u8>) -> Vec<u8> {
        let mut search_from = 0;
        while search_from < buf.len() {
            let Some(rel) = find(&buf[search_from..], &HEX_HEADER_PREFIX) else {
                break;
            };
            let at = search_from + rel;
            if buf.len() - at < 20 {
                break;
            }
            if !buf[at + 4..at + 18].iter().all(u8::is_ascii_hexdigit) {
                search_from = at + 1;
                continue;
            }
            let mut len = 18;
            let is_cr = |b: u8| b == 0x0d || b == 0x8d;
            let is_lf = |b: u8| b == 0x0a || b == 0x8a;
            if is_cr(buf[at + 18]) && is_lf(buf[at + 19]) {
                len = 20;
                if buf.get(at + 20) == Some(&XON) {
                    len = 21;
                } else if at + 20 == buf.len() {
                    // The XON may arrive with the next chunk.
                    self.suppress_next_xon = true;
                }
            }
            buf.drain(at..at + len);
            self.emitted_prefix = self.emitted_prefix.min(at);
            search_from = at;
        }
        buf
    }

    /// Index from which `buf` may be the start of a hex header that the
    /// next chunk completes.
    fn trailing_fragment(buf: &[u8]) -> Option<usize> {
        if buf.is_empty() {
            return None;
        }
        let window_start = buf.len().saturating_sub(HEX_HEADER_MAX_PARTIAL);
        if buf.len() >= 4 {
            for i in window_start..=buf.len() - 4 {
                if buf[i..i + 4] != HEX_HEADER_PREFIX {
                    continue;
                }
                let digits = buf[i + 4..]
                    .iter()
                    .take_while(|b| b.is_ascii_hexdigit())
                    .count();
                if i + 4 + digits == buf.len() {
                    return Some(i);
                }
                if digits != 14 {
                    continue;
                }
                if buf.len() - i <= 19 {
                    return Some(i);
                }
                break;
            }
        }
        for k in (1..=buf.len().min(3)).rev() {
            if buf[buf.len() - k..] == HEX_HEADER_PREFIX[..k] {
                return Some(buf.len() - k);
            }
        }
        None
    }

    fn defer_incomplete_header(&mut self, buf: Vec<u8>, now: Instant) -> Vec<u8> {
        let fragment_at = Self::trailing_fragment(&buf);
        let already = self.emitted_prefix;
        self.emitted_prefix = match fragment_at {
            None => 0,
            Some(at) => already.saturating_sub(at),
        };
        let Some(at) = fragment_at else {
            return buf[already.min(buf.len())..].to_vec();
        };
        if at < buf.len() {
            let fragment = buf[at..].to_vec();
            if self.fragment_deadline.is_none() && fragment.len() > self.emitted_prefix {
                let ttl = if fragment.iter().all(|&b| b == b'*') {
                    self.config.printable_prefix_ttl
                } else {
                    self.config.fragment_ttl
                };
                self.fragment_deadline = Some(now + ttl);
            }
            self.fragment = Some(fragment);
        }
        buf[already.min(at)..at].to_vec()
    }

    /// Release a withheld fragment whose deadline passed (it was ordinary
    /// output after all). Returns the bytes to show.
    pub fn flush_expired(&mut self, now: Instant) -> Vec<u8> {
        match self.fragment_deadline {
            Some(deadline) if now >= deadline => {}
            _ => return Vec::new(),
        }
        self.fragment_deadline = None;
        let Some(buf) = self.fragment.take() else {
            return Vec::new();
        };
        let output = buf[self.emitted_prefix.min(buf.len())..].to_vec();
        if buf.iter().all(|&b| b == b'*') {
            // Keep the stars as parsing context (a later ZDLE must still be
            // recognised) without replaying them.
            self.emitted_prefix = buf.len();
            self.fragment = Some(buf);
        } else {
            self.emitted_prefix = 0;
        }
        output
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        let rel = haystack[i..=haystack.len() - needle.len()]
            .iter()
            .position(|&b| b == first)?;
        let at = i + rel;
        if &haystack[at..at + needle.len()] == needle {
            return Some(at);
        }
        i = at + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::ZRINIT_FLAGS;
    use crate::subpacket::{self, FrameEnd};
    use crate::zdle::Encoder;

    fn zrqinit() -> Vec<u8> {
        Header::new(FrameType::ZRQINIT, [0; 4]).to_hex()
    }

    #[test]
    fn plain_output_passes_through() {
        let mut s = Sentry::default();
        let now = Instant::now();
        let r = s.consume(b"hello world\r\n", now);
        assert_eq!(r.terminal, b"hello world\r\n");
        assert!(r.detected.is_none());
        assert!(s.is_idle(now));
    }

    #[test]
    fn detects_sz_and_hides_the_header() {
        let mut s = Sentry::default();
        let now = Instant::now();
        let mut chunk = b"rz\r".to_vec();
        chunk.extend(zrqinit());
        let r = s.consume(&chunk, now);
        assert_eq!(r.detected, Some(Role::Receive));
        assert_eq!(r.terminal, b"rz\r");
        // Our ZRINIT went out.
        let out = s.take_outgoing();
        let (h, _) = header::parse_hex(&out[0]).unwrap().unwrap();
        assert_eq!(h.frame, FrameType::ZRINIT);
        assert!(s.is_active());
    }

    #[test]
    fn detects_rz() {
        let mut s = Sentry::default();
        let now = Instant::now();
        let r = s.consume(&Header::zrinit(ZRINIT_FLAGS, 0).to_hex(), now);
        assert_eq!(r.detected, Some(Role::Send));
        assert!(r.terminal.is_empty());
        assert_eq!(s.role(), Some(Role::Send));
    }

    #[test]
    fn split_hex_header_is_withheld_then_stripped() {
        // #3651: a header split across chunks must not paint garble.
        let mut s = Sentry::default();
        let now = Instant::now();
        let header = zrqinit();
        let mut first = b"$ ".to_vec();
        first.extend_from_slice(&header[..9]);
        let r = s.consume(&first, now);
        assert_eq!(r.terminal, b"$ ");
        assert!(s.next_deadline().is_some());
        let r = s.consume(&header[9..], now);
        // The detection cache saw the whole header across both chunks.
        assert_eq!(r.detected, Some(Role::Receive));
        assert!(r.terminal.is_empty(), "{:?}", r.terminal);
    }

    #[test]
    fn withheld_star_is_flushed_quickly() {
        // #3959: a typed `*` must not wait for the long protocol timeout.
        let mut s = Sentry::default();
        let t0 = Instant::now();
        let r = s.consume(b"echo *", t0);
        assert_eq!(r.terminal, b"echo ");
        let deadline = s.next_deadline().unwrap();
        assert!(deadline <= t0 + Duration::from_millis(16));
        assert!(s.flush_expired(t0).is_empty());
        assert_eq!(s.flush_expired(deadline), b"*");
        // The star is not replayed when the next chunk arrives.
        let r = s.consume(b"\r\nfile\r\n", deadline);
        assert_eq!(r.terminal, b"\r\nfile\r\n");
    }

    #[test]
    fn non_header_fragment_flushes_after_ttl() {
        let mut s = Sentry::default();
        let t0 = Instant::now();
        let r = s.consume(b"ab**\x18B01", t0);
        assert_eq!(r.terminal, b"ab");
        let deadline = s.next_deadline().unwrap();
        assert_eq!(deadline, t0 + Duration::from_millis(1000));
        assert_eq!(s.flush_expired(deadline), b"**\x18B01");
        assert!(s.next_deadline().is_none());
    }

    #[test]
    fn split_xon_after_stripped_header() {
        let mut s = Sentry::default();
        let now = Instant::now();
        // A visible ZRINIT (not at the end: no detection) with its XON cut off.
        let mut hdr = Header::zrinit(ZRINIT_FLAGS, 0).to_hex();
        hdr.pop();
        let mut chunk = b"x".to_vec();
        chunk.extend(&hdr);
        s.ignore_detection_for(Duration::from_secs(1), now);
        let r = s.consume(&chunk, now);
        assert_eq!(r.terminal, b"x");
        let r = s.consume(b"\x11prompt", now);
        assert_eq!(r.terminal, b"prompt");
    }

    #[test]
    fn drag_drop_command_echo_is_suppressed() {
        let mut s = Sentry::default();
        let now = Instant::now();
        s.arm_command_echo(b"rz -y\r", now);
        // Echo arrives in pieces.
        assert_eq!(s.consume(b"rz", now).terminal, b"");
        assert_eq!(s.consume(b" -y\r\n", now).terminal, b"\r\n");
        // Later output is untouched.
        assert_eq!(s.consume(b"rz -y", now).terminal, b"rz -y");
    }

    #[test]
    fn stale_suppression_expires() {
        // #3423: an unmatched suppression must not eat later commands.
        let mut s = Sentry::default();
        let t0 = Instant::now();
        s.arm_command_echo(b"rz -y\r", t0);
        let later = t0 + Duration::from_secs(6);
        assert_eq!(s.consume(b"rz -y", later).terminal, b"rz -y");
    }

    #[test]
    fn outgoing_echo_is_stripped() {
        let mut s = Sentry::default();
        let now = Instant::now();
        s.consume(&zrqinit(), now);
        let zrinit = s.take_outgoing().remove(0);
        // A PTY echoing our ZRINIT before sz switches to raw mode.
        let mut echoed = zrinit.clone();
        echoed.extend(Header::new(FrameType::ZFIN, [0; 4]).to_hex());
        let r = s.consume(&echoed, now);
        assert!(r.ended);
        assert!(r.error.is_none());
    }

    #[test]
    fn full_download_through_the_sentry() {
        let mut s = Sentry::default();
        let now = Instant::now();
        s.consume(&zrqinit(), now);
        s.take_outgoing();
        let enc = Encoder::default();
        let mut wire = Header::new(FrameType::ZFILE, [0; 4]).to_binary16(&enc);
        let info = FileInfo { name: "f.txt".into(), size: Some(2), ..Default::default() };
        subpacket::encode16(&info.to_offer_payload(), FrameEnd::EndAck, &enc, &mut wire);
        let r = s.consume(&wire, now);
        assert!(matches!(&r.rx_events[..], [ReceiveEvent::Offer(i)] if i.name == "f.txt"));
        s.rx_accept(0, now).unwrap();
        let mut wire = Header::with_offset(FrameType::ZDATA, 0).to_binary16(&enc);
        subpacket::encode16(b"hi", FrameEnd::EndNoAck, &enc, &mut wire);
        wire.extend(Header::with_offset(FrameType::ZEOF, 2).to_hex());
        wire.extend(Header::new(FrameType::ZFIN, [0; 4]).to_hex());
        let r = s.consume(&wire, now);
        assert_eq!(
            r.rx_events,
            vec![
                ReceiveEvent::Data(b"hi".to_vec()),
                ReceiveEvent::FileEnd,
                ReceiveEvent::SessionEnd
            ]
        );
        assert!(r.ended && !s.is_active());
        // "OO" arrives separately and is hidden; the prompt is shown.
        assert_eq!(s.consume(b"OO$ ", now).terminal, b"$ ");
    }

    #[test]
    fn protocol_error_aborts_and_cools_down() {
        let mut s = Sentry::default();
        let t0 = Instant::now();
        s.consume(&zrqinit(), t0);
        s.take_outgoing();
        // Unexpected ZDATA before any offer.
        let enc = Encoder::default();
        let r = s.consume(&Header::with_offset(FrameType::ZDATA, 0).to_binary16(&enc), t0);
        assert!(r.error.unwrap().contains("Unhandled header: ZDATA"));
        assert!(r.interrupt);
        assert!(!s.is_active());
        let out = s.take_outgoing().concat();
        assert!(out.starts_with(&[0x18; 5]));
        // Residue is swallowed during the cooldown, shown afterwards.
        assert!(s.consume(b"garbage", t0 + Duration::from_millis(100)).terminal.is_empty());
        assert_eq!(s.consume(b"$ ", t0 + Duration::from_millis(2100)).terminal, b"$ ");
    }

    #[test]
    fn cancel_and_ignore_window() {
        let mut s = Sentry::default();
        let t0 = Instant::now();
        s.consume(&Header::zrinit(ZRINIT_FLAGS, 0).to_hex(), t0);
        assert_eq!(s.cancel(t0), Some(Role::Send));
        assert!(!s.is_active());
        s.take_outgoing();
        s.ignore_detection_for(Duration::from_millis(300), t0);
        // A stray rz restart after the cooldown but inside the ignore window.
        let t1 = t0 + Duration::from_millis(2001);
        s.ignore_detection_for(Duration::from_millis(300), t1);
        let r = s.consume(&Header::zrinit(ZRINIT_FLAGS, 0).to_hex(), t1);
        assert!(r.detected.is_none());
        assert_eq!(s.take_outgoing(), vec![vec![0x18; 5]]);
    }
}
