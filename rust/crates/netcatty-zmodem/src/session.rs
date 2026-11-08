//! Sans-IO ZMODEM sessions (`zmodem.js` `zsession.js`, plus the send-side
//! robustness fixes of `electron/bridges/zmodemFastPath.cjs`).
//!
//! * [`ReceiveSession`]: the remote ran `sz` (download). Netcatty answers
//!   ZRQINIT with ZRINIT, accepts offers (ZRPOS), collects ZDATA payloads
//!   and acknowledges ZEOF / ZFIN.
//! * [`SendSession`]: the remote ran `rz` (upload). Netcatty offers files
//!   (ZFILE), streams ZDATA subpackets and closes with ZFIN / "OO".
//!
//! Both consume raw transport bytes and queue wire bytes to send in
//! [`ReceiveSession::take_outgoing`] / [`SendSession::take_outgoing`].

use crate::header::{self, zrinit_flags, CrcWidth, FrameType, Header, ZSINIT_ESCCTL};
use crate::subpacket::{self, FrameEnd};
use crate::zdle::Encoder;
use crate::{ZResult, ZmodemError, ABORT_SEQUENCE, ABORT_WITH_BACKSPACES, XOFF, XON, ZDLE};

/// Largest data subpacket Netcatty sends (lrzsz accepts 8 KiB).
pub const MAX_CHUNK_LENGTH: usize = 8192;
/// What Netcatty's ZRINIT advertises: full duplex, overlapped I/O, CRC32.
pub const ZRINIT_FLAGS: u8 = zrinit_flags::CANFDX | zrinit_flags::CANOVIO | zrinit_flags::CANFC32;
/// The "over and out" bytes that end a session.
pub const OVER_AND_OUT: [u8; 2] = *b"OO";

/// Byte buffer with a moving start so repeated front removal is cheap.
#[derive(Debug, Default)]
struct InputBuf {
    data: Vec<u8>,
    start: usize,
    /// Consecutive CANs seen at the end of the input so far (the abort
    /// sequence may be split across chunks).
    can_run: usize,
}

impl InputBuf {
    fn as_slice(&self) -> &[u8] {
        &self.data[self.start..]
    }

    fn is_empty(&self) -> bool {
        self.start >= self.data.len()
    }

    fn consume(&mut self, n: usize) {
        self.start = (self.start + n).min(self.data.len());
        if self.start == self.data.len() {
            self.data.clear();
            self.start = 0;
        }
    }

    /// Append `input` without XON / XOFF (and their high-bit variants),
    /// which ZMODEM ignores (`strip_ignored_bytes`). Returns `true` when
    /// the abort sequence (5× CAN) arrived.
    fn push_stripped(&mut self, input: &[u8]) -> bool {
        if self.start > 64 * 1024 && self.start * 2 > self.data.len() {
            self.data.drain(..self.start);
            self.start = 0;
        }
        let mut aborted = false;
        for &b in input {
            if matches!(b, XON | XOFF | 0x91 | 0x93) {
                continue;
            }
            if b == ZDLE {
                self.can_run += 1;
                aborted |= self.can_run >= ABORT_SEQUENCE.len();
            } else {
                self.can_run = 0;
            }
            self.data.push(b);
        }
        aborted
    }

    fn take_all(&mut self) -> Vec<u8> {
        let rest = self.as_slice().to_vec();
        self.data.clear();
        self.start = 0;
        rest
    }
}

/// File details of a ZFILE offer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileInfo {
    pub name: String,
    pub size: Option<u64>,
    /// Seconds since the epoch.
    pub mtime: Option<u64>,
    pub mode: Option<u32>,
    pub files_remaining: Option<u64>,
    pub bytes_remaining: Option<u64>,
}

impl FileInfo {
    /// Parse a ZFILE data subpacket: `name\0size mtime(octal) mode(octal) serial files bytes`.
    pub fn parse(payload: &[u8]) -> Self {
        let nul = payload.iter().position(|&b| b == 0).unwrap_or(payload.len());
        let name = String::from_utf8_lossy(&payload[..nul]).into_owned();
        let rest = payload.get(nul + 1..).unwrap_or(&[]);
        let rest_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let rest = String::from_utf8_lossy(&rest[..rest_end]).into_owned();
        let parts: Vec<&str> = rest.split(' ').collect();
        let dec = |i: usize| parts.get(i).and_then(|s| s.parse::<u64>().ok());
        let oct = |i: usize| {
            parts
                .get(i)
                .and_then(|s| u64::from_str_radix(s, 8).ok())
                .filter(|v| *v != 0)
        };
        FileInfo {
            name,
            size: dec(0),
            mtime: oct(1),
            mode: oct(2).map(|m| m as u32),
            files_remaining: dec(4),
            bytes_remaining: dec(5),
        }
    }

    /// ZFILE payload as `zmodem.js` builds it for an offer.
    pub fn to_offer_payload(&self) -> Vec<u8> {
        let mut out = self.name.as_bytes().to_vec();
        out.push(0);
        let mut pieces = vec![
            self.size.unwrap_or(0).to_string(),
            self.mtime.map_or_else(|| "0".to_string(), |m| format!("{m:o}")),
            self.mode
                .map_or_else(|| "0".to_string(), |m| format!("{:o}", 0x8000 | m)),
            "0".to_string(),
        ];
        if let Some(files) = self.files_remaining.filter(|n| *n > 0) {
            pieces.push(files.to_string());
            if let Some(bytes) = self.bytes_remaining.filter(|n| *n > 0) {
                pieces.push(bytes.to_string());
            }
        }
        out.extend_from_slice(pieces.join(" ").as_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// Receive session (remote `sz`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveEvent {
    /// A file is offered; answer with [`ReceiveSession::accept`] or
    /// [`ReceiveSession::skip`].
    Offer(FileInfo),
    /// File payload bytes (in order).
    Data(Vec<u8>),
    /// The current file is complete (ZEOF at the expected offset).
    FileEnd,
    /// The sender finished the batch (ZFIN); Netcatty answered ZFIN.
    /// Bytes after ZFIN (normally "OO" and the shell prompt) are in
    /// [`ReceiveSession::take_trailing`].
    SessionEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RxState {
    /// Waiting for ZFILE / ZSINIT / ZFIN.
    BetweenFiles,
    /// ZFILE seen: next comes its data subpacket.
    ZFileData,
    /// ZSINIT seen: next comes the attention string.
    ZSinitData,
    /// Offer emitted; waiting for accept / skip.
    OfferPending,
    /// Ignore one data subpacket, then go back to `OfferPending`.
    IgnoreRepeatedOffer,
    /// Ignore one data subpacket, then go back to `Accepted`.
    IgnoreRepeatedAccepted,
    /// Accepted (ZRPOS sent); waiting for ZDATA.
    Accepted,
    /// Inside a ZDATA frame.
    Data,
    /// A ZDATA frame ended; ZEOF or another ZDATA follows.
    AfterFrame,
    /// Skipped; drain until the next ZFILE / ZFIN.
    Skipping,
    Done,
}

#[derive(Debug)]
pub struct ReceiveSession {
    buf: InputBuf,
    state: RxState,
    width: CrcWidth,
    offset: u32,
    out: Vec<u8>,
    aborted: bool,
    trailing: Vec<u8>,
}

impl Default for ReceiveSession {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiveSession {
    pub fn new() -> Self {
        Self {
            buf: InputBuf::default(),
            state: RxState::BetweenFiles,
            width: CrcWidth::Crc16,
            offset: 0,
            out: Vec::new(),
            aborted: false,
            trailing: Vec::new(),
        }
    }

    /// Send the first ZRINIT (`zsession.start()`).
    pub fn start(&mut self) {
        self.send_zrinit();
    }

    fn send_zrinit(&mut self) {
        self.out
            .extend_from_slice(&Header::zrinit(ZRINIT_FLAGS, 0).to_hex());
    }

    fn send_hex(&mut self, header: Header) {
        self.out.extend_from_slice(&header.to_hex());
    }

    pub fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    pub fn has_ended(&self) -> bool {
        self.aborted || self.state == RxState::Done
    }

    /// Bytes that followed ZFIN (to be shown in the terminal).
    pub fn take_trailing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.trailing)
    }

    /// Answer the pending offer: start receiving at `offset`.
    pub fn accept(&mut self, offset: u32) -> ZResult<()> {
        if self.state != RxState::OfferPending && self.state != RxState::IgnoreRepeatedOffer {
            return Err(ZmodemError::protocol("No pending offer to accept"));
        }
        self.offset = offset;
        self.state = if self.state == RxState::IgnoreRepeatedOffer {
            RxState::IgnoreRepeatedAccepted
        } else {
            RxState::Accepted
        };
        self.send_hex(Header::with_offset(FrameType::ZRPOS, offset));
        Ok(())
    }

    /// Decline the pending offer (ZSKIP).
    pub fn skip(&mut self) -> ZResult<()> {
        self.state = match self.state {
            RxState::OfferPending | RxState::IgnoreRepeatedOffer => RxState::BetweenFiles,
            RxState::Accepted | RxState::Data | RxState::AfterFrame => RxState::Skipping,
            _ => return Err(ZmodemError::protocol("No offer to skip")),
        };
        self.send_hex(Header::new(FrameType::ZSKIP, [0; 4]));
        Ok(())
    }

    /// Abort the session (abort sequence + backspaces).
    pub fn abort(&mut self) {
        if !self.aborted {
            self.out.extend_from_slice(&ABORT_WITH_BACKSPACES);
            self.aborted = true;
        }
    }

    /// Feed transport bytes; returns protocol events plus any garbage
    /// bytes found before headers (shown in the terminal by the sentry).
    pub fn consume(&mut self, input: &[u8]) -> ZResult<(Vec<ReceiveEvent>, Vec<u8>)> {
        if self.aborted {
            return Err(ZmodemError::protocol("already_aborted"));
        }
        let mut events = Vec::new();
        let mut garbage = Vec::new();
        if self.state == RxState::Done {
            self.trailing.extend_from_slice(input);
            return Ok((events, garbage));
        }
        if self.buf.push_stripped(input) {
            self.aborted = true;
            return Err(ZmodemError::PeerAborted);
        }
        loop {
            if self.buf.is_empty() || self.state == RxState::Done {
                break;
            }
            let progressed = match self.state {
                RxState::ZFileData
                | RxState::ZSinitData
                | RxState::Data
                | RxState::IgnoreRepeatedOffer
                | RxState::IgnoreRepeatedAccepted => self.step_subpacket(&mut events)?,
                RxState::Skipping => self.step_skipping(&mut events, &mut garbage)?,
                _ => self.step_header(&mut events, &mut garbage)?,
            };
            if !progressed {
                break;
            }
        }
        if self.state == RxState::Done {
            self.trailing.extend(self.buf.take_all());
        }
        Ok((events, garbage))
    }

    fn step_subpacket(&mut self, events: &mut Vec<ReceiveEvent>) -> ZResult<bool> {
        let Some((sp, used)) = subpacket::parse(self.buf.as_slice(), self.width)? else {
            return Ok(false);
        };
        self.buf.consume(used);
        match self.state {
            RxState::ZFileData => {
                events.push(ReceiveEvent::Offer(FileInfo::parse(&sp.payload)));
                self.state = RxState::OfferPending;
            }
            RxState::ZSinitData => {
                self.send_hex(Header::new(FrameType::ZACK, [0; 4]));
                self.state = RxState::BetweenFiles;
            }
            RxState::IgnoreRepeatedOffer => {
                self.state = RxState::OfferPending;
            }
            RxState::IgnoreRepeatedAccepted => {
                self.state = RxState::Accepted;
            }
            RxState::Data => {
                self.offset = self.offset.wrapping_add(sp.payload.len() as u32);
                if !sp.payload.is_empty() {
                    events.push(ReceiveEvent::Data(sp.payload));
                }
                if sp.end.ack_expected() {
                    self.send_hex(Header::with_offset(FrameType::ZACK, self.offset));
                }
                if sp.end.frame_end() {
                    self.state = RxState::AfterFrame;
                }
            }
            _ => unreachable!("subpacket in header state"),
        }
        Ok(true)
    }

    /// After a skip mid-file, drop data until a header we care about.
    fn step_skipping(
        &mut self,
        events: &mut Vec<ReceiveEvent>,
        garbage: &mut Vec<u8>,
    ) -> ZResult<bool> {
        let buf = self.buf.as_slice();
        let skip = header::leading_garbage_len(buf);
        if skip > 0 {
            self.buf.consume(skip);
            return Ok(true);
        }
        match header::parse(self.buf.as_slice()) {
            Ok(Some((h, width, used))) => {
                if matches!(h.frame, FrameType::ZFILE | FrameType::ZFIN) {
                    self.state = RxState::BetweenFiles;
                    return self.step_header(events, garbage);
                }
                self.buf.consume(used);
                self.width = width;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(_) => {
                self.buf.consume(1);
                Ok(true)
            }
        }
    }

    fn step_header(
        &mut self,
        events: &mut Vec<ReceiveEvent>,
        garbage: &mut Vec<u8>,
    ) -> ZResult<bool> {
        let skip = header::leading_garbage_len(self.buf.as_slice());
        if skip > 0 {
            garbage.extend_from_slice(&self.buf.as_slice()[..skip]);
            self.buf.consume(skip);
        }
        let Some((h, width, used)) = header::parse(self.buf.as_slice())? else {
            return Ok(false);
        };
        self.buf.consume(used);
        self.width = width;
        let unhandled = || ZmodemError::protocol(format!("Unhandled header: {}", h.name()));
        match (self.state, h.frame) {
            (RxState::BetweenFiles, FrameType::ZFILE) => self.state = RxState::ZFileData,
            (RxState::BetweenFiles, FrameType::ZSINIT) => self.state = RxState::ZSinitData,
            (RxState::BetweenFiles, FrameType::ZRQINIT) => {
                // The sender missed our ZRINIT: say it again.
                self.send_zrinit();
            }
            (RxState::BetweenFiles, FrameType::ZFIN) => {
                self.send_hex(Header::new(FrameType::ZFIN, [0; 4]));
                self.state = RxState::Done;
                events.push(ReceiveEvent::SessionEnd);
            }
            // The sender repeats ZFILE while we have not decided yet.
            (RxState::OfferPending, FrameType::ZFILE) => self.state = RxState::IgnoreRepeatedOffer,
            (RxState::Accepted, FrameType::ZFILE) => {
                // Our ZRPOS crossed a repeated offer: drop its data
                // subpacket and answer again.
                self.send_hex(Header::with_offset(FrameType::ZRPOS, self.offset));
                self.state = RxState::IgnoreRepeatedAccepted;
            }
            (RxState::Accepted | RxState::AfterFrame, FrameType::ZDATA) => {
                if h.offset() != self.offset {
                    return Err(ZmodemError::protocol("Error correction is unimplemented."));
                }
                self.state = RxState::Data;
            }
            (RxState::AfterFrame, FrameType::ZEOF) => {
                if h.offset() != self.offset {
                    return Err(ZmodemError::protocol(format!(
                        "ZEOF offset mismatch; unimplemented (local: {}; ZEOF: {})",
                        self.offset,
                        h.offset()
                    )));
                }
                events.push(ReceiveEvent::FileEnd);
                self.offset = 0;
                self.state = RxState::BetweenFiles;
                self.send_zrinit();
            }
            _ => return Err(unhandled()),
        }
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Send session (remote `rz`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendEvent {
    /// The receiver accepted the offer at `offset` (ZRPOS).
    OfferAccepted { offset: u32 },
    /// The receiver skipped the offer (ZSKIP; e.g. `rz` protect mode).
    OfferSkipped,
    /// Mid-file ZRPOS: resend from `offset`.
    Reposition { offset: u32 },
    /// The receiver confirmed the file (ZRINIT after ZEOF).
    FileReceived,
    /// The receiver answered our ZFIN; "OO" was sent. The session is over.
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TxState {
    /// No file in flight (before the first offer and between files).
    Idle,
    /// Waiting for the ZACK of the ZSINIT that must precede this offer.
    AwaitZsinitAck(Vec<u8>),
    /// ZFILE sent; waiting for ZRPOS / ZSKIP.
    AwaitOfferReply,
    /// Streaming file data.
    Sending,
    /// ZEOF sent; waiting for ZRINIT.
    AwaitFileAck,
    /// ZFIN sent; waiting for ZFIN.
    AwaitFin,
    Done,
}

#[derive(Debug)]
pub struct SendSession {
    buf: InputBuf,
    state: TxState,
    encoder: Encoder,
    receiver_escapes_ctrl: bool,
    got_zsinit_ack: bool,
    zsinit_pending: bool,
    sent_zdata: bool,
    offset: u32,
    out: Vec<u8>,
    aborted: bool,
    last_zrinit: Header,
}

impl SendSession {
    /// Start from the receiver's ZRINIT (the header that triggered detection).
    pub fn new(zrinit: Header) -> ZResult<Self> {
        if zrinit.frame != FrameType::ZRINIT {
            return Err(ZmodemError::protocol(format!(
                "First header should be ZRINIT, not {}",
                zrinit.name()
            )));
        }
        let mut s = Self {
            buf: InputBuf::default(),
            state: TxState::Idle,
            encoder: Encoder::new(true),
            receiver_escapes_ctrl: false,
            got_zsinit_ack: false,
            zsinit_pending: false,
            sent_zdata: false,
            offset: 0,
            out: Vec::new(),
            aborted: false,
            last_zrinit: zrinit,
        };
        s.consume_zrinit(zrinit)?;
        Ok(s)
    }

    /// The ZRINIT that started the session (hex, for echo suppression).
    pub fn last_zrinit(&self) -> Header {
        self.last_zrinit
    }

    fn consume_zrinit(&mut self, h: Header) -> ZResult<()> {
        self.last_zrinit = h;
        if h.buffer_size() != 0 {
            return Err(ZmodemError::protocol(format!(
                "Buffer size ({}) is unsupported!",
                h.buffer_size()
            )));
        }
        if !h.can_full_duplex() {
            return Err(ZmodemError::protocol("Half-duplex I/O is unsupported!"));
        }
        if !h.can_overlap_io() {
            return Err(ZmodemError::protocol("Non-overlap I/O is unsupported!"));
        }
        if h.escape_8th_bit() {
            return Err(ZmodemError::protocol("8-bit escaping is unsupported!"));
        }
        self.receiver_escapes_ctrl = h.escape_ctrl_chars();
        Ok(())
    }

    pub fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    pub fn has_ended(&self) -> bool {
        self.aborted || self.state == TxState::Done
    }

    /// `true` while no file is in flight (keepalive / close allowed).
    pub fn is_idle(&self) -> bool {
        self.state == TxState::Idle
    }

    pub fn is_sending_file(&self) -> bool {
        matches!(self.state, TxState::Sending | TxState::AwaitFileAck)
    }

    fn send_zsinit(&mut self) {
        let mut wire = Header::new(FrameType::ZSINIT, [0, 0, 0, ZSINIT_ESCCTL]).to_hex();
        subpacket::encode16(&[0], FrameEnd::EndAck, &self.encoder, &mut wire);
        self.out.extend_from_slice(&wire);
        self.zsinit_pending = true;
    }

    /// Keepalive while waiting for the user (e.g. the file picker): a
    /// ZSINIT every few seconds keeps `rz` from timing out. At most one
    /// is in flight (`zmodemFastPath` duplicate-ZSINIT fix).
    pub fn keepalive(&mut self) {
        if self.state == TxState::Idle && !self.zsinit_pending && !self.aborted {
            self.send_zsinit();
        }
    }

    fn send_zfile(&mut self, payload: &[u8]) {
        let mut wire = Header::new(FrameType::ZFILE, [0; 4]).to_binary16(&self.encoder);
        subpacket::encode16(payload, FrameEnd::EndAck, &self.encoder, &mut wire);
        self.out.extend_from_slice(&wire);
        self.sent_zdata = false;
        self.state = TxState::AwaitOfferReply;
    }

    /// Offer a file. The answer arrives as [`SendEvent::OfferAccepted`] /
    /// [`SendEvent::OfferSkipped`].
    pub fn offer(&mut self, info: &FileInfo) -> ZResult<()> {
        if self.state != TxState::Idle {
            return Err(ZmodemError::protocol("Already sending file!"));
        }
        let payload = info.to_offer_payload();
        if !self.receiver_escapes_ctrl && !self.got_zsinit_ack {
            if !self.zsinit_pending {
                self.send_zsinit();
            }
            self.state = TxState::AwaitZsinitAck(payload);
        } else {
            self.send_zfile(&payload);
        }
        Ok(())
    }

    /// Send file bytes (after [`SendEvent::OfferAccepted`]). `last` ends
    /// the file: the final subpacket is ZCRCE and ZEOF follows.
    pub fn send_data(&mut self, data: &[u8], last: bool) -> ZResult<()> {
        if self.state != TxState::Sending {
            return Err(ZmodemError::protocol("Not sending a file currently!"));
        }
        if !self.sent_zdata {
            let h = Header::with_offset(FrameType::ZDATA, self.offset).to_binary16(&self.encoder);
            self.out.extend_from_slice(&h);
            self.sent_zdata = true;
        }
        let mut chunks = data.chunks(MAX_CHUNK_LENGTH).peekable();
        if chunks.peek().is_none() {
            if last {
                subpacket::encode16(&[], FrameEnd::EndNoAck, &self.encoder, &mut self.out);
            }
        } else {
            while let Some(chunk) = chunks.next() {
                let end = if last && chunks.peek().is_none() {
                    FrameEnd::EndNoAck
                } else {
                    FrameEnd::NoEndNoAck
                };
                subpacket::encode16(chunk, end, &self.encoder, &mut self.out);
                self.offset = self.offset.wrapping_add(chunk.len() as u32);
            }
        }
        if last {
            let eof = Header::with_offset(FrameType::ZEOF, self.offset).to_hex();
            self.out.extend_from_slice(&eof);
            self.offset = 0;
            self.state = TxState::AwaitFileAck;
        }
        Ok(())
    }

    /// Resume sending at `offset` after a mid-file ZRPOS: the next
    /// [`SendSession::send_data`] starts a new ZDATA frame there.
    pub fn reposition(&mut self, offset: u32) {
        self.offset = offset;
        self.sent_zdata = false;
        if self.state == TxState::AwaitFileAck {
            self.state = TxState::Sending;
        }
    }

    /// Finish the batch (ZFIN). Completes with [`SendEvent::Closed`].
    pub fn close(&mut self) -> ZResult<()> {
        // Only between files (after ZRINIT / ZSKIP / the ZSINIT ZACK).
        if self.state != TxState::Idle {
            return Err(ZmodemError::protocol("Can’t close while a file is in flight"));
        }
        self.send_hex(Header::new(FrameType::ZFIN, [0; 4]));
        self.state = TxState::AwaitFin;
        Ok(())
    }

    fn send_hex(&mut self, h: Header) {
        self.out.extend_from_slice(&h.to_hex());
    }

    pub fn abort(&mut self) {
        if !self.aborted {
            self.out.extend_from_slice(&ABORT_WITH_BACKSPACES);
            self.aborted = true;
        }
    }

    pub fn consume(&mut self, input: &[u8]) -> ZResult<(Vec<SendEvent>, Vec<u8>)> {
        if self.aborted {
            return Err(ZmodemError::protocol("already_aborted"));
        }
        let mut events = Vec::new();
        let mut garbage = Vec::new();
        if self.state == TxState::Done {
            return Ok((events, garbage));
        }
        if self.buf.push_stripped(input) {
            self.aborted = true;
            return Err(ZmodemError::PeerAborted);
        }
        loop {
            if self.buf.is_empty() || self.state == TxState::Done {
                break;
            }
            let skip = header::leading_garbage_len(self.buf.as_slice());
            if skip > 0 {
                garbage.extend_from_slice(&self.buf.as_slice()[..skip]);
                self.buf.consume(skip);
            }
            let Some((h, _width, used)) = header::parse(self.buf.as_slice())? else {
                break;
            };
            self.buf.consume(used);
            self.on_header(h, &mut events)?;
        }
        if self.buf.is_empty() && garbage == b"C" && self.state != TxState::Done {
            return Err(ZmodemError::YmodemFallback);
        }
        Ok((events, garbage))
    }

    fn on_header(&mut self, h: Header, events: &mut Vec<SendEvent>) -> ZResult<()> {
        let unhandled = || ZmodemError::protocol(format!("Unhandled header: {}", h.name()));
        match h.frame {
            FrameType::ZACK => {
                if self.zsinit_pending {
                    self.zsinit_pending = false;
                    self.got_zsinit_ack = true;
                }
                if let TxState::AwaitZsinitAck(payload) = &self.state {
                    let payload = payload.clone();
                    self.send_zfile(&payload);
                }
            }
            FrameType::ZRINIT => match self.state {
                TxState::AwaitFileAck => {
                    self.consume_zrinit(h)?;
                    self.state = TxState::Idle;
                    events.push(SendEvent::FileReceived);
                }
                // Pre-offer / between-file keepalive repeats of rz.
                TxState::Idle | TxState::AwaitZsinitAck(_) | TxState::AwaitOfferReply => {}
                TxState::Sending => {}
                TxState::AwaitFin | TxState::Done => {}
            },
            FrameType::ZRPOS => match self.state {
                TxState::AwaitOfferReply => {
                    self.offset = h.offset();
                    self.sent_zdata = false;
                    self.state = TxState::Sending;
                    events.push(SendEvent::OfferAccepted { offset: h.offset() });
                }
                TxState::Sending | TxState::AwaitFileAck => {
                    events.push(SendEvent::Reposition { offset: h.offset() });
                }
                // Late post-file ZRPOS ping: harmless.
                _ => {}
            },
            FrameType::ZSKIP => {
                if self.state == TxState::AwaitOfferReply {
                    self.state = TxState::Idle;
                    events.push(SendEvent::OfferSkipped);
                }
            }
            FrameType::ZFIN => {
                if self.state == TxState::AwaitFin {
                    self.out.extend_from_slice(&OVER_AND_OUT);
                    self.state = TxState::Done;
                    events.push(SendEvent::Closed);
                } else {
                    return Err(unhandled());
                }
            }
            FrameType::ZNAK => {}
            _ => return Err(unhandled()),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal `sz` stand-in driving a [`ReceiveSession`].
    fn sz_offer(name: &str, data: &[u8]) -> Vec<u8> {
        let enc = Encoder::new(true);
        let mut wire = Header::new(FrameType::ZFILE, [0; 4]).to_binary32(&enc);
        let info = FileInfo {
            name: name.into(),
            size: Some(data.len() as u64),
            mtime: Some(0o14_000_000_000),
            ..Default::default()
        };
        subpacket::encode32(&info.to_offer_payload(), FrameEnd::EndAck, &enc, &mut wire);
        wire
    }

    fn sz_data(data: &[u8]) -> Vec<u8> {
        let enc = Encoder::new(true);
        let mut wire = Header::with_offset(FrameType::ZDATA, 0).to_binary32(&enc);
        let mut chunks = data.chunks(1024).peekable();
        while let Some(c) = chunks.next() {
            let end = if chunks.peek().is_some() {
                FrameEnd::NoEndNoAck
            } else {
                FrameEnd::EndNoAck
            };
            subpacket::encode32(c, end, &enc, &mut wire);
        }
        wire.extend_from_slice(&Header::with_offset(FrameType::ZEOF, data.len() as u32).to_binary32(&enc));
        wire
    }

    #[test]
    fn receive_one_file_byte_by_byte() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
        let mut stream = sz_offer("hello.bin", &data);
        let mut rx = ReceiveSession::new();
        rx.start();
        let zrinit = rx.take_outgoing();
        let (h, _) = header::parse_hex(&zrinit).unwrap().unwrap();
        assert_eq!(h.frame, FrameType::ZRINIT);
        assert_eq!(h.flags(), ZRINIT_FLAGS);

        let mut events = Vec::new();
        for b in stream.drain(..) {
            events.extend(rx.consume(&[b]).unwrap().0);
        }
        let info = match &events[..] {
            [ReceiveEvent::Offer(info)] => info.clone(),
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(info.name, "hello.bin");
        assert_eq!(info.size, Some(5000));
        assert_eq!(info.mtime, Some(0o14_000_000_000));
        rx.accept(0).unwrap();
        let zrpos = rx.take_outgoing();
        assert_eq!(header::parse_hex(&zrpos).unwrap().unwrap().0.frame, FrameType::ZRPOS);

        let mut wire = sz_data(&data);
        wire.extend_from_slice(&Header::new(FrameType::ZFIN, [0; 4]).to_hex());
        wire.extend_from_slice(b"OO$ ");
        let mut got = Vec::new();
        let mut ended = false;
        for chunk in wire.chunks(333) {
            for e in rx.consume(chunk).unwrap().0 {
                match e {
                    ReceiveEvent::Data(d) => got.extend(d),
                    ReceiveEvent::FileEnd => {}
                    ReceiveEvent::SessionEnd => ended = true,
                    other => panic!("{other:?}"),
                }
            }
        }
        assert!(ended && rx.has_ended());
        assert_eq!(got, data);
        assert_eq!(rx.take_trailing(), b"OO$ ".to_vec());
        let out = rx.take_outgoing();
        // ZRINIT after ZEOF, then ZFIN.
        let (h1, n1) = header::parse_hex(&out).unwrap().unwrap();
        assert_eq!(h1.frame, FrameType::ZRINIT);
        let (h2, _) = header::parse_hex(&out[n1 + 1..]).unwrap().unwrap();
        assert_eq!(h2.frame, FrameType::ZFIN);
    }

    #[test]
    fn peer_abort_is_reported() {
        let mut rx = ReceiveSession::new();
        rx.start();
        assert_eq!(rx.consume(&[0x18; 3]).unwrap().0, vec![]);
        assert_eq!(rx.consume(&[0x18; 2]), Err(ZmodemError::PeerAborted));
        assert!(rx.has_ended());
    }

    fn rz_header(h: Header) -> Vec<u8> {
        h.to_hex()
    }

    #[test]
    fn send_session_full_flow() {
        // rz without ESCCTL: a ZSINIT must be acknowledged before ZFILE.
        let zrinit = Header::zrinit(ZRINIT_FLAGS, 0);
        let mut tx = SendSession::new(zrinit).unwrap();
        // Repeated pre-offer ZRINIT is ignored.
        assert_eq!(tx.consume(&rz_header(zrinit)).unwrap().0, vec![]);
        tx.keepalive();
        let zsinit = tx.take_outgoing();
        assert_eq!(header::parse_hex(&zsinit).unwrap().unwrap().0.frame, FrameType::ZSINIT);
        let info = FileInfo { name: "a.txt".into(), size: Some(3), ..Default::default() };
        tx.offer(&info).unwrap();
        // No duplicate ZSINIT while one is pending.
        assert!(tx.take_outgoing().is_empty());
        tx.consume(&rz_header(Header::new(FrameType::ZACK, [0; 4]))).unwrap();
        let zfile = tx.take_outgoing();
        let (h, w, used) = header::parse(&zfile).unwrap().unwrap();
        assert_eq!((h.frame, w), (FrameType::ZFILE, CrcWidth::Crc16));
        let (sp, _) = subpacket::parse(&zfile[used..], CrcWidth::Crc16).unwrap().unwrap();
        assert_eq!(FileInfo::parse(&sp.payload).name, "a.txt");

        let (ev, _) = tx.consume(&rz_header(Header::with_offset(FrameType::ZRPOS, 0))).unwrap();
        assert_eq!(ev, vec![SendEvent::OfferAccepted { offset: 0 }]);
        tx.send_data(b"abc", true).unwrap();
        let wire = tx.take_outgoing();
        let (h, _, used) = header::parse(&wire).unwrap().unwrap();
        assert_eq!(h.frame, FrameType::ZDATA);
        let (sp, used2) = subpacket::parse(&wire[used..], CrcWidth::Crc16).unwrap().unwrap();
        assert_eq!((sp.payload.as_slice(), sp.end), (&b"abc"[..], FrameEnd::EndNoAck));
        let (eof, _) = header::parse_hex(&wire[used + used2..]).unwrap().unwrap();
        assert_eq!((eof.frame, eof.offset()), (FrameType::ZEOF, 3));

        // Late ZRPOS ping is harmless; ZRINIT confirms the file.
        let (ev, _) = tx.consume(&rz_header(zrinit)).unwrap();
        assert_eq!(ev, vec![SendEvent::FileReceived]);
        tx.consume(&rz_header(Header::with_offset(FrameType::ZRPOS, 3))).unwrap();
        tx.close().unwrap();
        let fin = tx.take_outgoing();
        assert_eq!(header::parse_hex(&fin).unwrap().unwrap().0.frame, FrameType::ZFIN);
        let (ev, _) = tx.consume(&rz_header(Header::new(FrameType::ZFIN, [0; 4]))).unwrap();
        assert_eq!(ev, vec![SendEvent::Closed]);
        assert_eq!(tx.take_outgoing(), b"OO".to_vec());
        assert!(tx.has_ended());
    }

    #[test]
    fn send_session_rejects_buffered_receivers_and_detects_ymodem() {
        assert!(SendSession::new(Header::zrinit(ZRINIT_FLAGS, 1024)).is_err());
        let mut tx = SendSession::new(Header::zrinit(ZRINIT_FLAGS | zrinit_flags::ESCCTL, 0)).unwrap();
        let info = FileInfo { name: "x".into(), size: Some(0), ..Default::default() };
        tx.offer(&info).unwrap();
        // ESCCTL receiver: ZFILE goes out at once.
        assert!(!tx.take_outgoing().is_empty());
        let (ev, _) = tx.consume(&rz_header(Header::new(FrameType::ZSKIP, [0; 4]))).unwrap();
        assert_eq!(ev, vec![SendEvent::OfferSkipped]);
        assert_eq!(tx.consume(b"C"), Err(ZmodemError::YmodemFallback));
    }

    #[test]
    fn offer_payload_format() {
        let info = FileInfo {
            name: "f".into(),
            size: Some(10),
            mtime: Some(8),
            mode: Some(0o644),
            files_remaining: Some(2),
            bytes_remaining: Some(30),
        };
        assert_eq!(info.to_offer_payload(), b"f\x0010 10 100644 0 2 30".to_vec());
        let parsed = FileInfo::parse(&info.to_offer_payload());
        assert_eq!(parsed.mode, Some(0o100644));
        assert_eq!(parsed.files_remaining, Some(2));
    }
}
