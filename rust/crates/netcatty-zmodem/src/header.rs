//! ZMODEM headers (`zmodem.js` `zheader.js`): hex, binary16 and binary32
//! framing, parsing and leading-garbage trimming.

use crate::crc::{crc16, crc32};
use crate::zdle::{decode_count, Encoder};
use crate::{ZResult, ZmodemError, XON, ZDLE};

pub const ZPAD: u8 = b'*';
pub const ZBIN: u8 = b'A';
pub const ZHEX: u8 = b'B';
pub const ZBIN32: u8 = b'C';

/// `**` ZDLE `B`: start of every hex header.
pub const HEX_HEADER_PREFIX: [u8; 4] = [ZPAD, ZPAD, ZDLE, ZHEX];
const BINARY16_HEADER_PREFIX: [u8; 3] = [ZPAD, ZDLE, ZBIN];
const BINARY32_HEADER_PREFIX: [u8; 3] = [ZPAD, ZDLE, ZBIN32];

/// Frame types (index = type number).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    ZRQINIT = 0,
    ZRINIT = 1,
    ZSINIT = 2,
    ZACK = 3,
    ZFILE = 4,
    ZSKIP = 5,
    ZNAK = 6,
    ZABORT = 7,
    ZFIN = 8,
    ZRPOS = 9,
    ZDATA = 10,
    ZEOF = 11,
    ZFERR = 12,
    ZCRC = 13,
    ZCHALLENGE = 14,
    ZCOMPL = 15,
    ZCAN = 16,
    ZFREECNT = 17,
    ZCOMMAND = 18,
    ZSTDERR = 19,
}

impl FrameType {
    pub fn from_u8(n: u8) -> Option<Self> {
        use FrameType::*;
        Some(match n {
            0 => ZRQINIT,
            1 => ZRINIT,
            2 => ZSINIT,
            3 => ZACK,
            4 => ZFILE,
            5 => ZSKIP,
            6 => ZNAK,
            7 => ZABORT,
            8 => ZFIN,
            9 => ZRPOS,
            10 => ZDATA,
            11 => ZEOF,
            12 => ZFERR,
            13 => ZCRC,
            14 => ZCHALLENGE,
            15 => ZCOMPL,
            16 => ZCAN,
            17 => ZFREECNT,
            18 => ZCOMMAND,
            19 => ZSTDERR,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        use FrameType::*;
        match self {
            ZRQINIT => "ZRQINIT",
            ZRINIT => "ZRINIT",
            ZSINIT => "ZSINIT",
            ZACK => "ZACK",
            ZFILE => "ZFILE",
            ZSKIP => "ZSKIP",
            ZNAK => "ZNAK",
            ZABORT => "ZABORT",
            ZFIN => "ZFIN",
            ZRPOS => "ZRPOS",
            ZDATA => "ZDATA",
            ZEOF => "ZEOF",
            ZFERR => "ZFERR",
            ZCRC => "ZCRC",
            ZCHALLENGE => "ZCHALLENGE",
            ZCOMPL => "ZCOMPL",
            ZCAN => "ZCAN",
            ZFREECNT => "ZFREECNT",
            ZCOMMAND => "ZCOMMAND",
            ZSTDERR => "ZSTDERR",
        }
    }

    /// Types `zmodem.js` can parse; the rest are rejected.
    fn supported(self) -> bool {
        !matches!(
            self,
            FrameType::ZNAK
                | FrameType::ZCRC
                | FrameType::ZCHALLENGE
                | FrameType::ZCOMPL
                | FrameType::ZCAN
                | FrameType::ZFREECNT
                | FrameType::ZCOMMAND
                | FrameType::ZSTDERR
        )
    }
}

/// ZRINIT capability flags.
pub mod zrinit_flags {
    pub const CANFDX: u8 = 0x01;
    pub const CANOVIO: u8 = 0x02;
    pub const CANBRK: u8 = 0x04;
    pub const CANFC32: u8 = 0x20;
    pub const ESCCTL: u8 = 0x40;
    pub const ESC8: u8 = 0x80;
}

/// ZSINIT flag: the sender escapes control characters.
pub const ZSINIT_ESCCTL: u8 = 0x40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub frame: FrameType,
    pub bytes: [u8; 4],
}

impl Header {
    pub fn new(frame: FrameType, bytes: [u8; 4]) -> Self {
        Self { frame, bytes }
    }

    /// Offset headers (ZRPOS / ZDATA / ZEOF / ZACK with offset).
    pub fn with_offset(frame: FrameType, offset: u32) -> Self {
        Self::new(frame, offset.to_le_bytes())
    }

    /// ZRINIT with capability flags and buffer size.
    pub fn zrinit(flags: u8, bufsize: u16) -> Self {
        let size = bufsize.to_le_bytes();
        Self::new(FrameType::ZRINIT, [size[0], size[1], 0, flags])
    }

    pub fn name(&self) -> &'static str {
        self.frame.name()
    }

    pub fn offset(&self) -> u32 {
        u32::from_le_bytes(self.bytes)
    }

    // ZRINIT accessors.
    pub fn buffer_size(&self) -> u16 {
        u16::from_le_bytes([self.bytes[0], self.bytes[1]])
    }
    pub fn flags(&self) -> u8 {
        self.bytes[3]
    }
    pub fn can_full_duplex(&self) -> bool {
        self.flags() & zrinit_flags::CANFDX != 0
    }
    pub fn can_overlap_io(&self) -> bool {
        self.flags() & zrinit_flags::CANOVIO != 0
    }
    pub fn escape_ctrl_chars(&self) -> bool {
        self.flags() & zrinit_flags::ESCCTL != 0
    }
    pub fn escape_8th_bit(&self) -> bool {
        self.flags() & zrinit_flags::ESC8 != 0
    }

    fn crc_bytes(&self) -> [u8; 5] {
        [
            self.frame as u8,
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
        ]
    }

    /// Hex header: `**\x18B` + 14 lowercase hex digits + CR LF (+ XON
    /// except for ZACK / ZFIN).
    pub fn to_hex(&self) -> Vec<u8> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let body = self.crc_bytes();
        let crc = crc16(&body).to_be_bytes();
        let mut out = Vec::with_capacity(21);
        out.extend_from_slice(&HEX_HEADER_PREFIX);
        for b in body.iter().chain(crc.iter()) {
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0f) as usize]);
        }
        out.extend_from_slice(b"\r\n");
        if !matches!(self.frame, FrameType::ZACK | FrameType::ZFIN) {
            out.push(XON);
        }
        out
    }

    /// Binary header with CRC16 (ZFILE / ZDATA from the sender).
    pub fn to_binary16(&self, encoder: &Encoder) -> Vec<u8> {
        let body = self.crc_bytes();
        let crc = crc16(&body).to_be_bytes();
        let mut raw = body.to_vec();
        raw.extend_from_slice(&crc);
        let mut out = BINARY16_HEADER_PREFIX.to_vec();
        encoder.encode_into(&raw, &mut out);
        out
    }

    /// Binary header with CRC32.
    pub fn to_binary32(&self, encoder: &Encoder) -> Vec<u8> {
        let body = self.crc_bytes();
        let crc = crc32(&body).to_le_bytes();
        let mut raw = body.to_vec();
        raw.extend_from_slice(&crc);
        let mut out = BINARY32_HEADER_PREFIX.to_vec();
        encoder.encode_into(&raw, &mut out);
        out
    }
}

fn header_from_decoded(decoded: &[u8]) -> ZResult<Header> {
    let typenum = decoded[0];
    let frame = FrameType::from_u8(typenum)
        .ok_or_else(|| ZmodemError::protocol(format!("Received unsupported header: {typenum}")))?;
    if !frame.supported() {
        return Err(ZmodemError::protocol(format!(
            "Received unsupported header: {}",
            frame.name()
        )));
    }
    Ok(Header::new(
        frame,
        [decoded[1], decoded[2], decoded[3], decoded[4]],
    ))
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// CRC width of the frame a header was parsed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrcWidth {
    Crc16,
    Crc32,
}

/// Parse a hex header at the start of `buf`. `Ok(None)` means more bytes
/// are needed; on success returns the header and the bytes consumed.
pub fn parse_hex(buf: &[u8]) -> ZResult<Option<(Header, usize)>> {
    // Header is 4 + 14 (+ CR) bytes before the LF; lrzsz sends LF | 0x80.
    let window = &buf[..buf.len().min(21)];
    let Some(lf_pos) = window.iter().position(|&b| b == 0x8a || b == 0x0a) else {
        if buf.len() > 20 {
            return Err(ZmodemError::protocol(
                "Invalid hex header - no LF detected within 12 bytes!",
            ));
        }
        return Ok(None);
    };
    let mut hex_len = lf_pos;
    if hex_len == 19 {
        let cr = buf[18];
        if cr != 0x0d && cr != 0x8d {
            return Err(ZmodemError::protocol(
                "Invalid hex header: (CR/)LF doesn’t have CR!",
            ));
        }
        hex_len = 18;
    } else if hex_len != 18 {
        return Err(ZmodemError::protocol(
            "Invalid hex header: invalid number of bytes before LF!",
        ));
    }
    let digits = &buf[4..hex_len];
    let mut octets = [0u8; 7];
    for (i, pair) in digits.chunks(2).enumerate() {
        let hi = hex_value(pair[0]).ok_or_else(|| ZmodemError::protocol("Invalid hex digit"))?;
        let lo = hex_value(pair[1]).ok_or_else(|| ZmodemError::protocol("Invalid hex digit"))?;
        octets[i] = (hi << 4) | lo;
    }
    if crc16(&octets[..5]).to_be_bytes() != [octets[5], octets[6]] {
        return Err(ZmodemError::Crc);
    }
    let header = header_from_decoded(&octets)?;
    Ok(Some((header, lf_pos + 1)))
}

/// Parse a header at the start of `buf` (which begins with `ZPAD`, see
/// [`trim_leading_garbage`]). `Ok(None)` means more bytes are needed.
pub fn parse(buf: &[u8]) -> ZResult<Option<(Header, CrcWidth, usize)>> {
    if buf.len() >= 2 && buf[1] == ZPAD {
        return Ok(parse_hex(buf)?.map(|(h, n)| (h, CrcWidth::Crc16, n)));
    }
    if buf.len() >= 3 && buf[2] == ZBIN {
        let Some((decoded, used)) = decode_count(&buf[3..], 7) else {
            return Ok(None);
        };
        if crc16(&decoded[..5]).to_be_bytes() != [decoded[5], decoded[6]] {
            return Err(ZmodemError::Crc);
        }
        return Ok(Some((header_from_decoded(&decoded)?, CrcWidth::Crc16, 3 + used)));
    }
    if buf.len() >= 3 && buf[2] == ZBIN32 {
        let Some((decoded, used)) = decode_count(&buf[3..], 9) else {
            return Ok(None);
        };
        if crc32(&decoded[..5]).to_le_bytes() != [decoded[5], decoded[6], decoded[7], decoded[8]] {
            return Err(ZmodemError::Crc);
        }
        return Ok(Some((header_from_decoded(&decoded)?, CrcWidth::Crc32, 3 + used)));
    }
    if buf.len() < 3 {
        return Ok(None);
    }
    Err(ZmodemError::protocol(format!(
        "Unrecognized/unsupported octets: {:?}",
        &buf[..buf.len().min(8)]
    )))
}

/// Number of leading bytes of `buf` that cannot start a header
/// (`Zmodem.Header.trim_leading_garbage`). After removing them, `buf`
/// either is empty, starts with a header prefix, or holds an incomplete
/// prefix.
pub fn leading_garbage_len(buf: &[u8]) -> usize {
    let mut i = 0;
    loop {
        let rest = &buf[i..];
        if rest.is_empty() {
            return i;
        }
        let Some(pad) = rest.iter().position(|&b| b == ZPAD) else {
            return buf.len();
        };
        i += pad;
        let rest = &buf[i..];
        if rest.len() < 2 {
            return i;
        }
        if rest[1] == ZPAD {
            if rest.len() < HEX_HEADER_PREFIX.len() {
                if rest == &HEX_HEADER_PREFIX[..rest.len()] {
                    return i;
                }
            } else if rest[2] == HEX_HEADER_PREFIX[2] && rest[3] == HEX_HEADER_PREFIX[3] {
                return i;
            }
        } else if rest[1] == ZDLE {
            if rest.len() < BINARY16_HEADER_PREFIX.len() {
                return i;
            }
            if rest[2] == ZBIN || rest[2] == ZBIN32 {
                return i;
            }
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zrqinit_hex_matches_lrzsz() {
        let h = Header::new(FrameType::ZRQINIT, [0; 4]);
        assert_eq!(h.to_hex(), b"**\x18B00000000000000\r\n\x11".to_vec());
        let (parsed, consumed) = parse_hex(&h.to_hex()).unwrap().unwrap();
        assert_eq!(parsed, h);
        assert_eq!(consumed, 20);
    }

    #[test]
    fn lrzsz_style_cr_lf_with_high_bit() {
        // lrzsz terminates hex headers with CR | 0x80, LF | 0x80.
        let mut wire = Header::zrinit(0x23, 0).to_hex();
        wire[18] = 0x8d;
        wire[19] = 0x8a;
        let (h, n) = parse_hex(&wire).unwrap().unwrap();
        assert_eq!(h.frame, FrameType::ZRINIT);
        assert_eq!(h.flags(), 0x23);
        assert_eq!(n, 20);
    }

    #[test]
    fn binary_headers_roundtrip() {
        let enc = Encoder::default();
        let h = Header::with_offset(FrameType::ZDATA, 0x0102_1811);
        let (p, w, n) = parse(&h.to_binary16(&enc)).unwrap().unwrap();
        assert_eq!((p, w), (h, CrcWidth::Crc16));
        assert_eq!(n, h.to_binary16(&enc).len());
        let (p, w, _) = parse(&h.to_binary32(&enc)).unwrap().unwrap();
        assert_eq!((p, w), (h, CrcWidth::Crc32));
        assert_eq!(p.offset(), 0x0102_1811);
    }

    #[test]
    fn incomplete_and_corrupt_headers() {
        let wire = Header::new(FrameType::ZFIN, [0; 4]).to_hex();
        assert_eq!(parse(&wire[..10]).unwrap(), None);
        let mut bad = wire.clone();
        bad[6] = b'f';
        assert_eq!(parse(&bad), Err(ZmodemError::Crc));
    }

    #[test]
    fn garbage_trimming() {
        assert_eq!(leading_garbage_len(b"hello"), 5);
        assert_eq!(leading_garbage_len(b"ab**\x18B01"), 2);
        assert_eq!(leading_garbage_len(b"ab*"), 2);
        assert_eq!(leading_garbage_len(b"a*b**"), 3);
        assert_eq!(leading_garbage_len(b"x*\x18A"), 1);
        assert_eq!(leading_garbage_len(b"**x"), 3);
    }
}
