//! ZDLE escaping (`zmodem.js` `zdle.js`).

use crate::{XOFF, XON, ZDLE};

/// `ZRUB0`: escaped 0x7f.
const ZRUB0: u8 = b'l';
/// `ZRUB1`: escaped 0xff.
const ZRUB1: u8 = b'm';

/// ZDLE encoder. Netcatty always escapes every control character (the
/// `FORCE_ESCAPE_CTRL_CHARS` behaviour of `zmodem.js`), which every `rz`
/// accepts once told via ZSINIT.
#[derive(Debug, Clone)]
pub struct Encoder {
    escape_ctrl: bool,
}

impl Default for Encoder {
    fn default() -> Self {
        Self { escape_ctrl: true }
    }
}

impl Encoder {
    pub fn new(escape_ctrl: bool) -> Self {
        Self { escape_ctrl }
    }

    pub fn escapes_ctrl_chars(&self) -> bool {
        self.escape_ctrl
    }

    fn needs_escape(&self, b: u8) -> bool {
        if b & 0x60 != 0 {
            return false;
        }
        match b {
            ZDLE | XOFF | XON | 0x93 | 0x91 | 0x10 | 0x90 => true,
            // CR is only escaped after '@' without ESCCTL (Telenet CR-@-CR);
            // with ESCCTL every control character is escaped anyway.
            _ => self.escape_ctrl,
        }
    }

    /// Append the encoding of `data` to `out`.
    pub fn encode_into(&self, data: &[u8], out: &mut Vec<u8>) {
        out.reserve(data.len() + data.len() / 8 + 4);
        for &b in data {
            if self.needs_escape(b) {
                out.push(ZDLE);
                out.push(b ^ 0x40);
            } else {
                out.push(b);
            }
        }
    }

    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(data, &mut out);
        out
    }
}

/// Value of the escaped byte following a ZDLE.
#[inline]
pub fn unescape(b: u8) -> u8 {
    match b {
        ZRUB0 => 0x7f,
        ZRUB1 => 0xff,
        other => other ^ 0x40,
    }
}

/// Decode a complete ZDLE-encoded run.
pub fn decode(encoded: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(encoded.len());
    let mut i = 0;
    while i < encoded.len() {
        let b = encoded[i];
        if b == ZDLE {
            if let Some(&next) = encoded.get(i + 1) {
                out.push(unescape(next));
                i += 2;
                continue;
            }
            // Trailing bare ZDLE: malformed; the CRC check rejects it.
            out.push(unescape(0));
            i += 1;
            continue;
        }
        out.push(b);
        i += 1;
    }
    out
}

/// Decode `count` bytes starting at `buf[0]`. Returns the decoded bytes and
/// how many encoded bytes they took, or `None` when `buf` is too short
/// (`Zmodem.ZDLE.splice`).
pub fn decode_count(buf: &[u8], count: usize) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::with_capacity(count);
    let mut i = 0;
    while out.len() < count {
        let b = *buf.get(i)?;
        if b == ZDLE {
            let next = *buf.get(i + 1)?;
            out.push(unescape(next));
            i += 2;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Some((out, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_bytes() {
        let data: Vec<u8> = (0..=255u8).collect();
        for escape in [true, false] {
            let enc = Encoder::new(escape).encode(&data);
            assert_eq!(decode(&enc), data);
            // XON / XOFF / ZDLE never appear raw on the wire.
            assert!(!enc.contains(&XON));
            assert!(!enc.contains(&XOFF));
            let raw_zdles = enc.windows(2).filter(|w| w[0] == ZDLE).count();
            assert!(raw_zdles > 0);
        }
        let enc = Encoder::new(true).encode(&data);
        assert!(enc.iter().all(|&b| b & 0x60 != 0 || b == ZDLE));
    }

    #[test]
    fn decode_count_needs_complete_escapes() {
        assert_eq!(decode_count(b"ab", 3), None);
        assert_eq!(decode_count(&[b'a', ZDLE], 2), None);
        assert_eq!(
            decode_count(&[b'a', ZDLE, b'X', b'z'], 2),
            Some((vec![b'a', ZDLE], 3))
        );
        assert_eq!(decode(&[ZDLE, b'l', ZDLE, b'm']), vec![0x7f, 0xff]);
    }
}
