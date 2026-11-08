//! ZMODEM data subpackets (`zmodem.js` `zsubpacket.js`).

use crate::crc::{crc16_update, crc32_update};
use crate::header::CrcWidth;
use crate::zdle::{decode, decode_count, Encoder};
use crate::{ZResult, ZmodemError, ZDLE};

/// Subpacket terminator (the byte after the closing ZDLE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameEnd {
    /// `ZCRCE`: frame ends, header follows.
    EndNoAck = 0x68,
    /// `ZCRCG`: frame continues non-stop.
    NoEndNoAck = 0x69,
    /// `ZCRCQ`: frame continues, ZACK expected.
    NoEndAck = 0x6a,
    /// `ZCRCW`: frame ends, ZACK expected.
    EndAck = 0x6b,
}

impl FrameEnd {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x68 => FrameEnd::EndNoAck,
            0x69 => FrameEnd::NoEndNoAck,
            0x6a => FrameEnd::NoEndAck,
            0x6b => FrameEnd::EndAck,
            _ => return None,
        })
    }

    pub fn frame_end(self) -> bool {
        matches!(self, FrameEnd::EndNoAck | FrameEnd::EndAck)
    }

    pub fn ack_expected(self) -> bool {
        matches!(self, FrameEnd::NoEndAck | FrameEnd::EndAck)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subpacket {
    pub payload: Vec<u8>,
    pub end: FrameEnd,
}

/// Encode a subpacket with CRC16 (what Netcatty sends).
pub fn encode16(payload: &[u8], end: FrameEnd, encoder: &Encoder, out: &mut Vec<u8>) {
    encoder.encode_into(payload, out);
    out.push(ZDLE);
    out.push(end as u8);
    let crc = crc16_update(crc16_update(0, payload), &[end as u8]);
    encoder.encode_into(&crc.to_be_bytes(), out);
}

/// Encode a subpacket with CRC32.
pub fn encode32(payload: &[u8], end: FrameEnd, encoder: &Encoder, out: &mut Vec<u8>) {
    encoder.encode_into(payload, out);
    out.push(ZDLE);
    out.push(end as u8);
    let crc = !crc32_update(crc32_update(0xFFFF_FFFF, payload), &[end as u8]);
    encoder.encode_into(&crc.to_le_bytes(), out);
}

/// Parse a subpacket at the start of `buf`. `Ok(None)` means more bytes
/// are needed; on success returns the subpacket and the bytes consumed.
pub fn parse(buf: &[u8], width: CrcWidth) -> ZResult<Option<(Subpacket, usize)>> {
    let crc_len = match width {
        CrcWidth::Crc16 => 2,
        CrcWidth::Crc32 => 4,
    };
    // Find the closing ZDLE + frame-end byte. Escaped bytes are skipped in
    // pairs so an escaped value can never be mistaken for a terminator.
    let mut i = 0;
    let (end_at, end) = loop {
        let Some(rel) = buf[i..].iter().position(|&b| b == ZDLE) else {
            return Ok(None);
        };
        let zdle_at = i + rel;
        let Some(&next) = buf.get(zdle_at + 1) else {
            return Ok(None);
        };
        if let Some(end) = FrameEnd::from_u8(next) {
            break (zdle_at, end);
        }
        i = zdle_at + 2;
    };
    let Some((crc, crc_used)) = decode_count(&buf[end_at + 2..], crc_len) else {
        return Ok(None);
    };
    let payload = decode(&buf[..end_at]);
    let ok = match width {
        CrcWidth::Crc16 => {
            crc16_update(crc16_update(0, &payload), &[end as u8]).to_be_bytes()[..] == crc[..]
        }
        CrcWidth::Crc32 => {
            (!crc32_update(crc32_update(0xFFFF_FFFF, &payload), &[end as u8])).to_le_bytes()[..]
                == crc[..]
        }
    };
    if !ok {
        return Err(ZmodemError::Crc);
    }
    Ok(Some((Subpacket { payload, end }, end_at + 2 + crc_used)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_crc16_and_crc32() {
        let enc = Encoder::default();
        let payload: Vec<u8> = (0..=255u8).cycle().take(3000).collect();
        for end in [
            FrameEnd::EndNoAck,
            FrameEnd::NoEndNoAck,
            FrameEnd::NoEndAck,
            FrameEnd::EndAck,
        ] {
            let mut wire = Vec::new();
            encode16(&payload, end, &enc, &mut wire);
            let (sp, used) = parse(&wire, CrcWidth::Crc16).unwrap().unwrap();
            assert_eq!(used, wire.len());
            assert_eq!(sp, Subpacket { payload: payload.clone(), end });

            let mut wire32 = Vec::new();
            encode32(&payload, end, &enc, &mut wire32);
            wire32.extend_from_slice(b"tail");
            let (sp, used) = parse(&wire32, CrcWidth::Crc32).unwrap().unwrap();
            assert_eq!(used, wire32.len() - 4);
            assert_eq!(sp.payload, payload);
        }
    }

    #[test]
    fn partial_and_corrupt() {
        let enc = Encoder::default();
        let mut wire = Vec::new();
        encode16(b"hello", FrameEnd::EndAck, &enc, &mut wire);
        for cut in 0..wire.len() {
            assert_eq!(parse(&wire[..cut], CrcWidth::Crc16).unwrap(), None, "cut {cut}");
        }
        wire[0] ^= 1;
        assert_eq!(parse(&wire, CrcWidth::Crc16), Err(ZmodemError::Crc));
    }
}
