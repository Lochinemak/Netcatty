//! CRC-16/XMODEM (ZMODEM headers + CRC16 subpackets, YMODEM packets) and
//! CRC-32/IEEE (ZMODEM CRC32 frames).

const fn crc16_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC16: [u16; 256] = crc16_table();
static CRC32: [u32; 256] = crc32_table();

/// Incremental CRC-16/XMODEM update.
pub fn crc16_update(mut crc: u16, data: &[u8]) -> u16 {
    for &b in data {
        crc = (crc << 8) ^ CRC16[(((crc >> 8) as u8) ^ b) as usize];
    }
    crc
}

/// CRC-16/XMODEM (poly 0x1021, init 0).
pub fn crc16(data: &[u8]) -> u16 {
    crc16_update(0, data)
}

/// Incremental CRC-32 over the raw (pre-inverted) register.
pub fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = (crc >> 8) ^ CRC32[((crc as u8) ^ b) as usize];
    }
    crc
}

/// CRC-32/IEEE (the `crc-32` npm package `zmodem.js` uses).
pub fn crc32(data: &[u8]) -> u32 {
    !crc32_update(0xFFFF_FFFF, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_values() {
        assert_eq!(crc16(b"123456789"), 0x31C3);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc16(b""), 0);
        assert_eq!(crc16_update(crc16(b"1234"), b"56789"), 0x31C3);
    }
}
