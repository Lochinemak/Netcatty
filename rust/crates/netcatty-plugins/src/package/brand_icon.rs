//! Brand icon inspection (port of `packages/plugin-contract/src/brandIcon.ts`).

use crate::error::{PluginError, PluginResult};

pub const PLUGIN_BRAND_ICON_MAX_BYTES: usize = 256 * 1024;
pub const PLUGIN_BRAND_ICON_MAX_EDGE: u32 = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandIconInfo {
    pub mime_type: &'static str,
    pub width: u32,
    pub height: u32,
}

fn err(message: &str) -> PluginError {
    PluginError::host(message)
}

fn be32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}
fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}
fn le16(bytes: &[u8], offset: usize) -> u32 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as u32
}

/// `inspectPluginBrandIcon`: static, bounded PNG / WebP only.
pub fn inspect_brand_icon(bytes: &[u8], package_path: &str) -> PluginResult<BrandIconInfo> {
    if bytes.is_empty() || bytes.len() > PLUGIN_BRAND_ICON_MAX_BYTES {
        return Err(err("Plugin brand icon exceeds size limit or is empty"));
    }
    let (mime_type, width, height);
    if package_path.ends_with(".png") && bytes.len() >= 33 && bytes[..8] == [137, 80, 78, 71, 13, 10, 26, 10] {
        mime_type = "image/png";
        let (mut w, mut h) = (0, 0);
        let (mut end, mut data) = (false, false);
        let mut offset = 8usize;
        while offset < bytes.len() {
            if offset + 12 > bytes.len() {
                return Err(err("Invalid PNG chunk"));
            }
            let size = be32(bytes, offset) as usize;
            let kind = &bytes[offset + 4..offset + 8];
            if offset + 12 + size > bytes.len() {
                return Err(err("Invalid PNG length"));
            }
            if kind == b"acTL" || kind == b"fcTL" || kind == b"fdAT" {
                return Err(err("Animated brand icons are unsupported"));
            }
            if offset == 8 {
                if kind != b"IHDR" || size != 13 {
                    return Err(err("Invalid PNG header"));
                }
                w = be32(bytes, offset + 8);
                h = be32(bytes, offset + 12);
            } else if kind == b"IHDR" {
                return Err(err("Duplicate PNG header"));
            }
            if kind == b"IDAT" {
                data = true;
            }
            offset += 12 + size;
            if kind == b"IEND" {
                end = size == 0 && offset == bytes.len();
                break;
            }
        }
        if !end || !data {
            return Err(err("Incomplete PNG icon"));
        }
        width = w;
        height = h;
    } else if package_path.ends_with(".webp") && bytes.len() >= 30 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        mime_type = "image/webp";
        if le32(bytes, 4) as usize + 8 != bytes.len() {
            return Err(err("Invalid WebP length"));
        }
        let (mut w, mut h) = (0u32, 0u32);
        let mut image = false;
        let mut offset = 12usize;
        while offset < bytes.len() {
            if offset + 8 > bytes.len() {
                return Err(err("Invalid WebP chunk"));
            }
            let kind = &bytes[offset..offset + 4];
            let size = le32(bytes, offset + 4) as usize;
            let start = offset + 8;
            if start + size + (size % 2) > bytes.len() {
                return Err(err("Invalid WebP chunk length"));
            }
            if kind == b"ANIM" || kind == b"ANMF" || (kind == b"VP8X" && bytes[start] & 2 != 0) {
                return Err(err("Animated brand icons are unsupported"));
            }
            if kind == b"VP8X" && size == 10 {
                w = 1 + bytes[start + 4] as u32 + ((bytes[start + 5] as u32) << 8) + ((bytes[start + 6] as u32) << 16);
                h = 1 + bytes[start + 7] as u32 + ((bytes[start + 8] as u32) << 8) + ((bytes[start + 9] as u32) << 16);
            } else if kind == b"VP8L" && size >= 5 && bytes[start] == 0x2f {
                let bits = le32(bytes, start + 1);
                let (iw, ih) = (1 + (bits & 0x3fff), 1 + ((bits >> 14) & 0x3fff));
                if iw > 512 || ih > 512 {
                    return Err(err("WebP image dimensions exceed limit"));
                }
                if w == 0 {
                    w = iw;
                }
                if h == 0 {
                    h = ih;
                }
                image = true;
            } else if kind == b"VP8 " && size >= 10 && bytes[start + 3] == 0x9d && bytes[start + 4] == 1 && bytes[start + 5] == 0x2a {
                let (iw, ih) = (le16(bytes, start + 6) & 0x3fff, le16(bytes, start + 8) & 0x3fff);
                if iw > 512 || ih > 512 {
                    return Err(err("WebP image dimensions exceed limit"));
                }
                if w == 0 {
                    w = iw;
                }
                if h == 0 {
                    h = ih;
                }
                image = true;
            }
            offset = start + size + (size % 2);
        }
        if !image {
            return Err(err("Missing WebP image"));
        }
        width = w;
        height = h;
    } else {
        return Err(err("Brand icons require matching PNG or WebP bytes and extension"));
    }
    if width < 1 || height < 1 || width > PLUGIN_BRAND_ICON_MAX_EDGE || height > PLUGIN_BRAND_ICON_MAX_EDGE {
        return Err(err("Plugin brand icon dimensions exceed 512px or are invalid"));
    }
    Ok(BrandIconInfo { mime_type, width, height })
}
