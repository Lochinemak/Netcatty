//! Website icons per host and origin (Electron: `siteIconStore.cjs`), plus
//! the raster data-URL validation shared with bookmarks and the image MIME
//! sniffer used for fetched favicons.

use crate::fs::{atomic_write, read_json};
use crate::url::icon_origin;
use crate::DEFAULT_ICON_COLOR;
use base64::Engine;
use parking_lot::Mutex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const MAX_ICONS: usize = 1000;
pub const MAX_ICON_BYTES: usize = 64 * 1024;
pub const IMAGE_MIMES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
    "image/x-icon",
    "image/vnd.microsoft.icon",
];

fn data_url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^data:([^;,]+);base64,([A-Za-z0-9+/]+={0,2})$").unwrap())
}

fn color_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^#[0-9a-f]{6}$").unwrap())
}

/// `#rrggbb` or the default colour.
pub(crate) fn normalize_color(raw: Option<&str>) -> String {
    match raw {
        Some(value) if color_re().is_match(value) => value.to_string(),
        _ => DEFAULT_ICON_COLOR.to_string(),
    }
}

/// A `data:image/<raster>;base64,…` URL of at most 64 KiB decoded.
pub fn valid_image_data_url(value: &str) -> bool {
    if value.len() as f64 > MAX_ICON_BYTES as f64 * 1.4 {
        return false;
    }
    let Some(captures) = data_url_re().captures(value) else {
        return false;
    };
    if !IMAGE_MIMES.contains(&&captures[1]) {
        return false;
    }
    base64_len(&captures[2]) <= MAX_ICON_BYTES
}

/// Decoded byte length of a base64 payload (`Buffer.byteLength(x, "base64")`).
fn base64_len(payload: &str) -> usize {
    let padding = payload.bytes().rev().take_while(|b| *b == b'=').count();
    payload.len() * 3 / 4 - padding
}

/// Sniff the MIME type of fetched icon bytes (PNG, JPEG, GIF, WebP, ICO).
pub fn image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[137, 80, 78, 71, 13, 10, 26, 10]) {
        return Some("image/png");
    }
    if bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff {
        return Some("image/jpeg");
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if bytes.starts_with(&[0, 0, 1, 0]) {
        return Some("image/x-icon");
    }
    None
}

/// Encode fetched icon bytes as a data URL when they are a known raster format.
pub fn image_data_url(bytes: &[u8]) -> Option<String> {
    let mime = image_mime(bytes)?;
    Some(format!(
        "data:{mime};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IconMode {
    #[default]
    Auto,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteIcon {
    pub host_id: String,
    pub origin: String,
    pub mode: IconMode,
    pub data_url: Option<String>,
    pub glyph: String,
    pub color: String,
}

/// What a caller sets: the favicon fetcher (`Auto` + data URL) or the user
/// (`Custom` + glyph / colour / optional image).
#[derive(Debug, Clone, Default)]
pub struct SiteIconInput {
    pub mode: IconMode,
    pub data_url: Option<String>,
    pub glyph: Option<String>,
    pub color: Option<String>,
}

fn normalize_icon(raw: &serde_json::Value) -> Result<SiteIcon, String> {
    let object = raw.as_object().ok_or("Invalid website icon")?;
    let host_id: String = object
        .get("hostId")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(256).collect())
        .unwrap_or_default();
    let origin = object
        .get("origin")
        .and_then(|v| v.as_str())
        .and_then(icon_origin);
    let (Some(origin), false) = (origin, host_id.is_empty()) else {
        return Err("Invalid website icon target".into());
    };
    let mode = match object.get("mode").and_then(|v| v.as_str()) {
        Some("custom") => IconMode::Custom,
        _ => IconMode::Auto,
    };
    let data_url = object
        .get("dataUrl")
        .and_then(|v| v.as_str())
        .filter(|v| valid_image_data_url(v))
        .map(str::to_string);
    let glyph: String = object
        .get("glyph")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().chars().take(4).collect())
        .unwrap_or_default();
    let color = normalize_color(object.get("color").and_then(|v| v.as_str()));
    if data_url.is_none() && glyph.is_empty() {
        return Err("Website icon is empty".into());
    }
    Ok(SiteIcon {
        host_id,
        origin,
        mode,
        data_url,
        glyph,
        color,
    })
}

/// `host-browser-site-icons.json`: one icon per `(hostId, origin)`.
pub struct SiteIconStore {
    file: PathBuf,
    icons: Mutex<BTreeMap<String, SiteIcon>>,
}

fn key_for(host_id: &str, url: &str) -> Option<String> {
    icon_origin(url).map(|origin| format!("{host_id}\n{origin}"))
}

impl SiteIconStore {
    /// Load the store from `<dir>/host-browser-site-icons.json`.
    pub fn open(dir: &Path) -> Self {
        let file = dir.join("host-browser-site-icons.json");
        let mut icons = BTreeMap::new();
        match read_json(&file) {
            Ok(Some(serde_json::Value::Array(items))) => {
                for raw in items.iter().take(MAX_ICONS) {
                    if let Ok(icon) = normalize_icon(raw) {
                        icons.insert(format!("{}\n{}", icon.host_id, icon.origin), icon);
                    }
                }
            }
            Ok(_) => {}
            Err(err) => tracing::warn!(%err, "[HostBrowser] Could not read website icons"),
        }
        Self {
            file,
            icons: Mutex::new(icons),
        }
    }

    fn persist(&self, icons: &BTreeMap<String, SiteIcon>) {
        let values: Vec<&SiteIcon> = icons.values().collect();
        let bytes = serde_json::to_vec(&values).unwrap_or_else(|_| b"[]".to_vec());
        if let Err(err) = atomic_write(&self.file, &bytes) {
            tracing::warn!(%err, "[HostBrowser] Could not save website icons");
        }
    }

    pub fn get(&self, host_id: &str, url: &str) -> Option<SiteIcon> {
        let key = key_for(host_id, url)?;
        self.icons.lock().get(&key).cloned()
    }

    /// Store an icon for the origin of `url`. An automatic (favicon) update
    /// never replaces a user's custom icon.
    pub fn set(&self, host_id: &str, url: &str, input: SiteIconInput) -> Result<SiteIcon, String> {
        let key = key_for(host_id, url).ok_or("Invalid website address")?;
        let mut icons = self.icons.lock();
        if let Some(previous) = icons.get(&key) {
            if input.mode == IconMode::Auto && previous.mode == IconMode::Custom {
                return Ok(previous.clone());
            }
        } else if icons.len() >= MAX_ICONS {
            return Err("Website icon limit reached".into());
        }
        let next = normalize_icon(&serde_json::json!({
            "hostId": host_id,
            "origin": icon_origin(url),
            "mode": match input.mode { IconMode::Custom => "custom", IconMode::Auto => "auto" },
            "dataUrl": input.data_url,
            "glyph": input.glyph,
            "color": input.color,
        }))?;
        icons.insert(key, next.clone());
        self.persist(&icons);
        Ok(next)
    }

    /// Forget the icon of the origin of `url`; `true` when one existed.
    pub fn reset(&self, host_id: &str, url: &str) -> bool {
        let Some(key) = key_for(host_id, url) else {
            return false;
        };
        let mut icons = self.icons.lock();
        if icons.remove(&key).is_some() {
            self.persist(&icons);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAVICON: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLytQAAAABJRU5ErkJggg==";

    #[test]
    fn website_icons_persist_per_host_and_user_overrides_survive_automatic_updates() {
        let dir = tempfile::tempdir().unwrap();
        let first = SiteIconStore::open(dir.path());
        first
            .set(
                "host-a",
                "https://example.com/page",
                SiteIconInput {
                    mode: IconMode::Auto,
                    data_url: Some(FAVICON.into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            first.get("host-a", "https://example.com/other").unwrap().data_url.as_deref(),
            Some(FAVICON)
        );
        assert!(first.get("host-b", "https://example.com/page").is_none());
        first
            .set(
                "host-a",
                "https://example.com/page",
                SiteIconInput {
                    mode: IconMode::Custom,
                    glyph: Some("\u{2726}".into()),
                    color: Some("#123456".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        first
            .set(
                "host-a",
                "https://example.com/page",
                SiteIconInput {
                    mode: IconMode::Auto,
                    data_url: Some(FAVICON.into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let reopened = SiteIconStore::open(dir.path());
        assert_eq!(
            reopened.get("host-a", "https://example.com/page").unwrap(),
            SiteIcon {
                host_id: "host-a".into(),
                origin: "https://example.com".into(),
                mode: IconMode::Custom,
                data_url: None,
                glyph: "\u{2726}".into(),
                color: "#123456".into(),
            }
        );
        assert!(reopened.reset("host-a", "https://example.com/page"));
        assert!(SiteIconStore::open(dir.path())
            .get("host-a", "https://example.com/page")
            .is_none());
    }

    #[test]
    fn website_icon_images_accept_only_bounded_raster_data() {
        assert!(valid_image_data_url(FAVICON));
        assert!(!valid_image_data_url("data:image/svg+xml;base64,PHN2Zz4="));
        let big = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 65 * 1024]);
        assert!(!valid_image_data_url(&format!("data:image/png;base64,{big}")));
        assert!(!valid_image_data_url("data:image/png,notbase64"));
    }

    #[test]
    fn empty_icons_and_bad_targets_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = SiteIconStore::open(dir.path());
        assert_eq!(
            store
                .set("host", "https://example.com/", SiteIconInput::default())
                .unwrap_err(),
            "Website icon is empty"
        );
        assert_eq!(
            store
                .set("host", "ftp://example.com/", SiteIconInput::default())
                .unwrap_err(),
            "Invalid website address"
        );
        assert!(!store.reset("host", "https://example.com/"));
    }

    #[test]
    fn sniffs_raster_formats() {
        assert_eq!(image_mime(&[137, 80, 78, 71, 13, 10, 26, 10, 0]), Some("image/png"));
        assert_eq!(image_mime(&[0xff, 0xd8, 0xff, 0xe0]), Some("image/jpeg"));
        assert_eq!(image_mime(b"GIF89a..."), Some("image/gif"));
        assert_eq!(image_mime(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(image_mime(&[0, 0, 1, 0, 1]), Some("image/x-icon"));
        assert_eq!(image_mime(b"<svg/>"), None);
        assert!(image_data_url(&[137, 80, 78, 71, 13, 10, 26, 10])
            .unwrap()
            .starts_with("data:image/png;base64,"));
    }
}
