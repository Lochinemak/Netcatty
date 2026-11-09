//! Theme packs, contribution / brand icons and host-drawn views (ports of
//! `themeService.cjs`, `domain/pluginThemePack.cjs`,
//! `contributionIconService.cjs`, `viewResourceService.cjs`,
//! `hostDrawnViewHost.cjs` and `domain/pluginRemoteTreePolicy.cjs`).
//!
//! Icon difference: Electron rasterizes every icon to a 64 px PNG in an
//! isolated offscreen window. The Rust host validates format, magic bytes,
//! dimensions and size, then returns the original bytes as a data URL
//! (rendered through `<img>`, where SVG scripts never execute); SVG sources
//! with scripts, foreign objects or external references are rejected.

use crate::browser::read_contained;
use crate::contract;
use crate::contributions::ContributionService;
use crate::database::{PluginDatabase, PluginRecord};
use crate::error::{PluginError, PluginResult};
use crate::host::{channels, HostEvents};
use crate::package::brand_icon::inspect_brand_icon;
use crate::package::compat::is_static_theme_pack;
use crate::store::PackageStore;
use base64::Engine;
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn host(message: impl Into<String>) -> PluginError {
    PluginError::host(message)
}

// ---- theme palette projection ---------------------------------------------------

const LIGHT: &[(&str, &str)] = &[
    ("background", "#ffffff"), ("foreground", "#161a1d"), ("card", "#ffffff"), ("cardForeground", "#161a1d"),
    ("popover", "#ffffff"), ("popoverForeground", "#161a1d"), ("secondary", "#e5e7eb"), ("secondaryForeground", "#161a1d"),
    ("muted", "#f0f2f4"), ("mutedForeground", "#374151"), ("accent", "#1d4ed8"), ("destructive", "#b91c1c"),
    ("destructiveForeground", "#ffffff"), ("border", "#6b7280"), ("input", "#6b7280"),
];
const DARK: &[(&str, &str)] = &[
    ("background", "#111827"), ("foreground", "#f9fafb"), ("card", "#1f2937"), ("cardForeground", "#f9fafb"),
    ("popover", "#1f2937"), ("popoverForeground", "#f9fafb"), ("secondary", "#374151"), ("secondaryForeground", "#ffffff"),
    ("muted", "#273244"), ("mutedForeground", "#e5e7eb"), ("accent", "#93c5fd"), ("destructive", "#fca5a5"),
    ("destructiveForeground", "#111827"), ("border", "#9ca3af"), ("input", "#9ca3af"),
];

fn rgb(hex: &str) -> [f64; 3] {
    let channel = |o: usize| u8::from_str_radix(&hex[o..o + 2], 16).unwrap_or(0) as f64 / 255.0;
    [channel(1), channel(3), channel(5)]
}

fn luminance(hex: &str) -> f64 {
    let w = [0.2126, 0.7152, 0.0722];
    rgb(hex)
        .iter()
        .enumerate()
        .map(|(i, v)| w[i] * if *v <= 0.04045 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) })
        .sum()
}

pub fn contrast(a: &str, b: &str) -> f64 {
    let (x, y) = (luminance(a), luminance(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

/// `resolveThemePalette`: WCAG contrast checks; errors when unreadable.
pub fn resolve_theme_palette(palette: &Value) -> PluginResult<()> {
    let base = if palette["base"] == "dark" { DARK } else { LIGHT };
    let mut colors: HashMap<String, String> = base.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    if let Some(custom) = palette["colors"].as_object() {
        for (k, v) in custom {
            colors.insert(k.clone(), v.as_str().unwrap_or("").to_string());
        }
    }
    for value in colors.values() {
        if value.len() != 7 || !value.starts_with('#') || !value[1..].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(host("Invalid theme color"));
        }
    }
    let c = |k: &str| colors.get(k).cloned().unwrap_or_default();
    for (a, b) in [("foreground", "background"), ("cardForeground", "card"), ("popoverForeground", "popover"), ("secondaryForeground", "secondary"), ("mutedForeground", "muted"), ("destructiveForeground", "destructive")] {
        if contrast(&c(a), &c(b)) < 4.51 {
            return Err(host("Theme text contrast is below 4.5:1"));
        }
    }
    for surface in ["background", "card", "popover", "secondary", "muted"] {
        for key in ["foreground", "mutedForeground"] {
            if contrast(&c(key), &c(surface)) < 4.51 {
                return Err(host("Theme neutral-surface text contrast is below 4.5:1"));
            }
        }
    }
    for surface in ["background", "card", "popover"] {
        for key in ["accent", "destructive"] {
            if contrast(&c(key), &c(surface)) < 4.51 {
                return Err(host("Theme state contrast is below 4.5:1"));
            }
        }
        for key in ["border", "input"] {
            if contrast(&c(key), &c(surface)) < 3.01 {
                return Err(host("Theme control contrast is below 3:1"));
            }
        }
    }
    Ok(())
}

fn theme_key(r: &Value) -> String {
    json!([r["pluginId"], r["themeId"], r["version"], r["digest"], r["variant"]]).to_string()
}

pub struct ThemeService {
    database: Arc<PluginDatabase>,
    store: Arc<PackageStore>,
    events: Arc<dyn HostEvents>,
    cache: Mutex<HashMap<String, Value>>,
    tail: tokio::sync::Mutex<()>,
}

impl ThemeService {
    pub fn new(database: Arc<PluginDatabase>, store: Arc<PackageStore>, contributions: &ContributionService, events: Arc<dyn HostEvents>) -> Arc<Self> {
        let service = Arc::new(Self { database, store, events, cache: Mutex::new(HashMap::new()), tail: tokio::sync::Mutex::new(()) });
        let weak = Arc::downgrade(&service);
        contributions.on_did_change(Arc::new(move |event: &Value| {
            if matches!(event["reason"].as_str(), Some("initialized" | "plugin-enabled" | "plugin-disabled")) {
                if let Some(s) = weak.upgrade() {
                    s.cache.lock().clear();
                    s.events.emit(channels::THEMES_CHANGED, json!({}));
                }
            }
        }));
        service
    }

    fn active(&self, r: &Value) -> bool {
        self.database.get_active_plugin(r["pluginId"].as_str().unwrap_or("")).ok().flatten().is_some_and(|p| {
            p.enabled
                && p.active_version.as_deref() == r["version"].as_str()
                && p.archive_sha256.as_deref() == r["digest"].as_str()
                && p.manifest.as_ref().and_then(|m| m["contributes"]["themes"].as_array()).is_some_and(|t| {
                    t.iter().any(|t| t["id"] == r["themeId"] && t["variant"] == r["variant"])
                })
        })
    }

    fn read_palette(&self, plugin: &PluginRecord, theme: &Value) -> PluginResult<Value> {
        let limits = contract::def_const("ThemePackLimits").cloned().unwrap_or_else(|| json!({ "jsonBytes": 65536 }));
        let root = self.store.prepare_package_root(plugin)?;
        let entry = theme["entry"].as_str().unwrap_or("");
        if !entry.ends_with(".json") {
            return Err(host("Invalid path"));
        }
        let segments: Vec<String> = entry.split('/').map(str::to_string).collect();
        let (_, bytes) = read_contained(&root, &segments, limits["jsonBytes"].as_u64().unwrap_or(65536))?;
        let palette: Value = serde_json::from_slice(&bytes).map_err(|_| host("Invalid theme palette"))?;
        let expected_base = if theme["variant"].as_str().unwrap_or("").ends_with("dark") { "dark" } else { "light" };
        if !contract::is_valid("ThemePackPalette", &palette) || palette["base"] != expected_base {
            return Err(host("Invalid theme palette"));
        }
        resolve_theme_palette(&palette)?;
        Ok(palette)
    }

    /// `getPluginThemes` → `{ selection, entries, diagnostics }`.
    pub fn catalog(&self) -> PluginResult<Value> {
        let max = contract::def_const("ThemePackLimits").and_then(|l| l["catalogEntries"].as_u64()).unwrap_or(256) as usize;
        let mut entries = Vec::new();
        let mut diagnostics = Vec::new();
        for plugin in self.database.list_plugins()? {
            if !plugin.enabled {
                continue;
            }
            let manifest = plugin.manifest.clone().unwrap_or(Value::Null);
            for theme in manifest["contributes"]["themes"].as_array().cloned().unwrap_or_default() {
                if entries.len() >= max {
                    if diagnostics.len() < 256 {
                        diagnostics.push(json!({ "pluginId": plugin.id, "code": "capacity" }));
                    }
                    break;
                }
                let r = json!({ "pluginId": plugin.id, "themeId": theme["id"], "version": plugin.active_version, "digest": plugin.archive_sha256, "variant": theme["variant"] });
                let cached = self.cache.lock().get(&theme_key(&r)).cloned();
                let palette = match cached {
                    Some(p) => Ok(p),
                    None => self.read_palette(&plugin, &theme),
                };
                match palette {
                    Ok(palette) if self.active(&r) => {
                        self.cache.lock().insert(theme_key(&r), palette.clone());
                        let label = match &theme["label"] {
                            Value::String(s) => s.clone(),
                            Value::Object(m) => m.get("en").or(m.get("default")).or(m.values().next()).and_then(Value::as_str).unwrap_or("").to_string(),
                            _ => String::new(),
                        };
                        entries.push(json!({ "ref": r, "label": label, "pluginName": manifest["name"], "dataOnly": is_static_theme_pack(&manifest), "palette": palette }));
                    }
                    Ok(_) => {}
                    Err(_) => {
                        if diagnostics.len() < 256 {
                            diagnostics.push(json!({ "pluginId": plugin.id, "themeId": theme["id"], "code": "invalid" }));
                        }
                    }
                }
            }
        }
        let selection = self.database.get_host_theme_selection()?;
        if !contract::is_valid("ThemePackSelection", &selection) {
            return Err(host("Invalid saved theme selection"));
        }
        Ok(json!({ "selection": selection, "entries": entries, "diagnostics": diagnostics }))
    }

    /// `applyPluginTheme(request)`.
    pub async fn apply(&self, request: &Value) -> PluginResult<Value> {
        let _guard = self.tail.lock().await;
        if !contract::is_valid("ThemePackApplyRequest", request) {
            return Err(PluginError::invalid("Invalid theme selection request"));
        }
        let catalog = self.catalog()?;
        let selection = catalog["selection"].clone();
        let revision = selection["revision"].as_i64().unwrap_or(0);
        if Some(revision) != request["expectedRevision"].as_i64() {
            return Err(host("Theme selection changed; refresh before applying"));
        }
        let mode = request["mode"].as_str().unwrap_or("light");
        let choice = request.get("choice").cloned().unwrap_or(Value::Null);
        if !choice.is_null() {
            let found = catalog["entries"].as_array().into_iter().flatten().find(|e| theme_key(&e["ref"]) == theme_key(&choice["ref"]));
            if !found.is_some_and(|e| e["palette"]["base"] == mode && self.active(&e["ref"])) {
                return Err(host("Theme is no longer available"));
            }
        }
        let mut next = selection.clone();
        next["revision"] = json!(revision + 1);
        next[mode] = choice.clone();
        self.database.commit_host_theme_selection(revision, &next, choice["ref"]["pluginId"].as_str())?;
        self.events.emit(channels::THEMES_CHANGED, json!({}));
        self.catalog()
    }
}

// ---- icons -----------------------------------------------------------------------

const MAX_ICON_SOURCE_BYTES: u64 = 512 * 1024;
const MAX_ICON_SOURCE_EDGE: u32 = 4096;

fn be16(b: &[u8], o: usize) -> u32 {
    u16::from_be_bytes([b[o], b[o + 1]]) as u32
}

/// `inspectContributionIconSource` → mime type.
pub fn inspect_icon(body: &[u8], extension: &str, max_edge: u32) -> PluginResult<&'static str> {
    let expected = match extension {
        ".gif" => "image/gif",
        ".ico" => "image/x-icon",
        ".jpeg" | ".jpg" => "image/jpeg",
        ".png" => "image/png",
        ".svg" => "image/svg+xml",
        ".webp" => "image/webp",
        _ => return Err(host("Plugin contribution icon format is unsupported")),
    };
    if body.is_empty() {
        return Err(host("Plugin contribution icon is empty"));
    }
    let le16 = |o: usize| u16::from_le_bytes([body[o], body[o + 1]]) as u32;
    let (mime, w, h): (&str, u32, u32) = if body.len() >= 24 && body[..8] == [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] && &body[12..16] == b"IHDR" {
        ("image/png", u32::from_be_bytes([body[16], body[17], body[18], body[19]]), u32::from_be_bytes([body[20], body[21], body[22], body[23]]))
    } else if body.len() >= 10 && (body.starts_with(b"GIF87a") || body.starts_with(b"GIF89a")) {
        ("image/gif", le16(6), le16(8))
    } else if body.len() >= 22 && le16(0) == 0 && le16(2) == 1 {
        let count = le16(4) as usize;
        if count < 1 || body.len() < 6 + count * 16 {
            return Err(host("Plugin contribution icon header is invalid"));
        }
        let (mut w, mut h) = (0, 0);
        for i in 0..count {
            let o = 6 + i * 16;
            w = w.max(if body[o] == 0 { 256 } else { body[o] as u32 });
            h = h.max(if body[o + 1] == 0 { 256 } else { body[o + 1] as u32 });
        }
        ("image/x-icon", w, h)
    } else if body.len() >= 30 && &body[0..4] == b"RIFF" && &body[8..12] == b"WEBP" {
        ("image/webp", 1, 1)
    } else if body.len() >= 4 && body[0] == 0xff && body[1] == 0xd8 {
        let mut dims = None;
        let mut o = 2;
        while o + 3 < body.len() {
            while o < body.len() && body[o] == 0xff {
                o += 1;
            }
            if o >= body.len() {
                break;
            }
            let marker = body[o];
            o += 1;
            if marker == 0xd8 || marker == 0xd9 {
                continue;
            }
            if marker == 0xda || o + 2 > body.len() {
                break;
            }
            let len = be16(body, o) as usize;
            if len < 2 || o + len > body.len() {
                break;
            }
            if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) && len >= 7 {
                dims = Some((be16(body, o + 5), be16(body, o + 3)));
                break;
            }
            o += len;
        }
        let (w, h) = dims.ok_or_else(|| host("Plugin contribution icon header is invalid"))?;
        ("image/jpeg", w, h)
    } else if extension == ".svg" {
        let text = std::str::from_utf8(body).map_err(|_| host("Plugin contribution icon header is invalid"))?;
        let lower = text.to_ascii_lowercase();
        if text.contains('\0') || lower.contains("<script") || lower.contains("foreignobject") || lower.contains("href") || lower.contains("url(") || lower.contains("<!doctype") || lower.contains("<?xml-stylesheet") || lower.contains("@import") || !lower.contains("<svg") {
            return Err(host("Plugin SVG references are unavailable"));
        }
        ("image/svg+xml", 1, 1)
    } else {
        return Err(host("Plugin contribution icon header is invalid"));
    };
    if mime != expected {
        return Err(host("Plugin contribution icon format does not match its extension"));
    }
    if w < 1 || h < 1 || w > max_edge || h > max_edge {
        return Err(host("Plugin contribution icon dimensions are too large"));
    }
    Ok(mime)
}

fn extension(path: &str) -> String {
    Path::new(path).extension().and_then(|e| e.to_str()).map(|e| format!(".{}", e.to_ascii_lowercase())).unwrap_or_default()
}

fn data_url(mime: &str, bytes: &[u8]) -> String {
    format!("data:{mime};base64,{}", B64.encode(bytes))
}

fn is_declared_package_icon(manifest: &Value, icon: &Value) -> bool {
    icon["kind"] == "package"
        && ["commands", "menus", "views"].iter().any(|kind| {
            manifest["contributes"][kind].as_array().is_some_and(|items| {
                items.iter().any(|c| c["icon"]["kind"] == "package" && c["icon"]["light"] == icon["light"] && c["icon"]["dark"] == icon["dark"])
            })
        })
}

pub struct IconService {
    database: Arc<PluginDatabase>,
    store: Arc<PackageStore>,
    cache: Mutex<HashMap<String, Value>>,
}

impl IconService {
    pub fn new(database: Arc<PluginDatabase>, store: Arc<PackageStore>) -> Self {
        Self { database, store, cache: Mutex::new(HashMap::new()) }
    }

    fn read_icon(&self, root: &Path, package_path: &str, brand: bool) -> PluginResult<String> {
        let segments: Vec<String> = package_path.split('/').map(str::to_string).collect();
        let (_, body) = read_contained(root, &segments, MAX_ICON_SOURCE_BYTES)?;
        let mime = if brand {
            inspect_brand_icon(&body, package_path)?.mime_type
        } else {
            inspect_icon(&body, &extension(package_path), MAX_ICON_SOURCE_EDGE)?
        };
        Ok(data_url(mime, &body))
    }

    fn remember(&self, key: String, value: Value) -> Value {
        let mut cache = self.cache.lock();
        if cache.len() >= 256 {
            cache.clear();
        }
        cache.insert(key, value.clone());
        value
    }

    /// `getPluginContributionIcon(pluginId, icon)`.
    pub fn resolve(&self, plugin_id: &str, icon: &Value) -> PluginResult<Value> {
        let plugin = self.database.get_active_plugin(plugin_id)?;
        let Some(plugin) = plugin.filter(|p| p.manifest.as_ref().is_some_and(|m| is_declared_package_icon(m, icon))) else {
            return Err(PluginError::invalid("Plugin contribution icon is not declared by the active plugin"));
        };
        if !plugin.enabled || plugin.runtime.quarantined_at.is_some() {
            return Err(host("Plugin contribution icon is unavailable"));
        }
        let key = json!([plugin_id, plugin.active_version, icon["light"], icon["dark"]]).to_string();
        if let Some(hit) = self.cache.lock().get(&key).cloned() {
            return Ok(hit);
        }
        let root = self.store.prepare_package_root(&plugin)?;
        let mut out = json!({ "light": self.read_icon(&root, icon["light"].as_str().unwrap_or(""), false)? });
        if let Some(dark) = icon["dark"].as_str() {
            out["dark"] = json!(self.read_icon(&root, dark, false)?);
        }
        Ok(self.remember(key, out))
    }

    /// `getPluginBrandIcon(pluginId)` (installed metadata, enabled or not).
    pub fn resolve_brand(&self, plugin_id: &str) -> PluginResult<Value> {
        let Some(plugin) = self.database.get_active_plugin(plugin_id)?.filter(|p| p.active_version.is_some() && p.runtime.quarantined_at.is_none()) else {
            return Ok(Value::Null);
        };
        let icon = plugin.manifest.as_ref().map(|m| m["icon"].clone()).unwrap_or(Value::Null);
        if icon["kind"] != "package" {
            return Ok(Value::Null);
        }
        let key = json!(["brand", plugin_id, plugin.active_version, plugin.archive_sha256, icon]).to_string();
        if let Some(hit) = self.cache.lock().get(&key).cloned() {
            return Ok(hit);
        }
        let root = self.store.prepare_package_root(&plugin)?;
        let mut out = json!({ "light": self.read_icon(&root, icon["light"].as_str().unwrap_or(""), true)? });
        if let Some(dark) = icon["dark"].as_str() {
            out["dark"] = json!(self.read_icon(&root, dark, true)?);
        }
        Ok(self.remember(key, out))
    }

    /// Hash-bound catalog avatar bytes (`resolveCatalogAvatar`).
    pub fn catalog_avatar(&self, path: &str, sha256: &str, size: u64, body: &[u8]) -> PluginResult<String> {
        if body.len() as u64 != size || body.len() > 256 * 1024 || hex::encode(Sha256::digest(body)) != sha256 {
            return Err(host("Invalid plugin avatar bytes"));
        }
        let ext = extension(path);
        if ext != ".png" && ext != ".webp" {
            return Err(host("Invalid plugin avatar format"));
        }
        Ok(data_url(inspect_icon(body, &ext, MAX_ICON_SOURCE_EDGE)?, body))
    }

    /// `PluginViewResources.image`: a package image for a host-drawn view.
    pub fn view_image(&self, plugin: &PluginRecord, resource: &str) -> PluginResult<Value> {
        if resource.is_empty()
            || resource.len() > 256
            || !resource.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            || !resource.chars().all(|c| c.is_ascii_alphanumeric() || "_./-".contains(c))
            || resource.split('/').any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err(PluginError::invalid("Invalid plugin image path"));
        }
        let root = self.store.prepare_package_root(plugin)?;
        let segments: Vec<String> = resource.split('/').map(str::to_string).collect();
        let (_, body) = read_contained(&root, &segments, 512 * 1024)?;
        let mime = inspect_icon(&body, &extension(resource), 2048)?;
        Ok(json!({ "url": data_url(mime, &body) }))
    }
}

// ---- host-drawn views --------------------------------------------------------------

const VIEW_ELEMENTS: &[&str] = &["form", "img", "div", "span", "p", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "header", "footer", "main", "aside", "nav", "ul", "ol", "li", "dl", "dt", "dd", "strong", "em", "small", "b", "i", "code", "pre", "blockquote", "br", "hr", "table", "thead", "tbody", "tfoot", "tr", "th", "td", "button", "input", "textarea", "label", "select", "option", "fieldset", "legend", "progress", "details", "summary"];
const VIEW_ATTRIBUTES: &[&str] = &["lang", "dir", "anchor", "src", "alt", "width", "height", "class", "id", "title", "role", "style", "name", "placeholder", "value", "checked", "disabled", "readonly", "required", "multiple", "selected", "type", "for", "tabindex", "min", "max", "step", "minlength", "maxlength", "rows", "cols", "colspan", "rowspan", "scope", "open", "autocomplete"];
const INPUT_TYPES: &[&str] = &["text", "search", "email", "url", "tel", "number", "password", "checkbox", "radio", "range", "date", "time", "datetime-local", "color", "button"];

fn view_err(message: &str) -> PluginError {
    PluginError::invalid(message)
}

fn valid_node_id(value: &Value, root: bool) -> bool {
    value.as_str().is_some_and(|s| (root && s == "~") || (!s.is_empty() && s.len() <= 80 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')))
}

/// CSS preflight. The renderer re-validates with css-tree before insertion
/// (`domain/pluginViewStylePolicy.cjs`); the host rejects obviously unsafe
/// constructs early.
pub fn preflight_css(source: &str) -> PluginResult<()> {
    let lower = source.to_ascii_lowercase();
    if source.len() > 64 * 1024 || source.contains('\0') || lower.contains("url(") || lower.contains("@import") || lower.contains("expression(") || lower.contains("-moz-binding") || lower.contains("behavior") {
        return Err(view_err("Invalid plugin stylesheet"));
    }
    Ok(())
}

fn validate_attribute(element: &str, name: &str, value: &Value) -> PluginResult<()> {
    let name_ok = name.len() <= 80
        && name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && (VIEW_ATTRIBUTES.contains(&name) || name.starts_with("aria-") || name.starts_with("data-"));
    if !name_ok {
        return Err(view_err("Forbidden view attribute"));
    }
    if value.is_null() {
        return Ok(());
    }
    let v = value.as_str().filter(|v| v.len() <= 8192 && !v.contains('\0')).ok_or_else(|| view_err("Invalid view attribute value"))?;
    if name == "type" && element == "input" && !INPUT_TYPES.contains(&v.to_ascii_lowercase().as_str()) {
        return Err(view_err("Forbidden input type"));
    }
    if name == "type" && element == "button" && !["button", "reset", "submit"].contains(&v.to_ascii_lowercase().as_str()) {
        return Err(view_err("Forbidden button type"));
    }
    if name == "src" {
        let path = v.strip_prefix("asset:").ok_or_else(|| view_err("Only package images are permitted"))?;
        if path.is_empty() || path.len() > 256 || path.split('/').any(|p| p.is_empty() || p == "." || p == "..") {
            return Err(view_err("Only package images are permitted"));
        }
    }
    if name == "style" {
        preflight_css(v)?;
    }
    Ok(())
}

fn validate_tree(node: &Value, depth: usize, ids: &mut std::collections::HashSet<String>, count: &mut usize, text: &mut usize) -> PluginResult<()> {
    *count += 1;
    let object = node.as_object().ok_or_else(|| view_err("View tree exceeds limits"))?;
    if *count > 1024 || depth > 24 {
        return Err(view_err("View tree exceeds limits"));
    }
    if !valid_node_id(&node["id"], false) || !ids.insert(node["id"].as_str().unwrap_or("").into()) {
        return Err(view_err("Invalid view node ID"));
    }
    if node["type"] == 3 || node["type"] == 8 {
        let data = node["data"].as_str().filter(|d| d.len() <= 8192).ok_or_else(|| view_err("Invalid view text"))?;
        if object.keys().any(|k| !["id", "type", "data"].contains(&k.as_str())) {
            return Err(view_err("Invalid view text"));
        }
        *text += data.len();
        if *text > 128 * 1024 {
            return Err(view_err("View text exceeds limits"));
        }
        return Ok(());
    }
    let element = node["element"].as_str().unwrap_or("");
    let (Some(children), Some(attributes)) = (node["children"].as_array(), node["attributes"].as_object()) else {
        return Err(view_err("Forbidden view element"));
    };
    if node["type"] != 1 || !VIEW_ELEMENTS.contains(&element) || object.keys().any(|k| !["id", "type", "element", "attributes", "children"].contains(&k.as_str())) {
        return Err(view_err("Forbidden view element"));
    }
    if ["br", "hr", "img", "input"].contains(&element) && !children.is_empty() {
        return Err(view_err("Void view elements cannot have children"));
    }
    if attributes.len() > 64 {
        return Err(view_err("Too many view attributes"));
    }
    for (name, value) in attributes {
        validate_attribute(element, name, value)?;
        *text += name.len() + value.as_str().map_or(0, str::len);
        if *text > 128 * 1024 {
            return Err(view_err("View data exceeds limits"));
        }
    }
    for child in children {
        validate_tree(child, depth + 1, ids, count, text)?;
    }
    Ok(())
}

/// `validatePluginMutationBatch`.
pub fn validate_mutation_batch(batch: &Value) -> PluginResult<()> {
    let items = batch.as_array().filter(|b| b.len() <= 2048).ok_or_else(|| view_err("Invalid view mutations"))?;
    if serde_json::to_string(batch)?.len() > 256 * 1024 {
        return Err(view_err("View mutations exceed limits"));
    }
    for item in items {
        let m = item.as_array().ok_or_else(|| view_err("Invalid view mutation"))?;
        let op = m.first().and_then(Value::as_u64).filter(|o| *o <= 3).ok_or_else(|| view_err("Invalid view mutation"))?;
        if !m.get(1).is_some_and(|id| valid_node_id(id, true)) {
            return Err(view_err("Invalid view node ID"));
        }
        match op {
            0 => {
                if m.len() != 4 || !m[3].as_u64().is_some_and(|i| i <= 1024) {
                    return Err(view_err("Invalid insertion"));
                }
                validate_tree(&m[2], 1, &mut Default::default(), &mut 0, &mut 0)?;
            }
            1 => {
                if m.len() != 3 || !m[2].as_u64().is_some_and(|i| i <= 1024) {
                    return Err(view_err("Invalid removal"));
                }
            }
            2 => {
                if m.len() != 3 || !m[2].as_str().is_some_and(|t| t.len() <= 8192) {
                    return Err(view_err("Invalid text update"));
                }
            }
            _ => {
                if m.len() < 4 || m.len() > 5 || m.get(4).is_some_and(|v| v != 2) {
                    return Err(view_err("Only attribute updates are permitted"));
                }
                validate_attribute("", m[2].as_str().unwrap_or(""), &m[3])?;
            }
        }
    }
    Ok(())
}

struct ViewInstance {
    owner: String,
    plugin_id: String,
    plugin_version: String,
    view_id: String,
    runtime_id: String,
    context: Value,
    sequence: u64,
    rate: (std::time::Instant, u32),
    resources: HashMap<String, Value>,
    resource_bytes: usize,
}

/// `HostDrawnViewHost`: logical views only; the renderer draws them.
pub struct ViewHost {
    contributions: Arc<ContributionService>,
    icons: Arc<IconService>,
    events: Arc<dyn HostEvents>,
    instances: Mutex<HashMap<String, ViewInstance>>,
}

impl ViewHost {
    pub fn new(contributions: Arc<ContributionService>, icons: Arc<IconService>, events: Arc<dyn HostEvents>) -> Arc<Self> {
        let host = Arc::new(Self { contributions: contributions.clone(), icons, events, instances: Mutex::new(HashMap::new()) });
        let weak = Arc::downgrade(&host);
        contributions.on_did_post_view_message(Arc::new(move |event: &Value| {
            if let Some(h) = weak.upgrade() {
                h.receive(event);
            }
        }));
        let weak = Arc::downgrade(&host);
        contributions.on_did_change(Arc::new(move |event: &Value| {
            let Some(h) = weak.upgrade() else { return };
            let reason = event["reason"].as_str().unwrap_or("");
            let ids: Vec<(String, bool)> = h
                .instances
                .lock()
                .iter()
                .map(|(id, i)| {
                    let stale = (["plugin-disabled", "runtime-stopped", "runtime-error", "runtime-quarantined"].contains(&reason) && event["pluginId"].as_str() == Some(i.plugin_id.as_str()))
                        || h.contributions.assert_view_activation_current(&i.plugin_id, &i.plugin_version, &i.view_id, &i.runtime_id, Some(&i.context)).is_err();
                    (id.clone(), stale)
                })
                .collect();
            for (id, stale) in ids {
                if stale {
                    let h = h.clone();
                    let reason = if reason.starts_with("runtime-") || reason == "plugin-disabled" { reason.to_string() } else { "contribution-unavailable".into() };
                    tokio::spawn(async move { h.close(&id, None, &reason).await });
                }
            }
        }));
        host
    }

    /// `openHostDrawnPluginView(payload)` from window `owner`.
    pub async fn open(&self, owner: &str, payload: &Value) -> PluginResult<Value> {
        if !contract::is_valid("HostDrawnViewOpenRequest", payload) {
            return Err(view_err("Invalid plugin view request"));
        }
        let id = payload["instanceId"].as_str().unwrap_or("").to_string();
        {
            let instances = self.instances.lock();
            if instances.contains_key(&id) {
                return Err(host("Plugin view already exists"));
            }
            if instances.values().filter(|i| i.owner == owner).count() >= 32 || instances.len() >= 128 {
                return Err(host("Plugin view limit exceeded"));
            }
        }
        let scope = payload["scopeId"].as_str().unwrap_or("");
        if scope.is_empty() || scope.len() > 256 {
            return Err(view_err("Invalid plugin view scope"));
        }
        let context = payload.get("context").cloned().unwrap_or_else(|| json!({}));
        let (plugin, view, identity) = self.contributions.activate_view(payload["viewId"].as_str().unwrap_or(""), Some(&context)).await?;
        let instance = ViewInstance {
            owner: owner.into(),
            plugin_id: plugin.id.clone(),
            plugin_version: plugin.active_version.clone().unwrap_or_default(),
            view_id: view["id"].as_str().unwrap_or("").into(),
            runtime_id: identity.runtime_id.clone(),
            context: context.clone(),
            sequence: 0,
            rate: (std::time::Instant::now(), 0),
            resources: HashMap::new(),
            resource_bytes: 0,
        };
        let view_id = instance.view_id.clone();
        self.instances.lock().insert(id.clone(), instance);
        let state_scope = hex::encode(Sha256::digest(scope.as_bytes()));
        let started = self
            .contributions
            .supervisor
            .notify(&plugin.id, "plugin.view.message", json!({ "viewId": view_id, "message": { "kind": "host-ui.open", "instanceId": id, "stateScope": state_scope } }), Some(&identity))
            .await
            .and_then(|_| self.contributions.assert_view_activation_current(&plugin.id, plugin.active_version.as_deref().unwrap_or(""), &view_id, &identity.runtime_id, Some(&context)).map(|_| ()));
        if let Err(err) = started {
            self.close(&id, None, "open-failed").await;
            return Err(err);
        }
        Ok(json!({ "instanceId": id }))
    }

    fn receive(&self, event: &Value) {
        let message = &event["message"];
        if !contract::is_valid("HostDrawnViewMessage", message) || message["kind"] != "host-ui.update" {
            return;
        }
        let id = message["instanceId"].as_str().unwrap_or("").to_string();
        let outcome = {
            let mut instances = self.instances.lock();
            let Some(i) = instances.get_mut(&id) else { return };
            if event["pluginId"].as_str() != Some(i.plugin_id.as_str()) || event["viewId"].as_str() != Some(i.view_id.as_str()) {
                return;
            }
            let valid = (|| -> PluginResult<()> {
                if message["sequence"].as_u64() != Some(i.sequence + 1) {
                    return Err(view_err("Invalid view update sequence"));
                }
                let now = std::time::Instant::now();
                if now.duration_since(i.rate.0).as_millis() >= 1000 {
                    i.rate = (now, 0);
                }
                i.rate.1 += 1;
                if i.rate.1 > 120 {
                    return Err(view_err("Plugin view update rate exceeded"));
                }
                validate_mutation_batch(&message["mutations"])?;
                if let Some(css) = message["css"].as_str() {
                    preflight_css(css)?;
                }
                i.sequence += 1;
                Ok(())
            })();
            valid.map(|_| (i.owner.clone(), i.view_id.clone()))
        };
        match outcome {
            Ok((_owner, view_id)) => {
                let mut payload = message.clone();
                payload["viewId"] = json!(view_id);
                self.events.emit(channels::VIEW_UPDATE, payload);
            }
            Err(_) => {
                // Close asynchronously (notifies the runtime).
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    let instances = self.instances.lock().remove(&id);
                    if let Some(i) = instances {
                        self.events.emit(channels::VIEW_CLOSED, json!({ "instanceId": id, "pluginId": i.plugin_id, "viewId": i.view_id, "reason": "invalid-update" }));
                        let supervisor = self.contributions.supervisor.clone();
                        handle.spawn(async move {
                            let _ = supervisor.notify(&i.plugin_id, "plugin.view.message", json!({ "viewId": i.view_id, "message": { "kind": "host-ui.close", "instanceId": id } }), None).await;
                        });
                    }
                }
            }
        }
    }

    fn owned<'a>(instances: &'a mut HashMap<String, ViewInstance>, id: &str, owner: &str) -> PluginResult<&'a mut ViewInstance> {
        let instance = instances.get_mut(id).ok_or_else(|| host("Plugin view was not found"))?;
        if instance.owner != owner {
            return Err(host("Plugin view belongs to another window"));
        }
        Ok(instance)
    }

    /// `getPluginViewResource({ instanceId, path })`.
    pub fn resource(&self, owner: &str, payload: &Value) -> PluginResult<Value> {
        if !contract::is_valid("PluginViewResourceRequest", payload) {
            return Err(view_err("Invalid plugin resource request"));
        }
        let id = payload["instanceId"].as_str().unwrap_or("");
        let path = payload["path"].as_str().unwrap_or("").to_string();
        let (plugin_id, version, view_id, runtime_id, context) = {
            let mut instances = self.instances.lock();
            let i = Self::owned(&mut instances, id, owner)?;
            if let Some(hit) = i.resources.get(&path) {
                return Ok(hit.clone());
            }
            if i.resources.len() >= 32 {
                return Err(host("Plugin image limit exceeded"));
            }
            (i.plugin_id.clone(), i.plugin_version.clone(), i.view_id.clone(), i.runtime_id.clone(), i.context.clone())
        };
        let plugin = self.contributions.assert_view_activation_current(&plugin_id, &version, &view_id, &runtime_id, Some(&context))?;
        let result = self.icons.view_image(&plugin, &path)?;
        let mut instances = self.instances.lock();
        let i = Self::owned(&mut instances, id, owner)?;
        i.resource_bytes += result["url"].as_str().map_or(0, str::len);
        if i.resource_bytes > 8 * 1024 * 1024 {
            return Err(host("Plugin image budget exceeded"));
        }
        i.resources.insert(path, result.clone());
        Ok(result)
    }

    /// `sendHostDrawnPluginViewEvent(instanceId, event)`.
    pub async fn event(&self, owner: &str, id: &str, event: &Value) -> PluginResult<()> {
        if !contract::is_valid("HostDrawnViewEvent", event) {
            return Err(view_err("Invalid plugin view event"));
        }
        let (plugin_id, version, view_id, runtime_id, context) = {
            let mut instances = self.instances.lock();
            let i = Self::owned(&mut instances, id, owner)?;
            (i.plugin_id.clone(), i.plugin_version.clone(), i.view_id.clone(), i.runtime_id.clone(), i.context.clone())
        };
        self.contributions.assert_view_activation_current(&plugin_id, &version, &view_id, &runtime_id, Some(&context))?;
        let identity = self.contributions.supervisor.get_runtime_identity(&plugin_id);
        self.contributions
            .supervisor
            .notify(&plugin_id, "plugin.view.message", json!({ "viewId": view_id, "message": { "kind": "host-ui.event", "instanceId": id, "event": event } }), identity.as_deref())
            .await
    }

    /// `closeHostDrawnPluginView` / host-initiated close.
    pub async fn close(&self, id: &str, owner: Option<&str>, reason: &str) {
        let removed = {
            let mut instances = self.instances.lock();
            match instances.get(id) {
                Some(i) if owner.is_none_or(|o| o == i.owner) => instances.remove(id),
                _ => None,
            }
        };
        let Some(i) = removed else { return };
        self.events.emit(channels::VIEW_CLOSED, json!({ "instanceId": id, "pluginId": i.plugin_id, "viewId": i.view_id, "reason": reason }));
        let _ = self
            .contributions
            .supervisor
            .notify(&i.plugin_id, "plugin.view.message", json!({ "viewId": i.view_id, "message": { "kind": "host-ui.close", "instanceId": id } }), None)
            .await;
    }

    /// Close every view owned by a window (closed / reloaded).
    pub async fn release_owner(&self, owner: &str) {
        let ids: Vec<String> = self.instances.lock().iter().filter(|(_, i)| i.owner == owner).map(|(k, _)| k.clone()).collect();
        for id in ids {
            self.close(&id, None, "owner-closed").await;
        }
    }

    pub async fn shutdown(&self) {
        let ids: Vec<String> = self.instances.lock().keys().cloned().collect();
        for id in ids {
            self.close(&id, None, "shutdown").await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palette_contrast() {
        assert!(resolve_theme_palette(&json!({ "base": "dark", "colors": {} })).is_ok());
        assert!(resolve_theme_palette(&json!({ "base": "light", "colors": { "foreground": "#fefefe" } })).is_err());
        assert!(resolve_theme_palette(&json!({ "base": "light", "colors": { "accent": "red" } })).is_err());
    }

    #[test]
    fn view_mutations() {
        let node = json!({ "id": "a", "type": 1, "element": "div", "attributes": { "class": "x", "data-k": "v" }, "children": [{ "id": "t", "type": 3, "data": "hi" }] });
        assert!(validate_mutation_batch(&json!([[0, "~", node, 0], [2, "t", "bye"], [3, "a", "title", "x"]])).is_ok());
        assert!(validate_mutation_batch(&json!([[0, "~", { "id": "s", "type": 1, "element": "script", "attributes": {}, "children": [] }, 0]])).is_err());
        assert!(validate_mutation_batch(&json!([[3, "a", "onclick", "x"]])).is_err());
        assert!(validate_mutation_batch(&json!([[3, "a", "src", "https://evil"]])).is_err());
        assert!(validate_mutation_batch(&json!([[3, "a", "style", "background:url(x)"]])).is_err());
    }

    #[test]
    fn icons() {
        let png = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, b'I', b'H', b'D', b'R', 0, 0, 0, 16, 0, 0, 0, 16];
        assert_eq!(inspect_icon(&png, ".png", 64).unwrap(), "image/png");
        assert!(inspect_icon(&png, ".jpg", 64).is_err());
        assert!(inspect_icon(b"<svg><script>x</script></svg>", ".svg", 64).is_err());
        assert!(inspect_icon(b"<svg viewBox='0 0 1 1'></svg>", ".svg", 64).is_ok());
    }
}
