//! Browser bookmarks ("apps") shared by every host browser (Electron:
//! `bookmarkStore.cjs`). The list is also what cloud sync carries
//! (`getHostBrowserBookmarks` / `applyHostBrowserBookmarks`).

use crate::fs::{atomic_write, now_ms, read_json};
use crate::icons::{normalize_color, valid_image_data_url};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use url::Url;

pub const MAX_BOOKMARKS: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bookmark {
    pub id: String,
    pub title: String,
    pub url: String,
    /// `"host"` or `"all-hosts"`.
    pub scope: String,
    pub host_id: Option<String>,
    pub icon: String,
    /// `"auto"` or `"custom"`.
    pub icon_mode: String,
    pub icon_data_url: Option<String>,
    pub color: String,
    pub order: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

fn str_of(raw: &Value, key: &str) -> Option<String> {
    match raw.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(b.to_string()),
        _ => None,
    }
}

fn safe_int(raw: &Value, key: &str) -> Option<i64> {
    raw.get(key)
        .and_then(|v| v.as_i64())
        .filter(|n| n.unsigned_abs() <= 9_007_199_254_740_991)
}

fn take_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

/// Validate and complete a bookmark from renderer / sync JSON. `previous`
/// is the stored record being edited: its id, creation time and (when the
/// input carries no valid image) its image are kept.
pub fn normalize_bookmark(raw: &Value, previous: Option<&Bookmark>) -> Result<Bookmark, String> {
    if !raw.is_object() {
        return Err("Invalid bookmark".into());
    }
    let url = Url::parse(&str_of(raw, "url").unwrap_or_default())
        .map_err(|_| "Bookmarks require an HTTP or HTTPS address without credentials".to_string())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().map(str::is_empty).unwrap_or(true)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("Bookmarks require an HTTP or HTTPS address without credentials".into());
    }
    let hostname = url.host_str().unwrap_or_default().to_string();
    let scope = if str_of(raw, "scope").as_deref() == Some("all-hosts") {
        "all-hosts"
    } else {
        "host"
    };
    let host_id = if scope == "host" {
        let id = take_chars(&str_of(raw, "hostId").unwrap_or_default(), 256);
        if id.is_empty() {
            return Err("Host bookmark is missing its host".into());
        }
        Some(id)
    } else {
        None
    };
    let title = take_chars(
        str_of(raw, "title")
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| hostname.clone())
            .trim(),
        120,
    );
    let icon = take_chars(
        str_of(raw, "icon")
            .filter(|i| !i.is_empty())
            .or_else(|| title.chars().next().map(String::from))
            .unwrap_or_else(|| "\u{25c7}".into())
            .trim(),
        4,
    );
    let color = normalize_color(str_of(raw, "color").as_deref());
    let now = now_ms();
    let raw_id = str_of(raw, "id").filter(|id| !id.trim().is_empty() && id.len() <= 128);
    let icon_data_url = match raw.get("iconDataUrl") {
        Some(Value::Null) => None,
        Some(Value::String(value)) if valid_image_data_url(value) => Some(value.clone()),
        _ => previous.and_then(|p| p.icon_data_url.clone()),
    };
    Ok(Bookmark {
        id: previous
            .map(|p| p.id.clone())
            .or(raw_id)
            .unwrap_or_else(netcatty_core::ids::new_id),
        title: if title.is_empty() { hostname } else { title },
        url: url.to_string(),
        scope: scope.into(),
        host_id,
        icon: if icon.is_empty() { "\u{25c7}".into() } else { icon },
        icon_mode: if str_of(raw, "iconMode").as_deref() == Some("custom") {
            "custom".into()
        } else {
            "auto".into()
        },
        icon_data_url,
        color,
        order: safe_int(raw, "order").unwrap_or_else(|| previous.map(|p| p.order).unwrap_or(0)),
        created_at: previous
            .map(|p| p.created_at)
            .or_else(|| safe_int(raw, "createdAt").filter(|n| *n > 0))
            .unwrap_or(now),
        updated_at: if previous.is_some() {
            now
        } else {
            safe_int(raw, "updatedAt").filter(|n| *n > 0).unwrap_or(now)
        },
    })
}

/// `host-browser-bookmarks.json` with an optional change callback (used to
/// broadcast `netcatty:host-browser:bookmarks-changed`).
pub struct BookmarkStore {
    file: PathBuf,
    items: Mutex<Vec<Bookmark>>,
    on_change: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl BookmarkStore {
    pub fn open(dir: &Path) -> Self {
        let file = dir.join("host-browser-bookmarks.json");
        let mut items = Vec::new();
        match read_json(&file) {
            Ok(Some(Value::Array(parsed))) if parsed.len() <= MAX_BOOKMARKS => {
                items = parsed
                    .iter()
                    .filter_map(|item| normalize_bookmark(item, None).ok())
                    .collect();
            }
            Ok(_) => {}
            Err(err) => tracing::warn!(%err, "[HostBrowser] Could not read bookmarks"),
        }
        Self {
            file,
            items: Mutex::new(items),
            on_change: Mutex::new(None),
        }
    }

    /// Called after every persisted change.
    pub fn set_on_change(&self, callback: impl Fn() + Send + Sync + 'static) {
        *self.on_change.lock() = Some(Box::new(callback));
    }

    fn persist(&self, items: &[Bookmark]) -> Result<(), String> {
        let bytes = serde_json::to_vec(items).map_err(|e| e.to_string())?;
        atomic_write(&self.file, &bytes).map_err(|e| e.to_string())?;
        if let Some(callback) = self.on_change.lock().as_ref() {
            callback();
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<Bookmark> {
        self.items.lock().clone()
    }

    pub fn find(&self, id: &str) -> Option<Bookmark> {
        self.items.lock().iter().find(|item| item.id == id).cloned()
    }

    /// Insert or update (matched by `input.id`).
    pub fn upsert(&self, input: &Value) -> Result<Bookmark, String> {
        let mut items = self.items.lock();
        let input_id = input.get("id").and_then(|v| v.as_str());
        let index = input_id.and_then(|id| items.iter().position(|item| item.id == id));
        if index.is_none() && items.len() >= MAX_BOOKMARKS {
            return Err("Bookmark limit reached".into());
        }
        let next = normalize_bookmark(input, index.map(|i| &items[i]))?;
        match index {
            Some(i) => items[i] = next.clone(),
            None => items.push(next.clone()),
        }
        self.persist(&items)?;
        Ok(next)
    }

    /// Remove by id; `true` when something was removed.
    pub fn remove(&self, id: &str) -> Result<bool, String> {
        let mut items = self.items.lock();
        let before = items.len();
        items.retain(|item| item.id != id);
        if items.len() == before {
            return Ok(false);
        }
        self.persist(&items)?;
        Ok(true)
    }

    /// Replace the whole list (cloud sync).
    pub fn apply(&self, input: &Value) -> Result<(), String> {
        let Value::Array(list) = input else {
            return Err("Invalid bookmark list".into());
        };
        if list.len() > MAX_BOOKMARKS {
            return Err("Invalid bookmark list".into());
        }
        let mut ids = std::collections::HashSet::new();
        let mut next = Vec::with_capacity(list.len());
        for item in list {
            let normalized = normalize_bookmark(item, None)?;
            if !ids.insert(normalized.id.clone()) {
                return Err("Duplicate bookmark ID".into());
            }
            next.push(normalized);
        }
        let mut items = self.items.lock();
        *items = next;
        self.persist(&items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ICON: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLytQAAAABJRU5ErkJggg==";

    #[test]
    fn custom_bookmark_icons_persist_and_survive_cloud_apply() {
        let dir = tempfile::tempdir().unwrap();
        let first = BookmarkStore::open(dir.path());
        let saved = first
            .upsert(&json!({
                "title": "App", "url": "https://example.com/", "scope": "host", "hostId": "host-a",
                "icon": "A", "iconMode": "custom", "iconDataUrl": ICON
            }))
            .unwrap();
        assert_eq!(saved.icon_data_url.as_deref(), Some(ICON));
        assert_eq!(saved.icon_mode, "custom");
        let reopened = BookmarkStore::open(dir.path());
        assert_eq!(reopened.list()[0].icon_data_url.as_deref(), Some(ICON));
        let mut as_all_hosts = serde_json::to_value(&saved).unwrap();
        as_all_hosts["scope"] = json!("all-hosts");
        as_all_hosts["hostId"] = Value::Null;
        reopened.apply(&json!([as_all_hosts])).unwrap();
        let third = BookmarkStore::open(dir.path());
        assert_eq!(third.list()[0].icon_data_url.as_deref(), Some(ICON));
        assert_eq!(third.list()[0].icon_mode, "custom");
        assert_eq!(third.list()[0].scope, "all-hosts");
        assert_eq!(third.list()[0].host_id, None);
    }

    #[test]
    fn normalisation_fills_defaults_and_rejects_bad_input() {
        let bookmark = normalize_bookmark(
            &json!({ "url": "https://example.com", "hostId": "h", "color": "zzz" }),
            None,
        )
        .unwrap();
        assert_eq!(bookmark.title, "example.com");
        assert_eq!(bookmark.icon, "e");
        assert_eq!(bookmark.color, "#247969");
        assert_eq!(bookmark.scope, "host");
        assert_eq!(bookmark.icon_mode, "auto");
        assert_eq!(bookmark.url, "https://example.com/");
        assert!(bookmark.created_at > 0 && bookmark.updated_at > 0);
        assert_eq!(
            normalize_bookmark(&json!({ "url": "ftp://x.example/", "hostId": "h" }), None).unwrap_err(),
            "Bookmarks require an HTTP or HTTPS address without credentials"
        );
        assert_eq!(
            normalize_bookmark(&json!({ "url": "https://x.example/" }), None).unwrap_err(),
            "Host bookmark is missing its host"
        );
        assert_eq!(normalize_bookmark(&json!("nope"), None).unwrap_err(), "Invalid bookmark");
        let all = normalize_bookmark(
            &json!({ "url": "https://x.example/", "scope": "all-hosts", "id": "keep-me", "order": 7, "createdAt": 5, "updatedAt": 6 }),
            None,
        )
        .unwrap();
        assert_eq!((all.id.as_str(), all.host_id, all.order, all.created_at, all.updated_at), ("keep-me", None, 7, 5, 6));
    }

    #[test]
    fn edits_keep_identity_and_image_unless_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let store = BookmarkStore::open(dir.path());
        let saved = store
            .upsert(&json!({ "url": "https://example.com/", "hostId": "h", "iconDataUrl": ICON, "createdAt": 10 }))
            .unwrap();
        let edited = store
            .upsert(&json!({ "id": saved.id, "url": "https://example.com/x", "hostId": "h", "title": "X" }))
            .unwrap();
        assert_eq!(edited.id, saved.id);
        assert_eq!(edited.created_at, 10);
        assert_eq!(edited.icon_data_url.as_deref(), Some(ICON), "image kept when input has none");
        let cleared = store
            .upsert(&json!({ "id": saved.id, "url": "https://example.com/x", "hostId": "h", "iconDataUrl": null }))
            .unwrap();
        assert_eq!(cleared.icon_data_url, None);
        assert_eq!(store.list().len(), 1);
        assert!(store.remove(&saved.id).unwrap());
        assert!(!store.remove(&saved.id).unwrap());
        assert!(store.list().is_empty());
    }

    #[test]
    fn apply_rejects_duplicates_and_non_lists() {
        let dir = tempfile::tempdir().unwrap();
        let store = BookmarkStore::open(dir.path());
        let item = json!({ "id": "a", "url": "https://example.com/", "hostId": "h" });
        assert_eq!(store.apply(&json!([item, item])).unwrap_err(), "Duplicate bookmark ID");
        assert_eq!(store.apply(&json!({})).unwrap_err(), "Invalid bookmark list");
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = calls.clone();
        store.set_on_change(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        store.apply(&json!([item])).unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(store.find("a").unwrap().url, "https://example.com/");
    }
}
