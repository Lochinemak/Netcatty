//! Model catalog caching (Electron: `sdkStreamHandlers.cjs` model cache,
//! `sdk/modelCatalogLastKnown.cjs` last-known-good store).

use crate::EnvMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const MODEL_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
pub const MODEL_CACHE_MAX_ENTRIES: usize = 32;
pub const MODEL_LIST_TIMEOUT: Duration = Duration::from_millis(10_000);
pub const MODEL_LIST_DEADLINE_HEADROOM: Duration = Duration::from_millis(1_000);
pub const LAST_KNOWN_CATALOG_FILE: &str = "model-catalog-last-known.json";
pub const LAST_KNOWN_MAX_MODELS: usize = 200;
pub const LAST_KNOWN_MAX_ENTRIES: usize = 32;
const LAST_KNOWN_STORE_VERSION: u64 = 1;

/// Per-backend catalog budget (`MODEL_LIST_TIMEOUT_OVERRIDES_MS`, OpenCode cold start).
pub fn catalog_budget(backend: &str) -> Duration {
    match backend {
        "mimo" => Duration::from_millis(30_000),
        "opencode" => crate::drivers::opencode::OPENCODE_SERVER_START_TIMEOUT + MODEL_LIST_TIMEOUT,
        _ => MODEL_LIST_TIMEOUT,
    }
}

/// Env keys that change a backend's model catalog without changing its binary.
pub const SDK_MODEL_CACHE_ENV_KEYS: &[&str] = &[
    "HOME", "USERPROFILE", "XDG_CONFIG_HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR", "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN", "OPENCODE_BIN", "OPENCODE_CONFIG",
    "OPENCODE_CONFIG_DIR", "OPENCODE_CONFIG_CONTENT", "MIMOCODE_HOME", "MIMOCODE_BIN", "MIMOCODE_BIN_PATH",
    "MIMOCODE_CONFIG", "MIMOCODE_CONFIG_DIR", "MIMOCODE_MIMO_ONLY", "XDG_DATA_HOME", "XDG_CACHE_HOME",
    "CLAUDE_CODE_EXECUTABLE", "CODEBUDDY_CODE_PATH", "CODEBUDDY_API_KEY", "CODEBUDDY_AUTH_TOKEN",
    "CODEBUDDY_INTERNET_ENVIRONMENT", "XAI_API_KEY", "GROK_CONFIG_DIR", "COPILOT_GITHUB_TOKEN", "GH_TOKEN",
    "GITHUB_TOKEN", "GH_CONFIG_DIR", "CURSOR_API_KEY",
];

/// `buildSdkModelCacheKey`: backend + binPath + runtime + sha256(env fingerprint).
/// Credentials only ever enter the key hashed.
pub fn build_sdk_model_cache_key(backend: &str, bin_path: &str, env: &EnvMap, runtime: &str) -> String {
    let fingerprint = SDK_MODEL_CACHE_ENV_KEYS
        .iter()
        .map(|k| format!("{k}={}", env.get(*k).map(String::as_str).unwrap_or("")))
        .collect::<Vec<_>>()
        .join("\0");
    let hash = hex::encode(Sha256::digest(fingerprint.as_bytes()));
    [backend, bin_path, if runtime.is_empty() { "sdk" } else { runtime }, &hash].join("\0")
}

/// A normalized catalog (`{ currentModelId, models }`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelCatalog {
    pub current_model_id: Option<String>,
    pub models: Vec<Value>,
}

impl ModelCatalog {
    /// `normalizeSdkListModelsResult`: drop rows without an id.
    pub fn normalized(mut self) -> Self {
        self.models.retain(|m| m.get("id").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.models.is_empty() && self.current_model_id.is_none()
    }
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub at: Instant,
    pub catalog: ModelCatalog,
    pub fetched_at: String,
}

/// TTL + LRU in-memory catalog cache.
pub struct ModelCache {
    entries: VecDeque<(String, CacheEntry)>,
    ttl: Duration,
    max_entries: usize,
}

impl Default for ModelCache {
    fn default() -> Self {
        Self::new(MODEL_CACHE_TTL, MODEL_CACHE_MAX_ENTRIES)
    }
}

impl ModelCache {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self { entries: VecDeque::new(), ttl, max_entries }
    }

    fn prune(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.entries.retain(|(_, e)| now.duration_since(e.at) < ttl);
        while self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }
    }

    pub fn get(&mut self, key: &str) -> Option<CacheEntry> {
        self.prune(Instant::now());
        let idx = self.entries.iter().position(|(k, _)| k == key)?;
        let item = self.entries.remove(idx)?;
        let entry = item.1.clone();
        self.entries.push_back(item);
        Some(entry)
    }

    pub fn set(&mut self, key: &str, entry: CacheEntry) {
        self.prune(Instant::now());
        self.entries.retain(|(k, _)| k != key);
        self.entries.push_back((key.to_string(), entry));
        self.prune(Instant::now());
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Last-known-good store ──

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastKnownEntry {
    #[serde(default)]
    pub backend: String,
    pub models: Vec<Value>,
    #[serde(default)]
    pub current_model_id: Option<String>,
    #[serde(default)]
    pub fetched_at: String,
}

pub fn last_known_catalog_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LAST_KNOWN_CATALOG_FILE)
}

fn read_store(path: &Path) -> serde_json::Map<String, Value> {
    let Ok(raw) = std::fs::read_to_string(path) else { return Default::default() };
    let Ok(parsed) = serde_json::from_str::<Value>(&raw) else { return Default::default() };
    if parsed.get("version").and_then(|v| v.as_u64()) != Some(LAST_KNOWN_STORE_VERSION) {
        return Default::default();
    }
    parsed.get("entries").and_then(|e| e.as_object()).cloned().unwrap_or_default()
}

fn write_store(path: &Path, entries: serde_json::Map<String, Value>) -> bool {
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return false;
        }
    }
    let doc = serde_json::json!({ "version": LAST_KNOWN_STORE_VERSION, "entries": entries });
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&doc).unwrap_or_default())).is_ok()
}

fn model_id(m: &Value) -> Option<&str> {
    m.get("id").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
}

pub fn read_last_known_entry(path: &Path, key: &str) -> Option<LastKnownEntry> {
    let entry: LastKnownEntry = serde_json::from_value(read_store(path).get(key)?.clone()).ok()?;
    (!entry.models.is_empty()).then_some(entry)
}

pub fn write_last_known_entry(path: &Path, key: &str, backend: &str, models: &[Value], current: Option<&str>) -> bool {
    let valid: Vec<Value> = models.iter().filter(|m| model_id(m).is_some()).cloned().collect();
    if valid.is_empty() || key.is_empty() {
        return false;
    }
    let mut trimmed: Vec<Value> = valid.iter().take(LAST_KNOWN_MAX_MODELS).cloned().collect();
    if let Some(current) = current {
        if !trimmed.iter().any(|m| model_id(m) == Some(current)) {
            if let Some(row) = valid.iter().find(|m| model_id(m) == Some(current)) {
                if trimmed.len() >= LAST_KNOWN_MAX_MODELS {
                    trimmed.pop();
                }
                trimmed.push(row.clone());
            }
        }
    }
    let mut entries = read_store(path);
    let entry = LastKnownEntry {
        backend: backend.to_string(),
        models: trimmed,
        current_model_id: current.map(str::to_string),
        fetched_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    };
    entries.insert(key.to_string(), serde_json::to_value(entry).unwrap_or(Value::Null));
    let mut keys: Vec<(String, String)> = entries
        .iter()
        .map(|(k, v)| (k.clone(), v.get("fetchedAt").and_then(|f| f.as_str()).unwrap_or("").to_string()))
        .collect();
    keys.sort_by(|a, b| a.1.cmp(&b.1));
    while keys.len() > LAST_KNOWN_MAX_ENTRIES {
        let (k, _) = keys.remove(0);
        entries.remove(&k);
    }
    write_store(path, entries)
}

/// Adopt a new current id without replacing the persisted rows (synthesising
/// a minimal row when the id is missing).
pub fn refresh_last_known_current_id(path: &Path, key: &str, current: &str) -> bool {
    let mut entries = read_store(path);
    let Some(mut entry) = entries.get(key).and_then(|v| serde_json::from_value::<LastKnownEntry>(v.clone()).ok()) else {
        return false;
    };
    if entry.models.is_empty() || entry.current_model_id.as_deref() == Some(current) {
        return false;
    }
    if !entry.models.iter().any(|m| model_id(m) == Some(current)) {
        if entry.models.len() >= LAST_KNOWN_MAX_MODELS {
            entry.models.pop();
        }
        entry.models.push(serde_json::json!({ "id": current, "name": current }));
    }
    entry.current_model_id = Some(current.to_string());
    entries.insert(key.to_string(), serde_json::to_value(entry).unwrap_or(Value::Null));
    write_store(path, entries)
}

/// `remapLastKnownCurrentModelId`: keep a visible current id (incl. `id/effort`
/// decorations the row advertises), else the first row; none stays none.
pub fn remap_last_known_current_model_id(entry: &LastKnownEntry) -> Option<String> {
    let current = entry.current_model_id.as_deref()?;
    let visible = entry.models.iter().any(|m| {
        model_id(m) == Some(current)
            || m.get("thinkingLevels").and_then(|l| l.as_array()).map(|levels| {
                levels.iter().filter_map(|l| l.as_str()).any(|l| format!("{}/{l}", model_id(m).unwrap_or("")) == current)
            }).unwrap_or(false)
    });
    if visible {
        Some(current.to_string())
    } else {
        entry.models.first().and_then(model_id).map(str::to_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cache_key_hashes_credentials() {
        let mut env = EnvMap::new();
        env.insert("ANTHROPIC_API_KEY".into(), "sk-secret".into());
        let a = build_sdk_model_cache_key("claude", "/b", &env, "sdk:api-key");
        assert!(!a.contains("sk-secret"));
        env.insert("ANTHROPIC_API_KEY".into(), "other".into());
        assert_ne!(a, build_sdk_model_cache_key("claude", "/b", &env, "sdk:api-key"));
        env.insert("UNRELATED".into(), "x".into());
        let b = build_sdk_model_cache_key("claude", "/b", &env, "sdk:api-key");
        env.remove("UNRELATED");
        assert_eq!(b, build_sdk_model_cache_key("claude", "/b", &env, "sdk:api-key"));
    }

    #[test]
    fn cache_ttl_and_lru() {
        let mut cache = ModelCache::new(Duration::from_secs(60), 2);
        let entry = |id: &str| CacheEntry { at: Instant::now(), catalog: ModelCatalog { current_model_id: None, models: vec![json!({ "id": id })] }, fetched_at: "t".into() };
        cache.set("a", entry("a"));
        cache.set("b", entry("b"));
        assert!(cache.get("a").is_some()); // a now most recent
        cache.set("c", entry("c"));
        assert!(cache.get("b").is_none());
        assert!(cache.get("a").is_some());
        let mut expired = ModelCache::new(Duration::from_millis(0), 4);
        expired.set("x", entry("x"));
        assert!(expired.get("x").is_none());
    }

    #[test]
    fn last_known_store_round_trip_and_caps() {
        let dir = tempfile::tempdir().unwrap();
        let path = last_known_catalog_path(dir.path());
        assert!(read_last_known_entry(&path, "k").is_none());
        assert!(!write_last_known_entry(&path, "k", "claude", &[json!({ "name": "no id" })], None));
        let models: Vec<Value> = (0..250).map(|i| json!({ "id": format!("m{i}") })).collect();
        assert!(write_last_known_entry(&path, "k", "claude", &models, Some("m249")));
        let entry = read_last_known_entry(&path, "k").unwrap();
        assert_eq!(entry.models.len(), LAST_KNOWN_MAX_MODELS);
        assert!(entry.models.iter().any(|m| m["id"] == "m249"));
        assert!(refresh_last_known_current_id(&path, "k", "new-model"));
        let entry = read_last_known_entry(&path, "k").unwrap();
        assert_eq!(entry.current_model_id.as_deref(), Some("new-model"));
        assert!(entry.models.iter().any(|m| m["id"] == "new-model"));
        assert!(!refresh_last_known_current_id(&path, "missing", "x"));
        for i in 0..40 {
            write_last_known_entry(&path, &format!("key{i}"), "b", &[json!({ "id": "x" })], None);
        }
        assert!(read_store(&path).len() <= LAST_KNOWN_MAX_ENTRIES);
        std::fs::write(&path, "{\"version\":2,\"entries\":{}}").unwrap();
        assert!(read_store(&path).is_empty());
    }

    #[test]
    fn remap_current_model() {
        let entry = |current: Option<&str>| LastKnownEntry {
            backend: "grok".into(),
            models: vec![json!({ "id": "grok-4.6", "thinkingLevels": ["high"] }), json!({ "id": "b" })],
            current_model_id: current.map(str::to_string),
            fetched_at: String::new(),
        };
        assert_eq!(remap_last_known_current_model_id(&entry(None)), None);
        assert_eq!(remap_last_known_current_model_id(&entry(Some("b"))).as_deref(), Some("b"));
        assert_eq!(remap_last_known_current_model_id(&entry(Some("grok-4.6/high"))).as_deref(), Some("grok-4.6/high"));
        assert_eq!(remap_last_known_current_model_id(&entry(Some("grok-4.6/low"))).as_deref(), Some("grok-4.6"));
        assert_eq!(remap_last_known_current_model_id(&entry(Some("gone"))).as_deref(), Some("grok-4.6"));
    }

    #[test]
    fn catalog_normalization() {
        let c = ModelCatalog { current_model_id: None, models: vec![json!({ "id": "" }), json!({ "id": "a" }), json!(null)] }.normalized();
        assert_eq!(c.models.len(), 1);
        assert!(ModelCatalog::default().is_empty());
    }
}
