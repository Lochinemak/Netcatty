//! Durable store for truncated AI tool outputs (Electron `tempDirBridge.cjs`,
//! `netcatty:tempdir:toolOutput*` handlers).
//!
//! Content is written to the Netcatty temp directory as UTF-16LE
//! (`<ts>_<n>_tool-output-<chat24>-<term24>-<handle>.log`) next to a
//! manifest (`.log.meta.json`) holding the record, size, SHA-256 and an
//! HMAC-SHA256 signature. Offsets / lengths are UTF-16 code units (JS
//! string semantics) because the renderer computes them that way.
//!
//! Differences from Electron: the signing key is a random 32-byte file in
//! the app data directory (0600) instead of an Electron `safeStorage`
//! blob, so persistence is always reported durable when the key file can
//! be created.

use hmac::{Hmac, KeyInit, Mac};
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const MAX_TOOL_OUTPUT_TEMP_CHARS: usize = 4_000_000;
pub const MAX_TOOL_OUTPUT_TEMP_BYTES: usize = 8_000_000;
pub const TOOL_OUTPUT_PERSISTED_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
pub const TOOL_OUTPUT_MANIFEST_MAX_BYTES: u64 = 16_384;
pub const TOOL_OUTPUT_MAX_HANDLES_PER_SESSION: usize = 64;
pub const TOOL_OUTPUT_MAX_CHARS_PER_SESSION: usize = 8_000_000;
pub const TOOL_OUTPUT_MAX_HANDLES_GLOBAL: usize = 256;
pub const TOOL_OUTPUT_MAX_CHARS_GLOBAL: usize = 32_000_000;
pub const TOOL_OUTPUT_READ_MAX_CHARS: usize = 12_000;
pub const TOOL_OUTPUT_SEARCH_CONTEXT_CHARS: usize = 320;
pub const TOOL_OUTPUT_SEARCH_MAX_MATCHES: usize = 20;

pub type TempDirFn = Arc<dyn Fn() -> PathBuf + Send + Sync>;

pub struct ToolOutputStore {
    temp_dir: TempDirFn,
    key_path: PathBuf,
    key: Mutex<Option<[u8; 32]>>,
    counter: Mutex<u32>,
    closed_terminals: Mutex<HashSet<String>>,
    chat_deletion_generation: Mutex<HashMap<String, u64>>,
}

fn sha24(v: &str) -> String {
    hex::encode(Sha256::digest(v.as_bytes()))[..24].to_string()
}

fn bounded(v: &Value, max: usize, allow_empty: bool) -> bool {
    v.as_str().is_some_and(|s| s.encode_utf16().count() <= max && (allow_empty || !s.is_empty()))
}

/// `isSafeToolOutputRecord`.
pub fn is_safe_record(r: &Value) -> bool {
    let int = |k: &str| r[k].as_u64();
    let handle_ok = bounded(&r["handleId"], 200, false)
        && r["handleId"].as_str().is_some_and(|h| h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')));
    r["schemaVersion"] == json!(1)
        && handle_ok
        && bounded(&r["chatSessionId"], 512, false)
        && bounded(&r["capabilityId"], 256, false)
        && (r["terminalSessionId"].is_null() || bounded(&r["terminalSessionId"], 512, false))
        && int("totalChars").is_some()
        && int("storedChars").is_some_and(|s| s as usize <= MAX_TOOL_OUTPUT_TEMP_CHARS)
        && int("totalChars") >= int("storedChars")
        && r["sourceTruncated"].is_boolean()
        && bounded(&r["preview"], 2000, true)
        && r["storedAt"].as_f64().is_some_and(|v| v > 0.0)
        && r["accessedAt"].as_f64().is_some_and(|v| v > 0.0)
}

struct Entry {
    manifest: Value,
    manifest_path: PathBuf,
    content_path: PathBuf,
}

fn now_ms() -> u64 {
    crate::host::now_ms()
}

fn utf16_safe_bounds(content: &[u16], start: isize, end: isize) -> (usize, usize) {
    let len = content.len() as isize;
    let mut s = start.clamp(0, len) as usize;
    let mut e = end.clamp(s as isize, len) as usize;
    let is_high = |v: u16| (0xd800..=0xdbff).contains(&v);
    let is_low = |v: u16| (0xdc00..=0xdfff).contains(&v);
    if s > 0 && s < content.len() && is_low(content[s]) {
        s -= 1;
    }
    if e > s && e < content.len() && is_high(content[e - 1]) {
        e -= 1;
    }
    (s, e)
}

/// `readToolOutputChunk` over UTF-16 code units.
pub fn read_chunk(content: &[u16], request: &Value) -> Value {
    let stored = content.len();
    let requested = request["maxChars"].as_f64().map(|v| v.floor() as i64).unwrap_or(TOOL_OUTPUT_READ_MAX_CHARS as i64);
    let max_chars = requested.clamp(1, TOOL_OUTPUT_READ_MAX_CHARS as i64) as usize;
    let mode = request["mode"].as_str().unwrap_or("head");
    let text = |r: &[u16]| String::from_utf16_lossy(r);
    let offset = request["offset"].as_f64().map(|v| v.floor().max(0.0) as usize).unwrap_or(0);
    if mode == "search" {
        let query = request["query"].as_str().unwrap_or("");
        if query.is_empty() {
            return json!({ "mode": mode, "content": "Search query is required.", "totalChars": stored, "startOffset": 0, "endOffset": 0, "nextOffset": 0, "hasMore": false, "matchOffsets": [] });
        }
        let lower = |s: &str| s.to_lowercase().encode_utf16().collect::<Vec<u16>>();
        let haystack = lower(&text(content));
        let needle = lower(query);
        let query_len = query.encode_utf16().count();
        let find = |from: usize| -> Option<usize> {
            if needle.is_empty() || from > haystack.len() {
                return None;
            }
            haystack[from..].windows(needle.len()).position(|w| w == needle.as_slice()).map(|p| p + from)
        };
        let mut offsets = Vec::new();
        let mut cursor = offset;
        while offsets.len() < TOOL_OUTPUT_SEARCH_MAX_MATCHES {
            let Some(m) = find(cursor) else { break };
            offsets.push(m);
            cursor = m + needle.len().max(1);
        }
        let mut excerpts: Vec<String> = Vec::new();
        let mut rendered = Vec::new();
        let mut rendered_chars = 0usize;
        for m in offsets {
            let (s, e) = utf16_safe_bounds(content, m as isize - TOOL_OUTPUT_SEARCH_CONTEXT_CHARS as isize, (m + query_len + TOOL_OUTPUT_SEARCH_CONTEXT_CHARS) as isize);
            let excerpt: Vec<u16> = format!("[match offset={m}]\n{}", text(&content[s..e])).encode_utf16().collect();
            let sep = if excerpts.is_empty() { 0 } else { 2 };
            let available = max_chars as isize - rendered_chars as isize - sep as isize;
            if available <= 0 {
                break;
            }
            if excerpt.len() > available as usize {
                if !excerpts.is_empty() {
                    break;
                }
                let (_, safe_end) = utf16_safe_bounds(&excerpt, 0, available);
                excerpts.push(text(&excerpt[..safe_end]));
                rendered.push(m);
                break;
            }
            rendered_chars += sep + excerpt.len();
            excerpts.push(text(&excerpt));
            rendered.push(m);
        }
        let next = rendered.last().map(|m| m + query_len.max(1)).unwrap_or(stored);
        let body = if excerpts.is_empty() { format!("No matches found for \"{query}\".") } else { excerpts.join("\n\n") };
        return json!({
            "mode": mode, "content": body, "totalChars": stored, "startOffset": offset,
            "endOffset": next, "nextOffset": next, "hasMore": find(next).is_some(), "matchOffsets": rendered,
        });
    }
    let start = match mode {
        "tail" => stored.saturating_sub(max_chars),
        "range" => offset.min(stored),
        _ => 0,
    };
    let read_start = start.saturating_sub(1);
    let window = &content[read_start..(read_start + max_chars + 2).min(stored)];
    let rel = (start - read_start) as isize;
    let (s, e) = utf16_safe_bounds(window, rel, rel + max_chars as isize);
    let start = read_start + s;
    let chunk = &window[s..e];
    let end = start + chunk.len();
    json!({ "mode": mode, "content": text(chunk), "totalChars": stored, "startOffset": start, "endOffset": end, "nextOffset": end, "hasMore": end < stored })
}

impl ToolOutputStore {
    pub fn new(temp_dir: TempDirFn, key_path: PathBuf) -> Self {
        Self {
            temp_dir,
            key_path,
            key: Mutex::new(None),
            counter: Mutex::new(0),
            closed_terminals: Default::default(),
            chat_deletion_generation: Default::default(),
        }
    }

    fn signing_key(&self) -> Option<[u8; 32]> {
        let mut slot = self.key.lock();
        if let Some(k) = *slot {
            return Some(k);
        }
        if let Ok(bytes) = std::fs::read(&self.key_path) {
            if bytes.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                *slot = Some(k);
                return Some(k);
            }
        }
        let k: [u8; 32] = rand::random();
        if let Some(dir) = self.key_path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let text = hex::encode(k);
        let _ = text;
        if write_private(&self.key_path, &k).is_err() {
            return None;
        }
        *slot = Some(k);
        Some(k)
    }

    pub fn persistence_status(&self) -> Value {
        if self.signing_key().is_some() {
            json!({ "durable": true })
        } else {
            json!({ "durable": false, "reason": "Secure local storage is unavailable." })
        }
    }

    fn sign(manifest: &Value, key: &[u8; 32]) -> String {
        let unsigned = json!({
            "record": manifest["record"],
            "contentFile": manifest["contentFile"],
            "contentBytes": manifest["contentBytes"],
            "contentSha256": manifest["contentSha256"],
        });
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac key");
        mac.update(unsigned.to_string().as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn temp_file_path(&self, name: &str) -> PathBuf {
        let dir = (self.temp_dir)();
        let _ = std::fs::create_dir_all(&dir);
        let mut c = self.counter.lock();
        *c = (*c + 1) % 1_000_000;
        let safe: String = name.chars().map(|ch| if r#"<>:"/\|?*"#.contains(ch) { '_' } else { ch }).collect();
        dir.join(format!("{}_{}_{safe}", now_ms(), *c))
    }

    fn is_temp_path(&self, path: &Path) -> bool {
        let dir = (self.temp_dir)();
        path.parent().is_some_and(|p| p == dir) && !path.as_os_str().is_empty()
    }

    fn read_manifest(&self, manifest_path: &Path, key: &[u8; 32]) -> Option<Entry> {
        if !self.is_temp_path(manifest_path) || !manifest_path.to_string_lossy().ends_with(".log.meta.json") {
            return None;
        }
        let meta = std::fs::symlink_metadata(manifest_path).ok()?;
        if !meta.is_file() || meta.len() > TOOL_OUTPUT_MANIFEST_MAX_BYTES {
            return None;
        }
        let parsed: Value = serde_json::from_str(&std::fs::read_to_string(manifest_path).ok()?).ok()?;
        if !is_safe_record(&parsed["record"]) {
            return None;
        }
        let content_file = parsed["contentFile"].as_str()?;
        if content_file.is_empty() || content_file.contains(['/', '\\']) {
            return None;
        }
        if parsed["contentBytes"].as_u64().is_none_or(|b| b as usize > MAX_TOOL_OUTPUT_TEMP_BYTES) {
            return None;
        }
        let sig = parsed["signature"].as_str()?;
        let expected = Self::sign(&parsed, key);
        if sig.len() != 64 || !constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
            return None;
        }
        let content_path = manifest_path.parent()?.join(content_file);
        if PathBuf::from(format!("{}.meta.json", content_path.display())) != manifest_path {
            return None;
        }
        Some(Entry { manifest: parsed, manifest_path: manifest_path.to_path_buf(), content_path })
    }

    fn verified_content(entry: &Entry) -> Option<Vec<u8>> {
        let meta = std::fs::symlink_metadata(&entry.content_path).ok()?;
        if !meta.is_file() || meta.len() != entry.manifest["contentBytes"].as_u64()? {
            return None;
        }
        let bytes = std::fs::read(&entry.content_path).ok()?;
        (hex::encode(Sha256::digest(&bytes)) == entry.manifest["contentSha256"].as_str()?).then_some(bytes)
    }

    fn entries(&self) -> Vec<Entry> {
        let Some(key) = self.signing_key() else {
            return Vec::new();
        };
        let Ok(dir) = std::fs::read_dir((self.temp_dir)()) else {
            return Vec::new();
        };
        dir.flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".log.meta.json"))
            .filter_map(|e| self.read_manifest(&e.path(), &key))
            .collect()
    }

    fn delete_pair(&self, content_path: &Path) -> bool {
        if !self.is_temp_path(content_path) {
            return false;
        }
        let manifest = PathBuf::from(format!("{}.meta.json", content_path.display()));
        let rm = |p: &Path| match std::fs::remove_file(p) {
            Ok(()) => true,
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        };
        let m = rm(&manifest);
        let c = rm(content_path);
        m && c
    }

    fn expired(entry: &Entry) -> bool {
        let accessed = entry.manifest["record"]["accessedAt"].as_f64().unwrap_or(0.0) as u64;
        now_ms().saturating_sub(accessed) > TOOL_OUTPUT_PERSISTED_TTL_MS
    }

    fn touch(&self, entry: &Entry) {
        let Some(key) = self.signing_key() else {
            return;
        };
        let mut manifest = entry.manifest.clone();
        manifest["record"]["accessedAt"] = json!(now_ms());
        manifest.as_object_mut().map(|m| m.remove("signature"));
        manifest["signature"] = json!(Self::sign(&manifest, &key));
        let _ = write_private(&entry.manifest_path, manifest.to_string().as_bytes());
    }

    fn enforce_limits(&self) {
        let mut entries = self.entries();
        entries.sort_by_key(|e| e.manifest["record"]["accessedAt"].as_f64().unwrap_or(0.0) as u64);
        let chars = |e: &Entry| e.manifest["record"]["storedChars"].as_u64().unwrap_or(0) as usize;
        let mut per_session: HashMap<String, (usize, usize)> = HashMap::new();
        for e in &entries {
            let s = per_session.entry(e.manifest["record"]["chatSessionId"].as_str().unwrap_or("").to_string()).or_default();
            s.0 += 1;
            s.1 += chars(e);
        }
        let (mut total_handles, mut total_chars) = (entries.len(), entries.iter().map(chars).sum::<usize>());
        for e in &entries {
            let chat = e.manifest["record"]["chatSessionId"].as_str().unwrap_or("").to_string();
            let s = per_session.get_mut(&chat).unwrap();
            let over_session = s.0 > TOOL_OUTPUT_MAX_HANDLES_PER_SESSION || s.1 > TOOL_OUTPUT_MAX_CHARS_PER_SESSION;
            let over_global = total_handles > TOOL_OUTPUT_MAX_HANDLES_GLOBAL || total_chars > TOOL_OUTPUT_MAX_CHARS_GLOBAL;
            if !over_session && !over_global {
                continue;
            }
            if self.delete_pair(&e.content_path) {
                s.0 -= 1;
                s.1 -= chars(e);
                total_handles -= 1;
                total_chars -= chars(e);
            }
        }
    }

    fn generation(&self, chat: &str) -> u64 {
        self.chat_deletion_generation.lock().get(chat).copied().unwrap_or(0)
    }

    pub async fn write(&self, record: Value, content: String) -> Value {
        let units: Vec<u16> = content.encode_utf16().collect();
        if !is_safe_record(&record) || units.len() > MAX_TOOL_OUTPUT_TEMP_CHARS || record["storedChars"].as_u64() != Some(units.len() as u64) {
            return json!({ "ok": false, "error": "Tool output exceeds the temp-file limit." });
        }
        let bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
        if bytes.len() > MAX_TOOL_OUTPUT_TEMP_BYTES {
            return json!({ "ok": false, "error": "Tool output exceeds the temp-file limit." });
        }
        let chat = record["chatSessionId"].as_str().unwrap_or("").to_string();
        let terminal = record["terminalSessionId"].as_str().map(str::to_string);
        if terminal.as_ref().is_some_and(|t| self.closed_terminals.lock().contains(t)) {
            return json!({ "ok": false, "error": "Terminal session is already closed." });
        }
        let generation = self.generation(&chat);
        let Some(key) = self.signing_key() else {
            return json!({ "ok": false, "error": "Secure local storage is unavailable." });
        };
        let marker = format!("tool-output-{}-{}-", sha24(&chat), sha24(terminal.as_deref().unwrap_or("")));
        let handle = record["handleId"].as_str().unwrap_or("");
        let file_path = self.temp_file_path(&format!("{marker}{handle}.log"));
        let manifest_path = PathBuf::from(format!("{}.meta.json", file_path.display()));
        if let Err(e) = write_private(&file_path, &bytes) {
            return json!({ "ok": false, "error": e.to_string() });
        }
        let mut manifest = json!({
            "record": record,
            "contentFile": file_path.file_name().map(|f| f.to_string_lossy().into_owned()),
            "contentBytes": bytes.len(),
            "contentSha256": hex::encode(Sha256::digest(&bytes)),
        });
        manifest["signature"] = json!(Self::sign(&manifest, &key));
        if let Err(e) = write_private(&manifest_path, manifest.to_string().as_bytes()) {
            self.delete_pair(&file_path);
            return json!({ "ok": false, "error": e.to_string() });
        }
        if self.generation(&chat) != generation {
            self.delete_pair(&file_path);
            return json!({ "ok": false, "error": "Chat session was cleared while output was being saved." });
        }
        if terminal.as_ref().is_some_and(|t| self.closed_terminals.lock().contains(t)) {
            self.delete_pair(&file_path);
            return json!({ "ok": false, "error": "Terminal session closed while output was being saved." });
        }
        self.enforce_limits();
        if !manifest_path.exists() {
            return json!({ "ok": false, "error": "Saved output was removed while enforcing storage limits." });
        }
        json!({ "ok": true, "path": file_path.to_string_lossy(), "manifestPath": manifest_path.to_string_lossy() })
    }

    pub async fn restore(&self, handle_id: &str, chat: &str) -> Value {
        if handle_id.is_empty() || chat.is_empty() {
            return Value::Null;
        }
        let Some(entry) = self
            .entries()
            .into_iter()
            .find(|e| e.manifest["record"]["handleId"] == json!(handle_id) && e.manifest["record"]["chatSessionId"] == json!(chat))
        else {
            return Value::Null;
        };
        let closed = entry.manifest["record"]["terminalSessionId"].as_str().is_some_and(|t| self.closed_terminals.lock().contains(t));
        if closed || Self::expired(&entry) || Self::verified_content(&entry).is_none() {
            self.delete_pair(&entry.content_path);
            return Value::Null;
        }
        self.touch(&entry);
        json!({ "path": entry.content_path.to_string_lossy(), "record": entry.manifest["record"] })
    }

    pub async fn read(&self, path: &str, request: Option<Value>) -> Value {
        let Some(key) = self.signing_key() else {
            return Value::Null;
        };
        let manifest_path = PathBuf::from(format!("{path}.meta.json"));
        let Some(entry) = self.read_manifest(&manifest_path, &key) else {
            return Value::Null;
        };
        if entry.content_path != Path::new(path) {
            return Value::Null;
        }
        let closed = entry.manifest["record"]["terminalSessionId"].as_str().is_some_and(|t| self.closed_terminals.lock().contains(t));
        if closed || Self::expired(&entry) {
            self.delete_pair(&entry.content_path);
            return Value::Null;
        }
        let Some(bytes) = Self::verified_content(&entry) else {
            self.delete_pair(&entry.content_path);
            return Value::Null;
        };
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let result = match request.filter(|r| !r.is_null()) {
            None => json!(String::from_utf16_lossy(&units)),
            Some(r) => read_chunk(&units, &r),
        };
        self.touch(&entry);
        result
    }

    pub async fn delete(&self, path: &str) -> bool {
        self.delete_pair(Path::new(path))
    }

    fn delete_matching(&self, pred: impl Fn(&str) -> bool) -> usize {
        let Ok(dir) = std::fs::read_dir((self.temp_dir)()) else {
            return 0;
        };
        let mut n = 0;
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".log") && pred(&name) && self.delete_pair(&e.path()) {
                n += 1;
            }
        }
        n
    }

    pub async fn delete_chat(&self, chat: &str) -> usize {
        if chat.is_empty() {
            return 0;
        }
        *self.chat_deletion_generation.lock().entry(chat.to_string()).or_insert(0) += 1;
        let marker = format!("_tool-output-{}-", sha24(chat));
        self.delete_matching(|n| n.contains(&marker))
    }

    pub async fn delete_terminal_session(&self, chat: &str, terminal: &str) -> usize {
        if chat.is_empty() || terminal.is_empty() {
            return 0;
        }
        self.closed_terminals.lock().insert(terminal.to_string());
        let marker = format!("_tool-output-{}-{}-", sha24(chat), sha24(terminal));
        self.delete_matching(|n| n.contains(&marker))
    }

    pub async fn delete_terminal(&self, terminal: &str) -> usize {
        if terminal.is_empty() {
            return 0;
        }
        self.closed_terminals.lock().insert(terminal.to_string());
        let term = sha24(terminal);
        self.delete_matching(|n| {
            n.find("_tool-output-").is_some_and(|i| {
                let rest = &n[i + "_tool-output-".len()..];
                rest.len() > 50 && rest.as_bytes()[24] == b'-' && rest[25..].starts_with(&term) && rest.as_bytes().get(49) == Some(&b'-')
            })
        })
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(handle: &str, chat: &str, term: Option<&str>, content: &str) -> Value {
        let n = content.encode_utf16().count();
        let mut r = json!({
            "schemaVersion": 1, "handleId": handle, "chatSessionId": chat, "capabilityId": "terminal.execute",
            "totalChars": n, "storedChars": n, "sourceTruncated": false, "preview": "p", "storedAt": now_ms(), "accessedAt": now_ms(),
        });
        if let Some(t) = term {
            r["terminalSessionId"] = json!(t);
        }
        r
    }

    fn store(dir: &Path) -> ToolOutputStore {
        let d = dir.join("tmp");
        ToolOutputStore::new(Arc::new(move || d.clone()), dir.join("key"))
    }

    #[tokio::test]
    async fn write_restore_read_and_tamper_detection() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        assert_eq!(s.persistence_status()["durable"], true);
        let content = "hello 😀 world";
        let w = s.write(record("h1", "chat", Some("t1"), content), content.into()).await;
        assert_eq!(w["ok"], true, "{w}");
        let path = w["path"].as_str().unwrap().to_string();
        assert_eq!(s.read(&path, None).await, json!(content));
        let r = s.read(&path, Some(json!({ "mode": "range", "offset": 6, "maxChars": 2 }))).await;
        assert_eq!(r["content"], "😀");
        let r = s.read(&path, Some(json!({ "mode": "search", "query": "WORLD" }))).await;
        assert_eq!(r["matchOffsets"], json!([9]));
        let restored = s.restore("h1", "chat").await;
        assert_eq!(restored["path"], json!(path));
        assert!(s.restore("h1", "other").await.is_null());
        std::fs::write(&path, b"x\0").unwrap();
        assert!(s.read(&path, None).await.is_null());
        assert!(!Path::new(&path).exists(), "tampered pair is removed");
    }

    #[tokio::test]
    async fn rejects_invalid_records_and_deletes_by_owner() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let mut bad = record("h/x", "chat", None, "a");
        assert_eq!(s.write(bad.clone(), "a".into()).await["ok"], false);
        bad["handleId"] = json!("ok");
        assert_eq!(s.write(bad, "ab".into()).await["ok"], false);
        s.write(record("a", "chat", Some("t1"), "x"), "x".into()).await;
        s.write(record("b", "chat", Some("t2"), "y"), "y".into()).await;
        s.write(record("c", "other", Some("t1"), "z"), "z".into()).await;
        assert_eq!(s.delete_terminal_session("chat", "t1").await, 1);
        assert_eq!(s.delete_terminal("t1").await, 1);
        assert_eq!(s.write(record("d", "chat", Some("t1"), "x"), "x".into()).await["ok"], false);
        assert_eq!(s.delete_chat("chat").await, 1);
    }

    #[test]
    fn chunk_modes() {
        let units: Vec<u16> = "abcdefghij".encode_utf16().collect();
        assert_eq!(read_chunk(&units, &json!({ "mode": "tail", "maxChars": 3 }))["content"], "hij");
        let head = read_chunk(&units, &json!({ "maxChars": 4 }));
        assert_eq!(head["content"], "abcd");
        assert_eq!(head["hasMore"], true);
        assert_eq!(read_chunk(&units, &json!({ "mode": "search", "query": "" }))["content"], "Search query is required.");
        assert_eq!(read_chunk(&units, &json!({ "mode": "search", "query": "zz" }))["content"], "No matches found for \"zz\".");
    }
}
