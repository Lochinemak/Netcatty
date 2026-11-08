//! Opt-in local plugin logs (ports of `pluginLogService.cjs`,
//! `pluginLogger.cjs` and `pluginLogProvenance.cjs`).
//!
//! Persistence is off by default and remembered in
//! `plugins/local-logging.json`; verbose plugin diagnostics always require
//! fresh consent after a restart. Records are JSONL in
//! `plugins/logs/host-v1/runtime{,.1,.2}.jsonl`, rotated at 1 MiB, pruned
//! after seven days. Host audits record only HMAC'd resource identifiers;
//! plugin diagnostics are redacted and size bounded.

use crate::constants::{PLUGIN_LOG_MAX_BYTES, PLUGIN_LOG_MAX_FILES};
use crate::database::PluginDatabase;
use crate::error::{codes, PluginError, PluginResult};
use crate::quota::TokenBucket;
use crate::source::PluginPaths;
use hmac::{Hmac, KeyInit, Mac};
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const MAX_PENDING_BYTES: usize = 256 * 1024;
const MAX_RECORD_BYTES: usize = 16 * 1024;

fn sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let squash: String = lower.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    [
        "password", "passwd", "token", "secret", "apikey", "privatekey", "credential", "authorization",
        "cookie", "totp", "otpauth", "prompt", "note", "sql", "result", "terminal", "content", "body", "payload",
    ]
    .iter()
    .any(|needle| squash.contains(needle))
}

fn sanitize_text(text: &str, max: usize) -> String {
    text.chars()
        .take(max)
        .map(|c| {
            let code = c as u32;
            if code <= 0x1f || (0x7f..=0x9f).contains(&code) || (0x202a..=0x202e).contains(&code) || (0x2066..=0x2069).contains(&code) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// `redactLogValue`: bounded, key-based redaction.
pub fn redact_log_value(value: &Value, key: &str, depth: usize, budget: &mut i64) -> Value {
    if !key.is_empty() && sensitive_key(key) {
        return json!("[REDACTED]");
    }
    if depth >= 6 || *budget <= 0 {
        return json!("[TRUNCATED]");
    }
    *budget -= 16;
    match value {
        Value::Null | Value::Bool(_) => value.clone(),
        Value::Number(n) => {
            if n.as_f64().is_some_and(f64::is_finite) {
                value.clone()
            } else {
                Value::Null
            }
        }
        Value::String(s) => {
            let text = sanitize_text(s, (*budget).clamp(0, 2048) as usize);
            *budget -= text.chars().count() as i64;
            Value::String(text)
        }
        Value::Array(items) => {
            let mut out = Vec::new();
            for (index, item) in items.iter().enumerate() {
                if *budget <= 0 || index >= 32 {
                    break;
                }
                out.push(redact_log_value(item, &index.to_string(), depth + 1, budget));
            }
            Value::Array(out)
        }
        Value::Object(map) => {
            let mut out = Map::new();
            for (index, (entry_key, item)) in map.iter().enumerate() {
                if *budget <= 0 || index >= 32 {
                    break;
                }
                let safe_key = sanitize_text(entry_key, 64);
                *budget -= safe_key.len() as i64;
                out.insert(safe_key, redact_log_value(item, entry_key, depth + 1, budget));
            }
            Value::Object(out)
        }
    }
}

fn bounded(value: Option<&str>, len: usize) -> Value {
    match value {
        Some(text) => Value::String(
            text.chars()
                .take(len)
                .map(|c| if c.is_ascii_alphanumeric() || "._:@/-".contains(c) { c } else { '_' })
                .collect(),
        ),
        None => Value::Null,
    }
}

/// Host-assigned identity of a runtime (never plugin supplied).
#[derive(Debug, Clone, Default)]
pub struct LogIdentity {
    pub plugin_id: String,
    pub plugin_version: Option<String>,
    pub runtime_id: Option<String>,
    pub runtime_kind: Option<String>,
}

#[derive(Default)]
struct Sink {
    enabled: bool,
    closed: bool,
    dropped: u64,
    write_errors: u64,
    clearing: bool,
}

pub struct PluginLogService {
    pub directory: PathBuf,
    pub preferences_path: PathBuf,
    database: Option<Arc<PluginDatabase>>,
    salt: [u8; 32],
    sink: Mutex<Sink>,
    settings: Mutex<(bool, bool)>,
}

impl PluginLogService {
    pub fn new(paths: &PluginPaths, database: Option<Arc<PluginDatabase>>) -> Self {
        let directory = paths.logs.join("host-v1");
        let preferences_path = paths.root.join("local-logging.json");
        let mut save = false;
        if let Ok(meta) = fs::metadata(&preferences_path) {
            if meta.len() <= 1024 {
                if let Ok(text) = fs::read_to_string(&preferences_path) {
                    save = serde_json::from_str::<Value>(&text)
                        .ok()
                        .and_then(|v| v.get("saveToDisk").and_then(Value::as_bool))
                        == Some(true);
                }
            }
        }
        let service = Self {
            directory,
            preferences_path,
            database,
            salt: rand::random(),
            sink: Mutex::new(Sink::default()),
            settings: Mutex::new((false, false)),
        };
        if save {
            if service.set_sink_enabled(true).is_ok() {
                *service.settings.lock() = (true, false);
            } else {
                service.sink.lock().write_errors += 1;
            }
        } else if service.directory.exists() {
            let _ = service.prune();
        }
        service
    }

    fn file(&self, index: usize) -> PathBuf {
        self.directory.join(if index == 0 { "runtime.jsonl".to_string() } else { format!("runtime.{index}.jsonl") })
    }

    fn set_sink_enabled(&self, enabled: bool) -> PluginResult<()> {
        self.sink.lock().enabled = false;
        if enabled && !self.sink.lock().closed {
            self.prune()?;
            self.sink.lock().enabled = true;
        }
        Ok(())
    }

    fn retained(&self, file: &Path) -> bool {
        let Ok(mut handle) = fs::File::open(file) else { return false };
        let mut buffer = vec![0u8; MAX_RECORD_BYTES];
        let read = handle.read(&mut buffer).unwrap_or(0);
        let Some(newline) = buffer[..read].iter().position(|b| *b == b'\n') else { return false };
        let Ok(first) = serde_json::from_slice::<Value>(&buffer[..newline]) else { return false };
        first
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .is_some_and(|start| crate::constants::now_ms() - start.timestamp_millis() < RETENTION_MS)
    }

    fn prune(&self) -> PluginResult<()> {
        crate::package::archive::create_private_dir_all(&self.directory)?;
        for index in 0..PLUGIN_LOG_MAX_FILES {
            let file = self.file(index);
            match fs::symlink_metadata(&file) {
                Ok(meta) => {
                    if !meta.is_file() {
                        return Err(PluginError::host("Unsafe plugin log file"));
                    }
                    if meta.len() > PLUGIN_LOG_MAX_BYTES || !self.retained(&file) {
                        fs::remove_file(&file)?;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    fn enqueue(&self, mut record: Map<String, Value>) {
        let mut sink = self.sink.lock();
        if !sink.enabled || sink.closed {
            return;
        }
        if sink.clearing {
            sink.dropped += 1;
            return;
        }
        record.insert("timestamp".into(), json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)));
        record.insert("droppedRecords".into(), json!(sink.dropped));
        record.insert("writeErrors".into(), json!(sink.write_errors));
        let Ok(mut line) = serde_json::to_string(&record) else {
            sink.dropped += 1;
            return;
        };
        line.push('\n');
        if line.len() > MAX_RECORD_BYTES.min(PLUGIN_LOG_MAX_BYTES as usize) || line.len() > MAX_PENDING_BYTES {
            sink.dropped += 1;
            return;
        }
        let result = (|| -> PluginResult<()> {
            self.prune()?;
            let active = self.file(0);
            let size = fs::metadata(&active).map(|m| m.len()).unwrap_or(0);
            if size + line.len() as u64 > PLUGIN_LOG_MAX_BYTES {
                let _ = fs::remove_file(self.file(PLUGIN_LOG_MAX_FILES - 1));
                for index in (0..PLUGIN_LOG_MAX_FILES - 1).rev() {
                    match fs::rename(self.file(index), self.file(index + 1)) {
                        Ok(()) => {}
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => return Err(err.into()),
                    }
                }
            }
            let mut options = OpenOptions::new();
            options.append(true).create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc_nofollow());
            }
            let mut handle = options.open(&active)?;
            if !handle.metadata()?.is_file() {
                return Err(PluginError::host("Unsafe plugin log file"));
            }
            handle.write_all(line.as_bytes())?;
            Ok(())
        })();
        if result.is_err() {
            sink.dropped += 1;
            sink.write_errors += 1;
        }
    }

    /// `status()`.
    pub fn status(&self) -> Value {
        let (save, verbose) = *self.settings.lock();
        let sink = self.sink.lock();
        json!({
            "saveToDisk": save,
            "verbose": verbose,
            "droppedRecords": sink.dropped,
            "writeErrors": sink.write_errors,
            "pendingBytes": 0,
            "maxBytes": PLUGIN_LOG_MAX_BYTES * PLUGIN_LOG_MAX_FILES as u64,
            "retentionDays": RETENTION_MS / 86_400_000,
        })
    }

    /// `configure({ saveToDisk, verbose })`.
    pub fn configure(&self, request: &Value) -> PluginResult<Value> {
        let (Some(save), Some(verbose)) = (
            request.get("saveToDisk").and_then(Value::as_bool),
            request.get("verbose").and_then(Value::as_bool),
        ) else {
            return Err(PluginError::invalid("Invalid plugin log settings"));
        };
        if self.sink.lock().closed {
            return Err(PluginError::host("Plugin logging is closed"));
        }
        *self.settings.lock() = (false, false);
        self.set_sink_enabled(false)?;
        crate::package::archive::create_private_dir_all(self.preferences_path.parent().unwrap_or(Path::new(".")))?;
        let tmp = self.preferences_path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string(&json!({ "saveToDisk": save }))?)?;
        fs::rename(&tmp, &self.preferences_path)?;
        self.set_sink_enabled(save)?;
        *self.settings.lock() = (save, save && verbose);
        Ok(self.status())
    }

    /// Ensure the log folder exists (for "open folder").
    pub fn ensure_folder(&self) -> PluginResult<PathBuf> {
        crate::package::archive::create_private_dir_all(&self.directory)?;
        Ok(self.directory.clone())
    }

    /// Concatenate retained log files (oldest first) into `destination`.
    pub fn export_to(&self, destination: &Path) -> PluginResult<Value> {
        let resolved = destination.to_path_buf();
        if resolved.starts_with(&self.directory) && resolved != self.directory {
            return Err(PluginError::invalid("Choose a destination outside the log folder"));
        }
        let _guard = self.sink.lock();
        let mut out = Vec::new();
        for index in (0..PLUGIN_LOG_MAX_FILES).rev() {
            let file = self.file(index);
            match fs::symlink_metadata(&file) {
                Ok(meta) => {
                    if !meta.is_file() || meta.len() > PLUGIN_LOG_MAX_BYTES {
                        return Err(PluginError::host("Unsafe plugin log file"));
                    }
                    if self.retained(&file) {
                        out.extend(fs::read(&file)?);
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        drop(_guard);
        fs::write(destination, out)?;
        Ok(self.status())
    }

    /// Delete the saved log files.
    pub fn clear(&self) -> PluginResult<Value> {
        self.sink.lock().clearing = true;
        for index in 0..PLUGIN_LOG_MAX_FILES {
            let _ = fs::remove_file(self.file(index));
        }
        self.sink.lock().clearing = false;
        Ok(self.status())
    }

    pub fn verbose(&self) -> bool {
        self.settings.lock().1
    }

    /// Provenance-checked identity fields (`identity()`).
    pub fn identity_fields(&self, identity: &LogIdentity) -> Map<String, Value> {
        let mut fields = Map::new();
        fields.insert("pluginId".into(), bounded(Some(&identity.plugin_id), 128));
        fields.insert("pluginVersion".into(), bounded(identity.plugin_version.as_deref(), 128));
        fields.insert("runtimeId".into(), bounded(identity.runtime_id.as_deref(), 128));
        fields.insert("runtimeKind".into(), bounded(identity.runtime_kind.as_deref(), 128));
        let mut archive = Value::Null;
        let (mut source_id, mut source_kind, mut namespace) = (Value::Null, Value::Null, Value::Null);
        if let Some(db) = &self.database {
            if let Ok(Some(plugin)) = db.get_active_plugin(&identity.plugin_id) {
                if plugin.active_version.as_deref() == identity.plugin_version.as_deref() {
                    if let Some(sha) = plugin.archive_sha256.as_deref().filter(|s| s.len() == 64) {
                        archive = json!(sha);
                    }
                    let retained = db.get_retained_plugin_source(&identity.plugin_id).ok().flatten();
                    let owner = db.private_owner(&identity.plugin_id).ok();
                    if retained.as_ref().is_some_and(|r| r.id == plugin.source.id && r.kind == plugin.source.kind) {
                        if let Some(owner) = owner.filter(|o| db.public_plugin_id(o).as_deref() == Some(identity.plugin_id.as_str())) {
                            source_id = json!(plugin.source.id);
                            source_kind = json!(plugin.source.kind);
                            namespace = json!(owner);
                        }
                    }
                }
            }
        }
        fields.insert("archiveSha256".into(), archive);
        fields.insert("sourceId".into(), source_id);
        fields.insert("sourceKind".into(), source_kind);
        fields.insert("namespace".into(), namespace);
        fields
    }

    /// Host audit record (`audit`). `resources` are HMAC'd, never stored.
    #[allow(clippy::too_many_arguments)]
    pub fn audit(
        &self,
        identity: &LogIdentity,
        operation: &str,
        authorization: &str,
        ok: bool,
        error_code: Option<i64>,
        resources: &[String],
        duration_ms: Option<u64>,
    ) {
        if !self.sink.lock().enabled {
            return;
        }
        let mut record = self.identity_fields(identity);
        record.insert("recordType".into(), json!("host-audit"));
        record.insert("trust".into(), json!("host-observed"));
        record.insert("operation".into(), bounded(Some(operation), 256));
        let ids: Vec<Value> = resources
            .iter()
            .take(16)
            .map(|r| {
                let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.salt).expect("hmac key");
                mac.update(r.chars().take(8192).collect::<String>().as_bytes());
                json!(hex::encode(mac.finalize().into_bytes()))
            })
            .collect();
        record.insert("targetIds".into(), Value::Array(ids));
        let authorization = if ["allowed", "denied", "not-required", "not-reached", "unknown"].contains(&authorization) {
            authorization
        } else {
            "unknown"
        };
        record.insert("authorization".into(), json!(authorization));
        record.insert("result".into(), json!(if ok { "ok" } else { "error" }));
        let code = match error_code {
            Some(c) if codes::ALL.contains(&c) => json!(c),
            _ if ok => Value::Null,
            _ => json!(codes::INTERNAL),
        };
        record.insert("errorCode".into(), code);
        record.insert("durationMs".into(), duration_ms.map_or(Value::Null, |d| json!(d)));
        record.insert("inputBytes".into(), Value::Null);
        record.insert("outputBytes".into(), Value::Null);
        self.enqueue(record);
    }

    pub fn create_logger(self: &Arc<Self>, identity: LogIdentity) -> PluginLogger {
        PluginLogger {
            service: self.clone(),
            identity,
            bucket: Mutex::new(TokenBucket::new(240.0, 240.0 / 60_000.0)),
        }
    }

    pub fn close(&self) {
        let mut sink = self.sink.lock();
        sink.closed = true;
        sink.enabled = false;
    }
}

#[cfg(unix)]
fn libc_nofollow() -> i32 {
    // O_NOFOLLOW: 0x100 on macOS/BSD, 0o400000 on Linux.
    if cfg!(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")) {
        0x0100
    } else {
        0o400000
    }
}

/// Per-runtime diagnostics writer (`PluginLogger`).
pub struct PluginLogger {
    service: Arc<PluginLogService>,
    identity: LogIdentity,
    bucket: Mutex<TokenBucket>,
}

impl PluginLogger {
    pub fn write(&self, level: &str, message: &str, fields: Option<&Value>) {
        if !self.service.sink.lock().enabled || !self.service.verbose() {
            return;
        }
        if !self.bucket.lock().consume() {
            self.service.sink.lock().dropped += 1;
            return;
        }
        let mut record = self.service.identity_fields(&self.identity);
        record.insert("recordType".into(), json!("plugin-diagnostic"));
        record.insert("trust".into(), json!("plugin-authored-unverified"));
        let level = if ["debug", "info", "warn", "error"].contains(&level) { level } else { "info" };
        record.insert("level".into(), json!(level));
        let mut budget = 4096;
        let message = redact_log_value(&json!(message), "", 0, &mut budget);
        let mut budget = 4096;
        let fields = fields.map(|f| redact_log_value(f, "", 0, &mut budget)).unwrap_or(Value::Null);
        record.insert("diagnostic".into(), json!({ "message": message, "fields": fields }));
        self.service.enqueue(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction() {
        let mut budget = 4096;
        let value = redact_log_value(&json!({ "password": "x", "host": "a\u{1}b", "nested": { "token": 1 } }), "", 0, &mut budget);
        assert_eq!(value["password"], json!("[REDACTED]"));
        assert_eq!(value["host"], json!("a b"));
        assert_eq!(value["nested"]["token"], json!("[REDACTED]"));
    }

    #[test]
    fn configure_persists_and_writes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = PluginPaths::new(dir.path());
        let service = Arc::new(PluginLogService::new(&paths, None));
        assert_eq!(service.status()["saveToDisk"], json!(false));
        service.configure(&json!({ "saveToDisk": true, "verbose": true })).unwrap();
        let identity = LogIdentity { plugin_id: "com.example.a".into(), ..Default::default() };
        service.audit(&identity, "storage.get", "allowed", true, None, &["secret-path".into()], Some(3));
        service.create_logger(identity).write("info", "hello", Some(&json!({ "token": "t" })));
        let text = fs::read_to_string(service.directory.join("runtime.jsonl")).unwrap();
        assert!(!text.contains("secret-path"));
        assert!(!text.contains("\"t\""));
        assert_eq!(text.lines().count(), 2);
        // Persisted saveToDisk; verbose resets.
        let again = PluginLogService::new(&paths, None);
        assert_eq!(again.status()["saveToDisk"], json!(true));
        assert_eq!(again.status()["verbose"], json!(false));
        service.clear().unwrap();
        assert!(!service.directory.join("runtime.jsonl").exists());
        assert!(service.configure(&json!({ "saveToDisk": "yes" })).is_err());
    }
}
