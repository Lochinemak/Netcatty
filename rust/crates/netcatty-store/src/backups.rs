//! Local vault backups (Electron: `vaultBackupBridge.cjs`).
//!
//! Same record format and behaviour as Electron so the renderer's backup UI
//! works unchanged:
//! * one JSON file per backup, `vault-backup-<createdAt>-<id>.json`, mode
//!   0600, written atomically (tmp file + fsync + rename + dir fsync);
//! * the payload is encrypted — Electron uses `safeStorage-v1`, this build
//!   uses the credential cipher (`cipher-v2`, AES-256-GCM `enc:v2:` string);
//!   legacy `plain-json-v1` records are still readable, nothing is ever
//!   written in plain text;
//! * a create whose payload fingerprint equals the newest backup's is a
//!   no-op (`created: false`); retention keeps the newest `maxCount`
//!   (1–100, default 20);
//! * mutations are serialized and `createdAt` is strictly increasing.

use crate::credentials::CredentialCipher;
use netcatty_core::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};

pub const BACKUP_FILE_PREFIX: &str = "vault-backup-";
pub const BACKUP_FILE_EXT: &str = ".json";
pub const MIN_MAX_COUNT: u64 = 1;
pub const MAX_MAX_COUNT: u64 = 100;
pub const DEFAULT_MAX_COUNT: u64 = 20;
pub const MAX_PAYLOAD_BYTES: usize = 25 * 1024 * 1024;
const MAX_BACKUP_FILE_BYTES: u64 = (MAX_PAYLOAD_BYTES as u64) * 2;
const ENCODING_CIPHER: &str = "cipher-v2";
const ENCODING_PLAIN: &str = "plain-json-v1";
const ENCODING_SAFE_STORAGE: &str = "safeStorage-v1";

pub const ERR_ENCRYPTION_UNAVAILABLE: &str =
    "Secure storage is unavailable on this platform; vault backups cannot be created or read safely.";

/// Serializes create / trim / clear (Electron's `mutationLock`).
static MUTATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// Strictly increasing `createdAt` (Electron's `lastCreatedAt`).
static LAST_CREATED_AT: AtomicI64 = AtomicI64::new(0);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackupPreview {
    pub host_count: usize,
    pub key_count: usize,
    pub snippet_count: usize,
    pub note_count: usize,
    pub identity_count: usize,
    pub port_forwarding_rule_count: usize,
}

/// On-disk record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupRecord {
    #[serde(default)]
    format_version: u32,
    id: String,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sync_data_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_app_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_app_version: Option<String>,
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    preview: BackupPreview,
    #[serde(default)]
    payload_encoding: String,
    #[serde(default)]
    payload_data: String,
}

/// What the renderer sees (`toBackupSummary`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackupSummary {
    pub id: String,
    pub created_at: i64,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_data_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_app_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_app_version: Option<String>,
    pub preview: BackupPreview,
    pub fingerprint: String,
}

impl From<&BackupRecord> for BackupSummary {
    fn from(r: &BackupRecord) -> Self {
        Self {
            id: r.id.clone(),
            created_at: r.created_at,
            reason: r.reason.clone(),
            sync_data_version: r.sync_data_version,
            source_app_version: r.source_app_version.clone(),
            target_app_version: r.target_app_version.clone(),
            preview: r.preview.clone(),
            fingerprint: r.fingerprint.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOptions {
    pub payload: Option<Value>,
    pub reason: Option<Value>,
    pub source_app_version: Option<Value>,
    pub target_app_version: Option<Value>,
    pub sync_data_version: Option<Value>,
    pub max_count: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateResult {
    pub created: bool,
    pub backup: BackupSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadResult {
    pub backup: BackupSummary,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrimResult {
    pub deleted_count: usize,
    pub kept_count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClearResult {
    pub deleted_count: usize,
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Keys sorted, top-level `syncedAt` zeroed (Electron's
/// `normalizePayloadForHash`; array order is significant).
fn normalize_for_hash(value: &Value, is_root: bool) -> Value {
    match value {
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| normalize_for_hash(v, false)).collect())
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                let item = if is_root && key == "syncedAt" {
                    Value::from(0)
                } else {
                    normalize_for_hash(&map[key], false)
                };
                out.insert(key.clone(), item);
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

pub fn fingerprint(payload: &Value) -> String {
    hex::encode(Sha256::digest(
        normalize_for_hash(payload, true).to_string().as_bytes(),
    ))
}

pub fn build_preview(payload: &Value) -> BackupPreview {
    let count = |key: &str| {
        payload
            .get(key)
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    };
    BackupPreview {
        host_count: count("hosts"),
        key_count: count("keys"),
        snippet_count: count("snippets"),
        note_count: count("notes"),
        identity_count: count("identities"),
        port_forwarding_rule_count: count("portForwardingRules"),
    }
}

pub fn sanitize_max_count(raw: Option<&Value>) -> usize {
    let numeric = match raw {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.trim().parse::<f64>().ok(),
        _ => None,
    };
    match numeric {
        Some(n) if n.is_finite() && n > 0.0 => {
            (n.floor() as u64).clamp(MIN_MAX_COUNT, MAX_MAX_COUNT) as usize
        }
        _ => DEFAULT_MAX_COUNT as usize,
    }
}

fn sanitize_reason(raw: Option<&Value>) -> String {
    match raw.and_then(Value::as_str) {
        Some(r @ ("app_version_change" | "before_restore")) => r.to_owned(),
        _ => "before_restore".to_owned(),
    }
}

fn sanitize_version(raw: Option<&Value>) -> Option<String> {
    let trimmed = raw.and_then(Value::as_str)?.trim();
    let valid = (1..=64).contains(&trimmed.len())
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'));
    valid.then(|| trimmed.to_owned())
}

fn sanitize_sync_data_version(raw: Option<&Value>) -> Option<u64> {
    let n = raw.and_then(Value::as_f64)?;
    (n.is_finite() && n >= 1.0).then(|| n.floor() as u64)
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

pub struct BackupStore<'a> {
    dir: PathBuf,
    cipher: &'a CredentialCipher,
}

struct Entry {
    record: BackupRecord,
    path: PathBuf,
}

fn io_err(context: &str, err: impl std::fmt::Display) -> CoreError {
    CoreError::io(format!("{context}: {err}"))
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(dir) {
        if let Err(err) = handle.sync_all() {
            tracing::warn!(%err, "vault backup directory fsync failed");
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

impl<'a> BackupStore<'a> {
    pub fn new(dir: PathBuf, cipher: &'a CredentialCipher) -> Self {
        Self { dir, cipher }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn encryption_available(&self) -> bool {
        self.cipher.available()
    }

    fn list_entries(&self) -> CoreResult<Vec<Entry>> {
        create_private_dir(&self.dir).map_err(|e| io_err("create backup dir", e))?;
        let read_dir = std::fs::read_dir(&self.dir).map_err(|e| io_err("read backup dir", e))?;
        let mut entries = Vec::new();
        for item in read_dir.flatten() {
            let name = item.file_name().to_string_lossy().into_owned();
            if !item.file_type().is_ok_and(|t| t.is_file())
                || !name.starts_with(BACKUP_FILE_PREFIX)
                || !name.ends_with(BACKUP_FILE_EXT)
            {
                continue;
            }
            let path = item.path();
            match Self::read_record(&path) {
                Ok(record) => entries.push(Entry { record, path }),
                Err(err) => {
                    tracing::warn!(path = %path.display(), %err, "failed to parse vault backup")
                }
            }
        }
        entries.sort_by(|a, b| {
            b.record
                .created_at
                .cmp(&a.record.created_at)
                .then_with(|| b.record.id.cmp(&a.record.id))
        });
        Ok(entries)
    }

    fn read_record(path: &Path) -> CoreResult<BackupRecord> {
        let size = std::fs::metadata(path)
            .map_err(|e| io_err("stat vault backup", e))?
            .len();
        if size > MAX_BACKUP_FILE_BYTES {
            return Err(CoreError::invalid(format!(
                "Vault backup payload exceeds maximum allowed size ({size} > {MAX_PAYLOAD_BYTES})."
            )));
        }
        let raw = std::fs::read_to_string(path).map_err(|e| io_err("read vault backup", e))?;
        let record: BackupRecord = serde_json::from_str(&raw).map_err(|_| {
            CoreError::invalid(format!("Invalid vault backup record: {}", path.display()))
        })?;
        if record.id.is_empty() {
            return Err(CoreError::invalid(format!(
                "Invalid vault backup record: {}",
                path.display()
            )));
        }
        Ok(record)
    }

    fn decode(&self, record: &BackupRecord) -> CoreResult<Value> {
        let json = match record.payload_encoding.as_str() {
            ENCODING_CIPHER => {
                if !self.cipher.available() {
                    return Err(CoreError::unsupported(ERR_ENCRYPTION_UNAVAILABLE));
                }
                self.cipher.decrypt(&record.payload_data)?
            }
            ENCODING_PLAIN => record.payload_data.clone(),
            ENCODING_SAFE_STORAGE => {
                return Err(CoreError::unsupported(
                    "This backup was encrypted by the Electron build's safeStorage and cannot be read here.",
                ))
            }
            other => {
                return Err(CoreError::invalid(format!("Unsupported vault backup encoding: {other}")))
            }
        };
        serde_json::from_str(&json)
            .map_err(|e| CoreError::invalid(format!("Corrupt vault backup payload: {e}")))
    }

    fn prune(entries: &[Entry], max_count: usize) -> TrimResult {
        let mut deleted = 0;
        for entry in entries.iter().skip(max_count) {
            match std::fs::remove_file(&entry.path) {
                Ok(()) => deleted += 1,
                Err(err) => {
                    tracing::warn!(path = %entry.path.display(), %err, "failed to delete old vault backup")
                }
            }
        }
        TrimResult {
            deleted_count: deleted,
            kept_count: entries.len().min(max_count),
        }
    }

    pub async fn create(&self, options: CreateOptions) -> CoreResult<CreateResult> {
        let _guard = MUTATION_LOCK.lock().await;
        let payload = match options.payload {
            Some(p @ Value::Object(_)) => p,
            _ => return Err(CoreError::invalid("Missing vault backup payload.")),
        };
        let raw = payload.to_string();
        if raw.len() > MAX_PAYLOAD_BYTES {
            return Err(CoreError::invalid(format!(
                "Vault backup payload exceeds maximum allowed size ({} > {MAX_PAYLOAD_BYTES}).",
                raw.len()
            )));
        }
        if !self.cipher.available() {
            return Err(CoreError::unsupported(ERR_ENCRYPTION_UNAVAILABLE));
        }

        let existing = self.list_entries()?;
        let fingerprint = fingerprint(&payload);
        if let Some(latest) = existing.first() {
            if latest.record.fingerprint == fingerprint {
                return Ok(CreateResult {
                    created: false,
                    backup: BackupSummary::from(&latest.record),
                });
            }
        }

        let mut created_at = chrono::Utc::now().timestamp_millis();
        let last = LAST_CREATED_AT.load(Ordering::SeqCst);
        if created_at <= last {
            created_at = last + 1;
        }
        LAST_CREATED_AT.store(created_at, Ordering::SeqCst);
        let id = uuid_v4();
        let record = BackupRecord {
            format_version: 1,
            id: id.clone(),
            created_at,
            reason: sanitize_reason(options.reason.as_ref()),
            sync_data_version: sanitize_sync_data_version(options.sync_data_version.as_ref()),
            source_app_version: sanitize_version(options.source_app_version.as_ref()),
            target_app_version: sanitize_version(options.target_app_version.as_ref()),
            fingerprint,
            preview: build_preview(&payload),
            payload_encoding: ENCODING_CIPHER.to_owned(),
            payload_data: self.cipher.encrypt(&raw)?,
        };

        let path = self.dir.join(format!(
            "{BACKUP_FILE_PREFIX}{created_at}-{id}{BACKUP_FILE_EXT}"
        ));
        let body = format!(
            "{}\n",
            serde_json::to_string_pretty(&record)
                .map_err(|e| CoreError::internal(e.to_string()))?
        );
        write_atomic(&path, body.as_bytes())?;
        sync_dir(&self.dir);

        let summary = BackupSummary::from(&record);
        let mut entries = vec![Entry { record, path }];
        entries.extend(existing);
        Self::prune(&entries, sanitize_max_count(options.max_count.as_ref()));
        Ok(CreateResult {
            created: true,
            backup: summary,
        })
    }

    pub fn list(&self) -> CoreResult<Vec<BackupSummary>> {
        Ok(self
            .list_entries()?
            .iter()
            .map(|e| BackupSummary::from(&e.record))
            .collect())
    }

    pub fn read(&self, id: &str) -> CoreResult<ReadResult> {
        if id.is_empty() {
            return Err(CoreError::invalid("Missing vault backup id."));
        }
        let entries = self.list_entries()?;
        let entry = entries
            .iter()
            .find(|e| e.record.id == id)
            .ok_or_else(|| CoreError::not_found("Vault backup not found."))?;
        Ok(ReadResult {
            backup: BackupSummary::from(&entry.record),
            payload: self.decode(&entry.record)?,
        })
    }

    pub async fn trim(&self, max_count: Option<&Value>) -> CoreResult<TrimResult> {
        let _guard = MUTATION_LOCK.lock().await;
        let entries = self.list_entries()?;
        Ok(Self::prune(&entries, sanitize_max_count(max_count)))
    }

    /// Remove every backup file, including unreadable ones and interrupted
    /// `*.json.tmp-*` writes; unrelated files are kept.
    pub async fn clear(&self) -> CoreResult<ClearResult> {
        let _guard = MUTATION_LOCK.lock().await;
        create_private_dir(&self.dir).map_err(|e| io_err("create backup dir", e))?;
        let mut deleted = 0;
        let mut failed = 0;
        let read_dir = std::fs::read_dir(&self.dir).map_err(|e| io_err("read backup dir", e))?;
        for item in read_dir.flatten() {
            let name = item.file_name().to_string_lossy().into_owned();
            let Ok(kind) = item.file_type() else { continue };
            if !(kind.is_file() || kind.is_symlink()) || !name.starts_with(BACKUP_FILE_PREFIX) {
                continue;
            }
            if !name.ends_with(BACKUP_FILE_EXT)
                && !name.contains(&format!("{BACKUP_FILE_EXT}.tmp-"))
            {
                continue;
            }
            match std::fs::remove_file(item.path()) {
                Ok(()) => deleted += 1,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => failed += 1,
            }
        }
        sync_dir(&self.dir);
        if failed > 0 {
            return Err(CoreError::io(format!(
                "Could not delete {failed} vault backup file(s)."
            )));
        }
        Ok(ClearResult {
            deleted_count: deleted,
        })
    }
}

/// tmp file (0600) + fsync + rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> CoreResult<()> {
    use std::io::Write;
    let tmp = PathBuf::from(format!("{}.tmp-{}", path.display(), uuid_v4()));
    let result = (|| -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    result.map_err(|err| {
        let _ = std::fs::remove_file(&tmp);
        io_err("write vault backup", err)
    })
}

fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    if crate::credentials::fill_random(&mut bytes).is_err() {
        // Uniqueness only (file names); fall back to time-derived bytes.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        bytes.copy_from_slice(&nanos.to_le_bytes());
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn store<'a>(dir: &Path, cipher: &'a CredentialCipher) -> BackupStore<'a> {
        BackupStore::new(dir.join("backups"), cipher)
    }

    fn payload(hosts: usize, synced_at: i64) -> Value {
        json!({
            "hosts": (0..hosts).map(|i| json!({ "id": i, "label": format!("h{i}") })).collect::<Vec<_>>(),
            "keys": [{}], "snippets": [], "identities": [{}, {}],
            "syncedAt": synced_at,
        })
    }

    fn options(payload: Value, max_count: Option<u64>) -> CreateOptions {
        CreateOptions {
            payload: Some(payload),
            reason: Some(json!("app_version_change")),
            source_app_version: Some(json!("1.2.0")),
            target_app_version: Some(json!("bad version!")),
            sync_data_version: Some(json!(3.7)),
            max_count: max_count.map(Value::from),
        }
    }

    #[tokio::test]
    async fn create_dedupes_lists_reads_trims_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let cipher = CredentialCipher::with_key([7; 32]);
        let store = store(dir.path(), &cipher);

        let first = store.create(options(payload(2, 1), None)).await.unwrap();
        assert!(first.created);
        assert_eq!(first.backup.preview.host_count, 2);
        assert_eq!(first.backup.preview.identity_count, 2);
        assert_eq!(first.backup.reason, "app_version_change");
        assert_eq!(first.backup.source_app_version.as_deref(), Some("1.2.0"));
        assert_eq!(first.backup.target_app_version, None);
        assert_eq!(first.backup.sync_data_version, Some(3));

        // Same content, different top-level syncedAt → deduped.
        let again = store.create(options(payload(2, 999), None)).await.unwrap();
        assert!(!again.created);
        assert_eq!(again.backup.id, first.backup.id);

        let second = store.create(options(payload(3, 1), None)).await.unwrap();
        assert!(second.created && second.backup.created_at > first.backup.created_at);
        let listed = store.list().unwrap();
        assert_eq!(
            listed.iter().map(|b| b.id.clone()).collect::<Vec<_>>(),
            vec![second.backup.id.clone(), first.backup.id.clone()]
        );

        // Payload is stored encrypted and reads back intact.
        let file = std::fs::read_dir(store.dir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let raw = std::fs::read_to_string(file).unwrap();
        assert!(raw.contains("\"payloadEncoding\": \"cipher-v2\"") && !raw.contains("h0"));
        let read = store.read(&first.backup.id).unwrap();
        assert_eq!(read.payload, payload(2, 1));
        assert_eq!(
            store.read("nope").unwrap_err().message,
            "Vault backup not found."
        );

        assert_eq!(
            store.trim(Some(&json!(1))).await.unwrap(),
            TrimResult {
                deleted_count: 1,
                kept_count: 1
            }
        );
        assert_eq!(store.list().unwrap()[0].id, second.backup.id);

        std::fs::write(store.dir().join("vault-backup-x.json.tmp-1"), "partial").unwrap();
        std::fs::write(store.dir().join("unrelated.txt"), "keep").unwrap();
        assert_eq!(
            store.clear().await.unwrap(),
            ClearResult { deleted_count: 2 }
        );
        assert!(store.list().unwrap().is_empty());
        assert!(store.dir().join("unrelated.txt").exists());
    }

    #[tokio::test]
    async fn create_prunes_to_max_count_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let cipher = CredentialCipher::with_key([1; 32]);
        let store = store(dir.path(), &cipher);
        for i in 0..4 {
            store.create(options(payload(i, 0), Some(2))).await.unwrap();
        }
        assert_eq!(store.list().unwrap().len(), 2);
        let err = store.create(CreateOptions::default()).await.unwrap_err();
        assert_eq!(err.message, "Missing vault backup payload.");

        let plain = CredentialCipher::unavailable();
        let locked = BackupStore::new(dir.path().join("other"), &plain);
        let err = locked
            .create(options(payload(1, 0), None))
            .await
            .unwrap_err();
        assert_eq!(err.message, ERR_ENCRYPTION_UNAVAILABLE);
    }

    #[test]
    fn helpers_match_electron() {
        assert_eq!(sanitize_max_count(None), 20);
        assert_eq!(sanitize_max_count(Some(&json!(0))), 20);
        assert_eq!(sanitize_max_count(Some(&json!(500))), 100);
        assert_eq!(sanitize_max_count(Some(&json!(3.9))), 3);
        assert_eq!(sanitize_reason(Some(&json!("weird"))), "before_restore");
        assert_eq!(
            sanitize_version(Some(&json!(" 1.2.0-beta+1 "))).as_deref(),
            Some("1.2.0-beta+1")
        );
        assert_eq!(sanitize_sync_data_version(Some(&json!(0))), None);
        // Key order and top-level syncedAt do not change the fingerprint;
        // nested syncedAt does.
        assert_eq!(
            fingerprint(&json!({"a": 1, "b": 2, "syncedAt": 5})),
            fingerprint(&json!({"b": 2, "a": 1, "syncedAt": 9}))
        );
        assert_ne!(
            fingerprint(&json!({"x": {"syncedAt": 1}})),
            fingerprint(&json!({"x": {"syncedAt": 2}}))
        );
        assert_eq!(uuid_v4().len(), 36);
    }
}
