//! Vault backups (mirrors `vaultBackupBridge.cjs`).
//!
//! Files are named `vault-<YYYYMMDD-HHMMSS>-<ms>[-<reason>].json` (UTC) so
//! the directory sorts chronologically in any file browser and `createdAt`
//! can be recovered from the name alone when the file was copied around.

use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use netcatty_core::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const FILE_PREFIX: &str = "vault-";
const FILE_EXT: &str = ".json";
const MAX_REASON_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInfo {
    pub file_name: String,
    pub path: String,
    pub created_at: i64,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub struct BackupStore {
    pub dir: PathBuf,
    /// Maximum backups kept by [`BackupStore::trim`] (default 20).
    pub keep: usize,
}

impl BackupStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, keep: 20 }
    }

    /// Write `payload` (already serialized vault JSON) as
    /// `vault-<timestamp>[-<reason>].json` and trim old backups.
    pub async fn create(&self, payload: &str, reason: Option<&str>) -> CoreResult<BackupInfo> {
        tokio::fs::create_dir_all(&self.dir)
            .await
            .map_err(|err| io_error("create", &self.dir, err))?;

        let reason = reason.and_then(sanitize_reason);
        let mut created_at = Utc::now().timestamp_millis();
        let (file_name, path) = loop {
            let file_name = build_file_name(created_at, reason.as_deref());
            let path = self.dir.join(&file_name);
            match tokio::fs::try_exists(&path).await {
                Ok(true) => created_at += 1,
                _ => break (file_name, path),
            }
        };

        let tmp_path = self
            .dir
            .join(format!("{file_name}.tmp-{}", std::process::id()));
        if let Err(err) = write_durably(&tmp_path, payload.as_bytes()).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(io_error("write", &tmp_path, err));
        }
        if let Err(err) = tokio::fs::rename(&tmp_path, &path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(io_error("rename", &path, err));
        }
        sync_dir(&self.dir).await;

        let info = BackupInfo {
            file_name,
            path: path.to_string_lossy().into_owned(),
            created_at,
            size: payload.len() as u64,
            reason,
        };

        if let Err(err) = self.trim().await {
            tracing::warn!(error = %err, "failed to trim vault backups after create");
        }
        Ok(info)
    }

    /// All backups, newest first.
    pub async fn list(&self) -> CoreResult<Vec<BackupInfo>> {
        let mut dir = match tokio::fs::read_dir(&self.dir).await {
            Ok(dir) => dir,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(io_error("list", &self.dir, err)),
        };
        let mut backups = Vec::new();
        while let Some(entry) = dir
            .next_entry()
            .await
            .map_err(|err| io_error("list", &self.dir, err))?
        {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(parsed) = parse_file_name(name) else {
                continue;
            };
            let Ok(meta) = entry.metadata().await else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let created_at = parsed
                .created_at
                .or_else(|| meta.modified().ok().map(system_time_ms))
                .unwrap_or(0);
            backups.push(BackupInfo {
                file_name: name.to_string(),
                path: entry.path().to_string_lossy().into_owned(),
                created_at,
                size: meta.len(),
                reason: parsed.reason,
            });
        }
        backups.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.file_name.cmp(&a.file_name))
        });
        Ok(backups)
    }

    /// Read one backup by file name. Names must be plain backup file names
    /// (no path separators, no `..`).
    pub async fn read(&self, file_name: &str) -> CoreResult<String> {
        validate_file_name(file_name)?;
        let path = self.dir.join(file_name);
        tokio::fs::read_to_string(&path)
            .await
            .map_err(|err| io_error("read", &path, err))
    }

    /// Delete everything beyond the `keep` newest backups. Returns the number
    /// of deleted files.
    pub async fn trim(&self) -> CoreResult<usize> {
        let backups = self.list().await?;
        let mut deleted = 0;
        for backup in backups.iter().skip(self.keep) {
            match tokio::fs::remove_file(&backup.path).await {
                Ok(()) => deleted += 1,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    tracing::warn!(path = %backup.path, error = %err, "failed to delete old vault backup")
                }
            }
        }
        if deleted > 0 {
            sync_dir(&self.dir).await;
        }
        Ok(deleted)
    }

    /// Delete every backup (and interrupted temp files). Returns the number
    /// of deleted files.
    pub async fn clear(&self) -> CoreResult<usize> {
        let mut dir = match tokio::fs::read_dir(&self.dir).await {
            Ok(dir) => dir,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(err) => return Err(io_error("list", &self.dir, err)),
        };
        let mut deleted = 0;
        let mut failed = 0;
        while let Some(entry) = dir
            .next_entry()
            .await
            .map_err(|err| io_error("list", &self.dir, err))?
        {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let is_backup = name.starts_with(FILE_PREFIX)
                && (name.ends_with(FILE_EXT) || name.contains(&format!("{FILE_EXT}.tmp-")));
            if !is_backup {
                continue;
            }
            let is_file = entry
                .file_type()
                .await
                .map(|t| t.is_file() || t.is_symlink())
                .unwrap_or(false);
            if !is_file {
                continue;
            }
            match tokio::fs::remove_file(entry.path()).await {
                Ok(()) => deleted += 1,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    failed += 1;
                    tracing::warn!(path = %entry.path().display(), error = %err, "failed to delete vault backup");
                }
            }
        }
        sync_dir(&self.dir).await;
        if failed > 0 {
            return Err(CoreError::io(format!(
                "Could not delete {failed} vault backup file(s)."
            )));
        }
        Ok(deleted)
    }
}

struct ParsedName {
    created_at: Option<i64>,
    reason: Option<String>,
}

fn build_file_name(created_at_ms: i64, reason: Option<&str>) -> String {
    let stamp = Utc
        .timestamp_millis_opt(created_at_ms)
        .single()
        .map(|dt| dt.format("%Y%m%d-%H%M%S").to_string())
        .unwrap_or_else(|| "00000000-000000".to_string());
    let ms = created_at_ms.rem_euclid(1000);
    match reason {
        Some(reason) => format!("{FILE_PREFIX}{stamp}-{ms:03}-{reason}{FILE_EXT}"),
        None => format!("{FILE_PREFIX}{stamp}-{ms:03}{FILE_EXT}"),
    }
}

/// Parse `vault-YYYYMMDD-HHMMSS-mmm[-reason].json`. Returns `None` for
/// files that are not backups at all; a backup with an unparsable
/// timestamp still yields `Some` with `created_at: None`.
fn parse_file_name(name: &str) -> Option<ParsedName> {
    let stem = name.strip_prefix(FILE_PREFIX)?.strip_suffix(FILE_EXT)?;
    if stem.is_empty() {
        return None;
    }
    let mut parts = stem.splitn(4, '-');
    let date = parts.next().unwrap_or("");
    let time = parts.next().unwrap_or("");
    let ms = parts.next().unwrap_or("");
    let reason = parts.next().filter(|r| !r.is_empty()).map(str::to_string);

    let created_at = (|| {
        let date = NaiveDate::parse_from_str(date, "%Y%m%d").ok()?;
        let time = NaiveTime::parse_from_str(time, "%H%M%S").ok()?;
        let ms: u32 = ms.parse().ok().filter(|v| *v < 1000)?;
        let naive = NaiveDateTime::new(date, time);
        let dt: DateTime<Utc> = Utc.from_utc_datetime(&naive);
        Some(dt.timestamp_millis() + i64::from(ms))
    })();

    Some(ParsedName { created_at, reason })
}

fn sanitize_reason(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut last_dash = true;
    for ch in raw.chars().flat_map(char::to_lowercase) {
        let mapped = if ch.is_ascii_alphanumeric() { ch } else { '-' };
        if mapped == '-' {
            if last_dash {
                continue;
            }
            last_dash = true;
        } else {
            last_dash = false;
        }
        out.push(mapped);
        if out.len() >= MAX_REASON_LEN {
            break;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn validate_file_name(name: &str) -> CoreResult<()> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.contains('\0')
        || !name.starts_with(FILE_PREFIX)
        || !name.ends_with(FILE_EXT)
    {
        return Err(CoreError::invalid("invalid vault backup file name"));
    }
    Ok(())
}

fn system_time_ms(time: std::time::SystemTime) -> i64 {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

async fn write_durably(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await?;
    file.write_all(bytes).await?;
    file.flush().await?;
    file.sync_all().await?;
    Ok(())
}

/// Best-effort directory fsync so a rename is durable (no-op on Windows).
async fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    {
        if let Ok(handle) = tokio::fs::File::open(dir).await {
            if let Err(err) = handle.sync_all().await {
                tracing::debug!(path = %dir.display(), error = %err, "directory fsync failed");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

fn io_error(action: &str, path: &Path, err: std::io::Error) -> CoreError {
    let mut core = CoreError::from(err);
    core.message = format!("failed to {action} {}: {}", path.display(), core.message);
    core
}

#[cfg(test)]
mod tests {
    use super::*;
    use netcatty_core::ErrorCode;

    #[test]
    fn file_name_round_trips() {
        let ts = 1_762_180_501_123; // 2025-11-03T14:35:01.123Z
        let name = build_file_name(ts, Some("before-restore"));
        assert_eq!(name, "vault-20251103-143501-123-before-restore.json");
        let parsed = parse_file_name(&name).unwrap();
        assert_eq!(parsed.created_at, Some(ts));
        assert_eq!(parsed.reason.as_deref(), Some("before-restore"));

        let plain = build_file_name(ts, None);
        assert_eq!(plain, "vault-20251103-143501-123.json");
        let parsed = parse_file_name(&plain).unwrap();
        assert_eq!(parsed.created_at, Some(ts));
        assert_eq!(parsed.reason, None);

        assert!(parse_file_name("other.json").is_none());
        assert!(parse_file_name("vault-.json").is_none());
        let odd = parse_file_name("vault-garbage.json").unwrap();
        assert_eq!(odd.created_at, None);
    }

    #[test]
    fn reason_is_sanitized() {
        assert_eq!(
            sanitize_reason("App Version Change").as_deref(),
            Some("app-version-change")
        );
        assert_eq!(
            sanitize_reason("before_restore").as_deref(),
            Some("before-restore")
        );
        assert_eq!(
            sanitize_reason("../../etc/passwd").as_deref(),
            Some("etc-passwd")
        );
        assert_eq!(sanitize_reason("!!!"), None);
        assert!(sanitize_reason(&"x".repeat(100)).unwrap().len() <= MAX_REASON_LEN);
    }

    #[tokio::test]
    async fn create_list_read_trim_clear() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = BackupStore::new(dir.path().join("backups"));
        store.keep = 3;

        assert!(store.list().await.unwrap().is_empty());

        let mut created = Vec::new();
        for i in 0..5 {
            let payload = format!("{{\"i\":{i}}}");
            let reason = if i % 2 == 0 {
                Some("app_version_change")
            } else {
                None
            };
            let info = store.create(&payload, reason).await.unwrap();
            assert!(info.file_name.starts_with("vault-"));
            assert!(info.file_name.ends_with(".json"));
            assert_eq!(info.size, payload.len() as u64);
            if i % 2 == 0 {
                assert_eq!(info.reason.as_deref(), Some("app-version-change"));
                assert!(info.file_name.contains("-app-version-change.json"));
            } else {
                assert_eq!(info.reason, None);
            }
            created.push(info);
        }

        // Trimmed to `keep` after each create; newest first.
        let listed = store.list().await.unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].file_name, created[4].file_name);
        assert_eq!(listed[1].file_name, created[3].file_name);
        assert_eq!(listed[2].file_name, created[2].file_name);
        assert!(listed
            .windows(2)
            .all(|w| w[0].created_at >= w[1].created_at));

        let content = store.read(&created[4].file_name).await.unwrap();
        assert_eq!(content, "{\"i\":4}");
        assert_eq!(
            store.read(&created[0].file_name).await.unwrap_err().code,
            ErrorCode::NotFound
        );

        // No temp files were left behind.
        let leftovers: Vec<String> = std::fs::read_dir(&store.dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");

        store.keep = 1;
        assert_eq!(store.trim().await.unwrap(), 2);
        assert_eq!(store.list().await.unwrap().len(), 1);
        assert_eq!(store.trim().await.unwrap(), 0);

        std::fs::write(store.dir.join("unrelated.txt"), "keep me").unwrap();
        std::fs::write(store.dir.join("vault-x.json.tmp-123"), "partial").unwrap();
        assert_eq!(store.clear().await.unwrap(), 2);
        assert!(store.list().await.unwrap().is_empty());
        assert!(store.dir.join("unrelated.txt").exists());
        assert_eq!(store.clear().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn read_rejects_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().to_path_buf());
        std::fs::write(dir.path().join("secret.txt"), "nope").unwrap();
        for name in [
            "../secret.txt",
            "..\\secret.txt",
            "/etc/passwd",
            "sub/vault-20250101-000000-000.json",
            "vault-..json",
            "secret.txt",
            "",
        ] {
            let err = store.read(name).await.unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{name}");
        }
    }

    #[tokio::test]
    async fn list_on_missing_dir_is_empty_and_clear_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().join("nope"));
        assert!(store.list().await.unwrap().is_empty());
        assert_eq!(store.trim().await.unwrap(), 0);
        assert_eq!(store.clear().await.unwrap(), 0);
    }
}
