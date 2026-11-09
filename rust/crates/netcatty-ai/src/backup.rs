//! Durable disk mirror of the renderer's AI chat session store (Electron:
//! `electron/bridges/aiSessionsBackupBridge.cjs`).
//!
//! Timestamped JSON generations live under `<data dir>/ai-sessions-backup/`
//! so the newest store can be restored on boot when the live store is
//! missing or empty. Generations are capped at [`MAX_GENERATIONS`]; each
//! write is atomic (temp file + rename). Nothing here panics or returns a
//! hard error to the renderer: a backup failure must not break chat
//! persistence.

use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const BACKUP_DIR_NAME: &str = "ai-sessions-backup";
pub const FILE_PREFIX: &str = "ai-sessions-";
pub const EXPORT_PREFIX: &str = "export-";
pub const FILE_SUFFIX: &str = ".json";
pub const MAX_GENERATIONS: usize = 5;
/// Hard cap for a mirrored payload (synced histories can exceed 4 MB).
pub const MAX_BACKUP_JSON_BYTES: usize = 64 * 1024 * 1024;

/// `writeGeneration` / `readLatestGeneration` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct GenerationResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl GenerationResult {
    fn failure(error: impl Into<String>) -> Self {
        Self { ok: false, error: Some(error.into()), ..Self::default() }
    }
}

/// Export / import result (`{ success, filePath?, json?, canceled?, error? }`).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canceled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl FileResult {
    pub fn failure(error: impl Into<String>) -> Self {
        Self { success: false, error: Some(error.into()), ..Self::default() }
    }

    pub fn canceled() -> Self {
        Self { success: false, canceled: Some(true), ..Self::default() }
    }
}

/// `toISOString()` with `-` / `:` removed and the first `.` replaced:
/// `20260101T000000-000Z`. Sorts lexicographically by time.
pub fn timestamp_token(now: chrono::DateTime<chrono::Utc>) -> String {
    now.format("%Y%m%dT%H%M%S-%3fZ").to_string()
}

/// The backup directory, created on first use.
#[derive(Debug, Clone)]
pub struct AiSessionsBackup {
    dir: PathBuf,
}

fn list_with_prefix(dir: &Path, prefix: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut files: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|f| f.starts_with(prefix) && f.ends_with(FILE_SUFFIX))
        .collect();
    // Timestamped names sort lexicographically; newest first.
    files.sort();
    files.reverse();
    files
}

/// A structurally usable session (renderer `AISession` essentials).
fn is_usable_session(entry: &Value) -> bool {
    let Some(obj) = entry.as_object() else { return false };
    let is_str = |v: Option<&Value>| v.is_some_and(Value::is_string);
    let is_finite_number = |v: Option<&Value>| v.and_then(Value::as_f64).is_some_and(f64::is_finite);
    is_str(obj.get("id"))
        && is_str(obj.get("title"))
        && is_str(obj.get("agentId"))
        && obj.get("scope").and_then(Value::as_object).is_some_and(|s| is_str(s.get("type")))
        && obj.get("messages").and_then(Value::as_array).is_some_and(|messages| {
            messages.iter().all(|m| {
                m.as_object().is_some_and(|m| {
                    is_str(m.get("id"))
                        && is_str(m.get("role"))
                        && is_str(m.get("content"))
                        && is_finite_number(m.get("timestamp"))
                })
            })
        })
        && is_finite_number(obj.get("updatedAt"))
}

impl AiSessionsBackup {
    /// `<data dir>/ai-sessions-backup`.
    pub fn new(data_dir: &Path) -> Self {
        Self { dir: data_dir.join(BACKUP_DIR_NAME) }
    }

    /// Use `dir` itself as the backup directory (tests).
    pub fn at(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure_dir(&self) -> Option<&Path> {
        std::fs::create_dir_all(&self.dir).ok().map(|_| self.dir.as_path())
    }

    pub fn generation_files(&self) -> Vec<String> {
        list_with_prefix(&self.dir, FILE_PREFIX)
    }

    pub fn export_files(&self) -> Vec<String> {
        list_with_prefix(&self.dir, EXPORT_PREFIX)
    }

    /// Write one generation atomically and prune older ones.
    pub fn write_generation(&self, json: Option<&str>) -> GenerationResult {
        let Some(dir) = self.ensure_dir() else { return GenerationResult::failure("no-backup-dir") };
        let Some(json) = json.filter(|j| !j.is_empty()) else { return GenerationResult::failure("invalid-json") };
        if json.len() > MAX_BACKUP_JSON_BYTES {
            return GenerationResult::failure("payload-too-large");
        }
        let mut file = format!("{FILE_PREFIX}{}{FILE_SUFFIX}", timestamp_token(chrono::Utc::now()));
        // Two writes in the same millisecond must not overwrite each other's
        // generation silently: bump to the next free name instead.
        let mut bump = 0;
        while dir.join(&file).exists() && bump < 1000 {
            bump += 1;
            file = format!(
                "{FILE_PREFIX}{}{bump:03}{FILE_SUFFIX}",
                timestamp_token(chrono::Utc::now()).trim_end_matches('Z')
            );
        }
        let path = dir.join(&file);
        let tmp = dir.join(format!("{file}.tmp"));
        if let Err(err) = std::fs::write(&tmp, json).and_then(|_| std::fs::rename(&tmp, &path)) {
            let _ = std::fs::remove_file(&tmp);
            return GenerationResult::failure(err.to_string());
        }
        for stale in self.generation_files().into_iter().skip(MAX_GENERATIONS) {
            let _ = std::fs::remove_file(dir.join(stale));
        }
        GenerationResult { ok: true, file: Some(file), ..GenerationResult::default() }
    }

    /// Newest usable session array; invalid generations fall back to older
    /// ones. An empty array is an intentional wipe and wins.
    pub fn read_latest_generation(&self) -> GenerationResult {
        let Some(dir) = self.ensure_dir() else { return GenerationResult::default() };
        for file in self.generation_files() {
            let Ok(json) = std::fs::read_to_string(dir.join(&file)) else { continue };
            let Ok(parsed) = serde_json::from_str::<Value>(&json) else { continue };
            let Some(entries) = parsed.as_array() else { continue };
            if !entries.is_empty() && !entries.iter().any(is_usable_session) {
                continue;
            }
            return GenerationResult { ok: true, json: Some(json), file: Some(file), ..GenerationResult::default() };
        }
        GenerationResult::default()
    }

    /// Default file name for the export save dialog.
    pub fn export_file_name() -> String {
        format!("{EXPORT_PREFIX}{}{FILE_SUFFIX}", timestamp_token(chrono::Utc::now()))
    }

    /// Write an export to a user-chosen path.
    pub fn write_export(path: &Path, json: &str) -> FileResult {
        match std::fs::write(path, json) {
            Ok(()) => FileResult { success: true, file_path: Some(path.to_string_lossy().into_owned()), ..FileResult::default() },
            Err(err) => FileResult::failure(err.to_string()),
        }
    }

    /// Fallback when no dialog is available: a fixed path next to the generations.
    pub fn write_export_fixed(&self, json: &str) -> FileResult {
        let Some(dir) = self.ensure_dir() else { return FileResult::failure("no-backup-dir") };
        Self::write_export(&dir.join(Self::export_file_name()), json)
    }

    /// Read an import file chosen by the user.
    pub fn read_import(path: &Path) -> FileResult {
        match std::fs::read(path) {
            Ok(bytes) => FileResult { success: true, json: Some(String::from_utf8_lossy(&bytes).into_owned()), ..FileResult::default() },
            Err(err) => FileResult::failure(err.to_string()),
        }
    }

    /// Fallback import without a dialog: the newest fixed-path export.
    pub fn read_latest_export(&self) -> FileResult {
        let Some(dir) = self.ensure_dir() else { return FileResult::failure("no-backup-dir") };
        match self.export_files().first() {
            Some(file) => Self::read_import(&dir.join(file)),
            None => FileResult::failure("no-export-file"),
        }
    }
}

/// `typeof json === "string" && json.length > 0`.
pub fn valid_json_payload(json: Option<&str>) -> Option<&str> {
    json.filter(|j| !j.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn session() -> Value {
        json!({ "id": "s1", "title": "Session", "agentId": "agent", "scope": { "type": "global" }, "messages": [], "updatedAt": 1 })
    }

    fn backup() -> (tempfile::TempDir, AiSessionsBackup) {
        let dir = tempfile::tempdir().unwrap();
        let backup = AiSessionsBackup::at(dir.path().to_path_buf());
        (dir, backup)
    }

    #[test]
    fn timestamp_token_matches_electron() {
        let t = chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05.678Z").unwrap().with_timezone(&chrono::Utc);
        assert_eq!(timestamp_token(t), "20260102T030405-678Z");
    }

    #[test]
    fn writes_atomically_and_rotates_generations() {
        let (_dir, backup) = backup();
        for i in 0..MAX_GENERATIONS + 2 {
            assert!(backup.write_generation(Some(&json!({ "gen": i }).to_string())).ok);
            std::thread::sleep(std::time::Duration::from_millis(3));
        }
        let generations = backup.generation_files();
        assert_eq!(generations.len(), MAX_GENERATIONS);
        let newest: Value = serde_json::from_str(&std::fs::read_to_string(backup.dir().join(&generations[0])).unwrap()).unwrap();
        assert_eq!(newest, json!({ "gen": MAX_GENERATIONS + 1 }));
        let tmp_left = std::fs::read_dir(backup.dir()).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!tmp_left);
    }

    #[test]
    fn same_millisecond_writes_do_not_collide() {
        let (_dir, backup) = backup();
        let a = backup.write_generation(Some("[1]"));
        let b = backup.write_generation(Some("[2]"));
        assert!(a.ok && b.ok);
        assert_ne!(a.file, b.file);
    }

    #[test]
    fn read_latest_skips_corrupt_and_unusable_generations() {
        let (_dir, backup) = backup();
        let dir = backup.dir();
        std::fs::write(dir.join("ai-sessions-20260101T000000-000Z.json"), session().to_string().replace("s1", "old")).unwrap();
        std::fs::write(dir.join("ai-sessions-20260101T000000-000Z.json"), json!([session()]).to_string()).unwrap();
        std::fs::write(dir.join("ai-sessions-20260102T000000-000Z.json"), "not json").unwrap();
        std::fs::write(dir.join("ai-sessions-20260103T000000-000Z.json"), json!({ "not": "array" }).to_string()).unwrap();
        std::fs::write(dir.join("ai-sessions-20260104T000000-000Z.json"), json!([{ "id": 1 }]).to_string()).unwrap();
        let bad_message = json!([{ "id": "s", "title": "t", "agentId": "a", "scope": { "type": "g" }, "messages": [{ "id": "m" }], "updatedAt": 1 }]);
        std::fs::write(dir.join("ai-sessions-20260105T000000-000Z.json"), bad_message.to_string()).unwrap();
        let latest = backup.read_latest_generation();
        assert!(latest.ok);
        assert_eq!(serde_json::from_str::<Value>(&latest.json.unwrap()).unwrap(), json!([session()]));
        assert_eq!(latest.file.as_deref(), Some("ai-sessions-20260101T000000-000Z.json"));
    }

    #[test]
    fn corrupt_only_directory_reports_failure() {
        let (_dir, backup) = backup();
        std::fs::write(backup.dir().join("ai-sessions-20260103T000000-000Z.json"), "{oops").unwrap();
        assert!(!backup.read_latest_generation().ok);
    }

    #[test]
    fn empty_generation_is_an_authoritative_wipe() {
        let (_dir, backup) = backup();
        std::fs::write(backup.dir().join("ai-sessions-20260101T000000-000Z.json"), json!([session()]).to_string()).unwrap();
        std::fs::write(backup.dir().join("ai-sessions-20260102T000000-000Z.json"), "[]").unwrap();
        let latest = backup.read_latest_generation();
        assert!(latest.ok);
        assert_eq!(latest.json.as_deref(), Some("[]"));
    }

    #[test]
    fn rejects_invalid_or_oversized_payloads() {
        let (_dir, backup) = backup();
        assert_eq!(backup.write_generation(Some("")).error.as_deref(), Some("invalid-json"));
        assert_eq!(backup.write_generation(None).error.as_deref(), Some("invalid-json"));
        let oversized = "x".repeat(MAX_BACKUP_JSON_BYTES + 1);
        assert_eq!(backup.write_generation(Some(&oversized)).error.as_deref(), Some("payload-too-large"));
        assert!(backup.generation_files().is_empty());
    }

    #[test]
    fn fixed_export_and_import_fallbacks() {
        let (_dir, backup) = backup();
        assert_eq!(backup.read_latest_export().error.as_deref(), Some("no-export-file"));
        let result = backup.write_export_fixed("[{\"id\":\"s1\"}]");
        assert!(result.success);
        let path = PathBuf::from(result.file_path.unwrap());
        assert!(path.file_name().unwrap().to_string_lossy().starts_with("export-"));
        assert!(path.exists());
        let imported = backup.read_latest_export();
        assert!(imported.success);
        assert_eq!(imported.json.as_deref(), Some("[{\"id\":\"s1\"}]"));
        assert!(!AiSessionsBackup::read_import(&backup.dir().join("missing.json")).success);
    }

    #[test]
    fn result_shapes_serialize_like_electron() {
        assert_eq!(serde_json::to_value(GenerationResult::default()).unwrap(), json!({ "ok": false }));
        assert_eq!(serde_json::to_value(FileResult::canceled()).unwrap(), json!({ "success": false, "canceled": true }));
    }
}
