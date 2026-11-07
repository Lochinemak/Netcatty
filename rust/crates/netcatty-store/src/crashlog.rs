//! Crash / diagnostic log (Electron: `crashLogBridge.cjs`).
//!
//! JSONL files `<data>/crash-logs/crash-YYYY-MM-DD.log` (local date), one
//! entry per line. Files older than 30 days are pruned at startup, every
//! file is capped at 16 MB (later entries are dropped) and oversized files
//! left by earlier runs are trimmed to their tail. Writes are synchronous so
//! the panic hook can use them.

use serde::Serialize;
use serde_json::{json, Map, Value};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const LOG_RETENTION_DAYS: i64 = 30;
pub const MAX_LOG_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_LOG_ENTRY_BYTES: usize = 128 * 1024;
const MAX_MESSAGE_CHARS: usize = 4096;
const MAX_STACK_CHARS: usize = 16384;
const MAX_READ_ENTRIES: usize = 500;
const MAX_TAIL_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrashLogFile {
    pub file_name: String,
    pub date: String,
    pub size: u64,
    pub entry_count: usize,
}

/// Context stamped on every entry (Electron adds pid / platform / version).
#[derive(Debug, Clone, Default)]
pub struct EntryContext {
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct CrashLog {
    dir: PathBuf,
    context: EntryContext,
}

fn bounded(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_owned();
    }
    let cut: String = text.chars().take(max_chars).collect();
    format!("{cut} ... [truncated]")
}

fn is_log_name(name: &str) -> bool {
    name.starts_with("crash-") && name.ends_with(".log")
}

/// `crash-YYYY-MM-DD.log` only (path traversal guard, Electron's regex).
fn is_valid_read_name(name: &str) -> bool {
    let Some(date) = name
        .strip_prefix("crash-")
        .and_then(|rest| rest.strip_suffix(".log"))
    else {
        return false;
    };
    let bytes = date.as_bytes();
    bytes.len() == 10
        && bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            _ => b.is_ascii_digit(),
        })
}

impl CrashLog {
    pub fn new(dir: PathBuf, context: EntryContext) -> Self {
        Self { dir, context }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure_dir(&self) -> Option<&Path> {
        fs::create_dir_all(&self.dir).ok()?;
        Some(&self.dir)
    }

    fn today_file(&self) -> PathBuf {
        let today = chrono::Local::now().format("%Y-%m-%d");
        self.dir.join(format!("crash-{today}.log"))
    }

    /// Startup housekeeping: prune old files and trim oversized ones.
    pub fn init(&self) {
        if self.ensure_dir().is_none() {
            return;
        }
        self.prune_old_logs();
        self.trim_oversized_logs();
    }

    fn build_entry(
        &self,
        source: &str,
        message: &str,
        stack: Option<&str>,
        extra: Option<Value>,
    ) -> Value {
        let mut entry = Map::new();
        entry.insert(
            "timestamp".into(),
            json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        );
        entry.insert("source".into(), json!(source));
        entry.insert("message".into(), json!(bounded(message, MAX_MESSAGE_CHARS)));
        if let Some(stack) = stack.filter(|s| !s.is_empty()) {
            entry.insert("stack".into(), json!(bounded(stack, MAX_STACK_CHARS)));
        }
        if let Some(extra) = extra.filter(|v| !v.is_null()) {
            entry.insert("extra".into(), extra);
        }
        entry.insert("pid".into(), json!(std::process::id()));
        entry.insert("platform".into(), json!(node_platform()));
        entry.insert("arch".into(), json!(node_arch()));
        entry.insert("version".into(), json!(self.context.version));
        Value::Object(entry)
    }

    /// Serialize with progressively less detail until the line fits the
    /// per-entry byte budget (Electron's `serializeEntry`).
    fn serialize(entry: &Value) -> String {
        let line = entry.to_string();
        if line.len() < MAX_LOG_ENTRY_BYTES {
            return line;
        }
        let mut lean = entry.clone();
        if let Some(obj) = lean.as_object_mut() {
            obj.remove("extra");
            if let Some(message) = obj.get("message").and_then(Value::as_str) {
                let message = bounded(message, 1024);
                obj.insert("message".into(), json!(message));
            }
        }
        let line = lean.to_string();
        if line.len() < MAX_LOG_ENTRY_BYTES {
            return line;
        }
        let field = |key: &str| entry.get(key).cloned().unwrap_or(Value::Null);
        let text = |key: &str, max: usize| {
            bounded(entry.get(key).and_then(Value::as_str).unwrap_or(""), max)
        };
        json!({
            "timestamp": field("timestamp"),
            "source": text("source", 256),
            "message": text("message", 512),
            "pid": field("pid"),
            "version": field("version"),
        })
        .to_string()
    }

    /// Append `line` to `path` unless the entry or the file would exceed
    /// the caps. Returns whether it was written.
    fn append_line(path: &Path, line: &str) -> bool {
        let bytes = line.len() + 1;
        if bytes > MAX_LOG_ENTRY_BYTES {
            return false;
        }
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if size + bytes as u64 > MAX_LOG_FILE_BYTES {
            return false;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| f.write_all(format!("{line}\n").as_bytes()))
            .is_ok()
    }

    /// Record an error. Never fails or panics (used from the panic hook).
    pub fn capture(&self, source: &str, message: &str, stack: Option<&str>, extra: Option<Value>) {
        if self.ensure_dir().is_none() {
            return;
        }
        let entry = self.build_entry(source, message, stack, extra);
        Self::append_line(&self.today_file(), &Self::serialize(&entry));
    }

    fn log_files(&self) -> Vec<PathBuf> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(is_log_name)
            })
            .collect()
    }

    fn prune_old_logs(&self) {
        let cutoff = chrono::Local::now().date_naive() - chrono::Duration::days(LOG_RETENTION_DAYS);
        for path in self.log_files() {
            let Some(date) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix("crash-"))
                .and_then(|n| n.strip_suffix(".log"))
                .and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
            else {
                continue;
            };
            if date < cutoff {
                let _ = fs::remove_file(path);
            }
        }
    }

    fn trim_oversized_logs(&self) {
        for path in self.log_files() {
            let Ok(meta) = fs::metadata(&path) else {
                continue;
            };
            if meta.len() > MAX_LOG_FILE_BYTES {
                let _ = truncate_to_tail(&path, MAX_LOG_FILE_BYTES);
            }
        }
    }

    /// Newest first.
    pub fn list(&self) -> Vec<CrashLogFile> {
        if self.ensure_dir().is_none() {
            return Vec::new();
        }
        let mut files: Vec<CrashLogFile> = self
            .log_files()
            .into_iter()
            .filter_map(|path| {
                let name = path.file_name()?.to_str()?.to_owned();
                let size = fs::metadata(&path).ok()?.len();
                let entry_count = fs::read(&path)
                    .map(|b| b.split(|c| *c == b'\n').filter(|l| !l.is_empty()).count())
                    .unwrap_or(0);
                let date = name
                    .trim_start_matches("crash-")
                    .trim_end_matches(".log")
                    .to_owned();
                Some(CrashLogFile {
                    file_name: name,
                    date,
                    size,
                    entry_count,
                })
            })
            .collect();
        files.sort_by(|a, b| b.date.cmp(&a.date));
        files
    }

    /// Last 500 parsed entries from the last 256 KB of the file.
    pub fn read(&self, file_name: &str) -> Vec<Value> {
        if !is_valid_read_name(file_name) {
            return Vec::new();
        }
        let path = self.dir.join(file_name);
        let Ok(mut file) = fs::File::open(&path) else {
            return Vec::new();
        };
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut buf = Vec::new();
        let partial = size > MAX_TAIL_BYTES;
        if partial && file.seek(SeekFrom::Start(size - MAX_TAIL_BYTES)).is_err() {
            return Vec::new();
        }
        if file.read_to_end(&mut buf).is_err() {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&buf);
        let text = if partial {
            text.split_once('\n').map(|(_, rest)| rest).unwrap_or(&text)
        } else {
            &text
        };
        let lines: Vec<&str> = text.split('\n').filter(|l| !l.is_empty()).collect();
        let start = lines.len().saturating_sub(MAX_READ_ENTRIES);
        lines[start..]
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    pub fn clear(&self) -> usize {
        self.log_files()
            .into_iter()
            .filter(|p| fs::remove_file(p).is_ok())
            .count()
    }
}

/// Keep the last `keep` bytes, starting at a line boundary.
fn truncate_to_tail(path: &Path, keep: u64) -> std::io::Result<()> {
    let mut file = fs::File::open(path)?;
    let size = file.metadata()?.len();
    if size <= keep {
        return Ok(());
    }
    file.seek(SeekFrom::Start(size - keep))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let start = buf.iter().position(|b| *b == b'\n').map_or(0, |i| i + 1);
    fs::write(path, &buf[start..])
}

/// `process.platform` names.
fn node_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

/// `process.arch` names.
fn node_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> (tempfile::TempDir, CrashLog) {
        let dir = tempfile::tempdir().unwrap();
        let log = CrashLog::new(
            dir.path().join("crash-logs"),
            EntryContext {
                version: "1.2.3".into(),
            },
        );
        (dir, log)
    }

    #[test]
    fn capture_list_read_clear() {
        let (_dir, log) = log();
        log.init();
        assert!(log.list().is_empty());
        log.capture(
            "main-panic",
            "boom",
            Some("at foo"),
            Some(json!({ "thread": "main" })),
        );
        log.capture("renderer-diagnostic", "second", None, None);

        let files = log.list();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].entry_count, 2);
        assert!(is_valid_read_name(&files[0].file_name));

        let entries = log.read(&files[0].file_name);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["source"], "main-panic");
        assert_eq!(entries[0]["stack"], "at foo");
        assert_eq!(entries[0]["extra"]["thread"], "main");
        assert_eq!(entries[0]["version"], "1.2.3");
        assert!(entries[1].get("stack").is_none());

        assert_eq!(log.clear(), 1);
        assert!(log.list().is_empty());
    }

    #[test]
    fn read_rejects_traversal_and_bad_names() {
        let (_dir, log) = log();
        log.capture("s", "m", None, None);
        assert!(log.read("../secret").is_empty());
        assert!(log.read("crash-2024-1-01.log").is_empty());
        assert!(log.read("crash-2024-01-01.log").is_empty()); // missing file
    }

    #[test]
    fn oversized_entries_are_reduced() {
        let huge = "x".repeat(MAX_LOG_ENTRY_BYTES * 2);
        let (_dir, log) = log();
        log.capture("s", &huge, Some(&huge), Some(json!({ "blob": huge })));
        let files = log.list();
        let entries = log.read(&files[0].file_name);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].get("extra").is_none());
        assert!(entries[0]["message"]
            .as_str()
            .unwrap()
            .ends_with("[truncated]"));
    }

    #[test]
    fn prunes_old_files_and_trims_oversized() {
        let (_dir, log) = log();
        fs::create_dir_all(log.dir()).unwrap();
        fs::write(log.dir().join("crash-2000-01-01.log"), "{}\n").unwrap();
        let big = log.dir().join(format!(
            "crash-{}.log",
            chrono::Local::now().format("%Y-%m-%d")
        ));
        let line = format!("{}\n", json!({ "pad": "y".repeat(1000) }));
        fs::write(
            &big,
            line.repeat((MAX_LOG_FILE_BYTES as usize / line.len()) + 10),
        )
        .unwrap();
        log.init();
        assert!(!log.dir().join("crash-2000-01-01.log").exists());
        let size = fs::metadata(&big).unwrap().len();
        assert!(size <= MAX_LOG_FILE_BYTES);
        // Trimmed at a line boundary: every remaining line still parses.
        let entries = log.read(big.file_name().unwrap().to_str().unwrap());
        assert!(!entries.is_empty());
    }
}
