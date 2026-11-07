//! One-shot session log file operations (Electron: `autoSaveSessionLog`,
//! the content half of `exportSessionLog`, `clearSessionLogsDir`).

use crate::html::{terminal_data_to_html, terminal_plain_text_to_html};
use crate::naming::{is_session_log_artifact_name, safe_path_segment, to_local_iso_string};
use crate::sanitizer::terminal_data_to_plain_text;
use crate::stream::{node_io_error, normalize_path, LogFormat};
use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// `.log` for raw, `.html` for html, `.txt` otherwise (lenient, like Electron).
pub fn extension_for(format: &str) -> &'static str {
    LogFormat::from_setting(format).extension()
}

/// Default file name of the export dialog: `<label>_<YYYY-MM-DDTHH-MM-SS>.<ext>`.
pub fn export_default_file_name(host_label: &str, start_time: i64, format: &str) -> String {
    format!(
        "{}_{}.{}",
        safe_path_segment(host_label, "session"),
        to_local_iso_string(start_time),
        extension_for(format)
    )
}

/// Content written by `exportSessionLog` for the format implied by the
/// chosen file's extension (`html`, `log` / `raw`, anything else → text).
/// `plain_text` marks data that is already rendered screen text.
pub fn export_content(
    actual_format: &str,
    terminal_data: &str,
    plain_text: bool,
    host_label: &str,
    start_time: Option<i64>,
) -> String {
    match actual_format {
        "html" if plain_text => terminal_plain_text_to_html(terminal_data, host_label, start_time),
        "html" => terminal_data_to_html(terminal_data, host_label, start_time),
        // Raw format preserves ANSI codes.
        "log" | "raw" => terminal_data.to_string(),
        _ if plain_text => terminal_data.to_string(),
        _ => terminal_data_to_plain_text(terminal_data),
    }
}

/// Format of an export: the chosen file's extension (case-sensitive, like
/// Node's `path.extname`), else the requested format.
pub fn export_actual_format(path: &Path, requested: &str) -> String {
    match path.extension().map(|e| e.to_string_lossy().into_owned()) {
        Some(ext) if !ext.is_empty() => ext,
        _ => requested.to_string(),
    }
}

/// Inputs of [`auto_save`].
pub struct AutoSave<'a> {
    pub terminal_data: &'a str,
    pub host_label: &'a str,
    pub hostname: &'a str,
    pub host_id: &'a str,
    pub start_time: i64,
    pub format: &'a str,
    pub directory: &'a Path,
}

/// Write a whole session log to `directory/<safe label>/<timestamp>.<ext>`.
pub fn auto_save(input: &AutoSave<'_>) -> Result<PathBuf, String> {
    let label = [input.host_label, input.hostname, input.host_id]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or_default();
    let host_dir = input.directory.join(safe_path_segment(label, "unknown"));
    std::fs::create_dir_all(&host_dir).map_err(|e| node_io_error(&e, "mkdir", &host_dir))?;
    let file_path = host_dir.join(format!(
        "{}.{}",
        to_local_iso_string(input.start_time),
        extension_for(input.format)
    ));
    let content = match input.format {
        "html" => terminal_data_to_html(
            input.terminal_data,
            input.host_label,
            Some(input.start_time),
        ),
        "raw" => input.terminal_data.to_string(),
        _ => terminal_data_to_plain_text(input.terminal_data),
    };
    std::fs::write(&file_path, content).map_err(|e| node_io_error(&e, "open", &file_path))?;
    Ok(file_path)
}

/// Outcome of [`clear_session_logs_dir`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ClearOutcome {
    pub deleted_count: usize,
    pub failed_count: usize,
    /// Set when the directory itself could not be read.
    pub error: Option<String>,
}

/// Delete known session-log artifacts inside `directory` ("clear all logs").
///
/// Only removes top-level files with session-log names, host subdirectories
/// that contain nothing but session-log files (as one artifact), and the
/// session-log files inside mixed host subdirectories. Symlinks and
/// unrelated files / folders are never touched, and neither are the files of
/// `active_paths` (live streams) or host folders that hold a live stream
/// (a txt/html stream's file may not exist before its first snapshot).
/// A missing directory is a successful no-op.
pub fn clear_session_logs_dir(directory: &Path, active_paths: &HashSet<PathBuf>) -> ClearOutcome {
    let mut outcome = ClearOutcome::default();
    let is_active = |path: &Path| active_paths.contains(&normalize_path(path));

    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return outcome,
        Err(err) => {
            tracing::error!(%err, "failed to clear the session logs directory");
            outcome.error = Some(node_io_error(&err, "scandir", directory));
            return outcome;
        }
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        // lstat: never follow symlinks out of the save directory.
        let Ok(metadata) = std::fs::symlink_metadata(&entry_path) else {
            continue;
        };
        let file_type = metadata.file_type();
        if file_type.is_symlink() || !(file_type.is_file() || file_type.is_dir()) {
            continue;
        }

        if file_type.is_file() {
            if !is_session_log_artifact_name(&name) || is_active(&entry_path) {
                continue;
            }
            match remove_file_force(&entry_path) {
                Ok(()) => outcome.deleted_count += 1,
                Err(err) => {
                    outcome.failed_count += 1;
                    tracing::error!(%err, name, "could not delete session log");
                }
            }
            continue;
        }

        // Host subdirectory created by auto-save: only touch known log files.
        let nested = match std::fs::read_dir(&entry_path) {
            Ok(nested) => nested,
            Err(err) => {
                outcome.failed_count += 1;
                tracing::error!(%err, name, "could not read session log folder");
                continue;
            }
        };
        let resolved_entry = normalize_path(&entry_path);
        let mut log_files = Vec::new();
        let mut has_non_log_entry = false;
        let mut has_active_log = active_paths
            .iter()
            .any(|active| active.parent() == Some(resolved_entry.as_path()));

        for nested_entry in nested.flatten() {
            let nested_path = nested_entry.path();
            let is_plain_file = std::fs::symlink_metadata(&nested_path)
                .map(|m| m.file_type().is_file())
                .unwrap_or(false);
            let nested_name = nested_entry.file_name().to_string_lossy().into_owned();
            if is_plain_file && is_session_log_artifact_name(&nested_name) {
                if is_active(&nested_path) {
                    has_active_log = true;
                } else {
                    log_files.push(nested_path);
                }
            } else {
                has_non_log_entry = true;
            }
        }

        if log_files.is_empty() && !has_active_log {
            // Not an app host-log folder (or empty / only non-log content).
            continue;
        }

        if !has_non_log_entry && !has_active_log {
            // Pure session-log host folder with no live streams: one artifact.
            match std::fs::remove_dir_all(&entry_path) {
                Ok(()) => outcome.deleted_count += 1,
                Err(err) if err.kind() == ErrorKind::NotFound => outcome.deleted_count += 1,
                Err(err) => {
                    outcome.failed_count += 1;
                    tracing::error!(%err, name, "could not delete session log folder");
                }
            }
        } else {
            for log_path in log_files {
                match remove_file_force(&log_path) {
                    Ok(()) => outcome.deleted_count += 1,
                    Err(err) => {
                        outcome.failed_count += 1;
                        tracing::error!(%err, "could not delete session log");
                    }
                }
            }
        }
    }
    outcome
}

fn remove_file_force(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    //! Ported from `electron/bridges/sessionLogsBridge.test.cjs`.
    use super::*;
    use std::fs;

    fn write(path: &Path, content: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    #[test]
    fn auto_save_uses_a_safe_host_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = auto_save(&AutoSave {
            terminal_data: "hello\n",
            host_label: "生产/服务器:东京*?<>|\0",
            hostname: "fallback.example",
            host_id: "host-id",
            start_time: 0,
            format: "raw",
            directory: dir.path(),
        })
        .unwrap();
        assert_eq!(
            path.parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy(),
            "生产_服务器_东京______"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello\n");

        let path = auto_save(&AutoSave {
            terminal_data: "hello\n",
            host_label: "   ",
            hostname: "",
            host_id: "",
            start_time: 0,
            format: "txt",
            directory: dir.path(),
        })
        .unwrap();
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "unknown");
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
    }

    #[test]
    fn export_formats() {
        assert_eq!(
            export_content("txt", "a\x1b[31mb\n", false, "h", Some(0)),
            "ab"
        );
        assert_eq!(
            export_content("log", "a\x1b[31mb\n", false, "h", Some(0)),
            "a\x1b[31mb\n"
        );
        for data in ["  中文 😀\n\nend\n\n", ""] {
            assert_eq!(export_content("txt", data, true, "screen", Some(0)), data);
        }
        let html = export_content(
            "html",
            "<script>alert(1)</script>\n\n",
            true,
            "screen",
            Some(0),
        );
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;\n\n"));
        assert!(!html.contains("<script>"));
        assert_eq!(export_actual_format(Path::new("/x/a.html"), "txt"), "html");
        assert_eq!(export_actual_format(Path::new("/x/a."), "raw"), "raw");
        assert_eq!(export_actual_format(Path::new("/x/.bashrc"), "txt"), "txt");
        let name = export_default_file_name("生产/服务器:东京*?<>|\0", 0, "txt");
        assert!(name.starts_with("生产_服务器_东京_______"));
        assert!(name.ends_with(".txt"));
        assert!(!name.contains('/') && !name.contains(':') && !name.contains('\0'));
        assert!(export_default_file_name("", 0, "raw").starts_with("session_"));
        assert!(export_default_file_name("h", 0, "raw").ends_with(".log"));
    }

    #[test]
    fn clear_deletes_host_folders_and_labeled_exports_only() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write(&d.join("host-a/2026-01-01T00-00-00.txt"), "a");
        write(&d.join("host-a/2026-01-02T00-00-00.log"), "b");
        write(&d.join("my-host_2026-01-01T00-00-00.html"), "c");
        write(&d.join("notes.txt"), "keep");
        write(&d.join("Documents/report.docx"), "keep");
        fs::create_dir_all(d.join("Empty")).unwrap();
        let outcome = clear_session_logs_dir(d, &HashSet::new());
        assert_eq!(
            outcome,
            ClearOutcome {
                deleted_count: 2,
                failed_count: 0,
                error: None
            }
        );
        assert!(!d.join("host-a").exists());
        assert!(!d.join("my-host_2026-01-01T00-00-00.html").exists());
        assert!(d.join("notes.txt").exists());
        assert!(d.join("Documents/report.docx").exists());
        assert!(d.join("Empty").exists());
    }

    #[test]
    fn clear_only_removes_log_files_in_mixed_folders() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write(&d.join("host/2026-01-01T00-00-00.txt"), "a");
        write(&d.join("host/keep.md"), "keep");
        let outcome = clear_session_logs_dir(d, &HashSet::new());
        assert_eq!(outcome.deleted_count, 1);
        assert!(!d.join("host/2026-01-01T00-00-00.txt").exists());
        assert!(d.join("host/keep.md").exists());
    }

    #[test]
    fn clear_preserves_active_streams_and_their_folders() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write(&d.join("live/2026-01-01T00-00-00.log"), "live");
        write(&d.join("live/2026-01-02T00-00-00.log"), "old");
        // A txt stream before its first snapshot: no file yet.
        fs::create_dir_all(d.join("pending")).unwrap();
        write(&d.join("pending/2026-01-01T00-00-00.txt"), "old");
        let active: HashSet<PathBuf> = [
            normalize_path(&d.join("live/2026-01-01T00-00-00.log")),
            normalize_path(&d.join("pending/2026-03-01T00-00-00.txt")),
        ]
        .into_iter()
        .collect();
        let outcome = clear_session_logs_dir(d, &active);
        assert_eq!(outcome.deleted_count, 2);
        assert!(d.join("live/2026-01-01T00-00-00.log").exists());
        assert!(!d.join("live/2026-01-02T00-00-00.log").exists());
        assert!(d.join("pending").is_dir());
        assert!(!d.join("pending/2026-01-01T00-00-00.txt").exists());
    }

    #[test]
    fn clear_missing_directory_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            clear_session_logs_dir(&dir.path().join("missing"), &HashSet::new()),
            ClearOutcome::default()
        );
    }

    #[cfg(unix)]
    #[test]
    fn clear_never_follows_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(&outside.path().join("2026-01-01T00-00-00.txt"), "outside");
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("2026-01-01T00-00-00.txt"),
            dir.path().join("x_2026-01-01T00-00-00.txt"),
        )
        .unwrap();
        assert_eq!(
            clear_session_logs_dir(dir.path(), &HashSet::new()).deleted_count,
            0
        );
        assert!(outside.path().join("2026-01-01T00-00-00.txt").exists());
    }
}
