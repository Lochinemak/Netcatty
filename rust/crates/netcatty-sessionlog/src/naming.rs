//! File naming rules shared by auto-save, export, manual and automatic logs.

use chrono::{DateTime, Local, TimeZone};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

const FILE_NAME_UNSAFE_CHARS: [char; 9] = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

fn is_control_character(ch: char) -> bool {
    let code = ch as u32;
    code <= 0x1f || (0x7f..=0x9f).contains(&code)
}

/// `^(con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$` (case-insensitive).
fn is_windows_reserved_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or_default().to_lowercase();
    if matches!(stem.as_str(), "con" | "prn" | "aux" | "nul") {
        return true;
    }
    let mut chars = stem.chars();
    let prefix: String = chars.by_ref().take(3).collect();
    let rest: Vec<char> = chars.collect();
    (prefix == "com" || prefix == "lpt")
        && rest.len() == 1
        && matches!(rest[0], '1'..='9' | '¹' | '²' | '³')
}

/// Make `value` safe as one path segment (`safePathSegment`): path-unsafe and
/// control characters become `_`, the result is trimmed, trailing dots become
/// `_`, Windows device names get a `_` suffix; empty / `.` / `..` → `fallback`.
pub fn safe_path_segment(value: &str, fallback: &str) -> String {
    let replaced: String = value
        .chars()
        .map(|ch| {
            if FILE_NAME_UNSAFE_CHARS.contains(&ch) || is_control_character(ch) {
                '_'
            } else {
                ch
            }
        })
        .collect();
    let trimmed = replaced.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return fallback.to_string();
    }
    let without_dots = trimmed.trim_end_matches('.');
    let mut safe = format!(
        "{without_dots}{}",
        "_".repeat(trimmed.len() - without_dots.len())
    );
    if is_windows_reserved_device_name(&safe) {
        safe.push('_');
    }
    safe
}

fn local_time(ms: i64) -> Option<DateTime<Local>> {
    Local.timestamp_millis_opt(ms).single()
}

/// Local `YYYY-MM-DDTHH-MM-SS` (`toLocalISOString`), used in log file names.
pub fn to_local_iso_string(ms: i64) -> String {
    local_time(ms)
        .map(|t| t.format("%Y-%m-%dT%H-%M-%S").to_string())
        .unwrap_or_else(|| "NaN-NaN-NaNTNaN-NaN-NaN".to_string())
}

/// Local `YYYY-MM-DD HH:MM:SS.mmm` line prefix for timestamped logs
/// (`formatLogTimestamp`).
pub fn format_log_timestamp(ms: i64) -> String {
    local_time(ms)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        .unwrap_or_default()
}

/// `new Date(ms).toLocaleString()` in the `en-US` format
/// (`1/2/2026, 3:04:05 AM`); `Invalid Date` when `ms` is missing.
pub fn locale_date_string(ms: Option<i64>) -> String {
    match ms.and_then(local_time) {
        Some(t) => t.format("%-m/%-d/%Y, %-I:%M:%S %p").to_string(),
        None => "Invalid Date".to_string(),
    }
}

/// Current time in ms since the epoch.
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// True when a base name matches a Netcatty session-log artifact: auto-save
/// `{YYYY-MM-DDTHH-MM-SS}.{txt|log|html}` or labeled
/// `{label}_{YYYY-MM-DDTHH-MM-SS}.{ext}`. "Clear all" deletes nothing else.
pub fn is_session_log_artifact_name(name: &str) -> bool {
    static TIMESTAMP: OnceLock<Regex> = OnceLock::new();
    static LABELED: OnceLock<Regex> = OnceLock::new();
    let base = Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let timestamp = TIMESTAMP.get_or_init(|| {
        Regex::new(r"(?i)^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}\.(txt|log|html)$")
            .expect("valid regex")
    });
    let labeled = LABELED.get_or_init(|| {
        Regex::new(
            r"(?i)^.+_[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}\.(txt|log|html)$",
        )
        .expect("valid regex")
    });
    timestamp.is_match(&base) || labeled.is_match(&base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_path_segments() {
        assert_eq!(
            safe_path_segment("生产/服务器:东京*?<>|\0", "x"),
            "生产_服务器_东京______"
        );
        assert_eq!(
            safe_path_segment("\t生产服务器\n", "fallback"),
            "_生产服务器_"
        );
        assert_eq!(
            safe_path_segment("生产\u{85}服务器\u{9b}", "fallback"),
            "生产_服务器_"
        );
        assert_eq!(safe_path_segment("../name", "fallback"), ".._name");
        assert_eq!(safe_path_segment("CON", "fallback"), "CON_");
        assert_eq!(safe_path_segment("COM¹", "fallback"), "COM¹_");
        assert_eq!(safe_path_segment("LPT².txt", "fallback"), "LPT².txt_");
        assert_eq!(safe_path_segment("prod.", "fallback"), "prod_");
        assert_eq!(safe_path_segment("prod..", "fallback"), "prod__");
        assert_eq!(safe_path_segment("   ", "unknown"), "unknown");
        assert_eq!(safe_path_segment("..", "unknown"), "unknown");
        assert_eq!(safe_path_segment("console", "x"), "console");
        assert_eq!(safe_path_segment("com10", "x"), "com10");
    }

    #[test]
    fn artifact_names() {
        assert!(is_session_log_artifact_name("2026-01-01T00-00-00.txt"));
        assert!(is_session_log_artifact_name("2026-01-01T00-00-00.log"));
        assert!(is_session_log_artifact_name("2026-01-01T00-00-00.html"));
        assert!(is_session_log_artifact_name(
            "my-host_2026-01-01T00-00-00.txt"
        ));
        assert!(is_session_log_artifact_name(
            "生产_服务器_2026-08-05T15-33-00.log"
        ));
        assert!(!is_session_log_artifact_name("stray.log"));
        assert!(!is_session_log_artifact_name("notes.txt"));
        assert!(!is_session_log_artifact_name("2026-01-01.txt"));
        assert!(!is_session_log_artifact_name("readme.md"));
    }

    #[test]
    fn local_timestamps() {
        let ms = Local
            .with_ymd_and_hms(2026, 1, 2, 3, 4, 5)
            .single()
            .unwrap()
            .timestamp_millis();
        assert_eq!(to_local_iso_string(ms), "2026-01-02T03-04-05");
        assert_eq!(format_log_timestamp(ms + 89), "2026-01-02 03:04:05.089");
        assert_eq!(locale_date_string(Some(ms)), "1/2/2026, 3:04:05 AM");
        assert_eq!(locale_date_string(None), "Invalid Date");
    }
}
