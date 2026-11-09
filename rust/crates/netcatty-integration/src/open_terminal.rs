//! "Open terminal here" launches: `--open-terminal-path <dir>` and
//! `--open-terminal-shell <id|path>` from Explorer / Finder / file managers,
//! and macOS `open-file` (Electron: `electron/openTerminalPath.cjs`).

use serde::Serialize;
use std::path::{Component, Path, PathBuf};

pub const OPEN_TERMINAL_PATH_CHANNEL: &str = "netcatty:openTerminalPath";
pub const OPEN_TERMINAL_PATH_ARG: &str = "--open-terminal-path";
pub const OPEN_TERMINAL_SHELL_ARG: &str = "--open-terminal-shell";
/// Shell ids are short; the cap leaves room for a nested executable path.
pub const MAX_OPEN_TERMINAL_SHELL_LENGTH: usize = 4096;

/// `{ path?, shell? }` as delivered on `netcatty:openTerminalPath`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OpenTerminalRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
}

pub fn expand_home_path(target: &str, home: Option<&Path>) -> String {
    let Some(home) = home else {
        return target.to_owned();
    };
    if target == "~" {
        return home.to_string_lossy().into_owned();
    }
    if let Some(rest) = target.strip_prefix("~/") {
        return home.join(rest).to_string_lossy().into_owned();
    }
    target.to_owned()
}

fn strip_matching_quotes(value: &str) -> &str {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].trim()
    } else {
        value
    }
}

fn is_drive_root(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/')
}

fn looks_like_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/'))
        || value.contains('\\')
}

/// Strip leftover quotes, the trailing `.` of the Windows `"%1."` verb trick
/// and trailing separators (drive roots excepted).
pub fn normalize_path_token(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut value = strip_matching_quotes(trimmed).to_owned();
    if cfg!(windows) || looks_like_windows_path(&value) {
        if value.len() > 1 && value.ends_with('.') && !value.ends_with("..") {
            value.pop();
        }
        if is_drive_root(&value) {
            return value;
        }
        while value.len() > 1 && (value.ends_with('\\') || value.ends_with('/')) {
            value.pop();
        }
    }
    value
}

pub fn sanitize_shell(raw: &str) -> String {
    let value = strip_matching_quotes(raw.trim());
    if value.is_empty() || value.len() > MAX_OPEN_TERMINAL_SHELL_LENGTH || value.contains('\0') {
        return String::new();
    }
    value.to_owned()
}

fn is_open_terminal_flag(arg: &str) -> bool {
    arg == OPEN_TERMINAL_PATH_ARG
        || arg == OPEN_TERMINAL_SHELL_ARG
        || arg.starts_with(&format!("{OPEN_TERMINAL_PATH_ARG}="))
        || arg.starts_with(&format!("{OPEN_TERMINAL_SHELL_ARG}="))
}

/// `(value, consumed_next)` when `argv[index]` is `flag` or `flag=value`.
fn read_flag_value(argv: &[String], index: usize, flag: &str) -> Option<(String, bool)> {
    let arg = &argv[index];
    if arg == flag {
        return match argv.get(index + 1) {
            Some(next) if !next.trim().is_empty() && !is_open_terminal_flag(next) => {
                Some((next.clone(), true))
            }
            _ => Some((String::new(), false)),
        };
    }
    arg.strip_prefix(&format!("{flag}="))
        .map(|value| (value.to_owned(), false))
}

/// Group adjacent path / shell flags into requests; a repeated flag starts a
/// new request.
pub fn collect_requests(argv: &[String]) -> Vec<OpenTerminalRequest> {
    let mut requests = Vec::new();
    let mut current: Option<OpenTerminalRequest> = None;
    let flush = |current: &mut Option<OpenTerminalRequest>, requests: &mut Vec<OpenTerminalRequest>| {
        if let Some(request) = current.take() {
            if request.path.is_some() || request.shell.is_some() {
                requests.push(request);
            }
        }
    };
    let mut index = 0;
    while index < argv.len() {
        if let Some((value, consumed)) = read_flag_value(argv, index, OPEN_TERMINAL_PATH_ARG) {
            if current.as_ref().is_some_and(|c| c.path.is_some()) {
                flush(&mut current, &mut requests);
            }
            let normalized = normalize_path_token(&value);
            if !normalized.is_empty() {
                current.get_or_insert_with(Default::default).path = Some(normalized);
            }
            index += 1 + usize::from(consumed);
            continue;
        }
        if let Some((value, consumed)) = read_flag_value(argv, index, OPEN_TERMINAL_SHELL_ARG) {
            if current.as_ref().is_some_and(|c| c.shell.is_some()) {
                flush(&mut current, &mut requests);
            }
            let shell = sanitize_shell(&value);
            if !shell.is_empty() {
                current.get_or_insert_with(Default::default).shell = Some(shell);
            }
            index += 1 + usize::from(consumed);
            continue;
        }
        index += 1;
    }
    flush(&mut current, &mut requests);
    requests
}

pub fn collect_path_args(argv: &[String]) -> Vec<String> {
    collect_requests(argv).into_iter().filter_map(|r| r.path).collect()
}

/// Either flag with a non-empty value (shell values are not sanity-checked
/// here: an unusable shell still brings the window forward).
pub fn has_launch_args(argv: &[String]) -> bool {
    for (index, arg) in argv.iter().enumerate() {
        if arg == OPEN_TERMINAL_PATH_ARG || arg == OPEN_TERMINAL_SHELL_ARG {
            if argv
                .get(index + 1)
                .is_some_and(|next| !next.trim().is_empty() && !is_open_terminal_flag(next))
            {
                return true;
            }
            continue;
        }
        for flag in [OPEN_TERMINAL_PATH_ARG, OPEN_TERMINAL_SHELL_ARG] {
            if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
                if !value.trim().is_empty() {
                    return true;
                }
            }
        }
    }
    false
}

/// Lexical `path.resolve`: join onto `base` when relative, then drop `.` and
/// resolve `..` without touching the filesystem.
pub fn lexical_resolve(path: &Path, base: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut out = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Filesystem view used by [`resolve_path`] (stubbed in tests).
pub trait PathProbe {
    /// `Some(true)` for a directory, `Some(false)` for a file, `None` when
    /// missing or neither.
    fn kind(&self, path: &Path) -> Option<bool>;
}

/// The real filesystem.
pub struct RealFs;

impl PathProbe for RealFs {
    fn kind(&self, path: &Path) -> Option<bool> {
        let meta = std::fs::metadata(path).ok()?;
        if meta.is_dir() {
            Some(true)
        } else if meta.is_file() {
            Some(false)
        } else {
            None
        }
    }
}

/// Resolve a requested path to a directory (a file resolves to its parent).
pub fn resolve_path(
    raw: &str,
    base: Option<&Path>,
    home: Option<&Path>,
    fs: &dyn PathProbe,
) -> Option<String> {
    let normalized = normalize_path_token(raw);
    if normalized.is_empty() {
        return None;
    }
    let expanded = expand_home_path(&normalized, home);
    let cwd = std::env::current_dir().unwrap_or_default();
    let resolved = lexical_resolve(Path::new(&expanded), base.unwrap_or(&cwd));
    match fs.kind(&resolved) {
        Some(true) => Some(resolved.to_string_lossy().into_owned()),
        Some(false) => resolved.parent().map(|p| p.to_string_lossy().into_owned()),
        None => {
            tracing::warn!(path = %raw, "ignoring invalid terminal open path");
            None
        }
    }
}

/// Requests from argv with their paths resolved; a path that does not
/// resolve drops the whole request (never opens in the default directory).
pub fn resolve_requests_from_args(
    argv: &[String],
    base: Option<&Path>,
    home: Option<&Path>,
    fs: &dyn PathProbe,
) -> Vec<OpenTerminalRequest> {
    let mut out = Vec::new();
    for raw in collect_requests(argv) {
        if let Some(path) = &raw.path {
            let Some(resolved) = resolve_path(path, base, home, fs) else {
                continue;
            };
            out.push(OpenTerminalRequest {
                path: Some(resolved),
                shell: raw.shell,
            });
            continue;
        }
        if raw.shell.is_some() {
            out.push(OpenTerminalRequest {
                path: None,
                shell: raw.shell,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn req(path: Option<&str>, shell: Option<&str>) -> OpenTerminalRequest {
        OpenTerminalRequest {
            path: path.map(str::to_owned),
            shell: shell.map(str::to_owned),
        }
    }

    struct Dirs;
    impl PathProbe for Dirs {
        fn kind(&self, _: &Path) -> Option<bool> {
            Some(true)
        }
    }
    struct Missing;
    impl PathProbe for Missing {
        fn kind(&self, _: &Path) -> Option<bool> {
            None
        }
    }
    struct Files;
    impl PathProbe for Files {
        fn kind(&self, _: &Path) -> Option<bool> {
            Some(false)
        }
    }
    struct Panics;
    impl PathProbe for Panics {
        fn kind(&self, _: &Path) -> Option<bool> {
            panic!("shell-only must not stat")
        }
    }

    #[test]
    fn extracts_explicit_paths() {
        assert_eq!(
            collect_path_args(&argv(&[
                "/Applications/Netcatty.app/Contents/MacOS/Netcatty",
                "--open-terminal-path",
                "/Users/alice/project",
                "--open-terminal-path=/tmp/demo",
                "--ignored",
            ])),
            vec!["/Users/alice/project", "/tmp/demo"]
        );
        assert_eq!(
            collect_path_args(&argv(&[
                r"C:\Program Files\Netcatty\Netcatty.exe",
                "--",
                r"--open-terminal-path=C:\Users\alice\project.",
            ])),
            vec![r"C:\Users\alice\project"]
        );
    }

    #[test]
    fn normalizes_quotes_and_trailing_dots() {
        assert_eq!(normalize_path_token("\"C:\\Users\\alice\\Docs.\""), "C:\\Users\\alice\\Docs");
        assert_eq!(normalize_path_token("C:\\"), "C:\\");
        assert_eq!(normalize_path_token("C:\\."), "C:\\");
    }

    #[cfg(unix)]
    #[test]
    fn resolves_directories_relative_paths_and_files() {
        assert_eq!(resolve_path("/tmp/project", None, None, &Dirs).as_deref(), Some("/tmp/project"));
        assert_eq!(
            resolve_path("project", Some(Path::new("/Users/alice")), None, &Dirs).as_deref(),
            Some("/Users/alice/project")
        );
        assert_eq!(
            resolve_path("../bob/./x", Some(Path::new("/Users/alice")), None, &Dirs).as_deref(),
            Some("/Users/bob/x")
        );
        assert_eq!(
            resolve_path("/tmp/project/readme.md", None, None, &Files).as_deref(),
            Some("/tmp/project")
        );
        assert_eq!(
            resolve_path("~/code", None, Some(Path::new("/home/alice")), &Dirs).as_deref(),
            Some("/home/alice/code")
        );
        assert_eq!(resolve_path("/tmp/missing", None, None, &Missing), None);
    }

    #[test]
    fn expands_home() {
        let home = Path::new("/home/alice");
        assert_eq!(expand_home_path("~", Some(home)), "/home/alice");
        assert_eq!(
            Path::new(&expand_home_path("~/x", Some(home))),
            home.join("x").as_path()
        );
        assert_eq!(expand_home_path("/abs", Some(home)), "/abs");
    }

    #[test]
    fn pairs_shells_with_paths() {
        assert_eq!(
            collect_requests(&argv(&["Netcatty.exe", "--", "--open-terminal-shell=pwsh", "--open-terminal-path", r"D:\proj"])),
            vec![req(Some(r"D:\proj"), Some("pwsh"))]
        );
        assert_eq!(
            collect_requests(&argv(&["--open-terminal-path=/tmp/demo", "--open-terminal-shell", "/usr/local/bin/fish"])),
            vec![req(Some("/tmp/demo"), Some("/usr/local/bin/fish"))]
        );
        assert_eq!(
            collect_requests(&argv(&["--open-terminal-shell", "wsl-ubuntu"])),
            vec![req(None, Some("wsl-ubuntu"))]
        );
        assert_eq!(
            collect_requests(&argv(&[
                "--open-terminal-shell", "pwsh", "--open-terminal-path", "/tmp/a", "--open-terminal-shell",
                "cmd", "--open-terminal-path", "/tmp/b",
            ])),
            vec![req(Some("/tmp/a"), Some("pwsh")), req(Some("/tmp/b"), Some("cmd"))]
        );
        assert_eq!(
            collect_requests(&argv(&["--open-terminal-shell", "--open-terminal-path=/tmp/demo"])),
            vec![req(Some("/tmp/demo"), None)]
        );
    }

    #[test]
    fn sanitizes_shells() {
        assert_eq!(sanitize_shell("  pwsh  "), "pwsh");
        assert_eq!(sanitize_shell("\"pwsh\""), "pwsh");
        assert_eq!(sanitize_shell(""), "");
        assert_eq!(sanitize_shell("   "), "");
        assert_eq!(sanitize_shell("pwsh\0"), "");
        assert_eq!(sanitize_shell("\0pwsh"), "");
        let max = "a".repeat(MAX_OPEN_TERMINAL_SHELL_LENGTH);
        assert_eq!(sanitize_shell(&max), max);
        assert_eq!(sanitize_shell(&"a".repeat(MAX_OPEN_TERMINAL_SHELL_LENGTH + 1)), "");
    }

    #[cfg(unix)]
    #[test]
    fn resolves_requests() {
        assert_eq!(
            resolve_requests_from_args(&argv(&["--open-terminal-shell", "cmd"]), None, None, &Panics),
            vec![req(None, Some("cmd"))]
        );
        let base = Some(Path::new("/Users/alice"));
        assert_eq!(
            resolve_requests_from_args(&argv(&["--open-terminal-path", "project"]), base, None, &Dirs),
            vec![req(Some("/Users/alice/project"), None)]
        );
        assert_eq!(
            resolve_requests_from_args(
                &argv(&["--open-terminal-shell=pwsh", "--open-terminal-path", "project"]),
                base,
                None,
                &Dirs
            ),
            vec![req(Some("/Users/alice/project"), Some("pwsh"))]
        );
        assert_eq!(
            resolve_requests_from_args(
                &argv(&["--open-terminal-shell", "pwsh", "--open-terminal-path", "/tmp/missing"]),
                None,
                None,
                &Missing
            ),
            vec![]
        );
        assert_eq!(
            resolve_requests_from_args(
                &argv(&["--open-terminal-path", "/tmp/project", "--open-terminal-shell", "pwsh\0"]),
                None,
                None,
                &Dirs
            ),
            vec![req(Some("/tmp/project"), None)]
        );
    }

    #[test]
    fn detects_launch_args() {
        assert!(has_launch_args(&argv(&["--open-terminal-shell", "pwsh"])));
        assert!(has_launch_args(&argv(&["--open-terminal-path=/tmp/demo"])));
        assert!(has_launch_args(&argv(&["--open-terminal-shell", "bad\0shell"])));
        assert!(!has_launch_args(&argv(&["--open-terminal-shell="])));
        assert!(!has_launch_args(&argv(&["--open-terminal-path"])));
        assert!(!has_launch_args(&argv(&["--other"])));
    }

    #[test]
    fn request_payload_omits_absent_fields() {
        assert_eq!(
            serde_json::to_value(req(Some("/x"), None)).unwrap(),
            serde_json::json!({ "path": "/x" })
        );
    }
}
