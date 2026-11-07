//! Port of `electron/bridges/systemManager/tmuxEnv.cjs`: shell wrappers,
//! tmux version / environment detection and the `list-sessions` parser.

use super::js;
use crate::exec::{json_quote, sh_quote, ExecResult};
use regex::Regex;
use serde_json::{json, Value};
use std::sync::LazyLock;

static ANSI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])").unwrap());
static VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)tmux\s+([0-9]+)\.([0-9]+)([a-z0-9]*)").unwrap());
static DIAGNOSTIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(error connecting to|no server running|no current client|can't find|lost server|server exited|failed to connect|protocol version mismatch|open terminal failed|invalid option|usage:|unknown command)",
    )
    .unwrap()
});
static PLAIN_SESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^([^:]+):\s*([0-9]+)\s+windows?\b").unwrap());
static ATTACHED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\battached\b").unwrap());

/// Flatten a (possibly multi-line) script into one `; `-joined line.
fn one_line(command: &str) -> String {
    command
        .replace("\r\n", "\n")
        .split('\n')
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// `bash -lc <JSON>` (login shell so PATH from profiles applies).
pub fn wrap_login_shell(command: &str) -> String {
    format!("bash -lc {}", json_quote(&one_line(command)))
}

/// `exec sh -c <JSON>`.
pub fn wrap_sh_exec(command: &str) -> String {
    format!("exec sh -c {}", json_quote(&one_line(command)))
}

pub fn strip_ansi(text: &str) -> String {
    ANSI.replace_all(text, "").into_owned()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TmuxVersion {
    pub raw: String,
    pub major: u32,
    pub minor: u32,
    pub patch: String,
}

pub fn parse_tmux_version_string(text: &str) -> TmuxVersion {
    let clean = strip_ansi(text);
    match VERSION.captures(&clean) {
        Some(m) => TmuxVersion {
            raw: m[0].to_string(),
            major: m[1].parse().unwrap_or(0),
            minor: m[2].parse().unwrap_or(0),
            patch: m[3].to_string(),
        },
        None => TmuxVersion {
            raw: clean.trim().to_string(),
            ..Default::default()
        },
    }
}

/// `-F` format for `list-sessions` supported by `version` (tab separators
/// are the literal two characters `\t`, expanded by the remote `printf`).
pub fn get_list_sessions_format(version: &TmuxVersion) -> Option<String> {
    let (major, minor) = (version.major, version.minor);
    if major < 2 {
        return None;
    }
    let mut fields = vec![
        "#{session_name}",
        "#{session_windows}",
        "#{session_attached}",
    ];
    if major >= 3 || (major == 2 && minor >= 1) {
        fields.push("#{session_created}");
        fields.push("#{session_activity}");
    }
    if major > 3 || (major == 3 && minor >= 2) {
        fields.push("#{session_group}");
    }
    Some(fields.join(r"\t"))
}

/// Single-line detection script (version, binary, sockets). Multi-line
/// strings break when passed through `bash -lc` JSON quoting.
///
/// Deliberate fix vs Electron: Electron joins `"...; do"` and the loop body
/// with `"; "`, producing `do; [ -d ... ]`, which POSIX shells reject as a
/// syntax error — so its socket scan never ran. Here `do` is followed by a
/// space.
pub const TMUX_DETECT_SCRIPT: &str = concat!(
    "uid=$(id -u 2>/dev/null || echo 0); ",
    "echo \"__TMUX_VERSION__=$(tmux -V 2>/dev/null || true)\"; ",
    "echo \"__TMUX_BIN__=$(command -v tmux 2>/dev/null || which tmux 2>/dev/null || true)\"; ",
    "for d in \"${TMUX_TMPDIR:-/tmp}/tmux-$uid\" \"/tmp/tmux-$uid\"; do ",
    "[ -d \"$d\" ] || continue; ",
    "for s in \"$d\"/*; do [ -S \"$s\" ] && echo \"__SOCKET__=$s\"; done; ",
    "done",
);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectInfo {
    pub version: TmuxVersion,
    pub binary: String,
    pub sockets: Vec<String>,
}

pub fn parse_detect_script_output(stdout: &str) -> DetectInfo {
    let mut info = DetectInfo::default();
    for line in strip_ansi(stdout).split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("__TMUX_VERSION__=") {
            info.version = parse_tmux_version_string(rest);
        } else if let Some(rest) = trimmed.strip_prefix("__TMUX_BIN__=") {
            info.binary = rest.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("__SOCKET__=") {
            let socket = rest.trim().to_string();
            if !socket.is_empty() && !info.sockets.contains(&socket) {
                info.sockets.push(socket);
            }
        }
    }
    info
}

/// Merge stderr into stdout (tmux often reports on stderr) and treat a
/// failed exec that still produced output as a ran-with-code result.
pub fn normalize_exec_result(result: ExecResult) -> ExecResult {
    let stdout = strip_ansi(&result.stdout);
    let stderr = strip_ansi(&result.stderr);
    let combined = [stderr.as_str(), stdout.as_str()]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();
    if !result.success && !combined.is_empty() {
        return ExecResult {
            success: true,
            stdout: combined,
            stderr,
            code: Some(result.code.unwrap_or(1)),
            ..result
        };
    }
    ExecResult {
        stdout: if combined.is_empty() {
            stdout
        } else {
            combined
        },
        stderr,
        ..result
    }
}

/// `<binary> [-S '<socket>'] <args>` with whitespace collapsed.
pub fn build_tmux_invocation(binary: &str, socket_path: Option<&str>, args: &str) -> String {
    let bin = if binary.is_empty() { "tmux" } else { binary };
    let socket_flag = socket_path
        .filter(|s| !s.is_empty())
        .map(|s| format!("-S {} ", sh_quote(s)))
        .unwrap_or_default();
    format!("{bin} {socket_flag}{args}")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// tmux diagnostics that must never be mistaken for session names.
pub fn is_tmux_diagnostic_line(line: &str) -> bool {
    DIAGNOSTIC.is_match(line.trim())
}

fn session_row(
    name: &str,
    windows: Value,
    attached: bool,
    created: Value,
    activity: &str,
    group: &str,
) -> Value {
    json!({
        "name": name,
        "windows": windows,
        "attached": attached,
        "created": created,
        "activity": activity,
        "group": group,
    })
}

/// Parse `tmux ls` output: default lines, `-F` tab rows, or bare names.
pub fn parse_list_output(stdout: &str) -> Vec<Value> {
    let text = strip_ansi(stdout);
    let mut out = Vec::new();
    for line in text.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || is_tmux_diagnostic_line(trimmed) {
            continue;
        }
        if let Some(m) = PLAIN_SESSION.captures(trimmed) {
            out.push(session_row(
                m[1].trim(),
                js::num_or_zero(&m[2]),
                ATTACHED.is_match(trimmed),
                json!(0),
                "",
                "",
            ));
            continue;
        }
        let parts: Vec<&str> = trimmed.split('\t').collect();
        if parts.len() >= 4 {
            out.push(session_row(
                parts[0].trim(),
                js::num_or_zero(parts[1]),
                parts[2] == "1",
                js::num_or_zero(parts[3]),
                parts.get(4).copied().unwrap_or(""),
                parts.get(5).copied().unwrap_or(""),
            ));
            continue;
        }
        if parts.len() == 1 && !trimmed.contains(':') {
            out.push(session_row(trimmed, json!(0), false, json!(0), "", ""));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_handles_letter_patch() {
        let v = parse_tmux_version_string("tmux 3.0a");
        assert_eq!((v.major, v.minor, v.patch.as_str()), (3, 0, "a"));
        assert_eq!(v.raw, "tmux 3.0a");
        let v = parse_tmux_version_string("\x1b[1mtmux next-3.4\x1b[0m");
        assert_eq!(v.major, 0);
        assert_eq!(v.raw, "tmux next-3.4");
    }

    #[test]
    fn login_shell_flattens_multiline_scripts() {
        let wrapped = wrap_login_shell("echo one\necho two");
        assert!(!wrapped.contains("\\n"));
        assert!(wrapped.contains("; echo two"));
        assert_eq!(wrap_sh_exec("a\r\n  b  \n\n"), "exec sh -c \"a; b\"");
    }

    #[test]
    fn list_output_parses_default_ls_line() {
        let sessions =
            parse_list_output("test-session: 1 windows (created Thu Jun 11 00:38:14 2026)\n");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["name"], "test-session");
        assert_eq!(sessions[0]["windows"], 1);
        assert_eq!(sessions[0]["attached"], false);
        let sessions = parse_list_output("dev: 2 windows (created x) (attached)");
        assert_eq!(sessions[0]["attached"], true);
    }

    #[test]
    fn list_output_parses_format_rows_and_bare_names() {
        let sessions = parse_list_output("main\t3\t1\t1718000000\t1718000100\tgrp\nsolo\n");
        assert_eq!(sessions.len(), 2);
        assert_eq!(
            sessions[0],
            json!({"name":"main","windows":3,"attached":true,"created":1718000000,"activity":"1718000100","group":"grp"})
        );
        assert_eq!(sessions[1]["name"], "solo");
        assert_eq!(sessions[1]["windows"], 0);
    }

    #[test]
    fn list_sessions_format_by_version() {
        let v3 = TmuxVersion {
            major: 3,
            minor: 0,
            ..Default::default()
        };
        let fmt = get_list_sessions_format(&v3).unwrap();
        assert!(fmt.contains("session_name"));
        assert!(fmt.contains("session_created"));
        assert!(!fmt.contains("session_group"));
        let v32 = TmuxVersion {
            major: 3,
            minor: 2,
            ..Default::default()
        };
        assert!(get_list_sessions_format(&v32)
            .unwrap()
            .ends_with(r"\t#{session_group}"));
        let v20 = TmuxVersion {
            major: 2,
            minor: 0,
            ..Default::default()
        };
        assert!(!get_list_sessions_format(&v20)
            .unwrap()
            .contains("session_created"));
        assert!(get_list_sessions_format(&TmuxVersion::default()).is_none());
    }

    #[test]
    fn detect_output_reads_version_and_sockets() {
        let parsed = parse_detect_script_output(
            "__TMUX_VERSION__=tmux 3.0a\n__TMUX_BIN__=/usr/bin/tmux\n__SOCKET__=/tmp/tmux-0/default\n__SOCKET__=/tmp/tmux-0/default\n",
        );
        assert_eq!(parsed.version.major, 3);
        assert_eq!(parsed.binary, "/usr/bin/tmux");
        assert_eq!(parsed.sockets, vec!["/tmp/tmux-0/default"]);
    }

    #[test]
    fn detect_script_is_valid_single_line() {
        assert!(!TMUX_DETECT_SCRIPT.contains('\n'));
        assert!(!TMUX_DETECT_SCRIPT.contains("do;"));
        assert!(TMUX_DETECT_SCRIPT.contains("__SOCKET__="));
    }

    #[test]
    fn list_output_ignores_diagnostic_lines() {
        let sample = [
            "error connecting to /tmp/tmux-0/default (No such file or directory)",
            "no server running on /private/tmp/tmux-501/default",
            "can't find session: missing",
            "test-session: 1 windows (created Thu Jun 11 00:38:14 2026)",
        ]
        .join("\n");
        let sessions = parse_list_output(&sample);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["name"], "test-session");
        assert!(parse_list_output(
            "error connecting to /tmp/tmux-0/default (No such file or directory)\n"
        )
        .is_empty());
    }

    #[test]
    fn normalize_keeps_stdout_from_failed_exec() {
        let normalized = normalize_exec_result(ExecResult {
            success: false,
            error: Some("Command failed".into()),
            stderr: "test-session: 1 windows (created Thu Jun 11 00:38:14 2026)".into(),
            code: Some(1),
            ..Default::default()
        });
        assert!(normalized.success);
        assert_eq!(normalized.code, Some(1));
        assert_eq!(parse_list_output(&normalized.stdout).len(), 1);

        let failed = normalize_exec_result(ExecResult::fail("Not connected"));
        assert!(!failed.success);
        assert_eq!(failed.error.as_deref(), Some("Not connected"));

        let merged = normalize_exec_result(ExecResult::ok("out\n", "\x1b[31merr\x1b[0m", 0));
        assert_eq!(merged.stdout, "err\nout");
        assert_eq!(merged.stderr, "err");
    }

    #[test]
    fn invocation_quotes_socket_and_collapses_whitespace() {
        assert_eq!(
            build_tmux_invocation("", Some("/tmp/tmux-0/my sock"), "list-sessions  2>&1"),
            "tmux -S '/tmp/tmux-0/my sock' list-sessions 2>&1"
        );
        assert_eq!(
            build_tmux_invocation("/usr/bin/tmux", None, " ls "),
            "/usr/bin/tmux ls"
        );
    }
}
