//! `readRemoteHistory`: read the login shell's history file over exec —
//! port of `readRemoteHistory` in `electron/bridges/sshBridge/sessionOps.cjs`.

use crate::stats::quote_shell_arg;
use serde_json::{json, Value};

const SHELL_MARKER: &str = "__NC_SHELL__";
const BASH_MARKER: &str = "__NC_BASH__";
const ZSH_MARKER: &str = "__NC_ZSH__";
const FISH_MARKER: &str = "__NC_FISH__";

/// Exec bound (open + run), ms.
pub const HISTORY_TIMEOUT_MS: u64 = 8000;
/// Max output.
pub const HISTORY_MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;

/// Electron's limit sanitizing: finite, `0 < limit <= 10000`, floored;
/// otherwise 1000.
pub fn safe_limit(limit: Option<&Value>) -> u64 {
    match limit.and_then(Value::as_f64) {
        Some(l) if l.is_finite() && l > 0.0 && l <= 10000.0 => l.floor() as u64,
        _ => 1000,
    }
}

/// The POSIX command (`exec sh -c '<script>'`).
pub fn remote_history_command(limit: u64) -> String {
    let fish_limit = limit * 3;
    let zsh_hist = "${HISTFILE:-$HOME/.zsh_history}";
    let bash_hist = "${HISTFILE:-$HOME/.bash_history}";
    let fish_path = "${XDG_DATA_HOME:-$HOME/.local/share}/fish/fish_history";
    let script = [
        r#"SH="$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f7)"; [ -n "$SH" ] || SH="$SHELL""#.to_string(),
        format!(r#"FISH="{fish_path}"; [ -f "$FISH" ] || FISH="$HOME/.config/fish/fish_history""#),
        r#"case "$SH" in"#.to_string(),
        format!(r#"  *zsh) printf '%s\n' '{SHELL_MARKER}zsh'; printf '%s\n' '{ZSH_MARKER}'; tail -n {limit} "{zsh_hist}" 2>/dev/null || true ;;"#),
        format!(r#"  *bash) printf '%s\n' '{SHELL_MARKER}bash'; printf '%s\n' '{BASH_MARKER}'; tail -n {limit} "{bash_hist}" 2>/dev/null || true ;;"#),
        format!(r#"  *fish) printf '%s\n' '{SHELL_MARKER}fish'; printf '%s\n' '{FISH_MARKER}'; tail -n {fish_limit} "$FISH" 2>/dev/null || true ;;"#),
        format!(r#"  *) printf '%s\n' '{SHELL_MARKER}unknown'; printf '%s\n' '{BASH_MARKER}'; tail -n {limit} "$HOME/.bash_history" 2>/dev/null || true; printf '%s\n' '{ZSH_MARKER}'; tail -n {limit} "$HOME/.zsh_history" 2>/dev/null || true; printf '%s\n' '{FISH_MARKER}'; tail -n {fish_limit} "$FISH" 2>/dev/null || true ;;"#),
        "esac".to_string(),
    ]
    .join("\n");
    format!("exec sh -c {}", quote_shell_arg(&script))
}

fn section(text: &str, marker: &str) -> String {
    let Some(start) = text.find(marker) else {
        return String::new();
    };
    let from = start + marker.len();
    let end = [BASH_MARKER, ZSH_MARKER, FISH_MARKER]
        .iter()
        .filter_map(|m| text[from..].find(m).map(|i| i + from))
        .min()
        .unwrap_or(text.len());
    let body = &text[from..end];
    // `.replace(/^\r?\n/, '')`
    let body = body
        .strip_prefix("\r\n")
        .or_else(|| body.strip_prefix('\n'))
        .unwrap_or(body);
    // `.replace(/\r?\n\s*$/, '')`: the last newline followed only by
    // whitespace up to the end.
    let trimmed_end = body.trim_end();
    let tail = &body[trimmed_end.len()..];
    match tail.find('\n') {
        Some(nl) => {
            let cut = trimmed_end.len() + nl;
            let cut = if cut > 0 && body.as_bytes()[cut - 1] == b'\r' {
                cut - 1
            } else {
                cut
            };
            body[..cut].to_string()
        }
        None => body.to_string(),
    }
}

/// Parse the marked output into `{ shell, bash, zsh, fish }`.
pub fn parse_remote_history(stdout: &str) -> Value {
    let shell = match stdout.find(SHELL_MARKER) {
        Some(at) => {
            let after = &stdout[at + SHELL_MARKER.len()..];
            let first = after.split(['\r', '\n']).next().unwrap_or("").trim();
            if first.is_empty() {
                "unknown".to_string()
            } else {
                first.to_string()
            }
        }
        None => "unknown".to_string(),
    };
    json!({
        "shell": shell,
        "bash": section(stdout, BASH_MARKER),
        "zsh": section(stdout, ZSH_MARKER),
        "fish": section(stdout, FISH_MARKER),
    })
}

/// `{ success: true, shell, bash, zsh, fish }`.
pub fn history_reply(stdout: &str) -> Value {
    let mut reply = parse_remote_history(stdout);
    if let Value::Object(map) = &mut reply {
        map.insert("success".into(), json!(true));
    }
    reply
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_is_byte_identical_to_electron() {
        assert_eq!(
            remote_history_command(500),
            include_str!("../tests/fixtures/history500.txt")
        );
    }

    #[test]
    fn limits_are_sanitized() {
        assert_eq!(safe_limit(None), 1000);
        assert_eq!(safe_limit(Some(&json!(0))), 1000);
        assert_eq!(safe_limit(Some(&json!(20000))), 1000);
        assert_eq!(safe_limit(Some(&json!(12.9))), 12);
        assert_eq!(safe_limit(Some(&json!("5"))), 1000);
    }

    #[test]
    fn parses_marked_sections() {
        let out = "__NC_SHELL__zsh\n__NC_ZSH__\n: 1:0;ls\n: 2:0;pwd\n";
        let r = parse_remote_history(out);
        assert_eq!(r["shell"], "zsh");
        assert_eq!(r["zsh"], ": 1:0;ls\n: 2:0;pwd");
        assert_eq!(r["bash"], "");

        let out = "__NC_SHELL__unknown\r\n__NC_BASH__\r\nls\r\n__NC_ZSH__\n__NC_FISH__\n- cmd: ls\n  when: 1\n  \n";
        let r = history_reply(out);
        assert_eq!(r["success"], true);
        assert_eq!(r["shell"], "unknown");
        assert_eq!(r["bash"], "ls");
        assert_eq!(r["zsh"], "");
        assert_eq!(r["fish"], "- cmd: ls\n  when: 1");
        assert_eq!(parse_remote_history("")["shell"], "unknown");
    }
}
