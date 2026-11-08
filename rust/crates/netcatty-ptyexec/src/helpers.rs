//! Wrapper command builders, marker detection and output normalisation
//! (Electron `ptyExecHelpers.cjs`).

use crate::shell_utils::{is_cmd_prompt, is_posix_prompt, is_powershell_prompt, strip_ansi};

/// Prefix of every job marker; a PTY line containing it is internal.
pub const MARKER_PREFIX: &str = "__NCMCP_";

const PROMPT_SUFFIX_MIN_WINDOW_CHARS: usize = 2048;
const PROMPT_SUFFIX_WINDOW_PER_PROMPT_CHAR: usize = 8;

/// Last `n` chars of `s`.
pub fn tail_chars(s: &str, n: usize) -> &str {
    let total = s.chars().count();
    if total <= n {
        return s;
    }
    let skip = total - n;
    let start = s.char_indices().nth(skip).map(|(i, _)| i).unwrap_or(0);
    &s[start..]
}

/// Does the (ANSI-free, CR-less) tail of `text` end with `expected_prompt`?
pub fn has_expected_prompt_suffix(text: &str, expected_prompt: &str) -> bool {
    if expected_prompt.is_empty() {
        return false;
    }
    let ansi_free_prompt = strip_ansi(expected_prompt);
    let normalized_prompt = ansi_free_prompt.replace('\r', "");
    if normalized_prompt.is_empty() {
        return false;
    }
    let window_chars = PROMPT_SUFFIX_MIN_WINDOW_CHARS
        .max(expected_prompt.chars().count() * PROMPT_SUFFIX_WINDOW_PER_PROMPT_CHAR);
    let tail = tail_chars(text, window_chars);
    let stripped_tail = strip_ansi(tail);
    if stripped_tail.replace('\r', "").ends_with(&normalized_prompt) {
        return true;
    }
    if !ansi_free_prompt.contains('\n') {
        return false;
    }
    let cr_as_lf_prompt = ansi_free_prompt.replace('\r', "\n");
    stripped_tail.replace('\r', "\n").ends_with(&cr_as_lf_prompt)
}

pub fn escape_posix_single_quoted(text: &str) -> String {
    text.replace('\'', "'\\''")
}

pub fn escape_powershell_single_quoted(text: &str) -> String {
    text.replace('\'', "''")
}

pub fn escape_fish_single_quoted(text: &str) -> String {
    text.replace('\\', "\\\\").replace('\'', "\\'")
}

pub fn escape_cmd_for_nested_shell(text: &str) -> String {
    text.replace('"', "\"\"").replace('%', "%%")
}

const LOGIN_SHELL_HINTS: [&str; 4] = ["posix", "fish", "powershell", "cmd"];

/// Which wrapper to type: confirmed `shell_kind` wins; an open kind (`""` /
/// `unknown`) lets a live default PowerShell / cmd prompt override, and a
/// live POSIX prompt beats a Windows login-shell soft hint; otherwise the
/// login-shell hint, else `posix`.
pub fn resolve_effective_shell_kind(shell_kind: &str, expected_prompt: &str, login_shell_hint: &str) -> String {
    let base_kind = shell_kind;
    let hint = login_shell_hint;
    if base_kind.is_empty() || base_kind == "unknown" {
        if is_powershell_prompt(expected_prompt) {
            return "powershell".into();
        }
        if is_cmd_prompt(expected_prompt) {
            return "cmd".into();
        }
        if is_posix_prompt(expected_prompt) && (hint == "powershell" || hint == "cmd") {
            return "posix".into();
        }
    }
    if !base_kind.is_empty() {
        return base_kind.to_string();
    }
    if LOGIN_SHELL_HINTS.contains(&hint) {
        return hint.to_string();
    }
    "posix".into()
}

/// Keys that discard unfinished prompt-line input before the wrapper.
pub fn build_pending_input_clear_prefix(shell_kind: &str) -> &'static str {
    match shell_kind {
        "raw" => "",
        "cmd" => "\x1b",
        "powershell" => "\x1bggd2147483647d\x1br\x1b\x1bi\x08",
        _ => "\x0b\x15",
    }
}

pub fn bash_history_scratch_names(marker: &str) -> (String, String) {
    let lower: String = marker
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let suffix: String = tail_chars(&lower, 12).to_string();
    let suffix = if suffix.is_empty() { "dflt".to_string() } else { suffix };
    (format!("__nc_h_{suffix}"), format!("__nc_d_{suffix}"))
}

pub fn build_bash_history_cleanup(marker: &str, keep_dispatcher: bool) -> String {
    let (entry, dispatcher) = bash_history_scratch_names(marker);
    let previous = format!("{entry}_prev");
    let unset_names = if keep_dispatcher {
        format!("{entry} {previous}")
    } else {
        format!("{entry} {previous} {dispatcher}")
    };
    let parts = [
        format!("[ \"${{BASH_VERSION-}}\" ]&&{{ for {dispatcher} in command builtin;do {entry}=$(${dispatcher} printf x);[ \"${entry}\" = x ]||continue;"),
        format!("{entry}=$(${dispatcher} history 1);while :;do case \"${entry}\" in *{marker}*)"),
        format!("{entry}=${{{entry}#\"${{{entry}%%[^[:space:]]*}}\"}};{previous}=${{{entry}%%[[:space:]]*}};${dispatcher} history -d \"${previous}\";"),
        format!("{entry}=$(${dispatcher} history 1);case \"${entry}\" in *{marker}*)"),
        format!("{entry}=${{{entry}#\"${{{entry}%%[^[:space:]]*}}\"}};[ \"${{{entry}%%[[:space:]]*}}\" -lt \"${previous}\" ]||break;;*) break;;esac;;*) break;;esac;done;"),
        format!("case \"${entry}\" in *{marker}*) continue;;esac;"),
        format!("${dispatcher} unset {unset_names};break;done; }} 2>/dev/null"),
    ];
    parts.join(&format!(" \\\n: \"{marker}\"; "))
}

fn build_posix_wrapper_body(command: &str, marker: &str, start_format: &str, omit_bash_history_cleanup: bool) -> String {
    let no_pager = "PAGER=cat SYSTEMD_PAGER= GIT_PAGER=cat LESS= ";
    let normalized = command.replace("\r\n", "\n").replace('\r', "\n");
    let command_lines: Vec<&str> = normalized.split('\n').collect();
    let mut cmd_assign = if command_lines.len() > 1 {
        let quoted: Vec<String> = command_lines
            .iter()
            .map(|line| format!("'{}'", escape_posix_single_quoted(line)))
            .collect();
        format!("{marker}_cmd=$(printf '%s\\n' {})", quoted.join(" "))
    } else {
        format!("{marker}_cmd='{}'", escape_posix_single_quoted(command))
    };
    if cmd_assign.len() > 350 {
        // Keep every physical line below BusyBox's 512-byte editor limit.
        let mut writes: Vec<String> = Vec::new();
        for (index, line) in command_lines.iter().enumerate() {
            let mut chunk = String::new();
            let mut bytes = 0usize;
            for character in line.chars() {
                let quoted = escape_posix_single_quoted(&character.to_string());
                let size = quoted.len();
                if bytes + size > 300 {
                    writes.push(format!("printf '%s' '{chunk}'"));
                    chunk = String::new();
                    bytes = 0;
                }
                chunk.push_str(&quoted);
                bytes += size;
            }
            let fmt = if index < command_lines.len() - 1 { "%s\\n" } else { "%s" };
            writes.push(format!("printf '{fmt}' '{chunk}'"));
        }
        cmd_assign = format!("{marker}_cmd=$({})", writes.join(&format!("; \\\n: '{marker}'; ")));
    }
    let mut lines: Vec<String> = vec![
        format!(" : '{marker}'; {cmd_assign}"),
        format!("{{ printf '{start_format}' '{marker}_S'; trap ':' INT; ( {no_pager}eval \"${marker}_cmd\" ); __NCMCP_rc=$?; trap - INT"),
        format!("printf '%s\\n' '{marker}_E:'\"$__NCMCP_rc\""),
    ];
    if !omit_bash_history_cleanup {
        lines.push(build_bash_history_cleanup(marker, false));
    }
    lines.push("(exit $__NCMCP_rc); }".to_string());
    format!(
        "{marker}=0; printf '\\n%s\\n' '{marker}_I'\n{}",
        lines.join(&format!("; \\\n: '{marker}'; "))
    )
}

/// The full wrapper typed into the shell for `command`.
pub fn build_wrapped_command(
    command: &str,
    shell_kind: &str,
    marker: &str,
    separate_start_marker: bool,
    omit_bash_history_cleanup: bool,
) -> String {
    let start_format = if separate_start_marker { "\\n%s\\n" } else { "%s\\n" };
    match shell_kind {
        "powershell" => {
            let ps_pager = "$env:PAGER='cat'; $env:SYSTEMD_PAGER=''; $env:GIT_PAGER='cat'; $env:LESS=''; ";
            let ps_escaped = escape_powershell_single_quoted(command);
            format!(
                "${marker}=0; ${marker}_cmd='{ps_escaped}'; & {{ Write-Output '{marker}_S'; {ps_pager}$LASTEXITCODE=$null; try {{ Invoke-Expression ${marker}_cmd; ${marker}_rc = if ($LASTEXITCODE -ne $null) {{ $LASTEXITCODE }} elseif ($?) {{ 0 }} else {{ 1 }} }} catch {{ ${marker}_rc = 1 }}; Write-Output \"{marker}_E:${marker}_rc\" }}\r"
            )
        }
        "cmd" => {
            let cmd_escaped = escape_cmd_for_nested_shell(command);
            format!(
                "set \"{marker}=0\" & set \"{marker}_CMD={cmd_escaped}\" & (echo {marker}_S & set \"PAGER=cat\" & set \"SYSTEMD_PAGER=\" & set \"GIT_PAGER=cat\" & set \"LESS=\" & call cmd /d /s /c \"%{marker}_CMD%\" & call echo {marker}_E:^%errorlevel^%)\r\n"
            )
        }
        "fish" => format!(
            " set {marker} 0; function __ncmcp_int --on-signal INT; printf '%s\\n' '{marker}_E:130'; functions -e __ncmcp_int; end; set -l {marker}_cmd '{}'; begin; set -gx PAGER cat; set -gx SYSTEMD_PAGER ''; set -gx GIT_PAGER cat; set -gx LESS ''; printf '{start_format}' '{marker}_S'; eval ${marker}_cmd; set __NCMCP_rc $status; functions -e __ncmcp_int; printf '%s\\n' '{marker}_E:'$__NCMCP_rc; end\n",
            escape_fish_single_quoted(command)
        ),
        _ => format!(
            " {}\n",
            build_posix_wrapper_body(command, marker, "\\n%s\\n", omit_bash_history_cleanup)
        ),
    }
}

/// Byte index of `marker_E:` and the exit code after it. Before the start
/// marker is confirmed the match must sit on a line boundary.
pub fn find_end_marker(output: &str, marker: &str, allow_inline: bool) -> Option<(usize, i32)> {
    let end_pattern = format!("{marker}_E:");
    let mut search_from = 0usize;
    while search_from < output.len() {
        let rel = output[search_from..].find(&end_pattern)?;
        let end_idx = search_from + rel;
        let at_boundary = allow_inline
            || end_idx == 0
            || output[..end_idx].ends_with('\n')
            || output[..end_idx].ends_with('\r');
        if at_boundary {
            let after = &output[end_idx + end_pattern.len()..];
            let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !digits.is_empty() {
                if let Ok(code) = digits.parse::<i64>() {
                    return Some((end_idx, code.clamp(i32::MIN as i64, i32::MAX as i64) as i32));
                }
            }
        }
        search_from = end_idx + 1;
    }
    None
}

/// Strip whole lines containing `marker` (or any `__NCMCP_` line when
/// `marker` is `None`).
pub fn strip_marker_lines(text: &str, marker: Option<&str>) -> String {
    let needle = marker.unwrap_or(MARKER_PREFIX);
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let (line, remainder) = match rest.find('\n') {
            Some(i) => (&rest[..i + 1], &rest[i + 1..]),
            None => (rest, ""),
        };
        rest = remainder;
        let content = line.trim_end_matches(['\n', '\r']);
        if content.contains(needle) {
            continue;
        }
        out.push_str(line);
    }
    out
}

/// Strip this job's marker lines but keep text before the marker on the
/// same line (Electron `stripJobMarkerLines`).
pub fn strip_job_marker_lines(text: &str, marker: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        // Lines are terminated by \r or \n in the JS multiline regex sense.
        let line_end = rest.find(['\r', '\n']).unwrap_or(rest.len());
        let line = &rest[..line_end];
        let mut after = &rest[line_end..];
        if let Some(idx) = line.find(marker) {
            out.push_str(&line[..idx]);
            // Consume the trailing newline run.
            let trimmed = after.trim_start_matches(['\r', '\n']);
            after = trimmed;
        } else {
            out.push_str(line);
            // Preserve one line terminator sequence.
            let term_len = after.len() - after.trim_start_matches(['\r', '\n']).len();
            let (term, next) = after.split_at(term_len);
            out.push_str(term);
            after = next;
        }
        rest = after;
    }
    out
}

/// Length of the longest prefix of `prefix` that `text` ends with.
pub fn trailing_prefix_length(text: &str, prefix: &str) -> usize {
    let max = text.len().min(prefix.len());
    for length in (1..=max).rev() {
        if prefix.is_char_boundary(length) && text.ends_with(&prefix[..length]) {
            return length;
        }
    }
    0
}

/// Options for [`normalize_pty_output`].
#[derive(Debug, Clone, Default)]
pub struct NormalizeOptions<'a> {
    pub strip_markers: bool,
    pub expected_prompt: &'a str,
    pub trim_output: bool,
    pub strip_prompt: bool,
    pub marker_to_strip: Option<&'a str>,
}

pub fn normalize_pty_output(stdout: &str, opts: &NormalizeOptions<'_>) -> String {
    let mut cleaned = strip_ansi(stdout).replace('\r', "");
    if opts.strip_markers {
        cleaned = strip_marker_lines(&cleaned, opts.marker_to_strip);
    }
    let normalized_prompt = strip_ansi(opts.expected_prompt).replace('\r', "");
    if opts.strip_prompt && !normalized_prompt.is_empty() && cleaned.ends_with(&normalized_prompt) {
        cleaned.truncate(cleaned.len() - normalized_prompt.len());
    }
    if opts.trim_output {
        cleaned.trim().to_string()
    } else {
        cleaned
    }
}

/// Append `chunk` to `current` keeping at most `limit` chars; returns the
/// number of chars dropped from the front.
pub fn append_bounded_output(current: &mut String, chunk: &str, limit: usize) -> usize {
    let chunk_chars = chunk.chars().count();
    if limit > 0 && chunk_chars >= limit {
        let current_chars = current.chars().count();
        let kept = tail_chars(chunk, limit).to_string();
        *current = kept;
        return current_chars + chunk_chars - limit;
    }
    current.push_str(chunk);
    if limit == 0 {
        return 0;
    }
    let total = current.chars().count();
    if total <= limit {
        return 0;
    }
    let dropped = total - limit;
    let cut = current.char_indices().nth(dropped).map(|(i, _)| i).unwrap_or(0);
    current.drain(..cut);
    dropped
}

/// Strip complete CSI / OSC sequences and collapse `\r\n`; an incomplete
/// escape at the end is returned as `carry` for the next chunk.
pub fn consume_visible_text(carry: &str, chunk: &str) -> (String, String) {
    let input = format!("{carry}{chunk}");
    if input.is_empty() {
        return (String::new(), String::new());
    }
    let chars: Vec<char> = input.chars().collect();
    let mut visible = String::new();
    let mut index = 0usize;
    while index < chars.len() {
        let ch = chars[index];
        if ch == '\r' {
            if chars.get(index + 1) == Some(&'\n') {
                visible.push('\n');
                index += 2;
                continue;
            }
            visible.push('\r');
            index += 1;
            continue;
        }
        if ch != '\u{1b}' {
            visible.push(ch);
            index += 1;
            continue;
        }
        if index + 1 >= chars.len() {
            break;
        }
        let next = chars[index + 1];
        if next == '[' {
            let mut cursor = index + 2;
            let mut complete = false;
            while cursor < chars.len() {
                let code = chars[cursor] as u32;
                if (0x40..=0x7e).contains(&code) {
                    index = cursor + 1;
                    complete = true;
                    break;
                }
                cursor += 1;
            }
            if !complete {
                break;
            }
            continue;
        }
        if next == ']' {
            let mut cursor = index + 2;
            let mut complete = false;
            while cursor < chars.len() {
                let osc = chars[cursor];
                if osc == '\u{7}' {
                    index = cursor + 1;
                    complete = true;
                    break;
                }
                if osc == '\u{1b}' {
                    if cursor + 1 >= chars.len() {
                        break;
                    }
                    if chars[cursor + 1] == '\\' {
                        index = cursor + 2;
                        complete = true;
                        break;
                    }
                }
                cursor += 1;
            }
            if !complete {
                break;
            }
            continue;
        }
        visible.push(ch);
        index += 1;
    }
    let rest: String = chars[index..].iter().collect();
    (visible, rest)
}

/// Fresh random job marker (`__NCMCP_<base36 time>_<32 hex>__`).
pub fn new_marker() -> String {
    let bytes: [u8; 16] = rand::random();
    format!("{MARKER_PREFIX}{}_{}__", base36_now(), hex::encode(bytes))
}

pub(crate) fn base36_now() -> String {
    let mut n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if n == 0 {
        return "0".into();
    }
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    while n > 0 {
        out.push(digits[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_suffix_tolerates_cr_redraw_and_two_line_prompts() {
        assert!(has_expected_prompt_suffix("out\r\nroot@host:~\r# ", "root@host:~# "));
        assert!(has_expected_prompt_suffix(
            "out\r\nuser@host: /root\r\r\n$ ",
            "user@host: /root\n\n\n$ "
        ));
        assert!(!has_expected_prompt_suffix("out", ""));
        assert!(!has_expected_prompt_suffix("out\n$ ", "user@host:~$ "));
    }

    #[test]
    fn resolve_shell_kind_follows_prompt_and_hint_rules() {
        assert_eq!(resolve_effective_shell_kind("", "PS C:\\x>", ""), "powershell");
        assert_eq!(resolve_effective_shell_kind("unknown", "PS C:\\x>", ""), "powershell");
        assert_eq!(resolve_effective_shell_kind("", "C:\\x>", ""), "cmd");
        assert_eq!(resolve_effective_shell_kind("posix", "PS C:\\x>", ""), "posix");
        assert_eq!(resolve_effective_shell_kind("powershell", "alice@host:~$", ""), "powershell");
        assert_eq!(resolve_effective_shell_kind("", "", ""), "posix");
        assert_eq!(resolve_effective_shell_kind("", "", "fish"), "fish");
        assert_eq!(resolve_effective_shell_kind("", "", "cmd"), "cmd");
        assert_eq!(resolve_effective_shell_kind("", "alice@host:~$", "powershell"), "posix");
        assert_eq!(resolve_effective_shell_kind("", "alice@host:~$", "fish"), "fish");
        assert_eq!(resolve_effective_shell_kind("", "PS >", ""), "posix");
    }

    #[test]
    fn clear_prefix_per_shell() {
        assert_eq!(build_pending_input_clear_prefix("raw"), "");
        assert_eq!(build_pending_input_clear_prefix("cmd"), "\x1b");
        assert_eq!(build_pending_input_clear_prefix("posix"), "\x0b\x15");
        assert!(build_pending_input_clear_prefix("powershell").starts_with("\x1bgg"));
    }

    #[test]
    fn wrappers_have_expected_shape() {
        let m = "__NCMCP_t_abc__";
        let ps = build_wrapped_command("Get-Date", "powershell", m, false, false);
        assert!(ps.ends_with('\r') && !ps.ends_with("\r\n"));
        assert!(ps.contains("Invoke-Expression"));
        let cmd = build_wrapped_command("dir", "cmd", m, false, false);
        assert!(cmd.contains("call cmd /d /s /c \"%__NCMCP_t_abc___CMD%\""));
        assert!(cmd.ends_with("\r\n"));
        let fish = build_wrapped_command("echo hi", "fish", m, true, false);
        assert!(fish.starts_with(" set __NCMCP_t_abc__ 0;"));
        let posix = build_wrapped_command("echo 'hi'", "posix", m, true, false);
        assert!(posix.starts_with(" __NCMCP_t_abc__=0; printf '\\n%s\\n' '__NCMCP_t_abc___I'\n"));
        assert!(posix.contains("( PAGER=cat SYSTEMD_PAGER= GIT_PAGER=cat LESS= eval \"$__NCMCP_t_abc___cmd\" )"));
        assert!(posix.contains("history -d"));
        assert!(posix.ends_with("(exit $__NCMCP_rc); }\n"));
        for line in posix.lines() {
            assert!(line.len() < 512, "line too long: {}", line.len());
        }
        let zsh = build_wrapped_command("echo", "posix", m, true, true);
        assert!(!zsh.contains("history -d"));
    }

    #[test]
    fn long_posix_commands_are_chunked() {
        let m = "__NCMCP_t_abc__";
        let long = "x".repeat(900);
        let wrapped = build_wrapped_command(&long, "posix", m, true, false);
        assert!(wrapped.contains("printf '%s' '"));
        for line in wrapped.lines() {
            assert!(line.len() < 512);
        }
    }

    #[test]
    fn end_marker_detection() {
        let m = "__NCMCP_t_abc__";
        assert_eq!(find_end_marker("out\n__NCMCP_t_abc___E:3\n", m, false), Some((4, 3)));
        assert_eq!(find_end_marker("echo __NCMCP_t_abc___E:3", m, false), None);
        assert_eq!(find_end_marker("tail__NCMCP_t_abc___E:0", m, true), Some((4, 0)));
        assert_eq!(find_end_marker("__NCMCP_t_abc___E:", m, true), None);
    }

    #[test]
    fn normalisation_and_bounded_append() {
        let m = "__NCMCP_t_abc__";
        let text = "x\r\n__NCMCP_t_abc___S\nhello\n__NCMCP_t_abc___E:0\nuser@host:~$ ";
        assert_eq!(
            normalize_pty_output(
                text,
                &NormalizeOptions {
                    strip_markers: true,
                    expected_prompt: "user@host:~$ ",
                    trim_output: true,
                    strip_prompt: true,
                    marker_to_strip: Some(m),
                }
            ),
            "x\nhello"
        );
        assert_eq!(strip_job_marker_lines("a __NCMCP_t_abc___E:0\nb\n", m), "a b\n");
        let mut buf = String::from("abc");
        assert_eq!(append_bounded_output(&mut buf, "defg", 5), 2);
        assert_eq!(buf, "cdefg");
        let mut buf = String::from("abc");
        assert_eq!(append_bounded_output(&mut buf, "0123456789", 5), 8);
        assert_eq!(buf, "56789");
    }

    #[test]
    fn visible_text_strips_escapes_and_carries_partials() {
        let (v, c) = consume_visible_text("", "a\u{1b}[31mb\r\nc\u{1b}[");
        assert_eq!(v, "ab\nc");
        assert_eq!(c, "\u{1b}[");
        let (v, c) = consume_visible_text(&c, "0m\u{1b}]0;t\u{7}d");
        assert_eq!(v, "d");
        assert_eq!(c, "");
        assert_eq!(trailing_prefix_length("abc__NCM", "__NCMCP_x_E:"), 5);
        assert_eq!(trailing_prefix_length("abc", "__NCMCP_"), 0);
    }

    #[test]
    fn markers_are_unique() {
        let a = new_marker();
        let b = new_marker();
        assert_ne!(a, b);
        assert!(a.starts_with(MARKER_PREFIX) && a.ends_with("__"));
    }
}
