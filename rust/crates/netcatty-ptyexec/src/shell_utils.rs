//! Shell utilities shared by the exec engine (Electron `shellUtils.cjs`):
//! ANSI stripping, default-prompt recognition, idle-prompt extraction and
//! the per-session rolling prompt tracker.

use regex::Regex;
use std::sync::LazyLock;

static ANSI_ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("\u{1b}\\[[0-?]*[ -/]*[@-~]").unwrap());
static ANSI_OSC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("\u{1b}\\][^\u{7}]*?(?:\u{7}|\u{1b}\\\\)").unwrap());

/// Max characters kept in the prompt-tracking tail.
pub const MAX_PROMPT_TRACK_TAIL: usize = 4096;

/// Remove CSI and OSC escape sequences.
pub fn strip_ansi(input: &str) -> String {
    let no_osc = ANSI_OSC.replace_all(input, "");
    ANSI_ESCAPE.replace_all(&no_osc, "").into_owned()
}

/// The agent's typed command is not echoed by the PTY as-is, so bridges
/// emit a synthetic echo; every line break becomes `\r\n`.
pub fn format_synthetic_echo(command: &str) -> String {
    let mut out = String::with_capacity(command.len() + 2);
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push_str("\r\n");
            }
            '\n' => out.push_str("\r\n"),
            c => out.push(c),
        }
    }
    out.push_str("\r\n");
    out
}

static POWERSHELL_PROMPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^PS(?:\s+\S.*)?>$").unwrap());
static CMD_PROMPT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^[A-Za-z]:(?:\\[^<>"|]*)?>$"#).unwrap());
static POSIX_PROMPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[^\s@]+@[^\s:]+(?::[^\n\r]*)?|\[[^\s@\]]+@[^\s\]:]+(?:\s+[^\n\r]+)?\])[#$]$")
        .unwrap()
});
static ZSH_PROMPT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[^\s@]+@[^\s:]+ [^\s%#$][^%#$\r\n]* [%#]$").unwrap());
static PAREN_POSIX_PROMPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\([^\s@()]+@[^\s:()]+\s+(?:[^()\r\n]|\([^()\r\n]*\))+\)[#$]$").unwrap()
});
static POSIX_PROMPT_HOST_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[^\s@]+@[^\s:]+(?::[^\n\r]*)?$").unwrap());
static OH_MY_ZSH_YS_HOST_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^#\s+[^\s@]+\s+@\s+[^\s]+(?:\s+[^\n\r]+)?$").unwrap());
static ALPINE_PROMPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*:(?:~(?:/[^#$\n\r]*)?|/[^#$\n\r]*)[#$]$").unwrap()
});
static POWERLEVEL10K_PROMPT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[^\s@]+@[^\s:]+\s+)?[^\s❯][^❯\r\n]*\s+❯$").unwrap());
static OH_MY_ZSH_ROBBYRUSSELL_PROMPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^➜(?:\s{2,}[^\s➜][^\s➜]*|\s~)(?:\s+git:\([^)\r\n]+\))?(?:\s+[✗✓])?$").unwrap()
});
static ENV_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\([^()\n\r]+\)\s+").unwrap());

fn trim_end_ws(s: &str) -> &str {
    s.trim_end_matches(|c: char| c.is_whitespace())
}

/// Default PowerShell prompt (`PS C:\Users\alice>`, `PS>`, `PS /home/alice>`).
pub fn is_default_powershell_prompt_line(line: &str) -> bool {
    POWERSHELL_PROMPT.is_match(line)
}

/// Default cmd.exe prompt (`C:\>`, `D:\data>`).
pub fn is_default_cmd_prompt_line(line: &str) -> bool {
    CMD_PROMPT.is_match(trim_end_ws(line))
}

/// Default POSIX login prompts (bash/zsh/RHEL/Alpine/p10k/robbyrussell).
pub fn is_default_posix_prompt_line(line: &str) -> bool {
    let normalized = trim_end_ws(line);
    let without_env = ENV_PREFIX.replace(normalized, "");
    let s: &str = &without_env;
    POSIX_PROMPT.is_match(s)
        || PAREN_POSIX_PROMPT.is_match(s)
        || ALPINE_PROMPT.is_match(s)
        || ZSH_PROMPT.is_match(s)
        || POWERLEVEL10K_PROMPT.is_match(s)
        || OH_MY_ZSH_ROBBYRUSSELL_PROMPT.is_match(s)
}

/// Last line of `prompt` with `\r` treated as a line break (PSReadLine
/// redraws), right-trimmed.
pub fn last_prompt_line(prompt: &str) -> String {
    let stripped = strip_ansi(prompt).replace('\r', "\n");
    trim_end_ws(stripped.rsplit('\n').next().unwrap_or("")).to_string()
}

pub fn is_powershell_prompt(prompt: &str) -> bool {
    is_default_powershell_prompt_line(&last_prompt_line(prompt))
}

pub fn is_cmd_prompt(prompt: &str) -> bool {
    is_default_cmd_prompt_line(&last_prompt_line(prompt))
}

pub fn is_posix_prompt(prompt: &str) -> bool {
    is_default_posix_prompt_line(&last_prompt_line(prompt))
}

/// The idle prompt at the end of `output`, or an empty string.
///
/// `\r` is a line break (ConPTY repaints). Recognises the default
/// PowerShell / POSIX / cmd prompts on the last line and the two-line
/// `user@host[:path]` + `$`/`#` (or Oh My Zsh `ys`) form, keeping the
/// blank lines a `\r\r\n` sequence produces.
pub fn extract_trailing_idle_prompt(output: &str) -> String {
    let normalized = strip_ansi(output).replace('\r', "\n");
    if normalized.is_empty() || normalized.ends_with('\n') {
        return String::new();
    }
    let mut lines: Vec<&str> = normalized.split('\n').collect();
    let last_line = lines.pop().unwrap_or("");
    let right_trimmed = trim_end_ws(last_line);
    if right_trimmed.is_empty() {
        return String::new();
    }
    if is_default_powershell_prompt_line(right_trimmed)
        || is_default_posix_prompt_line(right_trimmed)
        || is_default_cmd_prompt_line(right_trimmed)
    {
        return last_line.to_string();
    }
    if right_trimmed == "$" || right_trimmed == "#" {
        let mut host_index = lines.len() as isize - 1;
        while host_index >= 0 && trim_end_ws(lines[host_index as usize]).is_empty() {
            host_index -= 1;
        }
        let previous_line = if host_index >= 0 {
            lines[host_index as usize]
        } else {
            ""
        };
        let previous_trimmed = trim_end_ws(previous_line);
        let previous_host_line = ENV_PREFIX.replace(previous_trimmed, "");
        if POSIX_PROMPT_HOST_LINE.is_match(&previous_host_line)
            || OH_MY_ZSH_YS_HOST_LINE.is_match(&previous_host_line)
        {
            let start = host_index.max(0) as usize;
            return format!("{}\n{}", lines[start..].join("\n"), last_line);
        }
    }
    String::new()
}

/// Rolling per-session prompt state (Electron `trackSessionIdlePrompt`,
/// `getFreshIdlePrompt`, `getVisibleIdlePrompt`).
#[derive(Debug, Default, Clone)]
pub struct PromptTracker {
    /// Recent decoded output (last [`MAX_PROMPT_TRACK_TAIL`] chars).
    pub tail: String,
    /// Alternate-screen mode at the first byte of `tail`.
    pub alt_screen_at_tail_start: bool,
    pub last_idle_prompt: Option<String>,
    pub last_idle_prompt_at: Option<i64>,
    /// Whether any output was ever tracked (`_promptTrackTail` is a string).
    pub tracked: bool,
}

impl PromptTracker {
    /// Feed a decoded chunk. Returns the idle prompt it ends with, if any.
    pub fn track(&mut self, chunk: &str, now_ms: i64) -> String {
        if chunk.is_empty() {
            return String::new();
        }
        self.tracked = true;
        let mut combined = std::mem::take(&mut self.tail);
        combined.push_str(chunk);
        let total = combined.chars().count();
        if total > MAX_PROMPT_TRACK_TAIL {
            let overflow = total - MAX_PROMPT_TRACK_TAIL;
            let cut = combined
                .char_indices()
                .nth(overflow)
                .map(|(i, _)| i)
                .unwrap_or(combined.len());
            // Replay the dropped prefix so an alternate-screen switch that
            // scrolled off is still the mode at the first kept byte.
            self.alt_screen_at_tail_start =
                alternate_screen_active_after(&combined[..cut], self.alt_screen_at_tail_start);
            combined = combined[cut..].to_string();
        }
        self.tail = combined;
        let prompt = extract_trailing_idle_prompt(&self.tail);
        if !prompt.is_empty() {
            self.last_idle_prompt = Some(prompt.clone());
            self.last_idle_prompt_at = Some(now_ms);
        }
        prompt
    }

    /// `last_idle_prompt` only while the tail still ends with it.
    pub fn fresh_idle_prompt(&self) -> String {
        let Some(cached) = self.last_idle_prompt.as_deref() else {
            return String::new();
        };
        if cached.is_empty() || self.tail.is_empty() {
            return String::new();
        }
        let normalized_tail = strip_ansi(&self.tail).replace('\r', "\n");
        let normalized_cached = strip_ansi(cached).replace('\r', "\n");
        if normalized_cached.is_empty() {
            return String::new();
        }
        if normalized_tail.ends_with(&normalized_cached) {
            cached.to_string()
        } else {
            String::new()
        }
    }

    /// Readiness companion: the line the cursor is on after cursor / erase
    /// operations are applied, when it is a default prompt.
    pub fn visible_idle_prompt(&self) -> String {
        if self.tail.is_empty() {
            return String::new();
        }
        let cursor_line = terminal_cursor_line(&self.tail, self.alt_screen_at_tail_start);
        let right_trimmed = trim_end_ws(&cursor_line);
        if right_trimmed.is_empty() {
            return String::new();
        }
        if !is_default_powershell_prompt_line(right_trimmed)
            && !is_default_posix_prompt_line(right_trimmed)
            && !is_default_cmd_prompt_line(right_trimmed)
        {
            return String::new();
        }
        if cursor_line.ends_with(|c: char| c.is_whitespace()) {
            format!("{right_trimmed} ")
        } else {
            right_trimmed.to_string()
        }
    }

    /// `getFreshIdlePrompt(session) || getVisibleIdlePrompt(session)`.
    pub fn ready_prompt(&self) -> String {
        let fresh = self.fresh_idle_prompt();
        if !fresh.is_empty() {
            return fresh;
        }
        self.visible_idle_prompt()
    }
}

/// Line under the cursor after replaying `terminal_data` (empty while a
/// full-screen program owns the alternate screen).
pub fn terminal_cursor_line(terminal_data: &str, alternate_screen_active: bool) -> String {
    let mut renderer = netcatty_sessionlog::sanitizer::TerminalTextRenderer::new(alternate_screen_active);
    renderer.feed(terminal_data, None);
    let _ = renderer.finish();
    if renderer.alternate_screen_active() {
        return String::new();
    }
    renderer.cursor_line()
}

/// Alternate-screen mode after `text`, starting from `active`.
pub fn alternate_screen_active_after(text: &str, active: bool) -> bool {
    if text.is_empty() {
        return active;
    }
    let mut renderer = netcatty_sessionlog::sanitizer::TerminalTextRenderer::new(active);
    renderer.feed(text, None);
    renderer.alternate_screen_active()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ansi_and_osc() {
        assert_eq!(strip_ansi("\u{1b}[31mred\u{1b}[0m"), "red");
        assert_eq!(strip_ansi("\u{1b}]0;title\u{7}x"), "x");
        assert_eq!(strip_ansi("\u{1b}]0;title\u{1b}\\y"), "y");
    }

    #[test]
    fn synthetic_echo_normalises_line_breaks() {
        assert_eq!(format_synthetic_echo("a\nb\r\nc"), "a\r\nb\r\nc\r\n");
    }

    #[test]
    fn recognises_default_prompts() {
        assert!(is_powershell_prompt("PS C:\\Users\\alice>"));
        assert!(is_powershell_prompt("PS>"));
        assert!(is_powershell_prompt("PS /home/alice>"));
        assert!(is_powershell_prompt("PS C:\\Users\\alice>   "));
        assert!(!is_powershell_prompt("PS >"));
        assert!(!is_powershell_prompt("PSO>"));
        assert!(is_powershell_prompt("\u{1b}[32mPS C:\\x>\u{1b}[0m"));
        assert!(is_cmd_prompt("C:\\Users\\alice>"));
        assert!(!is_cmd_prompt("C: >"));
        assert!(is_posix_prompt("alice@host:~$"));
        assert!(is_posix_prompt("[alice@host ~]$"));
        assert!(is_posix_prompt("alice@mac ~ %"));
        assert!(is_posix_prompt("localhost:~#"));
        assert!(is_posix_prompt("(venv) alice@host:~$"));
        assert!(is_posix_prompt("~ ❯"));
        assert!(!is_posix_prompt("❯"));
        assert!(is_posix_prompt("➜  netcatty git:(main) ✗"));
        assert!(!is_posix_prompt("➜ ls"));
        assert!(!is_posix_prompt("alice@host ~ % echo %"));
    }

    #[test]
    fn redrawn_last_line_is_the_prompt() {
        assert!(is_powershell_prompt("PS C:\\old>\rPS C:\\new>"));
        assert_eq!(
            extract_trailing_idle_prompt("PS C:\\old>\rPS C:\\new>"),
            "PS C:\\new>"
        );
    }

    #[test]
    fn extracts_two_line_prompts() {
        assert_eq!(
            extract_trailing_idle_prompt("alice@host:~\r\r\n$ "),
            "alice@host:~\n\n\n$ "
        );
        assert_eq!(extract_trailing_idle_prompt("just text\n$ "), "");
        assert_eq!(extract_trailing_idle_prompt("alice@host:~$ \n"), "");
        assert_eq!(
            extract_trailing_idle_prompt("# alice @ host in ~ [12:00:00]\n$ "),
            "# alice @ host in ~ [12:00:00]\n$ "
        );
    }

    #[test]
    fn tracker_keeps_fresh_prompt_only_while_tail_ends_with_it() {
        let mut t = PromptTracker::default();
        t.track("login\r\nalice@host:~$ ", 1);
        assert_eq!(t.fresh_idle_prompt(), "alice@host:~$ ");
        t.track("ls\r\n", 2);
        assert_eq!(t.fresh_idle_prompt(), "");
        assert_eq!(t.ready_prompt(), "");
        t.track("alice@host:~$ ", 3);
        assert_eq!(t.ready_prompt(), "alice@host:~$ ");
    }

    #[test]
    fn visible_prompt_survives_csi_erase() {
        let mut t = PromptTracker::default();
        t.track("PS C:\\Users\\alice> ", 1);
        t.track("abc\u{1b}[3D\u{1b}[K", 2);
        assert_eq!(t.fresh_idle_prompt(), "");
        assert_eq!(t.visible_idle_prompt(), "PS C:\\Users\\alice> ");
    }

    #[test]
    fn tracker_tail_is_bounded() {
        let mut t = PromptTracker::default();
        t.track(&"x".repeat(5000), 1);
        assert_eq!(t.tail.chars().count(), MAX_PROMPT_TRACK_TAIL);
    }
}
