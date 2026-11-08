//! Live shell probe typed into the interactive PTY before the wrapper
//! (Electron `liveShellProbe.cjs`): reveals the active shell (fish / posix)
//! without opening a second SSH channel.

use crate::helpers::{bash_history_scratch_names, build_bash_history_cleanup};

/// Both fish and POSIX shells accept this; it names the parent of a
/// short-lived `sh` (the interactive shell, not the SSH login shell).
pub fn build_live_shell_probe(marker: &str) -> String {
    let script = format!(
        "if test -r \"/proc/$PPID/comm\"; then IFS= read -r name < \"/proc/$PPID/comm\"; else name=$(ps -p \"$PPID\" -o comm= 2>/dev/null); fi; printf \"\\n{marker}_P:%s\\n\" \"$name\""
    );
    format!(" true {marker}; printf '\\n%s\\n' '{marker}_I'\n : '{marker}'; command sh -c '{script}' 2>/dev/null; printf '%s' '{marker}_Q'\n")
}

/// Bash-only history cleanup sent after the probe (skipped for zsh / fish).
pub fn build_live_shell_probe_cleanup(marker: &str) -> String {
    let cleanup = build_bash_history_cleanup(marker, true);
    let (_, dispatcher) = bash_history_scratch_names(marker);
    let clear = format!("[ -z \"${{{dispatcher}-}}\" ]||${dispatcher} unset {dispatcher}");
    let fallback = format!("[ \"${{{dispatcher}-}}\" = command ]||{{ {cleanup}; }};{clear}");
    format!(" : '{marker}'; \\command eval '{cleanup}' 2>/dev/null || true; \\\n: '{marker}'; \\eval '{fallback}' 2>/dev/null || true; \\\n: '{marker}'; \\command eval '{clear}' 2>/dev/null || true\n")
}

/// Strip PS2 continuation / prompt leftovers from a probe reply line.
pub fn normalize_live_shell_probe_line(line: &str) -> &str {
    line.trim_start_matches(|c: char| matches!(c, '>' | '#' | '$' | '%') || c.is_whitespace())
}

/// Parsed probe reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveShellProbe {
    pub shell_name: String,
    /// `fish` / `posix` / `None` when unclassified.
    pub kind: Option<&'static str>,
}

/// `None` until the `_Q` sentinel arrived.
pub fn parse_live_shell_probe(output: &str, marker: &str) -> Option<LiveShellProbe> {
    let normalized = output.replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    let q = format!("{marker}_Q");
    if !lines.iter().any(|l| normalize_live_shell_probe_line(l).starts_with(&q)) {
        return None;
    }
    let p = format!("{marker}_P:");
    for line in &lines {
        let n = normalize_live_shell_probe_line(line);
        let Some(rest) = n.strip_prefix(&p) else {
            continue;
        };
        let name = rest.trim().rsplit('/').next().unwrap_or("").trim_start_matches('-').to_string();
        let kind = if name == "fish" {
            Some("fish")
        } else if is_posix_shell_name(&name) {
            Some("posix")
        } else {
            None
        };
        return Some(LiveShellProbe { shell_name: name, kind });
    }
    Some(LiveShellProbe {
        shell_name: String::new(),
        kind: None,
    })
}

fn is_posix_shell_name(name: &str) -> bool {
    matches!(name, "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash")
}

/// `zsh`, `zsh-5.9`, `zsh.exe`-ish names.
pub fn is_zsh_shell_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "zsh"
        || (lower.starts_with("zsh")
            && lower[3..]
                .chars()
                .next()
                .is_some_and(|c| c == '-' || c == '.')
            && lower[4..].starts_with(|c: char| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_probe_replies() {
        let m = "__NCMCP_t_abc__";
        assert_eq!(parse_live_shell_probe("__NCMCP_t_abc___P:bash\n", m), None);
        let r = parse_live_shell_probe("\n__NCMCP_t_abc___P:bash\n__NCMCP_t_abc___Q", m).unwrap();
        assert_eq!(r.kind, Some("posix"));
        assert_eq!(r.shell_name, "bash");
        let r = parse_live_shell_probe("> __NCMCP_t_abc___P:-fish\r\n$ __NCMCP_t_abc___Q", m).unwrap();
        assert_eq!(r.kind, Some("fish"));
        let r = parse_live_shell_probe("__NCMCP_t_abc___P:/usr/bin/nu\n__NCMCP_t_abc___Q", m).unwrap();
        assert_eq!(r.kind, None);
        assert_eq!(r.shell_name, "nu");
        let r = parse_live_shell_probe("__NCMCP_t_abc___Q", m).unwrap();
        assert_eq!(r.shell_name, "");
        assert!(is_zsh_shell_name("zsh") && is_zsh_shell_name("zsh-5.9") && !is_zsh_shell_name("zshrc"));
    }

    #[test]
    fn probe_text_shape() {
        let p = build_live_shell_probe("__NCMCP_t_abc__");
        assert!(p.starts_with(" true __NCMCP_t_abc__; printf '\\n%s\\n' '__NCMCP_t_abc___I'\n"));
        assert!(p.ends_with("printf '%s' '__NCMCP_t_abc___Q'\n"));
        let c = build_live_shell_probe_cleanup("__NCMCP_t_abc__");
        assert!(c.contains("\\command eval"));
    }
}
