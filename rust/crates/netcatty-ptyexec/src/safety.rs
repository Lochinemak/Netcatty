//! Shell-aware command blocklist (Electron `lib/commandBlocklist.cjs` +
//! `commandSafety.cjs`). The default table is `lib/commandBlocklist.json`
//! (embedded at build time); patterns are JavaScript-style regexes compiled
//! case-insensitively with `fancy-regex` (lookaround support).

use fancy_regex::Regex;
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Table {
    common: Vec<String>,
    posix_native: Vec<String>,
    posix: Vec<String>,
    powershell: Vec<String>,
    shell_groups: HashMap<String, Vec<String>>,
}

static TABLE: LazyLock<Table> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../../lib/commandBlocklist.json"))
        .expect("lib/commandBlocklist.json is valid")
});

/// Flat union of every default pattern (strictest selection).
pub fn default_command_blocklist() -> Vec<String> {
    let t = &*TABLE;
    t.common
        .iter()
        .chain(&t.posix_native)
        .chain(&t.posix)
        .chain(&t.powershell)
        .cloned()
        .collect()
}

pub fn common_patterns() -> &'static [String] {
    &TABLE.common
}

static DEFAULT_SET: LazyLock<HashSet<String>> =
    LazyLock::new(|| default_command_blocklist().into_iter().collect());

pub fn is_default_blocklist_pattern(pattern: &str) -> bool {
    DEFAULT_SET.contains(pattern)
}

/// Default patterns for a shell kind; unknown kinds keep the full table.
pub fn select_default_blocklist_patterns(shell_kind: &str) -> Vec<String> {
    let t = &*TABLE;
    match t.shell_groups.get(&shell_kind.to_lowercase()) {
        Some(groups) => groups
            .iter()
            .flat_map(|g| match g.as_str() {
                "common" => t.common.clone(),
                "posixNative" => t.posix_native.clone(),
                "posix" => t.posix.clone(),
                "powershell" => t.powershell.clone(),
                _ => Vec::new(),
            })
            .collect(),
        None => default_command_blocklist(),
    }
}

static COMPILED: LazyLock<Mutex<HashMap<String, Option<Regex>>>> = LazyLock::new(Default::default);

fn compiled(pattern: &str) -> Option<Regex> {
    let mut cache = COMPILED.lock();
    if let Some(entry) = cache.get(pattern) {
        return entry.clone();
    }
    let re = Regex::new(&format!("(?i){pattern}")).ok();
    if cache.len() > 4096 {
        cache.clear();
    }
    cache.insert(pattern.to_string(), re.clone());
    re
}

/// Is `pattern` a valid blocklist regex?
pub fn is_valid_pattern(pattern: &str) -> bool {
    compiled(pattern).is_some()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyCheck {
    pub blocked: bool,
    pub matched_pattern: Option<String>,
}

impl SafetyCheck {
    pub fn ok() -> Self {
        Self { blocked: false, matched_pattern: None }
    }
    /// `Command blocked by safety policy. Pattern: <p>` for the renderer.
    pub fn error_message(&self) -> String {
        format!(
            "Command blocked by safety policy. Pattern: {}",
            self.matched_pattern.clone().unwrap_or_default()
        )
    }
}

fn first_match<'a>(command: &str, patterns: impl Iterator<Item = &'a String>) -> Option<SafetyCheck> {
    for pattern in patterns {
        if let Some(re) = compiled(pattern) {
            if re.is_match(command).unwrap_or(false) {
                return Some(SafetyCheck { blocked: true, matched_pattern: Some(pattern.clone()) });
            }
        }
    }
    None
}

/// User additions (non-default entries of `configured`) always apply; the
/// shell-selected default groups apply when enabled in `configured`.
pub fn check_blocklist_for_shell(command: &str, shell_kind: &str, configured: &[String]) -> SafetyCheck {
    let enabled: HashSet<&String> = configured.iter().collect();
    let user: Vec<&String> = configured.iter().filter(|p| !is_default_blocklist_pattern(p)).collect();
    if let Some(hit) = first_match(command, user.into_iter()) {
        return hit;
    }
    let defaults = select_default_blocklist_patterns(shell_kind);
    first_match(command, defaults.iter().filter(|p| enabled.contains(p))).unwrap_or_else(SafetyCheck::ok)
}

/// User additions plus the shell-independent (common) defaults only.
pub fn check_blocklist_common_only(command: &str, configured: &[String]) -> SafetyCheck {
    let enabled: HashSet<&String> = configured.iter().collect();
    let user: Vec<&String> = configured.iter().filter(|p| !is_default_blocklist_pattern(p)).collect();
    if let Some(hit) = first_match(command, user.into_iter()) {
        return hit;
    }
    first_match(command, common_patterns().iter().filter(|p| enabled.contains(p))).unwrap_or_else(SafetyCheck::ok)
}

/// Best-effort shell kind for blocklist selection: confirmed kind, live idle
/// prompt and login-shell hint; an unclassified remote session stays `""`
/// (strict full table) unless the prompt is a recognised default.
pub fn resolve_session_blocklist_shell_kind(shell_kind: &str, login_shell_hint: &str, fresh_prompt: &str) -> String {
    let base_kind = if shell_kind == "unknown" { "" } else { shell_kind };
    let resolved = crate::helpers::resolve_effective_shell_kind(base_kind, fresh_prompt, login_shell_hint);
    if !base_kind.is_empty() || !login_shell_hint.is_empty() {
        return resolved;
    }
    let last = crate::shell_utils::last_prompt_line(fresh_prompt);
    if crate::shell_utils::is_default_powershell_prompt_line(&last)
        || crate::shell_utils::is_default_cmd_prompt_line(&last)
        || crate::shell_utils::is_default_posix_prompt_line(&last)
    {
        return resolved;
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_table_blocks_destructive_commands_per_shell() {
        let all = default_command_blocklist();
        assert!(check_blocklist_for_shell("rm -rf /", "posix", &all).blocked);
        assert!(check_blocklist_for_shell("sudo reboot", "powershell", &all).blocked);
        assert!(check_blocklist_for_shell("echo $(whoami)", "posix", &all).blocked);
        // PowerShell-native commands are not caught by POSIX-only patterns.
        assert!(!check_blocklist_for_shell("Get-ChildItem $(Get-Location)", "powershell", &all).blocked);
        assert!(check_blocklist_for_shell("Remove-Item -Recurse -Force C:\\x", "powershell", &all).blocked);
        // Unknown kinds keep the strict full table.
        assert!(check_blocklist_for_shell("echo $(whoami)", "", &all).blocked);
        assert!(!check_blocklist_for_shell("ls -la", "posix", &all).blocked);
    }

    #[test]
    fn user_patterns_apply_everywhere_and_disabled_defaults_do_not() {
        let configured = vec!["\\bdanger\\b".to_string()];
        let hit = check_blocklist_for_shell("run danger now", "powershell", &configured);
        assert_eq!(hit.matched_pattern.as_deref(), Some("\\bdanger\\b"));
        assert!(!check_blocklist_for_shell("rm -rf /", "posix", &configured).blocked);
        assert!(check_blocklist_common_only("shutdown -h now", &default_command_blocklist()).blocked);
        assert!(!check_blocklist_common_only("echo $(x)", &default_command_blocklist()).blocked);
        assert!(!is_valid_pattern("(unclosed"));
        assert_eq!(
            SafetyCheck { blocked: true, matched_pattern: Some("x".into()) }.error_message(),
            "Command blocked by safety policy. Pattern: x"
        );
    }

    #[test]
    fn blocklist_shell_kind_resolution() {
        assert_eq!(resolve_session_blocklist_shell_kind("posix", "", ""), "posix");
        assert_eq!(resolve_session_blocklist_shell_kind("", "fish", ""), "fish");
        assert_eq!(resolve_session_blocklist_shell_kind("", "", "PS C:\\>"), "powershell");
        assert_eq!(resolve_session_blocklist_shell_kind("", "", "weird ❯❯"), "");
        assert_eq!(resolve_session_blocklist_shell_kind("unknown", "", ""), "");
    }
}
