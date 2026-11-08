//! Shell prompt detection patterns (`electron/scripts/shellPromptPatterns.cjs`,
//! mirrored from `domain/snippetScript.ts`).

use crate::pattern::WaitPattern;

/// `DEFAULT_SHELL_PROMPT_PATTERNS`.
pub const DEFAULT_SHELL_PROMPT_PATTERNS: [&str; 5] = ["# ", "$ ", "~# ", "~$ ", "% "];

/// `SHELL_PROMPT_END_REGEX` source (flags `m`).
pub const SHELL_PROMPT_END_REGEX: &str = r"(?:~[#$]\s*|[@][^\n]{0,120}[:][^\n]{0,120}[#$%]\s*)$";

/// The patterns `waitForPrompt` waits for: the literal prompt endings plus
/// the `user@host:path$` regex.
pub fn shell_prompt_patterns() -> Vec<WaitPattern> {
    let mut patterns: Vec<WaitPattern> = DEFAULT_SHELL_PROMPT_PATTERNS
        .iter()
        .map(|p| WaitPattern::text(*p))
        .collect();
    patterns.push(WaitPattern::regex(SHELL_PROMPT_END_REGEX, "m"));
    patterns
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::JsRegex;

    #[test]
    fn shell_prompt_regex_matches_root_and_user_prompts() {
        let regex = JsRegex::new(SHELL_PROMPT_END_REGEX, "m").unwrap();
        assert!(regex.exec("root@host:~# ").is_some());
        assert!(regex.exec("user@host:/var/log$ ").is_some());
        assert!(regex.exec("plain text").is_none());
    }
}
