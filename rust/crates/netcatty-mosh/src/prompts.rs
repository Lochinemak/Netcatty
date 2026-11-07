//! Prompt handling during the Mosh SSH bootstrap.
//!
//! Port of `createMoshSshPasswordResponder` (`terminalBridge/moshSession.cjs`)
//! plus a reduced port of `isUntrustedTerminalInputPrompt`
//! (`domain/terminalPromptSecurity.shared.cjs`). The responder types the
//! saved passphrase / password into the ssh PTY once each, and reports when
//! ssh waits on input Netcatty cannot answer, so the renderer marks the
//! session connected and lets the user type.

use regex::Regex;
use std::sync::OnceLock;

const TAIL_LIMIT: usize = 512;
const SECURITY_TAIL_LIMIT: usize = 2048;

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid prompt regex"))
}

fn strip_prompt_controls(text: &str) -> String {
    static ANSI: OnceLock<Regex> = OnceLock::new();
    static CONTROLS: OnceLock<Regex> = OnceLock::new();
    let stripped = re(
        &ANSI,
        r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))",
    )
    .replace_all(text, "");
    re(&CONTROLS, r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
        .replace_all(&stripped, "")
        .into_owned()
}

pub fn is_passphrase_prompt(tail: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)(?:^|[\r\n]).*passphrase.*:\s*$").is_match(&strip_prompt_controls(tail))
}

pub fn is_password_prompt(tail: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)(?:^|[\r\n]).*password:\s*$").is_match(&strip_prompt_controls(tail))
}

pub fn is_host_key_confirmation_prompt(tail: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)are you sure you want to continue connecting \(yes/no(?:/\[fingerprint\])?\)\?\s*$",
    )
    .is_match(&strip_prompt_controls(tail))
}

pub fn is_mfa_prompt(tail: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)(?:verification code|one[- ]time (?:password|code)|otp|passcode|authentication code|duo passcode|token):\s*$",
    )
    .is_match(&strip_prompt_controls(tail))
}

/// Last logical line (after the last CR / LF), escapes removed.
fn last_logical_line(value: &str) -> String {
    static OSC: OnceLock<Regex> = OnceLock::new();
    static CSI: OnceLock<Regex> = OnceLock::new();
    let plain = re(&OSC, r"\x1b\][^\x07]*(?:\x07|\x1b\\)").replace_all(value, "");
    let plain = re(&CSI, r"\x1b\[[0-?]*[ -/]*[@-~]").replace_all(&plain, "");
    let line = plain.rsplit(['\n', '\r']).next().unwrap_or("");
    let count = line.chars().count();
    line.chars()
        .skip(count.saturating_sub(SECURITY_TAIL_LIMIT))
        .collect()
}

fn sensitive_label() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)(?:pass(?:word|phrase|code)|one[\s-]?time(?:\s+(?:password|passcode|code|token))?|\botp\b|verification(?:\s+(?:code|token|passcode))?|authentication\s+(?:code|token|passcode)|security\s+(?:code|token|passcode|pin)|\bpin\b|\btoken\b|2fa|two[\s-]?factor|multi[\s-]?factor|\bmfa\b|second\s+factor|\bduo\b|密码|口令|动态|一次性|验证码|验证信息|令牌|双因素|多因素|短信验证|手机验证|二次|安全密码|挑战码)",
    )
}

/// `isSensitiveTerminalChallenge`: a password / OTP style label ending the
/// line (optionally after "enter" / "your" ...) or followed by a colon.
pub fn is_sensitive_challenge(value: &str) -> bool {
    static PREFIX_EN: OnceLock<Regex> = OnceLock::new();
    static PREFIX_CJK: OnceLock<Regex> = OnceLock::new();
    static FOR_OF: OnceLock<Regex> = OnceLock::new();
    static COLON: OnceLock<Regex> = OnceLock::new();
    let line = last_logical_line(value);
    let line = line.trim();
    if line.is_empty() {
        return false;
    }
    let Some(label) = sensitive_label().find(line) else {
        return false;
    };
    let prefix = line[..label.start()].trim();
    let suffix = &line[label.end()..];
    if suffix.trim().is_empty() {
        return prefix.is_empty()
            || re(
                &PREFIX_EN,
                r"(?i)(?:^|\s)(?:enter|input|provide|type|scan|please|your|current|new|old)\s*$",
            )
            .is_match(prefix)
            || re(&PREFIX_CJK, r"(?:输入|请输入|请)\s*$").is_match(prefix);
    }
    if re(&FOR_OF, r"(?i)^\s+(?:for|of)\s+[^\r\n]{1,96}$").is_match(suffix) {
        return true;
    }
    re(&COLON, r"^[^\r\n:：>›»]{0,96}[:：>›»]\s*[^\r\n]{0,1024}$").is_match(suffix)
}

/// Reduced `isConfirmedTerminalShellPrompt`: prompt glyphs, `$ # %`
/// endings, Windows `C:\...>` and `user@host:~>` style prompts.
fn is_confirmed_shell_prompt(prompt: &str) -> bool {
    static WIN: OnceLock<Regex> = OnceLock::new();
    static PATHY: OnceLock<Regex> = OnceLock::new();
    if prompt.is_empty() || is_sensitive_challenge(prompt) {
        return false;
    }
    if prompt.chars().any(|c| "❯❮→➜➤⟩»›".contains(c) || ('\u{E000}'..='\u{F8FF}').contains(&c)) {
        return true;
    }
    if prompt.ends_with(['$', '#', '%']) {
        return true;
    }
    if !prompt.ends_with('>') || prompt == ">" {
        return false;
    }
    re(&WIN, r"^(?:PS\s+)?[A-Za-z]:[\\/].*>$").is_match(prompt)
        || re(&PATHY, r"[@\\/~:]\S*>$").is_match(prompt)
}

/// Reduced `isUntrustedTerminalInputPrompt`: the output ends at an input
/// prompt (`:` / `>` style) that is not a recognised shell prompt.
pub fn is_untrusted_input_prompt(value: &str) -> bool {
    static ENDS_PROMPT: OnceLock<Regex> = OnceLock::new();
    let line = last_logical_line(value);
    let prompt = line.trim();
    if prompt.is_empty() {
        return false;
    }
    if is_sensitive_challenge(prompt) {
        return true;
    }
    if !re(&ENDS_PROMPT, r"[:：>›»]\s*$").is_match(prompt) {
        return false;
    }
    !is_confirmed_shell_prompt(prompt)
}

/// Outcome of feeding one chunk of handshake output.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ResponderOutcome {
    /// Secret (+ CR) to write into the ssh PTY.
    pub write: Option<String>,
    /// ssh is blocked on input Netcatty does not answer.
    pub requires_user_input: bool,
}

/// Answers the first passphrase and password prompt with saved secrets.
#[derive(Debug, Default)]
pub struct MoshPasswordResponder {
    password: Option<String>,
    passphrase: Option<String>,
    answered_password: bool,
    answered_passphrase: bool,
    tail: String,
}

impl MoshPasswordResponder {
    pub fn new(password: Option<String>, passphrase: Option<String>) -> Self {
        Self {
            password: password.filter(|p| !p.is_empty()),
            passphrase: passphrase.filter(|p| !p.is_empty()),
            ..Default::default()
        }
    }

    pub fn feed(&mut self, text: &str) -> ResponderOutcome {
        if text.is_empty() {
            return ResponderOutcome::default();
        }
        self.tail.push_str(text);
        if self.tail.len() > TAIL_LIMIT {
            let count = self.tail.chars().count();
            self.tail = self
                .tail
                .chars()
                .skip(count.saturating_sub(TAIL_LIMIT))
                .collect();
        }
        let passphrase_prompt = is_passphrase_prompt(&self.tail);
        let mfa_prompt = is_mfa_prompt(&self.tail);
        let password_prompt = !mfa_prompt && is_password_prompt(&self.tail);
        if passphrase_prompt && !self.answered_passphrase {
            if let Some(secret) = &self.passphrase {
                self.answered_passphrase = true;
                return ResponderOutcome {
                    write: Some(format!("{secret}\r")),
                    requires_user_input: false,
                };
            }
        }
        if password_prompt && !self.answered_password {
            if let Some(secret) = &self.password {
                self.answered_password = true;
                return ResponderOutcome {
                    write: Some(format!("{secret}\r")),
                    requires_user_input: false,
                };
            }
        }
        ResponderOutcome {
            write: None,
            requires_user_input: passphrase_prompt
                || password_prompt
                || is_host_key_confirmation_prompt(&self.tail)
                || is_untrusted_input_prompt(&self.tail),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_password_once() {
        let mut r = MoshPasswordResponder::new(Some("secret".into()), None);
        assert_eq!(r.feed("Welcome\r\n").write, None);
        let out = r.feed("alice@host's password: ");
        assert_eq!(out.write.as_deref(), Some("secret\r"));
        // A second prompt (wrong password) is left to the user.
        let out = r.feed("\r\nPermission denied, please try again.\r\nalice@host's password: ");
        assert_eq!(out.write, None);
        assert!(out.requires_user_input);
    }

    #[test]
    fn answers_passphrase_before_password() {
        let mut r = MoshPasswordResponder::new(Some("pw".into()), Some("pp".into()));
        let out = r.feed("Enter passphrase for key '/tmp/k': ");
        assert_eq!(out.write.as_deref(), Some("pp\r"));
        let out = r.feed("\r\nalice@host's password: ");
        assert_eq!(out.write.as_deref(), Some("pw\r"));
    }

    #[test]
    fn mfa_and_host_key_prompts_need_the_user() {
        let mut r = MoshPasswordResponder::new(Some("pw".into()), None);
        let out = r.feed("Verification code: ");
        assert_eq!(out.write, None);
        assert!(out.requires_user_input);

        let mut r = MoshPasswordResponder::new(None, None);
        let out = r.feed(
            "The authenticity of host 'h' can't be established.\r\nAre you sure you want to continue connecting (yes/no/[fingerprint])? ",
        );
        assert!(out.requires_user_input);

        let mut r = MoshPasswordResponder::new(None, None);
        assert!(r.feed("alice@host's password: ").requires_user_input);
    }

    #[test]
    fn ordinary_output_does_not_need_input() {
        let mut r = MoshPasswordResponder::new(None, None);
        assert!(!r.feed("Last login: Mon\r\n").requires_user_input);
        assert!(!r.feed("mosh-server (mosh 1.4.0)\r\n").requires_user_input);
        assert!(!r.feed("user@host:~$ ").requires_user_input);
    }

    #[test]
    fn untrusted_prompt_classifier() {
        assert!(is_untrusted_input_prompt("Enter token: "));
        assert!(is_untrusted_input_prompt("Choose an option: "));
        assert!(is_untrusted_input_prompt("请输入密码"));
        assert!(!is_untrusted_input_prompt("user@host:~$ "));
        assert!(!is_untrusted_input_prompt("C:\\Users\\me>"));
        assert!(!is_untrusted_input_prompt("plain text"));
        assert!(is_sensitive_challenge("Password for alice"));
        assert!(!is_sensitive_challenge("password reset succeeded"));
    }
}
