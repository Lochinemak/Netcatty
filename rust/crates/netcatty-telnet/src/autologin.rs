//! Login-prompt auto-login detector shared by telnet and serial sessions.
//!
//! Port of `electron/bridges/telnetAutoLogin.cjs`. The detector watches the
//! decoded terminal output, answers a "Press RETURN" banner once, sends the
//! saved username / password at the matching prompts and reports completion
//! once a command prompt appears. Instead of callbacks it returns
//! [`AutoLoginAction`]s; the caller performs the writes and emits the
//! renderer events. The expiry timer is owned by the caller too: arm it at
//! [`AutoLogin::expiry_deadline`] and call [`AutoLogin::expire`] when it fires.

use regex::Regex;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Auto-login window (`DEFAULT_TIMEOUT_MS`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const TAIL_LIMIT: usize = 2048;
const PROMPT_LINE_LIMIT: usize = 320;

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid auto-login regex"))
}

fn ansi_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))",
    )
}

fn last_login_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)(?:^|[\s(\[])(?:last|previous)\s+login(?:\s*[:：>])?\s*$",
    )
}

fn username_prompt_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)(?:^|[^A-Za-z0-9])(?:user\s*name|username|login|logon|account|userid|user\s*id|user|用户名|帐号|账号|登录|登入)(?:\s*[:：>])?\s*$",
    )
}

fn password_prompt_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)(?:^|[^A-Za-z0-9])(?:password|passwd|passcode|passphrase|pass\s*phrase|pin|密码|口令)(?:\s*[:：>])?\s*$",
    )
}

fn continue_prompt_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)(?:press|hit)\s+(?:[<\[(]?\s*)?(?:return|enter|any\s+key|space)\b(?:\s*[>\])])?.*(?:continue|get\s+started|start|begin|started)?\.?\s*$",
    )
}

fn command_prompt_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"[$#>]\s*$")
}

fn strip_ansi(text: &str) -> String {
    ansi_pattern().replace_all(text, "").into_owned()
}

fn normalize_prompt_tail(text: &str) -> String {
    static TRAILING_BLANKS: OnceLock<Regex> = OnceLock::new();
    let stripped = strip_ansi(text).replace('\r', "\n");
    re(&TRAILING_BLANKS, r"[ \t]+\n")
        .replace_all(&stripped, "\n")
        .into_owned()
}

/// Last `n` characters of `s` (JS `slice(-n)` on short strings).
fn last_chars(s: &str, n: usize) -> &str {
    let count = s.chars().count();
    if count <= n {
        return s;
    }
    let skip = count - n;
    let idx = s.char_indices().nth(skip).map(|(i, _)| i).unwrap_or(0);
    &s[idx..]
}

fn last_prompt_line(text: &str) -> String {
    let normalized = normalize_prompt_tail(text);
    let line = normalized.rsplit('\n').next().unwrap_or("");
    last_chars(line, PROMPT_LINE_LIMIT).to_string()
}

fn prompt_lines(text: &str) -> Vec<String> {
    normalize_prompt_tail(text)
        .split('\n')
        .map(|line| last_chars(line, PROMPT_LINE_LIMIT).to_string())
        .collect()
}

pub fn is_continue_prompt(text: &str) -> bool {
    continue_prompt_pattern().is_match(&last_prompt_line(text))
}

pub fn is_username_prompt(text: &str) -> bool {
    let line = last_prompt_line(text);
    !last_login_pattern().is_match(&line) && username_prompt_pattern().is_match(&line)
}

pub fn is_password_prompt(text: &str) -> bool {
    password_prompt_pattern().is_match(&last_prompt_line(text))
}

pub fn is_command_prompt(text: &str) -> bool {
    let line = last_prompt_line(text);
    let line = line.trim_end();
    if line.is_empty() || line.chars().count() > 200 {
        return false;
    }
    if last_login_pattern().is_match(line)
        || username_prompt_pattern().is_match(line)
        || password_prompt_pattern().is_match(line)
        || continue_prompt_pattern().is_match(line)
    {
        return false;
    }
    command_prompt_pattern().is_match(line)
}

fn has_username_prompt_before_password(text: &str) -> bool {
    let lines = prompt_lines(text);
    let Some(last_password) = lines
        .iter()
        .rposition(|line| password_prompt_pattern().is_match(line))
    else {
        return false;
    };
    lines[..last_password]
        .iter()
        .any(|line| !last_login_pattern().is_match(line) && username_prompt_pattern().is_match(line))
}

/// Bare CR / LF used to wake a silent serial console before `login:` shows.
pub fn is_auto_login_wake_input(data: &str) -> bool {
    !data.is_empty() && data.chars().all(|c| c == '\r' || c == '\n')
}

/// Terminal-originated automatic replies (focus reports, CPR / DA / DSR,
/// mode reports, colour query replies, DCS) that travel through xterm's
/// `onData` alongside user input. Port of `terminalReportSequence.cjs`.
pub fn is_terminal_report_sequence(data: &str) -> bool {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    if data.is_empty() {
        return false;
    }
    if data == "\x1b[I" || data == "\x1b[O" {
        return true;
    }
    PATTERNS
        .get_or_init(|| {
            [
                r"^\x1b\[[?>]?[0-9;]*[Rcn]$",
                r"^\x1b\[\?[0-9]+u$",
                r"^\x1b\[\??[0-9]+;[0-4]\$y$",
                r"^\x1b\[(?:4|6|8);[0-9]+;[0-9]+t$",
                r"(?i)^\x1b\](?:4;[0-9]{1,3}|1[012]);rgb:[0-9a-f]{1,4}/[0-9a-f]{1,4}/[0-9a-f]{1,4}(?:\x07|\x1b\\)$",
                r"(?s)^\x1bP.*\x1b\\$",
            ]
            .iter()
            .map(|p| Regex::new(p).expect("valid report regex"))
            .collect()
        })
        .iter()
        .any(|r| r.is_match(data))
}

/// Saved credentials and the detection window.
#[derive(Debug, Clone)]
pub struct AutoLoginOptions {
    /// Saved username (trimmed); `None` / empty when not saved.
    pub username: Option<String>,
    /// Saved password; `Some("")` is an intentionally blank password.
    pub password: Option<String>,
    /// Detection window; `None` never expires.
    pub timeout: Option<Duration>,
}

impl Default for AutoLoginOptions {
    fn default() -> Self {
        Self {
            username: None,
            password: None,
            timeout: Some(DEFAULT_TIMEOUT),
        }
    }
}

impl AutoLoginOptions {
    /// Electron's `hasSerialAutoLoginCredentials` / telnet credential check:
    /// a non-blank username or any saved password (even an empty one).
    pub fn has_credentials(&self) -> bool {
        self.username
            .as_deref()
            .map(|u| !u.trim().is_empty())
            .unwrap_or(false)
            || self.password.is_some()
    }
}

/// Side effects requested by the detector, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoLoginAction {
    /// Write this text to the remote (not user input).
    Write(String),
    /// Login finished: a command prompt appeared after credentials were sent
    /// (`netcatty:telnet:auto-login-complete`).
    Complete,
    /// The user took over (`netcatty:telnet:auto-login-cancelled`).
    UserInput,
    /// The exchange stalled at a prompt the detector cannot answer.
    Incomplete,
}

#[derive(Debug)]
pub struct AutoLogin {
    username: String,
    password: String,
    has_password: bool,
    timeout: Option<Duration>,
    started_at: Instant,
    tail: String,
    sent_wake: bool,
    sent_username: bool,
    sent_password: bool,
    disabled: bool,
    completed: bool,
    user_input_notified: bool,
    incomplete_notified: bool,
    timer_armed: bool,
}

impl AutoLogin {
    pub fn new(options: AutoLoginOptions) -> Self {
        Self::new_at(options, Instant::now())
    }

    /// Construct with an explicit start time (tests).
    pub fn new_at(options: AutoLoginOptions, now: Instant) -> Self {
        let username = options
            .username
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        let has_password = options.password.is_some();
        let has_credentials = !username.is_empty() || has_password;
        Self {
            username,
            password: options.password.unwrap_or_default(),
            has_password,
            timeout: options.timeout,
            started_at: now,
            tail: String::new(),
            sent_wake: false,
            sent_username: false,
            sent_password: false,
            disabled: !has_credentials,
            completed: false,
            user_input_notified: false,
            incomplete_notified: false,
            timer_armed: options.timeout.is_some(),
        }
    }

    /// When the caller should call [`AutoLogin::expire`]; `None` once the
    /// timer is disarmed (completion, user input, cancel) or never armed.
    pub fn expiry_deadline(&self) -> Option<Instant> {
        if !self.timer_armed {
            return None;
        }
        self.timeout.map(|t| self.started_at + t)
    }

    /// Is the detector still trying to log in?
    pub fn is_active(&self) -> bool {
        !self.disabled && !self.completed
    }

    fn is_expired(&self, now: Instant) -> bool {
        match self.timeout {
            Some(t) => now.saturating_duration_since(self.started_at) > t,
            None => false,
        }
    }

    fn has_sent_credentials(&self) -> bool {
        self.sent_password || self.sent_username
    }

    fn complete(&mut self, actions: &mut Vec<AutoLoginAction>) {
        if self.completed {
            return;
        }
        self.completed = true;
        self.timer_armed = false;
        actions.push(AutoLoginAction::Complete);
    }

    fn complete_if_ready(&mut self, actions: &mut Vec<AutoLoginAction>) {
        if self.has_sent_credentials() && is_command_prompt(&self.tail) {
            self.disabled = true;
            self.complete(actions);
        }
    }

    fn notify_incomplete(&mut self, actions: &mut Vec<AutoLoginAction>) {
        if self.incomplete_notified || self.completed {
            return;
        }
        self.incomplete_notified = true;
        actions.push(AutoLoginAction::Incomplete);
    }

    fn append_tail(&mut self, text: &str) {
        self.tail.push_str(text);
        if self.tail.len() > TAIL_LIMIT {
            self.tail = last_chars(&self.tail, TAIL_LIMIT).to_string();
        }
    }

    /// Feed decoded terminal output.
    pub fn handle_text(&mut self, text: &str) -> Vec<AutoLoginAction> {
        self.handle_text_at(text, Instant::now())
    }

    pub fn handle_text_at(&mut self, text: &str, now: Instant) -> Vec<AutoLoginAction> {
        let mut actions = Vec::new();
        if self.is_expired(now) {
            self.disabled = true;
            // Keep observing after expiry: a slow-booting device can show its
            // first prompt late. Report it so callers cancel deferred
            // post-login actions; credentials are never sent here.
            self.append_tail(text);
            if is_username_prompt(&self.tail) || is_password_prompt(&self.tail) {
                self.notify_incomplete(&mut actions);
            }
            return actions;
        }
        if self.disabled {
            return actions;
        }

        self.append_tail(text);
        self.complete_if_ready(&mut actions);
        if self.disabled {
            return actions;
        }

        if !self.sent_wake && is_continue_prompt(&self.tail) {
            self.sent_wake = true;
            actions.push(AutoLoginAction::Write("\r".to_string()));
            return actions;
        }

        if !self.sent_username
            && (!self.username.is_empty() || self.has_password)
            && (is_username_prompt(&self.tail) || has_username_prompt_before_password(&self.tail))
        {
            self.sent_username = true;
            actions.push(AutoLoginAction::Write(format!("{}\r", self.username)));
            self.complete_if_ready(&mut actions);
        }

        if !self.disabled
            && !self.sent_password
            && self.has_password
            && is_password_prompt(&self.tail)
        {
            self.sent_password = true;
            actions.push(AutoLoginAction::Write(format!("{}\r", self.password)));
            self.complete_if_ready(&mut actions);
        }

        // No password saved but the device asks for one: report the stall.
        // The detector stays enabled so a later command prompt can complete.
        if !self.disabled && !self.completed && !self.has_password && is_password_prompt(&self.tail)
        {
            self.notify_incomplete(&mut actions);
        }
        actions
    }

    /// User input reached the session. `None` is the line-mode "user started
    /// typing" notification. A bare CR/LF before any prompt is a console
    /// wake, not a takeover, while the detector is still active.
    pub fn handle_user_input(&mut self, data: Option<&str>) -> Vec<AutoLoginAction> {
        let wake_only = data.map(is_auto_login_wake_input).unwrap_or(false);
        if wake_only
            && !self.disabled
            && !self.sent_username
            && !self.sent_password
            && !is_username_prompt(&self.tail)
            && !is_password_prompt(&self.tail)
        {
            return Vec::new();
        }
        self.disabled = true;
        self.timer_armed = false;
        if self.user_input_notified {
            return Vec::new();
        }
        self.user_input_notified = true;
        vec![AutoLoginAction::UserInput]
    }

    /// The expiry timer fired. Does not depend on further output: a device
    /// that rejects the credentials, re-prompts and goes silent is reported.
    pub fn expire(&mut self) -> Vec<AutoLoginAction> {
        let mut actions = Vec::new();
        self.timer_armed = false;
        if self.completed || self.disabled {
            return actions;
        }
        self.disabled = true;
        if self.has_sent_credentials()
            && (is_username_prompt(&self.tail) || is_password_prompt(&self.tail))
        {
            self.notify_incomplete(&mut actions);
        }
        actions
    }

    /// Disable without emitting anything (session displaced / closed).
    pub fn cancel(&mut self) {
        self.disabled = true;
        self.timer_armed = false;
    }
}

#[cfg(test)]
mod tests {
    //! Ported from `electron/bridges/telnetAutoLogin.test.cjs`.
    use super::*;

    fn opts(username: Option<&str>, password: Option<&str>) -> AutoLoginOptions {
        AutoLoginOptions {
            username: username.map(str::to_string),
            password: password.map(str::to_string),
            timeout: Some(DEFAULT_TIMEOUT),
        }
    }

    /// Feed chunks; collect writes and counts of the other actions.
    #[derive(Default, Debug)]
    struct Log {
        writes: Vec<String>,
        complete: usize,
        user_input: usize,
        incomplete: usize,
    }

    impl Log {
        fn record(&mut self, actions: Vec<AutoLoginAction>) {
            for a in actions {
                match a {
                    AutoLoginAction::Write(s) => self.writes.push(s),
                    AutoLoginAction::Complete => self.complete += 1,
                    AutoLoginAction::UserInput => self.user_input += 1,
                    AutoLoginAction::Incomplete => self.incomplete += 1,
                }
            }
        }
    }

    fn feed(al: &mut AutoLogin, log: &mut Log, chunks: &[&str]) {
        for c in chunks {
            log.record(al.handle_text(c));
        }
    }

    fn run(username: Option<&str>, password: Option<&str>, chunks: &[&str]) -> Log {
        let mut al = AutoLogin::new(opts(username, password));
        let mut log = Log::default();
        feed(&mut al, &mut log, chunks);
        log
    }

    #[test]
    fn split_prompts() {
        let log = run(
            Some("admin"),
            Some("secret"),
            &["\x1b[32mUser", "name:\x1b[0m ", "\r\nPass", "word: "],
        );
        assert_eq!(log.writes, vec!["admin\r", "secret\r"]);
    }

    #[test]
    fn completes_only_after_command_prompt() {
        let mut al = AutoLogin::new(opts(Some("admin"), Some("secret")));
        let mut log = Log::default();
        feed(&mut al, &mut log, &["Username: ", "\r\nPassword: "]);
        assert_eq!(log.writes, vec!["admin\r", "secret\r"]);
        assert_eq!(log.complete, 0);
        feed(&mut al, &mut log, &["\r\nWelcome\r\nrouter# ", "\r\nrouter# "]);
        assert_eq!(log.complete, 1);
    }

    #[test]
    fn username_only_waits_for_prompt() {
        let mut al = AutoLogin::new(opts(Some("admin"), None));
        let mut log = Log::default();
        feed(&mut al, &mut log, &["Username: "]);
        assert_eq!(log.writes, vec!["admin\r"]);
        assert_eq!(log.complete, 0);
        feed(&mut al, &mut log, &["\r\nrouter> "]);
        assert_eq!(log.complete, 1);
    }

    #[test]
    fn password_ready_host_only_asks_username() {
        let log = run(Some("admin"), Some("secret"), &["Username: ", "\r\nrouter# "]);
        assert_eq!(log.writes, vec!["admin\r"]);
        assert_eq!(log.complete, 1);
    }

    #[test]
    fn prompts_arriving_together() {
        let log = run(Some("admin"), Some("secret"), &["Username: \r\nPassword: "]);
        assert_eq!(log.writes, vec!["admin\r", "secret\r"]);
    }

    #[test]
    fn password_only_and_blank_values() {
        assert_eq!(
            run(None, Some("line-password"), &["Password: "]).writes,
            vec!["line-password\r"]
        );
        assert_eq!(
            run(Some(""), Some("line-password"), &["Username: ", "\r\nPassword: "]).writes,
            vec!["\r", "line-password\r"]
        );
        assert_eq!(
            run(Some("admin"), Some(""), &["Username: ", "\r\nPassword: "]).writes,
            vec!["admin\r", "\r"]
        );
    }

    #[test]
    fn wake_banners() {
        for banner in [
            "Press RETURN to get started.",
            "Press <ENTER> to continue",
            "Press [Enter] to continue",
        ] {
            let log = run(
                Some("admin"),
                Some("secret"),
                &[banner, "\r\nrouter login: ", "\r\nPassword: "],
            );
            assert_eq!(log.writes, vec!["\r", "admin\r", "secret\r"], "{banner}");
        }
        let log = run(
            Some("admin"),
            Some("secret"),
            &["Press RETURN to get started.", "Username: ", "\r\nPassword: "],
        );
        assert_eq!(log.writes, vec!["\r", "admin\r", "secret\r"]);
        let log = run(
            Some("admin"),
            Some("secret"),
            &[
                "Netcatty local Telnet test servicePress RETURN to get started.",
                "Username: ",
                "\r\nPassword: ",
            ],
        );
        assert_eq!(log.writes, vec!["\r", "admin\r", "secret\r"]);
    }

    #[test]
    fn user_typing_stops_detector() {
        let mut al = AutoLogin::new(opts(Some("admin"), Some("secret")));
        let mut log = Log::default();
        log.record(al.handle_user_input(None));
        log.record(al.handle_user_input(None));
        feed(&mut al, &mut log, &["Username: ", "Password: "]);
        assert!(log.writes.is_empty());
        assert_eq!(log.user_input, 1);
        assert!(al.expiry_deadline().is_none());
    }

    #[test]
    fn wake_enter_before_prompt_keeps_detector_armed() {
        for wakes in [&["\r"][..], &["\n", "\r\n"][..]] {
            let mut al = AutoLogin::new(opts(Some("admin"), Some("secret")));
            let mut log = Log::default();
            for w in wakes {
                log.record(al.handle_user_input(Some(w)));
            }
            feed(&mut al, &mut log, &["login: ", "\r\nPassword: "]);
            assert_eq!(log.user_input, 0);
            assert_eq!(log.writes, vec!["admin\r", "secret\r"]);
        }
    }

    #[test]
    fn wake_enter_after_expiry_notifies() {
        let mut al = AutoLogin::new(opts(Some("admin"), Some("secret")));
        let mut log = Log::default();
        log.record(al.expire());
        assert_eq!(log.user_input, 0);
        log.record(al.handle_user_input(Some("\r")));
        assert_eq!(log.user_input, 1);
        feed(
            &mut al,
            &mut log,
            &["Press RETURN to continue", "login: ", "\r\nPassword: "],
        );
        assert_eq!(log.user_input, 1);
        assert!(log.writes.is_empty());
    }

    #[test]
    fn continue_prompt_after_blind_wake() {
        let mut al = AutoLogin::new(opts(Some("admin"), Some("secret")));
        let mut log = Log::default();
        log.record(al.handle_user_input(Some("\r")));
        feed(
            &mut al,
            &mut log,
            &["Press RETURN to continue", "\r\nlogin: ", "\r\nPassword: "],
        );
        assert_eq!(log.user_input, 0);
        assert_eq!(log.writes, vec!["\r", "admin\r", "secret\r"]);
    }

    #[test]
    fn normal_character_cancels() {
        let mut al = AutoLogin::new(opts(Some("admin"), Some("secret")));
        let mut log = Log::default();
        log.record(al.handle_user_input(Some("x")));
        feed(&mut al, &mut log, &["login: ", "\r\nPassword: "]);
        assert_eq!(log.user_input, 1);
        assert!(log.writes.is_empty());
    }

    #[test]
    fn enter_after_credentials_started_cancels() {
        let mut al = AutoLogin::new(opts(Some("admin"), Some("secret")));
        let mut log = Log::default();
        feed(&mut al, &mut log, &["login: "]);
        log.record(al.handle_user_input(Some("\r")));
        feed(&mut al, &mut log, &["\r\nPassword: "]);
        assert_eq!(log.user_input, 1);
        assert_eq!(log.writes, vec!["admin\r"]);
    }

    #[test]
    fn enter_with_prompt_in_tail_after_expiry_cancels() {
        let t0 = Instant::now();
        let mut al = AutoLogin::new_at(opts(Some("admin"), Some("secret")), t0);
        let mut log = Log::default();
        log.record(al.handle_text_at("login: ", t0 + Duration::from_millis(60_001)));
        log.record(al.handle_user_input(Some("\r")));
        assert_eq!(log.user_input, 1);
        assert!(log.writes.is_empty());
    }

    #[test]
    fn ignores_last_login_text() {
        assert!(run(Some("admin"), Some("secret"), &["Last login:"])
            .writes
            .is_empty());
    }

    #[test]
    fn kylin_prompts() {
        assert_eq!(
            run(Some("admin"), Some("secret"), &["Username", "\r\nPassword"]).writes,
            vec!["admin\r", "secret\r"]
        );
        assert_eq!(
            run(Some("admin"), Some("secret"), &["用户名", "\r\n密码"]).writes,
            vec!["admin\r", "secret\r"]
        );
        assert_eq!(
            run(
                Some("lybing"),
                Some("secret"),
                &["Kylin V10 SP1\r\nlybing-pc login: ", "Input Password"]
            )
            .writes,
            vec!["lybing\r", "secret\r"]
        );
    }

    #[test]
    fn missing_password_reports_incomplete_then_completes() {
        let mut al = AutoLogin::new(opts(Some("admin"), None));
        let mut log = Log::default();
        feed(&mut al, &mut log, &["Username: ", "\r\nPassword: "]);
        assert_eq!(log.writes, vec!["admin\r"]);
        assert_eq!(log.complete, 0);
        assert_eq!(log.incomplete, 1);
        feed(&mut al, &mut log, &["\r\nrouter# "]);
        assert_eq!(log.complete, 1);
        assert_eq!(log.incomplete, 1);
    }

    #[test]
    fn expiry_mid_exchange_reports_incomplete_once() {
        let t0 = Instant::now();
        let late = t0 + Duration::from_millis(60_001);
        let mut al = AutoLogin::new_at(opts(Some("admin"), Some("secret")), t0);
        let mut log = Log::default();
        for c in ["Username: ", "\r\nPassword: ", "\r\nUsername: "] {
            log.record(al.handle_text_at(c, t0));
        }
        assert_eq!(log.incomplete, 0);
        log.record(al.handle_text_at("\r\nUsername: ", late));
        assert_eq!(log.incomplete, 1);
        log.record(al.handle_text_at("more output", late));
        assert_eq!(log.incomplete, 1);
    }

    #[test]
    fn quiet_device_never_incomplete() {
        let t0 = Instant::now();
        let mut al = AutoLogin::new_at(opts(Some("admin"), None), t0);
        let mut log = Log::default();
        log.record(al.handle_text_at("\r\nWelcome banner\r\n", t0));
        log.record(al.handle_text_at("\r\nmore banner", t0 + Duration::from_millis(60_001)));
        assert_eq!(log.incomplete, 0);

        // Timer variant: no credentials ever sent.
        let mut al = AutoLogin::new(opts(Some("admin"), None));
        assert!(al.expire().is_empty());
    }

    #[test]
    fn expiry_timer_reports_silent_rejection() {
        let mut al = AutoLogin::new(opts(Some("admin"), Some("secret")));
        let mut log = Log::default();
        feed(&mut al, &mut log, &["Username: ", "\r\nPassword: ", "\r\nUsername: "]);
        assert!(al.expiry_deadline().is_some());
        assert_eq!(log.incomplete, 0);
        log.record(al.expire());
        assert_eq!(log.incomplete, 1);
    }

    #[test]
    fn expiry_after_completion_is_noop() {
        let mut al = AutoLogin::new(opts(Some("admin"), Some("secret")));
        let mut log = Log::default();
        feed(&mut al, &mut log, &["Username: ", "\r\nPassword: ", "\r\nrouter# "]);
        assert_eq!(log.complete, 1);
        assert!(al.expiry_deadline().is_none());
        log.record(al.expire());
        assert_eq!(log.complete, 1);
        assert_eq!(log.incomplete, 0);
    }

    #[test]
    fn cancel_disarms_everything() {
        let mut al = AutoLogin::new(opts(Some("admin"), Some("secret")));
        let mut log = Log::default();
        feed(&mut al, &mut log, &["Username: ", "\r\nPassword: "]);
        al.cancel();
        assert!(al.expiry_deadline().is_none());
        log.record(al.expire());
        feed(&mut al, &mut log, &["\r\nPassword: "]);
        assert_eq!(log.complete, 0);
        assert_eq!(log.incomplete, 0);
    }

    #[test]
    fn late_prompt_after_expiry_reports_without_sending() {
        let t0 = Instant::now();
        let late = t0 + Duration::from_millis(60_001);
        let mut al = AutoLogin::new_at(opts(Some("admin"), Some("secret")), t0);
        let mut log = Log::default();
        log.record(al.handle_text_at("\r\nWelcome banner\r\n", t0));
        log.record(al.handle_text_at("\r\nUsername: ", late));
        log.record(al.handle_text_at("\r\nPassword: ", late));
        assert_eq!(log.incomplete, 1);
        assert!(log.writes.is_empty());
    }

    #[test]
    fn no_credentials_means_disabled() {
        let mut al = AutoLogin::new(opts(None, None));
        assert!(!al.is_active());
        assert!(al.handle_text("Username: ").is_empty());
        assert!(!opts(Some("  "), None).has_credentials());
        assert!(opts(None, Some("")).has_credentials());
    }

    #[test]
    fn prompt_classifiers() {
        assert!(is_command_prompt("router# "));
        assert!(is_command_prompt("user@host:~$ "));
        assert!(!is_command_prompt("Password: "));
        assert!(!is_command_prompt("Last login: "));
        assert!(is_continue_prompt("Hit any key to continue"));
        assert!(is_username_prompt("\x1b[1mlogin:\x1b[0m "));
        assert!(!is_username_prompt("Last login:"));
        assert!(is_password_prompt("口令："));
        assert!(is_auto_login_wake_input("\r\n"));
        assert!(!is_auto_login_wake_input(""));
        assert!(!is_auto_login_wake_input("a\r"));
    }

    #[test]
    fn terminal_report_sequences() {
        for s in [
            "\x1b[I",
            "\x1b[O",
            "\x1b[12;40R",
            "\x1b[?1;2c",
            "\x1b[>0;276;0c",
            "\x1b[0n",
            "\x1b[?1u",
            "\x1b[?2004;1$y",
            "\x1b[8;24;80t",
            "\x1b]11;rgb:0000/0000/0000\x07",
            "\x1b]4;12;rgb:ff/ff/ff\x1b\\",
            "\x1bP1+r544e=787465726d\x1b\\",
        ] {
            assert!(is_terminal_report_sequence(s), "{s:?}");
        }
        for s in ["", "a", "\r", "\x1b[A", "\x1b[200~paste\x1b[201~"] {
            assert!(!is_terminal_report_sequence(s), "{s:?}");
        }
    }
}
