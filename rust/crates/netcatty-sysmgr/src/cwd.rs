//! Interactive SSH shell cwd discovery (Electron `getSessionPwd` in
//! `sshBridge/sessionOps.cjs`).
//!
//! The probe runs on a sibling exec channel of the terminal's SSH
//! connection. It finds the user's interactive shell (a sibling under the
//! per-connection `sshd`, or a cousin sharing `SSH_CONNECTION` on older
//! OpenSSH), follows the foreground shell subtree (`su` / `sudo`), reads its
//! cwd from `/proc/<pid>/cwd` or `lsof`, and optionally falls back to the
//! login shell's cwd and then to the home directory. The script text is the
//! Electron one byte for byte (comments stripped so it fits Dropbear's
//! 9000-byte exec limit, #3731).

use crate::stats::{quote_shell_arg, with_remote_watchdog};

/// The probe script with `@@TARGET_LOGIN@@` / `@@ALLOW_HOME@@` /
/// `@@ALLOW_LOGIN@@` placeholders.
const PROBE_TEMPLATE: &str = include_str!("cwd_probe.sh");

/// Marker printed before an lsof-escaped pathname.
pub const LSOF_PREFIX: &str = "NETCATTY_LSOF_CWD=";

/// Default and maximum run bound (ms) of the probe.
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;
const MIN_TIMEOUT_MS: u64 = 100;

/// `getSessionPwd` options of the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CwdProbeOptions {
    pub allow_home_fallback: bool,
    pub allow_login_shell_fallback: bool,
    pub timeout_ms: u64,
}

impl CwdProbeOptions {
    /// Electron defaults: home fallback unless `false`; login-shell fallback
    /// follows the home fallback unless set; timeout clamped to 100..=5000.
    pub fn from_request(
        allow_home_fallback: Option<bool>,
        allow_login_shell_fallback: Option<bool>,
        timeout_ms: Option<f64>,
    ) -> Self {
        let allow_home_fallback = allow_home_fallback != Some(false);
        let timeout_ms = match timeout_ms {
            Some(ms) if ms.is_finite() => {
                ms.clamp(MIN_TIMEOUT_MS as f64, DEFAULT_TIMEOUT_MS as f64) as u64
            }
            _ => DEFAULT_TIMEOUT_MS,
        };
        Self {
            allow_home_fallback,
            allow_login_shell_fallback: allow_login_shell_fallback.unwrap_or(allow_home_fallback),
            timeout_ms,
        }
    }
}

impl Default for CwdProbeOptions {
    fn default() -> Self {
        Self::from_request(None, None, None)
    }
}

/// Only decimal pids are spliced into the script.
fn sanitize_pid(pid: Option<&str>) -> &str {
    match pid {
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p,
        _ => "",
    }
}

/// The POSIX probe script (`posixScript`).
pub fn probe_script(target_login_pid: Option<&str>, options: &CwdProbeOptions) -> String {
    PROBE_TEMPLATE
        .replace("@@TARGET_LOGIN@@", sanitize_pid(target_login_pid))
        .replace(
            "@@ALLOW_HOME@@",
            if options.allow_home_fallback {
                "1"
            } else {
                "0"
            },
        )
        .replace(
            "@@ALLOW_LOGIN@@",
            if options.allow_login_shell_fallback {
                "1"
            } else {
                "0"
            },
        )
}

/// The full exec command: `exec sh -c` (so `$PPID` is sshd even under a fish
/// / zsh login shell), sshd's pid exported as `NC_SSHD_PPID`, and the probe
/// under the remote watchdog.
pub fn probe_command(target_login_pid: Option<&str>, options: &CwdProbeOptions) -> String {
    let script = probe_script(target_login_pid, options);
    let inner = format!(
        "export NC_SSHD_PPID=$PPID; {}",
        with_remote_watchdog(
            &format!("sh -c {}", quote_shell_arg(&script)),
            options.timeout_ms
        )
    );
    format!("exec sh -c {}", quote_shell_arg(&inner))
}

/// Electron `decodeLsofFileName`: undo lsof's `\xNN`, octal and C escapes
/// (UTF-8 validated). The caret form (`^G`) is ambiguous and rejected.
pub fn decode_lsof_file_name(value: &str) -> Option<String> {
    let raw = value.as_bytes();
    for window in raw.windows(2) {
        if window[0] == b'^' && ((0x40..=0x5f).contains(&window[1]) || window[1] == b'?') {
            return None;
        }
    }
    let mut bytes = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if c != b'\\' {
            bytes.push(c);
            i += 1;
            continue;
        }
        let escaped = *raw.get(i + 1)?;
        let simple = match escaped {
            b'b' => Some(0x08),
            b'f' => Some(0x0c),
            b'n' => Some(0x0a),
            b'r' => Some(0x0d),
            b't' => Some(0x09),
            b'v' => Some(0x0b),
            b'\\' => Some(0x5c),
            _ => None,
        };
        if let Some(b) = simple {
            bytes.push(b);
            i += 2;
            continue;
        }
        if escaped == b'x' {
            let hex = raw.get(i + 2..i + 4)?;
            let text = std::str::from_utf8(hex).ok()?;
            if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            bytes.push(u8::from_str_radix(text, 16).ok()?);
            i += 4;
            continue;
        }
        let mut len = 0;
        while len < 3
            && raw
                .get(i + 1 + len)
                .is_some_and(|b| (b'0'..=b'7').contains(b))
        {
            len += 1;
        }
        if len == 0 {
            return None;
        }
        let octal = std::str::from_utf8(&raw[i + 1..i + 1 + len]).ok()?;
        bytes.push(u16::from_str_radix(octal, 8).ok()? as u8);
        i += 1 + len;
    }
    String::from_utf8(bytes).ok()
}

/// Parsed probe output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CwdProbeOutcome {
    /// Absolute cwd, when one was found.
    pub cwd: Option<String>,
    /// `NETCATTY_LOGIN_PID=` reported on stderr.
    pub login_pid: Option<String>,
}

/// Interpret stdout / stderr of [`probe_command`].
pub fn parse_probe_output(stdout: &str, stderr: &str) -> CwdProbeOutcome {
    let raw = stdout
        .strip_suffix("\r\n")
        .or_else(|| stdout.strip_suffix('\n'))
        .unwrap_or(stdout);
    let path = match raw.strip_prefix(LSOF_PREFIX) {
        Some(escaped) => decode_lsof_file_name(escaped),
        None => Some(raw.to_string()),
    };
    let login_pid = stderr.split('\n').find_map(|line| {
        line.strip_prefix("NETCATTY_LOGIN_PID=")
            .filter(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
            .map(str::to_string)
    });
    CwdProbeOutcome {
        cwd: path.filter(|p| p.starts_with('/')),
        login_pid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_follow_electron_defaults() {
        let d = CwdProbeOptions::default();
        assert!(d.allow_home_fallback && d.allow_login_shell_fallback);
        assert_eq!(d.timeout_ms, 5000);
        // Login fallback couples to home fallback when unset (#2886).
        let o = CwdProbeOptions::from_request(Some(false), None, Some(50.0));
        assert!(!o.allow_home_fallback && !o.allow_login_shell_fallback);
        assert_eq!(o.timeout_ms, 100);
        // ...but stays on when requested explicitly.
        let o = CwdProbeOptions::from_request(Some(false), Some(true), Some(99_999.0));
        assert!(!o.allow_home_fallback && o.allow_login_shell_fallback);
        assert_eq!(o.timeout_ms, 5000);
    }

    #[test]
    fn script_targets_a_known_shell_pid_only_when_numeric() {
        let opts = CwdProbeOptions::default();
        assert!(probe_script(Some("4242"), &opts).contains("TARGET_LOGIN=4242\n"));
        assert!(probe_script(Some("42; rm -rf /"), &opts).contains("TARGET_LOGIN=\n"));
        assert!(probe_script(None, &opts).contains("TARGET_LOGIN=\n"));
        let no_home = CwdProbeOptions::from_request(Some(false), Some(true), None);
        let s = probe_script(None, &no_home);
        assert!(s.contains("ALLOW_HOME_FALLBACK=0") && s.contains("ALLOW_LOGIN_FALLBACK=1"));
    }

    #[test]
    fn command_forces_posix_sh_captures_sshd_ppid_and_keeps_watchdog() {
        let cmd = probe_command(Some("4242"), &CwdProbeOptions::default());
        assert!(cmd.starts_with("exec sh -c '"));
        assert!(cmd.contains("export NC_SSHD_PPID=$PPID; ( sleep 5"));
        assert!(cmd.contains("TARGET_LOGIN=4242"));
        assert!(cmd.contains("LC_ALL=C lsof"));
        assert!(cmd.contains("$3 !~ /^\\?+$/"));
        assert!(cmd.contains("sub(/^.*\\//"));
    }

    #[test]
    fn command_fits_dropbear_limit_and_keeps_lsof_validation() {
        for pid in [None, Some("4242")] {
            let cmd = probe_command(pid, &CwdProbeOptions::default());
            assert!(cmd.len() <= 9000, "{} bytes", cmd.len());
            assert!(cmd.contains("readlink \"/proc/$1/cwd\""));
            assert!(cmd.contains("-Fnt 2>/dev/null"));
            assert!(cmd.contains("_rc_test_cwd"));
            assert!(!cmd.contains("# Find the user's interactive shell"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn script_and_command_parse_as_posix_sh() {
        let opts = CwdProbeOptions::default();
        for text in [probe_script(Some("1"), &opts), probe_command(None, &opts)] {
            let status = std::process::Command::new("sh")
                .args(["-n", "-c", &text])
                .status()
                .expect("sh");
            assert!(status.success());
        }
    }

    #[test]
    fn lsof_names_decode_utf8_and_escapes() {
        assert_eq!(
            decode_lsof_file_name("/tmp/\\xe4\\xb8\\xad\\xe6\\x96\\x87").as_deref(),
            Some("/tmp/中文")
        );
        assert_eq!(
            decode_lsof_file_name("/tmp/line1\\nline2\\\\tail").as_deref(),
            Some("/tmp/line1\nline2\\tail")
        );
        assert_eq!(
            decode_lsof_file_name("/tmp/oct\\101").as_deref(),
            Some("/tmp/octA")
        );
        assert_eq!(decode_lsof_file_name("/tmp/bad\\xQZ"), None);
        assert_eq!(decode_lsof_file_name("/tmp/control-^G-name"), None);
        assert_eq!(decode_lsof_file_name("/tmp/trailing\\"), None);
        assert_eq!(decode_lsof_file_name("/tmp/\\xff"), None);
    }

    #[test]
    fn output_parsing_handles_lsof_marker_and_login_pid() {
        let out = parse_probe_output("/srv/app\n", "NETCATTY_LOGIN_PID=4242\n");
        assert_eq!(out.cwd.as_deref(), Some("/srv/app"));
        assert_eq!(out.login_pid.as_deref(), Some("4242"));
        let out = parse_probe_output(
            "NETCATTY_LSOF_CWD=/Users/a\\x20b\n",
            "noise\nNETCATTY_LOGIN_PID=7\n",
        );
        assert_eq!(out.cwd.as_deref(), Some("/Users/a b"));
        assert_eq!(out.login_pid.as_deref(), Some("7"));
        let out = parse_probe_output("relative\n", "");
        assert_eq!(out.cwd, None);
        assert_eq!(out.login_pid, None);
    }
}
