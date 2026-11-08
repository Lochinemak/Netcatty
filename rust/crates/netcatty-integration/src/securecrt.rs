//! SecureCRT-style command lines (`/SSH2 /L user /P 22 /PASSWORD pass host`,
//! case-insensitive), emitted by 4A / PAM bastion launchers configured as
//! "SecureCRT" (Electron: `electron/secureCrtCommandLine.cjs`).

use crate::putty::{
    contains, is_runtime_noise_arg, mask, parse_host_spec, parse_port, to_deep_link_url,
    LaunchProtocol, ParsedLaunch, PUTTY_VALUE_FLAGS,
};
use std::collections::BTreeSet;

const PROTOCOL_FLAGS: &[(&str, LaunchProtocol)] = &[
    ("/ssh", LaunchProtocol::Ssh),
    ("/ssh1", LaunchProtocol::Ssh),
    ("/ssh2", LaunchProtocol::Ssh),
    ("/telnet", LaunchProtocol::Telnet),
];
const UNSUPPORTED_PROTOCOL_FLAGS: &[&str] = &["/serial", "/rlogin", "/tapi"];
const VALUE_FLAGS: &[&str] = &[
    "/l", "/p", "/password", "/auth", "/i", "/passphrase", "/s", "/n", "/titlebar", "/log",
    "/logappend", "/firewall", "/fwfirewall", "/proxy",
];
const IGNORED_VALUE_FLAGS: &[&str] = &[
    "/auth", "/i", "/passphrase", "/s", "/n", "/titlebar", "/log", "/logappend", "/firewall",
    "/fwfirewall", "/proxy",
];
const SKIP_FLAGS: &[&str] = &["/t", "/new", "/x", "/c", "/v", "/a", "/z"];
const PASSWORD_REDACT_FLAGS: &[&str] = &["/password", "/passphrase"];

/// Result of [`parse_secure_crt_tokens`]: the launch (or `None` on a parse
/// failure) plus the argv indices it used.
#[derive(Debug, Default)]
pub struct SecureCrtTokens {
    pub result: Option<ParsedLaunch>,
    /// Every token used by a successful parse (switches, operands, the host).
    pub consumed: BTreeSet<usize>,
    /// Operands of known value switches; never standalone URLs, even when
    /// the parse fails.
    pub operands: BTreeSet<usize>,
    /// Username / password / passphrase operands.
    pub credentials: BTreeSet<usize>,
}

fn flag_of(arg: &str) -> String {
    arg.to_lowercase()
}

fn has_launch_signal(argv: &[String]) -> bool {
    let mut index = 1;
    while index < argv.len() {
        let flag = flag_of(&argv[index]);
        if PROTOCOL_FLAGS.iter().any(|(f, _)| *f == flag) || contains(PASSWORD_REDACT_FLAGS, &flag)
        {
            return true;
        }
        if contains(VALUE_FLAGS, &flag) || contains(PUTTY_VALUE_FLAGS, &argv[index]) {
            index += 1;
        }
        index += 1;
    }
    false
}

/// Identify every known option operand before validating values, so an early
/// failure cannot turn a later option value into a standalone scheme URL.
fn find_operands(argv: &[String]) -> (BTreeSet<usize>, BTreeSet<usize>) {
    let mut operands = BTreeSet::new();
    let mut credentials = BTreeSet::new();
    let mut index = 0;
    while index < argv.len() {
        let flag = flag_of(&argv[index]);
        if contains(VALUE_FLAGS, &flag) && index + 1 < argv.len() {
            operands.insert(index + 1);
            if contains(PASSWORD_REDACT_FLAGS, &flag) || flag == "/l" {
                credentials.insert(index + 1);
            }
            index += 1;
        }
        index += 1;
    }
    (operands, credentials)
}

fn is_scheme_url(arg: &str) -> bool {
    let trimmed = arg.trim();
    let Some((scheme, _)) = trimmed.split_once("://") else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

fn is_electron_entry_point(index: usize, argv: &[String], arg: &str) -> bool {
    if index != 1 {
        return false;
    }
    let exe = argv[0].to_ascii_lowercase();
    let base = exe.rsplit(['/', '\\']).next().unwrap_or(&exe);
    let lower = arg.to_ascii_lowercase();
    (base == "electron" || base == "electron.exe")
        && [".js", ".cjs", ".mjs", ".asar"].iter().any(|e| lower.ends_with(e))
}

/// `None` without a SecureCRT launch signal; otherwise the parse result and
/// the token indices (see [`SecureCrtTokens`]).
pub fn parse_secure_crt_tokens(argv: &[String]) -> Option<SecureCrtTokens> {
    if !has_launch_signal(argv) {
        return None;
    }
    let (operands, credentials) = find_operands(argv);
    let mut tokens = SecureCrtTokens {
        result: None,
        consumed: BTreeSet::new(),
        operands,
        credentials,
    };
    let mut protocol = LaunchProtocol::Ssh;
    let mut username: Option<String> = None;
    let mut password: Option<zeroize::Zeroizing<String>> = None;
    let mut port: Option<u16> = None;
    let mut tab_name: Option<String> = None;
    let mut positionals = Vec::new();

    let mut index = 0;
    while index < argv.len() {
        let arg = argv[index].as_str();
        let current = index;
        index += 1;
        if arg.is_empty() {
            continue;
        }
        let flag = flag_of(arg);
        if contains(UNSUPPORTED_PROTOCOL_FLAGS, &flag) {
            return Some(tokens);
        }
        if let Some((_, selected)) = PROTOCOL_FLAGS.iter().find(|(f, _)| *f == flag) {
            protocol = *selected;
            tokens.consumed.insert(current);
            continue;
        }
        if contains(SKIP_FLAGS, &flag) {
            tokens.consumed.insert(current);
            continue;
        }
        if contains(VALUE_FLAGS, &flag) {
            let Some(value) = argv.get(index) else {
                return Some(tokens);
            };
            tokens.consumed.insert(current);
            tokens.consumed.insert(index);
            let operand = index;
            index += 1;
            if flag == "/p" {
                match parse_port(value) {
                    Some(p) => port = Some(p),
                    None => return Some(tokens),
                }
                continue;
            }
            if flag == "/l" {
                tokens.credentials.insert(operand);
                let user = value.trim();
                if user.is_empty() {
                    return Some(tokens);
                }
                username = Some(user.to_owned());
                continue;
            }
            if flag == "/password" {
                tokens.credentials.insert(operand);
                if value.is_empty() {
                    return Some(tokens);
                }
                password = Some(zeroize::Zeroizing::new(value.clone()));
                continue;
            }
            if flag == "/n" {
                tab_name = Some(value.trim().to_owned());
            }
            if !contains(IGNORED_VALUE_FLAGS, &flag) || value.trim().is_empty() {
                return Some(tokens);
            }
            continue;
        }
        // Only the executable and an Electron development entry point are
        // paths; other slash-prefixed tokens are (unknown) switches.
        if current > 0 && !is_electron_entry_point(current, argv, arg) && arg.starts_with('/') {
            return Some(tokens);
        }
        if is_scheme_url(arg) {
            continue;
        }
        if is_runtime_noise_arg(arg, current, argv) {
            tokens.consumed.insert(current);
            continue;
        }
        // Single-dash client switches are not SecureCRT syntax.
        if arg.starts_with('-') {
            return Some(tokens);
        }
        if let Some(spec) = parse_host_spec(arg) {
            positionals.push(spec);
            tokens.consumed.insert(current);
        }
    }

    // One destination only: never guess between hosts.
    if positionals.len() != 1 {
        return Some(tokens);
    }
    let host_spec = positionals.remove(0);
    let resolved_username = username
        .or(host_spec.username)
        .map(|u| u.trim().to_owned())
        .filter(|u| !u.is_empty());
    let resolved_port = port.or(host_spec.port);
    let hostname = host_spec.hostname;
    let url = to_deep_link_url(
        protocol,
        resolved_username.as_deref(),
        password.as_deref().map(String::as_str),
        &hostname,
        resolved_port,
    );
    tokens.result = Some(ParsedLaunch {
        protocol,
        url,
        hostname,
        username: resolved_username,
        password: password.map(|p| p.to_string()),
        port: resolved_port,
        tab_name: tab_name.filter(|t| !t.is_empty()),
    });
    Some(tokens)
}

pub fn parse_secure_crt_command_line(argv: &[String]) -> Option<ParsedLaunch> {
    parse_secure_crt_tokens(argv).and_then(|t| t.result)
}

/// Mask `/PASSWORD` and `/PASSPHRASE` operands in place, skipping operands of
/// other switches (a username equal to `/PASSWORD` is not a switch).
pub fn redact_secure_crt_command_line_passwords(argv: &mut [String]) {
    let mut index = 0;
    while index < argv.len() {
        let flag = flag_of(&argv[index]);
        if !contains(VALUE_FLAGS, &flag) && !contains(PUTTY_VALUE_FLAGS, &argv[index]) {
            index += 1;
            continue;
        }
        if index + 1 >= argv.len() {
            index += 1;
            continue;
        }
        if contains(PASSWORD_REDACT_FLAGS, &flag) {
            let next = &mut argv[index + 1];
            let masked = mask(next);
            zeroize::Zeroize::zeroize(next);
            *next = masked;
        }
        index += 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn parse(items: &[&str]) -> Option<ParsedLaunch> {
        parse_secure_crt_command_line(&argv(items))
    }

    fn set(items: &[usize]) -> BTreeSet<usize> {
        items.iter().copied().collect()
    }

    #[test]
    fn accepts_4a_ssh2_launch() {
        let parsed = parse(&[
            r"C:\Program Files\Netcatty\Netcatty.exe", "/SSH2", "/L", "alice", "/P", "2222",
            "/PASSWORD", "s3cret", "10.0.0.8",
        ])
        .unwrap();
        assert_eq!(parsed.url, "ssh://alice:s3cret@10.0.0.8:2222");
        assert_eq!(parsed.hostname, "10.0.0.8");
        assert_eq!(parsed.password.as_deref(), Some("s3cret"));
        assert_eq!(parsed.port, Some(2222));
    }

    #[test]
    fn accepts_pam_style_line_with_tab_name() {
        let parsed = parse(&[
            "Netcatty.exe", "/T", "/N", "Device", "/SSH2", "/L", "root", "192.168.10.2", "/P", "22",
        ])
        .unwrap();
        assert_eq!(parsed.url, "ssh://root@192.168.10.2:22");
        assert_eq!(parsed.password, None);
        assert_eq!(parsed.tab_name.as_deref(), Some("Device"));
    }

    #[test]
    fn case_insensitive_flags_telnet_and_ignored_values() {
        let parsed = parse(&["Netcatty.exe", "/ssh2", "/password", "pw", "bob@host.example.com"]).unwrap();
        assert_eq!(parsed.url, "ssh://bob:pw@host.example.com");
        let telnet = parse(&["Netcatty.exe", "/TELNET", "old.example.com", "/P", "2323"]).unwrap();
        assert_eq!(telnet.protocol, LaunchProtocol::Telnet);
        assert_eq!(telnet.url, "telnet://old.example.com:2323");
        let ignored = parse(&[
            "Netcatty.exe", "/SSH2", "/AUTH", "keyboard-interactive", "/I", r"C:\keys\id_rsa", "/S",
            "Production", "/L", "ops", "/PASSWORD", "hunter2", "bastion.example.com",
        ])
        .unwrap();
        assert_eq!(ignored.url, "ssh://ops:hunter2@bastion.example.com");
    }

    #[test]
    fn rejects_unsupported_and_missing_values() {
        assert!(parse(&["Netcatty.exe", "/SERIAL", "com1"]).is_none());
        assert!(parse(&["Netcatty.exe", "/SSH2", "/L"]).is_none());
        assert!(parse(&["Netcatty.exe", "/SSH2", "/P", "99999"]).is_none());
        assert!(parse(&["Netcatty.exe", "/SSH2", "/PASSWORD", ""]).is_none());
        assert!(parse(&["Netcatty.exe", "-ssh", "user@host", "-pw", "x"]).is_none());
    }

    #[test]
    fn consumed_indices_on_success_and_failure() {
        let ok = parse_secure_crt_tokens(&argv(&[
            "Netcatty.exe", "/SSH2", "/L", "alice", "/PASSWORD", "ssh://s3cret", "10.0.0.8",
        ]))
        .unwrap();
        assert_eq!(
            ok.result.as_ref().unwrap().url,
            "ssh://alice:ssh%3A%2F%2Fs3cret@10.0.0.8"
        );
        assert_eq!(ok.consumed, set(&[0, 1, 2, 3, 4, 5, 6]));

        let fail = parse_secure_crt_tokens(&argv(&[
            "Netcatty.exe", "/SSH2", "/PASSWORD", "ssh://s3cret", "/SERIAL", "com1",
        ]))
        .unwrap();
        assert!(fail.result.is_none());
        assert_eq!(fail.consumed, set(&[0, 1, 2, 3]));

        let bad_port = parse_secure_crt_tokens(&argv(&[
            "Netcatty.exe", "/SSH2", "/PASSWORD", "ssh://s3cret", "/P", "99999", "10.0.0.8",
        ]))
        .unwrap();
        assert!(bad_port.result.is_none());
        assert_eq!(bad_port.consumed, set(&[0, 1, 2, 3, 4, 5]));
        assert_eq!(bad_port.credentials, set(&[3]));
    }

    #[test]
    fn credential_operands_are_reported_after_an_early_failure() {
        for (items, expected) in [
            (vec!["Netcatty.exe", "/SSH2", "/P", "99999", "/PASSWORD", "ssh://secret", "real.example.com"], 5),
            (vec!["Netcatty.exe", "/SSH2", "/PASSPHRASE", "ssh://secret", "/P", "99999", "10.0.0.8"], 3),
            (vec!["Netcatty.exe", "/SSH2", "/P", "99999", "/L", "ssh://alice", "real.example.com"], 5),
        ] {
            let tokens = parse_secure_crt_tokens(&argv(&items)).unwrap();
            assert!(tokens.result.is_none());
            assert_eq!(tokens.credentials, set(&[expected]));
        }
    }

    #[test]
    fn no_signal_returns_none() {
        assert!(parse_secure_crt_tokens(&argv(&["Netcatty.exe", "ssh://alice@example.com"])).is_none());
    }

    #[test]
    fn redaction_masks_password_and_passphrase_only() {
        let mut items = argv(&["Netcatty.exe", "/SSH2", "/PASSWORD", "s3cret", "/PASSPHRASE", "phrase", "host"]);
        redact_secure_crt_command_line_passwords(&mut items);
        assert_eq!(
            items,
            argv(&["Netcatty.exe", "/SSH2", "/PASSWORD", "******", "/PASSPHRASE", "******", "host"])
        );
        let mut tricky = argv(&["Netcatty.exe", "/SSH2", "/L", "/PASSWORD", "/PASSWORD", "secret", "server.example.com"]);
        redact_secure_crt_command_line_passwords(&mut tricky);
        assert_eq!(
            tricky,
            argv(&["Netcatty.exe", "/SSH2", "/L", "/PASSWORD", "/PASSWORD", "******", "server.example.com"])
        );
    }

    #[test]
    fn title_address_is_never_the_destination() {
        let parsed = parse(&[
            r"C:\Program Files\Netcatty\Netcatty.exe", "/TITLEBAR", "192.0.2.10", "/N", "192.0.2.10",
            "/T", "/SSH2", "198.51.100.20", "/P", "2200", "/L", "alice", "/PASSWORD", "example",
        ])
        .unwrap();
        assert_eq!(parsed.url, "ssh://alice:example@198.51.100.20:2200");
    }

    #[test]
    fn unknown_switches_are_rejected() {
        assert!(parse(&["Netcatty.exe", "/SSH2", "/SCRIPT", "login.vbs", "/L", "alice", "/PASSWORD", "secret", "server"]).is_none());
        for flag in ["/UNKNOWN-FLAG", "/UNKNOWN_FLAG", "/UNKNOWN=value", "/UNKNOWN:value", "/unknown/path"] {
            assert!(parse(&["Netcatty.exe", "/SSH2", flag, "server.example.com"]).is_none());
        }
    }

    #[test]
    fn electron_development_entry_is_accepted() {
        assert_eq!(
            parse(&[
                "/Applications/Electron.app/Contents/MacOS/Electron", "/workspace/electron/main.cjs",
                "/SSH2", "/L", "alice", "server.example.com",
            ])
            .unwrap()
            .url,
            "ssh://alice@server.example.com"
        );
    }
}
