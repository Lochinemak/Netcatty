//! PuTTY-style command lines (`-ssh user@host -P 22 -pw secret`), as emitted
//! by bastion / PAM launchers such as JumpServer (Electron:
//! `electron/puttyCommandLine.cjs`). The parsed launch becomes an `ssh://` or
//! `telnet://` URL that flows through the same deep-link queue as scheme
//! links.

/// Connection protocol selected by a command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchProtocol {
    Ssh,
    Telnet,
}

impl LaunchProtocol {
    pub fn scheme(self) -> &'static str {
        match self {
            LaunchProtocol::Ssh => "ssh",
            LaunchProtocol::Telnet => "telnet",
        }
    }
}

/// A parsed PuTTY / SecureCRT launch. `url` embeds the password, so the
/// `Debug` output redacts it.
#[derive(Clone, PartialEq, Eq)]
pub struct ParsedLaunch {
    pub protocol: LaunchProtocol,
    pub url: String,
    pub hostname: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub port: Option<u16>,
    pub tab_name: Option<String>,
}

impl std::fmt::Debug for ParsedLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedLaunch")
            .field("protocol", &self.protocol)
            .field("hostname", &self.hostname)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("port", &self.port)
            .field("tab_name", &self.tab_name)
            .finish()
    }
}

impl Drop for ParsedLaunch {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.url.zeroize();
        if let Some(password) = self.password.as_mut() {
            password.zeroize();
        }
    }
}

/// `user@host[:port]` / `[v6]:port` positional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSpec {
    pub username: Option<String>,
    pub hostname: String,
    pub port: Option<u16>,
}

const PROTOCOL_FLAGS: &[(&str, LaunchProtocol)] =
    &[("-ssh", LaunchProtocol::Ssh), ("-telnet", LaunchProtocol::Telnet)];
const UNSUPPORTED_PROTOCOL_FLAGS: &[&str] =
    &["-raw", "-rlogin", "-serial", "-ssh-connection", "-supdup"];
/// PuTTY switches whose next token is a value (case-sensitive like PuTTY).
pub const PUTTY_VALUE_FLAGS: &[&str] = &[
    "-P", "-p", "-l", "-pw", "-pwfile", "-load", "-i", "-m", "-cmd", "-L", "-R", "-D", "-nc",
    "-hostkey", "-loghost", "-sercfg", "-sessionlog", "-sshlog", "-sshrawlog", "-proxycmd",
    "-newtab", "-title", "-url",
];
const REJECT_VALUE_FLAGS: &[&str] = &["-pwfile", "-i", "-hostkey", "-loghost"];
const PORT_FLAGS: &[&str] = &["-P", "-p"];
const SKIP_FLAGS: &[&str] = &[
    "-1", "-2", "-4", "-6", "-ipv4", "-ipv6", "-A", "-a", "-C", "-N", "-T", "-t", "-X", "-x",
    "-v", "-agent", "-pagent", "-pageant", "-noagent", "-nopagent", "-nopageant", "-share",
    "-noshare", "-batch", "-nethack", "-pgpfp", "-cleanup", "-help", "-no-antispoof",
    "-sanitise-stderr", "-sanitise-stdout", "-no-sanitise-stderr", "-no-sanitise-stdout",
    "-restrict-acl", "-restrict_acl", "-restrictacl",
];

pub(crate) fn contains(list: &[&str], value: &str) -> bool {
    list.contains(&value)
}

/// `Number(raw.trim())` integer in 1..=65535 (decimal, `0x` hex, exponent
/// and `22.0` forms are accepted like JavaScript's `Number`).
pub fn parse_port(raw: &str) -> Option<u16> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let value = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()? as f64
    } else {
        // Rust accepts `inf` / `nan` spellings JavaScript does not; neither is
        // an integer port anyway.
        trimmed.parse::<f64>().ok()?
    };
    if !value.is_finite() || value.fract() != 0.0 || !(1.0..=65535.0).contains(&value) {
        return None;
    }
    Some(value as u16)
}

pub(crate) fn looks_like_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
}

pub(crate) fn looks_like_ipv6(value: &str) -> bool {
    value.matches(':').count() >= 2
}

fn is_display_ipv4(value: &str) -> bool {
    looks_like_ipv4(value) && value.split('.').all(|p| p.parse::<u16>().is_ok_and(|n| n <= 255))
}

/// Node's `net.isIP(value) === 6`, which also accepts a `%zone` suffix.
fn is_display_ipv6(value: &str) -> bool {
    let (addr, zone) = match value.split_once('%') {
        Some((addr, zone)) => (addr, Some(zone)),
        None => (value, None),
    };
    if let Some(zone) = zone {
        if zone.is_empty()
            || !zone
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':'))
        {
            return false;
        }
    }
    addr.parse::<std::net::Ipv6Addr>().is_ok()
}

fn is_electron_executable_name(arg: &str) -> bool {
    let base = arg.rsplit(['/', '\\']).next().unwrap_or(arg).to_ascii_lowercase();
    base == "electron" || base == "electron.exe"
}

fn has_script_extension(arg: &str) -> bool {
    let lower = arg.to_ascii_lowercase();
    [".js", ".cjs", ".mjs", ".asar"]
        .iter()
        .any(|ext| lower.ends_with(ext))
}

/// Tokens that belong to the runtime rather than the launch: the executable,
/// `.` / `--`, `--switches`, the Electron development entry point and paths
/// (a path never carries `@`).
pub fn is_runtime_noise_arg(arg: &str, index: usize, argv: &[String]) -> bool {
    if index == 0 || arg == "." || arg == "--" || arg.starts_with("--") {
        return true;
    }
    if index == 1
        && argv.first().is_some_and(|a| is_electron_executable_name(a))
        && has_script_extension(arg)
        && !arg.contains('@')
    {
        return true;
    }
    (arg.contains('/') || arg.contains('\\')) && !arg.contains('@')
}

/// Parse a `user@host[:port]`, `[v6]:port` or bare host token.
pub fn parse_host_spec(raw: &str) -> Option<HostSpec> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('-') {
        return None;
    }
    let (username, host_part) = match trimmed.rfind('@') {
        Some(at) => {
            let user = trimmed[..at].trim();
            (
                (!user.is_empty()).then(|| user.to_owned()),
                trimmed[at + 1..].trim(),
            )
        }
        None => (None, trimmed),
    };
    if host_part.is_empty() {
        return None;
    }
    let (hostname, port) = if let Some(inner) = host_part.strip_prefix('[') {
        let end = inner.find(']')?;
        let hostname = inner[..end].trim();
        let rest = &inner[end + 1..];
        let port = if rest.is_empty() {
            None
        } else {
            Some(parse_port(rest.strip_prefix(':')?)?)
        };
        (hostname, port)
    } else if !looks_like_ipv6(host_part) && host_part.contains(':') {
        let colon = host_part.rfind(':').unwrap_or(0);
        let port = parse_port(&host_part[colon + 1..])?;
        (host_part[..colon].trim(), Some(port))
    } else {
        (host_part.trim(), None)
    };
    if hostname.is_empty() {
        return None;
    }
    Some(HostSpec {
        username,
        hostname: hostname.to_owned(),
        port,
    })
}

fn host_candidate_score(spec: &HostSpec) -> u32 {
    let mut score = 1;
    if spec.username.is_some() {
        score += 4;
    }
    if spec.port.is_some() {
        score += 2;
    }
    if looks_like_ipv4(&spec.hostname) || looks_like_ipv6(&spec.hostname) {
        score += 3;
    } else if spec.hostname.contains('.') {
        score += 2;
    }
    score
}

/// One leftover IP positional names the tab (the PuTTY analogue of
/// SecureCRT `/N`); several are ambiguous.
fn positional_target_display_host(positionals: &[HostSpec], chosen: usize) -> Option<String> {
    let chosen_spec = &positionals[chosen];
    chosen_spec.username.as_ref()?;
    let leftovers: Vec<&HostSpec> = positionals
        .iter()
        .enumerate()
        .filter(|(i, spec)| {
            *i != chosen
                && spec.hostname != chosen_spec.hostname
                && (is_display_ipv4(&spec.hostname) || is_display_ipv6(&spec.hostname))
        })
        .map(|(_, spec)| spec)
        .collect();
    (leftovers.len() == 1).then(|| leftovers[0].hostname.clone())
}

/// 4A / jump launchers stash the final server in the login name
/// (`user@203.0.113.10@bastion`, `user#203.0.113.10#ssh#22#root@bastion`).
fn embedded_target_display_host(username: Option<&str>, connection_host: &str) -> Option<String> {
    let username = username?;
    if !username.contains(['@', '#', '/', '|']) {
        return None;
    }
    let mut display = None;
    for segment in username.split(['@', '#', '/', '|']) {
        let Some(spec) = parse_host_spec(segment.trim()) else {
            continue;
        };
        let host = spec.hostname;
        if host == connection_host {
            continue;
        }
        if !is_display_ipv4(&host) && !is_display_ipv6(&host) {
            continue;
        }
        display = Some(host);
    }
    display
}

/// JavaScript `encodeURIComponent`.
pub fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')')
        {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `scheme://[user[:password]@]host[:port]` with `[v6]` brackets.
pub fn to_deep_link_url(
    protocol: LaunchProtocol,
    username: Option<&str>,
    password: Option<&str>,
    hostname: &str,
    port: Option<u16>,
) -> String {
    let auth = match (username, password) {
        (Some(user), Some(pass)) => {
            format!("{}:{}", encode_uri_component(user), encode_uri_component(pass))
        }
        (Some(user), None) => encode_uri_component(user),
        (None, Some(pass)) => format!(":{}", encode_uri_component(pass)),
        (None, None) => String::new(),
    };
    let host = if hostname.contains(':') {
        format!("[{hostname}]")
    } else {
        hostname.to_owned()
    };
    let port = port.map(|p| format!(":{p}")).unwrap_or_default();
    let auth = if auth.is_empty() {
        auth
    } else {
        format!("{auth}@")
    };
    format!("{}://{auth}{host}{port}", protocol.scheme())
}

fn has_putty_launch_signal(argv: &[String]) -> bool {
    argv.iter().any(|arg| {
        PROTOCOL_FLAGS.iter().any(|(flag, _)| flag == arg)
            || arg == "-pw"
            || arg == "-pwfile"
            || arg == "-l"
            || contains(PORT_FLAGS, arg)
    })
}

/// Parse a PuTTY-style launch; `None` when the argv is not one or uses an
/// option Netcatty cannot honour (password files, keys, other transports).
pub fn parse_putty_command_line(argv: &[String]) -> Option<ParsedLaunch> {
    if !has_putty_launch_signal(argv) {
        return None;
    }
    let mut protocol = LaunchProtocol::Ssh;
    let mut username: Option<String> = None;
    let mut password: Option<zeroize::Zeroizing<String>> = None;
    let mut port: Option<u16> = None;
    let mut tab_name: Option<String> = None;
    let mut positionals: Vec<HostSpec> = Vec::new();

    let mut index = 0;
    while index < argv.len() {
        let arg = argv[index].as_str();
        let current = index;
        index += 1;
        if arg.is_empty() || is_runtime_noise_arg(arg, current, argv) {
            continue;
        }
        if let Some((_, selected)) = PROTOCOL_FLAGS.iter().find(|(flag, _)| *flag == arg) {
            protocol = *selected;
            continue;
        }
        if contains(UNSUPPORTED_PROTOCOL_FLAGS, arg) {
            return None;
        }
        if contains(SKIP_FLAGS, arg) {
            continue;
        }
        if contains(PUTTY_VALUE_FLAGS, arg) {
            let value = argv.get(index)?.as_str();
            index += 1;
            if contains(REJECT_VALUE_FLAGS, arg) {
                return None;
            }
            if contains(PORT_FLAGS, arg) {
                port = Some(parse_port(value)?);
                continue;
            }
            match arg {
                "-l" => {
                    let user = value.trim();
                    if user.is_empty() {
                        return None;
                    }
                    username = Some(user.to_owned());
                    continue;
                }
                "-pw" => {
                    if value.is_empty() {
                        return None;
                    }
                    password = Some(zeroize::Zeroizing::new(value.to_owned()));
                    continue;
                }
                "-newtab" => tab_name = Some(value.trim().to_owned()),
                _ => {}
            }
            if value.trim().is_empty() {
                return None;
            }
            continue;
        }
        if arg.starts_with('-') {
            return None;
        }
        if parse_port(arg).is_some() && arg.trim().bytes().all(|b| b.is_ascii_digit()) {
            if port.is_none() {
                port = parse_port(arg);
            }
            continue;
        }
        if let Some(spec) = parse_host_spec(arg) {
            positionals.push(spec);
        }
    }

    if positionals.is_empty() {
        return None;
    }
    let mut chosen = 0;
    for (i, candidate) in positionals.iter().enumerate().skip(1) {
        if host_candidate_score(candidate) > host_candidate_score(&positionals[chosen]) {
            chosen = i;
        }
    }
    let host_spec = &positionals[chosen];
    let resolved_username = username
        .or_else(|| host_spec.username.clone())
        .map(|u| u.trim().to_owned())
        .filter(|u| !u.is_empty());
    let resolved_port = port.or(host_spec.port);
    let hostname = host_spec.hostname.clone();
    let resolved_tab = tab_name
        .filter(|t| !t.is_empty())
        .or_else(|| positional_target_display_host(&positionals, chosen))
        .or_else(|| embedded_target_display_host(resolved_username.as_deref(), &hostname));
    let url = to_deep_link_url(
        protocol,
        resolved_username.as_deref(),
        password.as_deref().map(String::as_str),
        &hostname,
        resolved_port,
    );
    Some(ParsedLaunch {
        protocol,
        url,
        hostname,
        username: resolved_username,
        password: password.map(|p| p.to_string()),
        port: resolved_port,
        tab_name: resolved_tab,
    })
}

pub(crate) fn mask(value: &str) -> String {
    let len = value.chars().count().min(8);
    if len == 0 {
        "********".to_owned()
    } else {
        "*".repeat(len)
    }
}

/// Mask `-pw` operands in place (for anything that may be logged).
pub fn redact_putty_command_line_passwords(argv: &mut [String]) {
    for index in 0..argv.len() {
        if argv[index] != "-pw" {
            continue;
        }
        if let Some(next) = argv.get_mut(index + 1) {
            let masked = mask(next);
            zeroize::Zeroize::zeroize(next);
            *next = masked;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn parse(items: &[&str]) -> Option<ParsedLaunch> {
        parse_putty_command_line(&argv(items))
    }

    #[test]
    fn accepts_jumpserver_template() {
        let parsed = parse(&[
            r"C:\Program Files\Netcatty\Netcatty.exe",
            "-ssh",
            "alice@10.0.0.8",
            "-P",
            "2222",
            "-pw",
            "s3cret",
        ])
        .unwrap();
        assert_eq!(parsed.protocol, LaunchProtocol::Ssh);
        assert_eq!(parsed.url, "ssh://alice:s3cret@10.0.0.8:2222");
        assert_eq!(parsed.hostname, "10.0.0.8");
        assert_eq!(parsed.username.as_deref(), Some("alice"));
        assert_eq!(parsed.password.as_deref(), Some("s3cret"));
        assert_eq!(parsed.port, Some(2222));
        assert_eq!(parsed.tab_name, None);
    }

    #[test]
    fn accepts_dash_l_and_mixed_order() {
        let parsed = parse(&[
            "Netcatty.exe",
            "bastion.example.com",
            "-P",
            "22",
            "-l",
            "ops",
            "-pw",
            "hunter2",
            "-ssh",
        ])
        .unwrap();
        assert_eq!(parsed.url, "ssh://ops:hunter2@bastion.example.com:22");
        assert_eq!(parsed.username.as_deref(), Some("ops"));
    }

    #[test]
    fn prefers_user_at_host_over_newtab_names() {
        let parsed = parse(&[
            "Netcatty.exe",
            "-newtab",
            "Production",
            "-ssh",
            "root@192.168.10.2",
            "-P",
            "22",
            "-pw",
            "one-time",
        ])
        .unwrap();
        assert_eq!(parsed.hostname, "192.168.10.2");
        assert_eq!(parsed.url, "ssh://root:one-time@192.168.10.2:22");
        assert_eq!(parsed.tab_name.as_deref(), Some("Production"));
    }

    #[test]
    fn percent_encodes_passwords() {
        let parsed = parse(&["Netcatty.exe", "-ssh", "alice@example.com", "-pw", "p@ss:w/rd"]).unwrap();
        assert_eq!(parsed.url, "ssh://alice:p%40ss%3Aw%2Frd@example.com");
        assert_eq!(parsed.password.as_deref(), Some("p@ss:w/rd"));
    }

    #[test]
    fn ipv6_and_positional_port() {
        let parsed = parse(&["electron", ".", "-ssh", "bob@[2001:db8::10]", "2200"]).unwrap();
        assert_eq!(parsed.hostname, "2001:db8::10");
        assert_eq!(parsed.port, Some(2200));
        assert_eq!(parsed.url, "ssh://bob@[2001:db8::10]:2200");
    }

    #[test]
    fn host_port_without_dash_p_and_telnet() {
        assert_eq!(
            parse(&["Netcatty.exe", "-ssh", "alice@bastion.example.com:2222", "-pw", "token"])
                .unwrap()
                .url,
            "ssh://alice:token@bastion.example.com:2222"
        );
        let telnet = parse(&["Netcatty.exe", "-telnet", "router.lab", "-P", "23"]).unwrap();
        assert_eq!(telnet.protocol, LaunchProtocol::Telnet);
        assert_eq!(telnet.url, "telnet://router.lab:23");
    }

    #[test]
    fn ignores_runtime_flags_missing_hosts_and_bad_ports() {
        assert!(parse(&["Netcatty.exe", "--enable-logging", "-ssh"]).is_none());
        assert!(parse(&["Netcatty.exe", "just-a-file.txt"]).is_none());
        assert!(parse(&["Netcatty.exe", "-P", "22"]).is_none());
        assert!(parse(&["Netcatty.exe", "-ssh", "host.example", "-P", "99999"]).is_none());
    }

    #[test]
    fn value_operands_are_not_hosts_or_ports() {
        let m = parse(&[
            "Netcatty.exe", "-ssh", "-l", "alice", "server.example", "-m", "commands.txt", "-pw",
            "secret",
        ])
        .unwrap();
        assert_eq!(m.url, "ssh://alice:secret@server.example");
        let d = parse(&["Netcatty.exe", "-ssh", "alice@server.example", "-D", "1080", "-pw", "secret"])
            .unwrap();
        assert_eq!(d.port, None);
        assert_eq!(d.url, "ssh://alice:secret@server.example");
        let cmd = parse(&["Netcatty.exe", "-ssh", "alice@server.example", "-cmd", "whoami", "-pw", "secret"])
            .unwrap();
        assert_eq!(cmd.hostname, "server.example");
        let batch = parse(&["Netcatty.exe", "-ssh", "-batch", "alice@server.example", "-pw", "secret"])
            .unwrap();
        assert_eq!(batch.url, "ssh://alice:secret@server.example");
    }

    #[test]
    fn rejects_unsupported_and_incomplete_launches() {
        assert!(parse(&["Netcatty.exe", "server.example", "-raw", "-P", "8000", "-pw", "secret"]).is_none());
        assert!(parse(&["Netcatty.exe", "-serial", "COM1", "-P", "22"]).is_none());
        assert!(parse(&["Netcatty.exe", "-ssh", "-not-a-putty-flag", "alice@server.example"]).is_none());
        assert!(parse(&["Netcatty.exe", "-ssh", "alice@server.example", "-pw"]).is_none());
        assert!(parse(&["Netcatty.exe", "-ssh", "alice@server.example", "-pw", ""]).is_none());
        assert!(parse(&["Netcatty.exe", "-ssh", "alice@server.example", "-P"]).is_none());
        assert!(parse(&["Netcatty.exe", "-ssh", "server.example", "-l", "", "-pw", "secret"]).is_none());
        for flag in ["-pwfile", "-i", "-hostkey", "-loghost"] {
            assert!(parse(&["Netcatty.exe", "-ssh", "alice@server.example", flag, "x", "-pw", "secret"]).is_none());
        }
    }

    #[test]
    fn executable_like_destinations() {
        assert_eq!(
            parse(&["Netcatty.exe", "-ssh", "alice@prod.app", "-pw", "secret"]).unwrap().hostname,
            "prod.app"
        );
        assert_eq!(
            parse(&["Netcatty.exe", "gateway.exe", "-ssh", "-l", "alice", "-pw", "secret"])
                .unwrap()
                .url,
            "ssh://alice:secret@gateway.exe"
        );
        assert_eq!(
            parse(&["Netcatty.exe", "prod.js", "-ssh", "-l", "alice", "-pw", "secret"]).unwrap().hostname,
            "prod.js"
        );
        assert_eq!(
            parse(&["electron", "main.cjs", "-ssh", "alice@host.example", "-pw", "secret"])
                .unwrap()
                .url,
            "ssh://alice:secret@host.example"
        );
    }

    #[test]
    fn jump_login_tab_names() {
        let at = parse(&["Netcatty.exe", "-ssh", "alice@192.0.2.10@198.51.100.20", "-P", "2200", "-pw", "example"])
            .unwrap();
        assert_eq!(at.hostname, "198.51.100.20");
        assert_eq!(at.username.as_deref(), Some("alice@192.0.2.10"));
        assert_eq!(at.url, "ssh://alice%40192.0.2.10:example@198.51.100.20:2200");
        assert_eq!(at.tab_name.as_deref(), Some("192.0.2.10"));

        let hash = parse(&[
            "Netcatty.exe", "-ssh", "zhangsan#192.0.2.10#ssh#22#root@198.51.100.20", "-P", "2200",
            "-pw", "example",
        ])
        .unwrap();
        assert_eq!(
            hash.url,
            "ssh://zhangsan%23192.0.2.10%23ssh%2322%23root:example@198.51.100.20:2200"
        );
        assert_eq!(hash.tab_name.as_deref(), Some("192.0.2.10"));

        let explicit = parse(&[
            "Netcatty.exe", "-newtab", "Production", "-ssh", "alice@192.0.2.10@198.51.100.20", "-pw",
            "example",
        ])
        .unwrap();
        assert_eq!(explicit.tab_name.as_deref(), Some("Production"));

        let same = parse(&["Netcatty.exe", "-ssh", "alice@10.0.0.8@10.0.0.8", "-pw", "s3cret"]).unwrap();
        assert_eq!(same.tab_name, None);
    }

    #[test]
    fn leftover_positional_tab_names() {
        let one = parse(&[
            "Netcatty.exe", "-ssh", "alice@198.51.100.20", "-P", "2200", "-pw", "example", "192.0.2.10",
        ])
        .unwrap();
        assert_eq!(one.hostname, "198.51.100.20");
        assert_eq!(one.url, "ssh://alice:example@198.51.100.20:2200");
        assert_eq!(one.tab_name.as_deref(), Some("192.0.2.10"));
        let two = parse(&[
            "Netcatty.exe", "-ssh", "alice@198.51.100.20", "-pw", "example", "192.0.2.10", "192.0.2.11",
        ])
        .unwrap();
        assert_eq!(two.tab_name, None);
    }

    #[test]
    fn ipv6_jump_targets() {
        let mapped = parse(&["Netcatty.exe", "-ssh", "alice@[::ffff:192.0.2.10]@198.51.100.20", "-pw", "example"])
            .unwrap();
        assert_eq!(mapped.tab_name.as_deref(), Some("::ffff:192.0.2.10"));
        let zoned = parse(&["Netcatty.exe", "-ssh", "alice@[fe80::1%eth0]@198.51.100.20", "-pw", "example"])
            .unwrap();
        assert_eq!(zoned.tab_name.as_deref(), Some("fe80::1%eth0"));
        let malformed = parse(&["Netcatty.exe", "-ssh", "alice@a:b:c@198.51.100.20", "-pw", "example"]).unwrap();
        assert_eq!(malformed.hostname, "198.51.100.20");
        assert_eq!(malformed.tab_name, None);
        let bracketed = parse(&["Netcatty.exe", "-ssh", "alice@[2001:db8::10]@198.51.100.20", "-pw", "example"])
            .unwrap();
        assert_eq!(bracketed.tab_name.as_deref(), Some("2001:db8::10"));
        assert_eq!(
            bracketed.url,
            "ssh://alice%40%5B2001%3Adb8%3A%3A10%5D:example@198.51.100.20"
        );
    }

    #[test]
    fn redaction_masks_pw_values() {
        let mut items = argv(&["Netcatty.exe", "-ssh", "alice@host", "-pw", "s3cret!!"]);
        redact_putty_command_line_passwords(&mut items);
        assert_eq!(items[4], "********");
    }

    #[test]
    fn debug_output_never_contains_the_password() {
        let parsed = parse(&["Netcatty.exe", "-ssh", "alice@host", "-pw", "topsecret"]).unwrap();
        assert!(!format!("{parsed:?}").contains("topsecret"));
    }

    #[test]
    fn js_number_port_parsing() {
        assert_eq!(parse_port("22"), Some(22));
        assert_eq!(parse_port(" 22 "), Some(22));
        assert_eq!(parse_port("22.0"), Some(22));
        assert_eq!(parse_port("0x16"), Some(22));
        assert_eq!(parse_port("0"), None);
        assert_eq!(parse_port("65536"), None);
        assert_eq!(parse_port("2.5"), None);
        assert_eq!(parse_port(""), None);
        assert_eq!(parse_port("abc"), None);
    }
}
