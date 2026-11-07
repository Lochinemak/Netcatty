//! OpenSSH command-line options for the external clients (Mosh bootstrap
//! `ssh`, EternalTerminal's internal `ssh`).
//!
//! Port of `buildMoshSshAuthArgs` (`terminalBridge/moshSession.cjs`) and the
//! host-key helpers of `externalSshHostKeyPolicy.cjs`. Secrets (private keys,
//! certificates, agent selectors, known_hosts snapshots) are materialised
//! through a [`SecretFiles`] sink so the planning stays testable.

use std::path::{Path, PathBuf};

/// Where planned secret files are written (0600, removed with the session).
pub trait SecretFiles {
    /// Write `content` to a new private file whose name ends in `suffix`;
    /// returns its path.
    fn write(&mut self, suffix: &str, content: &str) -> Result<PathBuf, String>;
}

/// A vault known-hosts pin (`KnownHost` subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostPin {
    pub hostname: String,
    pub port: u16,
    pub key_type: String,
    pub public_key: String,
}

impl KnownHostPin {
    /// `known_hosts` line: `host key-type base64` / `[host]:port ...`.
    pub fn known_hosts_line(&self) -> Option<String> {
        let host = self.hostname.trim();
        if host.is_empty() || self.key_type.trim().is_empty() || self.public_key.trim().is_empty() {
            return None;
        }
        let pattern = if self.port == 22 || self.port == 0 {
            host.to_string()
        } else {
            format!("[{host}]:{}", self.port)
        };
        let prefix = format!("{} ", self.key_type);
        let blob = self
            .public_key
            .trim()
            .strip_prefix(&prefix)
            .unwrap_or(self.public_key.trim());
        Some(format!("{pattern} {} {blob}", self.key_type))
    }
}

/// Vault pins for `hostname:port` (case-insensitive hostname).
pub fn vault_pins_for<'a>(
    pins: &'a [KnownHostPin],
    hostname: &str,
    port: u16,
) -> Vec<&'a KnownHostPin> {
    let wanted = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    pins.iter()
        .filter(|p| {
            p.hostname.trim().trim_end_matches('.').to_ascii_lowercase() == wanted
                && (if p.port == 0 { 22 } else { p.port }) == port
        })
        .collect()
}

/// `quoteOpenSshOptionValue`: quote values containing blanks or quotes.
pub fn quote_option_value(value: &str) -> String {
    if value.is_empty() || !value.chars().any(|c| c.is_whitespace() || c == '"') {
        return value.to_string();
    }
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// `-o` values enforcing the host-key policy.
///
/// * verification off: empty trust files + `StrictHostKeyChecking=no`;
/// * vault pins the host: the pinned keys are the only trust source;
/// * otherwise the user's own known_hosts with `StrictHostKeyChecking`
///   `ask` (Mosh: answered in the terminal) or `accept-new` (ET: its ssh
///   cannot show the yes/no prompt).
pub fn host_key_options(
    verify_host_keys: bool,
    authoritative_known_hosts: Option<&Path>,
    empty_known_hosts: Option<&Path>,
    protocol_is_et: bool,
) -> Vec<String> {
    let mut values = Vec::new();
    if !verify_host_keys {
        if let Some(path) = empty_known_hosts {
            let quoted = quote_option_value(&path.to_string_lossy());
            values.push(format!("UserKnownHostsFile={quoted}"));
            values.push(format!("GlobalKnownHostsFile={quoted}"));
        }
        values.push("KnownHostsCommand=none".into());
        values.push("StrictHostKeyChecking=no".into());
        return values;
    }
    if let Some(path) = authoritative_known_hosts {
        let quoted = quote_option_value(&path.to_string_lossy());
        values.push(format!("UserKnownHostsFile={quoted}"));
        values.push(format!("GlobalKnownHostsFile={quoted}"));
        values.push("KnownHostsCommand=none".into());
    }
    values.push(format!(
        "StrictHostKeyChecking={}",
        if protocol_is_et { "accept-new" } else { "ask" }
    ));
    values
}

/// Default identities in `~/.ssh` (`id_*` without extension), preferred
/// names first then alphabetical — `orderSshIdentityNames`.
pub fn discover_identity_paths(ssh_dir: &Path) -> Vec<PathBuf> {
    const PREFERRED: [&str; 3] = ["id_ed25519", "id_ecdsa", "id_rsa"];
    let Ok(entries) = std::fs::read_dir(ssh_dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type()
                .map(|t| t.is_file() || t.is_symlink())
                .unwrap_or(false)
        })
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| {
            n.strip_prefix("id_")
                .map(|rest| {
                    !rest.is_empty()
                        && rest
                            .chars()
                            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                })
                .unwrap_or(false)
        })
        .collect();
    names.sort();
    names.dedup();
    let mut ordered: Vec<String> = PREFERRED
        .iter()
        .filter(|p| names.iter().any(|n| n == *p))
        .map(|p| p.to_string())
        .collect();
    ordered.extend(
        names
            .into_iter()
            .filter(|n| !PREFERRED.contains(&n.as_str())),
    );
    ordered.into_iter().map(|n| ssh_dir.join(n)).collect()
}

/// Expand a leading `~` in an identity path.
pub fn expand_home(path: &str, home: Option<&Path>) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(home) = home {
        if trimmed == "~" {
            return Some(home.to_string_lossy().into_owned());
        }
        if let Some(rest) = trimmed.strip_prefix("~/") {
            return Some(home.join(rest).to_string_lossy().into_owned());
        }
    }
    Some(trimmed.to_string())
}

/// Authentication inputs shared by the Mosh and ET planners.
#[derive(Debug, Clone, Default)]
pub struct ExternalSshAuth {
    pub hostname: String,
    pub port: u16,
    pub username: Option<String>,
    /// `password` | `key` | `certificate` | `auto` | ...
    pub auth_method: Option<String>,
    pub requires_mfa: bool,
    pub password: Option<String>,
    pub passphrase: Option<String>,
    pub private_key: Option<String>,
    pub certificate: Option<String>,
    pub agent_public_keys: Vec<String>,
    pub identity_file_paths: Vec<String>,
    /// `None` = not configured (ssh's defaults apply).
    pub use_ssh_agent: Option<bool>,
    pub identities_only: bool,
    /// Agent socket to authenticate with (`IdentityAgent`).
    pub agent_socket: Option<String>,
    /// Agent socket to forward (`ForwardAgent`), when forwarding is on.
    pub forwarding_socket: Option<String>,
    pub known_hosts: Vec<KnownHostPin>,
    pub verify_host_keys: bool,
    pub legacy_algorithms: bool,
}

impl ExternalSshAuth {
    pub fn auth_method(&self) -> &str {
        self.auth_method.as_deref().unwrap_or("")
    }
    pub fn has_password(&self) -> bool {
        self.password.as_deref().is_some_and(|p| !p.is_empty())
    }
}

/// `buildMoshPreferredAuthentications`.
pub fn mosh_preferred_authentications(
    auth_method: &str,
    requires_mfa: bool,
    has_password: bool,
    has_public_key: bool,
) -> String {
    if auth_method == "password" {
        return if requires_mfa {
            "keyboard-interactive,password".into()
        } else {
            "password,keyboard-interactive".into()
        };
    }
    if !requires_mfa {
        return String::new();
    }
    match (has_public_key, has_password) {
        (true, true) => "publickey,keyboard-interactive,password".into(),
        (true, false) => "publickey,keyboard-interactive".into(),
        (false, true) => "keyboard-interactive,password".into(),
        (false, false) => "keyboard-interactive".into(),
    }
}

/// Planned Mosh bootstrap options.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MoshSshPlan {
    pub ssh_args: Vec<String>,
    /// Identity files on disk the companion connection may reuse.
    pub identity_file_paths: Vec<String>,
}

/// `buildMoshSshAuthArgs`. `default_identities` is the `~/.ssh` discovery
/// (used for `auth_method == "auto"`); `windows` selects the
/// `${SSH_AUTH_SOCK}` form of `ForwardAgent`.
pub fn plan_mosh_ssh_args(
    auth: &ExternalSshAuth,
    files: &mut dyn SecretFiles,
    default_identities: &[PathBuf],
    home: Option<&Path>,
    windows: bool,
) -> Result<MoshSshPlan, String> {
    let mut args: Vec<String> = Vec::new();
    let mut identity_paths: Vec<String> = Vec::new();
    let remember = |p: &str, list: &mut Vec<String>| {
        if !list.iter().any(|x| x == p) {
            list.push(p.to_string());
        }
    };
    let use_agent = auth.use_ssh_agent == Some(true);
    let push_o = |args: &mut Vec<String>, value: String| {
        args.push("-o".into());
        args.push(value);
    };

    if let Some(key) = auth.private_key.as_deref().filter(|k| !k.trim().is_empty()) {
        let key_path = files.write(".pem", key)?;
        args.push("-i".into());
        args.push(key_path.to_string_lossy().into_owned());
        push_o(&mut args, "IdentitiesOnly=yes".into());
        if let Some(cert) = auth.certificate.as_deref().filter(|c| !c.trim().is_empty()) {
            let cert_path = files.write("-cert.pub", cert)?;
            push_o(
                &mut args,
                format!("CertificateFile={}", cert_path.to_string_lossy()),
            );
        }
    } else if use_agent && !auth.agent_public_keys.is_empty() {
        for public_key in &auth.agent_public_keys {
            let selector = files.write(".pub", public_key)?;
            args.push("-i".into());
            args.push(selector.to_string_lossy().into_owned());
        }
    } else if !auth.identity_file_paths.is_empty() {
        for key_path in &auth.identity_file_paths {
            if let Some(normalized) = expand_home(key_path, home) {
                remember(&normalized, &mut identity_paths);
                let selector = if use_agent && !normalized.to_ascii_lowercase().ends_with(".pub") {
                    format!("{normalized}.pub")
                } else {
                    normalized
                };
                args.push("-i".into());
                args.push(selector);
            }
        }
        if !args.is_empty() && (!use_agent || auth.identities_only) {
            push_o(&mut args, "IdentitiesOnly=yes".into());
        }
        if let Some(cert) = auth.certificate.as_deref().filter(|c| !c.trim().is_empty()) {
            let cert_path = files.write("-cert.pub", cert)?;
            push_o(
                &mut args,
                format!("CertificateFile={}", cert_path.to_string_lossy()),
            );
        }
    }

    if auth.auth_method() == "auto" {
        let agent_only_selectors = use_agent && auth.identities_only;
        let mut selected: Vec<String> = args
            .windows(2)
            .filter(|w| w[0] == "-i")
            .map(|w| w[1].clone())
            .collect();
        for key_path in default_identities {
            let key_path = key_path.to_string_lossy().into_owned();
            remember(&key_path, &mut identity_paths);
            let selector = if agent_only_selectors {
                format!("{key_path}.pub")
            } else {
                key_path
            };
            if !selected.contains(&selector) {
                args.push("-i".into());
                args.push(selector.clone());
                selected.push(selector);
            }
        }
    }

    let has_selected_identity = args.iter().any(|a| a == "-i");
    if matches!(auth.auth_method(), "key" | "certificate") && !has_selected_identity {
        push_o(&mut args, "IdentityFile=none".into());
        push_o(&mut args, "IdentitiesOnly=yes".into());
    }

    if auth.use_ssh_agent == Some(false) {
        push_o(&mut args, "IdentityAgent=none".into());
    } else if let Some(socket) = auth.agent_socket.as_deref().filter(|_| use_agent) {
        let quoted = format!("\"{}\"", socket.replace('\\', "\\\\").replace('"', "\\\""));
        push_o(&mut args, format!("IdentityAgent={quoted}"));
        if auth.identities_only && !args.iter().any(|a| a == "IdentitiesOnly=yes") {
            push_o(&mut args, "IdentitiesOnly=yes".into());
        }
    }
    if let Some(socket) = auth.forwarding_socket.as_deref() {
        let value = if windows {
            "${SSH_AUTH_SOCK}".to_string()
        } else {
            socket.to_string()
        };
        push_o(&mut args, format!("ForwardAgent={value}"));
    }

    if auth.auth_method() == "password" {
        push_o(&mut args, "PubkeyAuthentication=no".into());
    }
    let preferred = mosh_preferred_authentications(
        auth.auth_method(),
        auth.requires_mfa,
        auth.has_password(),
        use_agent || has_selected_identity,
    );
    if !preferred.is_empty() {
        push_o(&mut args, format!("PreferredAuthentications={preferred}"));
    }

    // Host-key policy (issue #2501): vault pins are authoritative.
    let mut authoritative = None;
    let mut empty = None;
    if auth.verify_host_keys {
        let pins = vault_pins_for(&auth.known_hosts, &auth.hostname, auth.port);
        let lines: Vec<String> = pins.iter().filter_map(|p| p.known_hosts_line()).collect();
        if !lines.is_empty() {
            authoritative = Some(files.write(".txt", &(lines.join("\n") + "\n"))?);
        }
    } else {
        empty = Some(files.write(".txt", "")?);
    }
    for value in host_key_options(
        auth.verify_host_keys,
        authoritative.as_deref(),
        empty.as_deref(),
        false,
    ) {
        push_o(&mut args, value);
    }

    Ok(MoshSshPlan {
        ssh_args: args,
        identity_file_paths: identity_paths,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Records files instead of writing them.
    #[derive(Default)]
    pub struct FakeFiles {
        pub written: Vec<(PathBuf, String)>,
    }

    impl SecretFiles for FakeFiles {
        fn write(&mut self, suffix: &str, content: &str) -> Result<PathBuf, String> {
            let path = PathBuf::from(format!("/tmp/nc/f{}{suffix}", self.written.len()));
            self.written.push((path.clone(), content.to_string()));
            Ok(path)
        }
    }

    fn base() -> ExternalSshAuth {
        ExternalSshAuth {
            hostname: "example.com".into(),
            port: 22,
            username: Some("alice".into()),
            verify_host_keys: true,
            ..Default::default()
        }
    }

    fn opt_values(args: &[String]) -> Vec<String> {
        args.windows(2)
            .filter(|w| w[0] == "-o")
            .map(|w| w[1].clone())
            .collect()
    }

    #[test]
    fn password_auth() {
        let mut auth = base();
        auth.auth_method = Some("password".into());
        auth.password = Some("pw".into());
        let mut files = FakeFiles::default();
        let plan = plan_mosh_ssh_args(&auth, &mut files, &[], None, false).unwrap();
        let opts = opt_values(&plan.ssh_args);
        assert!(opts.contains(&"PubkeyAuthentication=no".to_string()));
        assert!(
            opts.contains(&"PreferredAuthentications=password,keyboard-interactive".to_string())
        );
        assert!(opts.contains(&"StrictHostKeyChecking=ask".to_string()));
        assert!(files.written.is_empty());
    }

    #[test]
    fn private_key_and_certificate_are_written() {
        let mut auth = base();
        auth.auth_method = Some("certificate".into());
        auth.private_key = Some("-----BEGIN KEY-----".into());
        auth.certificate = Some("ssh-ed25519-cert-v01@openssh.com AAAA".into());
        let mut files = FakeFiles::default();
        let plan = plan_mosh_ssh_args(&auth, &mut files, &[], None, false).unwrap();
        assert_eq!(files.written.len(), 2);
        assert_eq!(plan.ssh_args[0], "-i");
        assert!(plan.ssh_args[1].ends_with(".pem"));
        let opts = opt_values(&plan.ssh_args);
        assert!(opts.contains(&"IdentitiesOnly=yes".to_string()));
        assert!(opts.iter().any(|o| o.starts_with("CertificateFile=")));
        assert!(!opts.contains(&"IdentityFile=none".to_string()));
    }

    #[test]
    fn key_auth_without_identity_disables_defaults() {
        let mut auth = base();
        auth.auth_method = Some("key".into());
        let plan = plan_mosh_ssh_args(&auth, &mut FakeFiles::default(), &[], None, false).unwrap();
        let opts = opt_values(&plan.ssh_args);
        assert!(opts.contains(&"IdentityFile=none".to_string()));
    }

    #[test]
    fn agent_selectors_and_socket() {
        let mut auth = base();
        auth.use_ssh_agent = Some(true);
        auth.identities_only = true;
        auth.agent_public_keys = vec!["ssh-ed25519 AAAA one".into(), "ssh-rsa BBBB two".into()];
        auth.agent_socket = Some("/tmp/agent.sock".into());
        auth.forwarding_socket = Some("/tmp/agent.sock".into());
        let mut files = FakeFiles::default();
        let plan = plan_mosh_ssh_args(&auth, &mut files, &[], None, false).unwrap();
        assert_eq!(plan.ssh_args.iter().filter(|a| *a == "-i").count(), 2);
        let opts = opt_values(&plan.ssh_args);
        assert!(opts.contains(&"IdentityAgent=\"/tmp/agent.sock\"".to_string()));
        assert!(opts.contains(&"IdentitiesOnly=yes".to_string()));
        assert!(opts.contains(&"ForwardAgent=/tmp/agent.sock".to_string()));
        let plan = plan_mosh_ssh_args(&auth, &mut FakeFiles::default(), &[], None, true).unwrap();
        assert!(opt_values(&plan.ssh_args).contains(&"ForwardAgent=${SSH_AUTH_SOCK}".to_string()));
    }

    #[test]
    fn identity_paths_and_auto_discovery() {
        let mut auth = base();
        auth.auth_method = Some("auto".into());
        auth.identity_file_paths = vec!["~/.ssh/work".into()];
        let home = PathBuf::from("/home/alice");
        let defaults = vec![
            PathBuf::from("/home/alice/.ssh/id_ed25519"),
            PathBuf::from("/home/alice/.ssh/work"),
        ];
        let plan = plan_mosh_ssh_args(
            &auth,
            &mut FakeFiles::default(),
            &defaults,
            Some(&home),
            false,
        )
        .unwrap();
        let ids: Vec<&String> = plan
            .ssh_args
            .windows(2)
            .filter(|w| w[0] == "-i")
            .map(|w| &w[1])
            .collect();
        assert_eq!(
            ids,
            vec!["/home/alice/.ssh/work", "/home/alice/.ssh/id_ed25519"]
        );
        assert_eq!(
            plan.identity_file_paths,
            vec!["/home/alice/.ssh/work", "/home/alice/.ssh/id_ed25519"]
        );
    }

    #[test]
    fn host_key_policy() {
        let mut auth = base();
        auth.known_hosts = vec![KnownHostPin {
            hostname: "Example.com".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            public_key: "AAAAC3".into(),
        }];
        let mut files = FakeFiles::default();
        let plan = plan_mosh_ssh_args(&auth, &mut files, &[], None, false).unwrap();
        assert_eq!(files.written[0].1, "Example.com ssh-ed25519 AAAAC3\n");
        let opts = opt_values(&plan.ssh_args);
        assert!(opts.iter().any(|o| o.starts_with("UserKnownHostsFile=")));
        assert!(opts.iter().any(|o| o.starts_with("GlobalKnownHostsFile=")));
        assert!(opts.contains(&"KnownHostsCommand=none".to_string()));
        assert!(opts.contains(&"StrictHostKeyChecking=ask".to_string()));

        auth.verify_host_keys = false;
        let plan = plan_mosh_ssh_args(&auth, &mut FakeFiles::default(), &[], None, false).unwrap();
        assert!(opt_values(&plan.ssh_args).contains(&"StrictHostKeyChecking=no".to_string()));
    }

    #[test]
    fn preferred_authentications_matrix() {
        assert_eq!(
            mosh_preferred_authentications("password", true, true, false),
            "keyboard-interactive,password"
        );
        assert_eq!(mosh_preferred_authentications("key", false, true, true), "");
        assert_eq!(
            mosh_preferred_authentications("key", true, true, true),
            "publickey,keyboard-interactive,password"
        );
        assert_eq!(
            mosh_preferred_authentications("auto", true, false, false),
            "keyboard-interactive"
        );
    }

    #[test]
    fn misc_helpers() {
        assert_eq!(quote_option_value("/a b/c"), "\"/a b/c\"");
        assert_eq!(quote_option_value("/abc"), "/abc");
        let pin = KnownHostPin {
            hostname: "h".into(),
            port: 2222,
            key_type: "ssh-rsa".into(),
            public_key: "ssh-rsa AAAA".into(),
        };
        assert_eq!(pin.known_hosts_line().unwrap(), "[h]:2222 ssh-rsa AAAA");
        let dir = std::env::temp_dir().join(format!("nc-ids-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for n in ["id_rsa", "id_rsa.pub", "id_ed25519", "id_zeta", "config"] {
            std::fs::write(dir.join(n), "x").unwrap();
        }
        let found: Vec<String> = discover_identity_paths(&dir)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(found, vec!["id_ed25519", "id_rsa", "id_zeta"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
