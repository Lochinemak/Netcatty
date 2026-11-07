//! EternalTerminal (`et`) client invocation.
//!
//! Port of `prepareEtSshEnvironment` / `startEtSession`
//! (`electron/bridges/terminalBridge/etSession.cjs`). `et` performs its own
//! SSH bootstrap, so Netcatty prepares a private session directory with:
//!
//! * the session's key / certificate / agent selector files,
//! * an ssh `config` for options that contain commas or spaces (ET splits
//!   `--ssh-option` values on commas), with `Include`s of the user's and the
//!   system ssh config appended,
//! * a PATH-fronted `ssh` wrapper that passes `-F <config>` (OpenSSH reads
//!   the account home's config, not `$HOME`),
//! * an `SSH_ASKPASS` entry map answering saved passwords / passphrases
//!   (the Netcatty executable is the helper, see [`crate::askpass`]).
//!
//! Host-key policy: the user's `~/.ssh/known_hosts` with
//! `StrictHostKeyChecking=accept-new` (ET's ssh cannot show the yes/no
//! prompt), the vault's pins when it pins the host, or an empty trust file
//! when verification is off.

use crate::askpass::{
    passphrase_prompt_matchers, password_prompt_matchers, to_json, Entry, ASKPASS_MAP_ENV,
    ASKPASS_MARKER_ENV,
};
use crate::auth::{host_key_options, vault_pins_for, ExternalSshAuth};
use std::path::{Path, PathBuf};

/// ET's default server port.
pub const DEFAULT_ET_PORT: u16 = 2022;

pub const TOO_MANY_JUMP_HOSTS: &str =
    "EternalTerminal currently supports at most one jump host in Netcatty.";

/// `buildPreferredAuthentications` (ET flavour).
pub fn et_preferred_authentications(
    auth_method: &str,
    has_password: bool,
    has_public_key: bool,
) -> String {
    match auth_method {
        "password" => "password,keyboard-interactive".into(),
        "auto" => "publickey,password,keyboard-interactive".into(),
        _ if has_public_key && has_password => "publickey,password,keyboard-interactive".into(),
        _ if has_public_key => "publickey".into(),
        _ if has_password => "password,keyboard-interactive".into(),
        _ => String::new(),
    }
}

/// Path in ssh config syntax (forward slashes).
pub fn config_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// `quoteSshConfigValue`: always double-quoted, forward slashes.
pub fn quote_config_path(path: &Path) -> String {
    let normalized = config_path(path);
    format!(
        "\"{}\"",
        normalized.replace('\\', "\\\\").replace('"', "\\\"")
    )
}

fn quote_raw(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn public_selector(path: &str) -> String {
    if path.to_ascii_lowercase().ends_with(".pub") {
        path.to_string()
    } else {
        format!("{path}.pub")
    }
}

/// Write a private file (0600 / 0700 on Unix).
pub fn write_secure(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, content).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

const LEGACY_ALGORITHMS: [&str; 4] = [
    "KexAlgorithms +diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
    "Ciphers +aes128-cbc,aes256-cbc,3des-cbc",
    "HostKeyAlgorithms +ssh-rsa,ssh-dss",
    "PubkeyAcceptedAlgorithms +ssh-rsa,ssh-dss",
];

/// Everything [`plan_et`] needs besides the session options.
#[derive(Debug, Clone)]
pub struct EtEnvironment {
    /// Private session directory (`et-ssh-home-<id>`), used as `HOME`.
    pub temp_home: PathBuf,
    /// The user's real `~/.ssh`.
    pub real_ssh_dir: PathBuf,
    /// `~/.ssh` identities for `auth_method == "auto"`.
    pub default_identities: Vec<PathBuf>,
    /// Existing user / system ssh configs to `Include`.
    pub include_configs: Vec<PathBuf>,
    /// Absolute path of the real `ssh` (for the `-F` wrapper).
    pub real_ssh: Option<PathBuf>,
    /// PATH the session would otherwise get.
    pub base_path: Option<String>,
    /// Name of the PATH variable (`PATH`, or `Path` on Windows).
    pub path_key: String,
    /// Local user name (default remote user).
    pub local_username: String,
    /// The `SSH_ASKPASS` helper (the Netcatty executable).
    pub askpass_exe: Option<PathBuf>,
    pub display: Option<String>,
    pub windows: bool,
}

/// Prepared `et` invocation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EtPlan {
    /// Arguments after the `et` executable.
    pub args: Vec<String>,
    /// Environment additions.
    pub env: Vec<(String, String)>,
    pub identity_file_paths: Vec<String>,
    /// `user@host` target.
    pub user_host: String,
}

/// Plan an ET session: writes the session files under `env.temp_home`.
pub fn plan_et(
    auth: &ExternalSshAuth,
    et_port: Option<u16>,
    jump_hosts: &[ExternalSshAuth],
    env: &EtEnvironment,
    session_id: &str,
) -> Result<EtPlan, String> {
    if jump_hosts.len() > 1 {
        return Err(TOO_MANY_JUMP_HOSTS.into());
    }
    let ssh_dir = env.temp_home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).map_err(|e| e.to_string())?;
    let safe_id: String = session_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let safe_id = if safe_id.is_empty() {
        "session".to_string()
    } else {
        safe_id
    };
    let file = |name: &str| ssh_dir.join(format!("{safe_id}-{name}"));

    let mut ssh_options: Vec<String> = Vec::new();
    let mut config_lines: Vec<String> = Vec::new();
    let mut askpass: Vec<Entry> = Vec::new();
    let add_askpass = |askpass: &mut Vec<Entry>, kind: &str, matchers: Vec<String>, path: &Path| {
        let mut unique: Vec<String> = Vec::new();
        for m in matchers.into_iter().map(|m| m.to_lowercase()) {
            if !m.is_empty() && !unique.contains(&m) {
                unique.push(m);
            }
        }
        askpass.push(Entry {
            kind: kind.to_string(),
            matchers: unique,
            secret_file: path.to_string_lossy().into_owned(),
        });
    };

    // Host keys.
    let known_hosts_path = env.real_ssh_dir.join("known_hosts");
    let mut target_authoritative = None;
    let mut jump_authoritative = None;
    let mut empty_known_hosts = None;
    if auth.verify_host_keys {
        let pin_file = |hostname: &str, port: u16, name: &str| -> Result<Option<PathBuf>, String> {
            let lines: Vec<String> = vault_pins_for(&auth.known_hosts, hostname, port)
                .iter()
                .filter_map(|p| p.known_hosts_line())
                .collect();
            if lines.is_empty() {
                return Ok(None);
            }
            let path = file(name);
            write_secure(&path, &(lines.join("\n") + "\n"), 0o600)?;
            Ok(Some(path))
        };
        target_authoritative = pin_file(
            &auth.hostname,
            auth.port,
            "authoritative-target-known_hosts",
        )?;
        if let Some(jump) = jump_hosts.first() {
            jump_authoritative =
                pin_file(&jump.hostname, jump.port, "authoritative-jump-known_hosts")?;
        }
    } else {
        let path = file("empty-known_hosts");
        write_secure(&path, "", 0o600)?;
        empty_known_hosts = Some(path);
    }
    if auth.verify_host_keys && target_authoritative.is_none() {
        ssh_options.push(format!(
            "UserKnownHostsFile={}",
            config_path(&known_hosts_path)
        ));
    }
    ssh_options.extend(host_key_options(
        auth.verify_host_keys,
        target_authoritative.as_deref(),
        empty_known_hosts.as_deref(),
        true,
    ));
    ssh_options.push("LogLevel=ERROR".into());
    if auth.port != 0 && auth.port != 22 {
        ssh_options.push(format!("Port={}", auth.port));
    }

    let use_agent = auth.use_ssh_agent == Some(true);
    if auth.use_ssh_agent == Some(false) {
        config_lines.push("IdentityAgent none".into());
    } else if let Some(socket) = auth.agent_socket.as_deref().filter(|_| use_agent) {
        config_lines.push(format!("IdentityAgent {}", quote_raw(socket)));
    }

    // Identities.
    let mut identity_paths: Vec<String> = Vec::new();
    if let Some(key) = auth.private_key.as_deref().filter(|k| !k.trim().is_empty()) {
        let key_path = file("key");
        write_secure(&key_path, key, 0o600)?;
        identity_paths.push(key_path.to_string_lossy().into_owned());
        if let Some(passphrase) = auth.passphrase.as_deref().filter(|p| !p.is_empty()) {
            let pass_path = file("passphrase.txt");
            write_secure(&pass_path, &format!("{passphrase}\n"), 0o600)?;
            add_askpass(
                &mut askpass,
                "passphrase",
                passphrase_prompt_matchers(&config_path(&key_path)),
                &pass_path,
            );
        }
    }
    if use_agent {
        for (index, public_key) in auth.agent_public_keys.iter().enumerate() {
            if public_key.trim().is_empty() {
                continue;
            }
            let path = file(&format!("agent-{index}.pub"));
            write_secure(&path, public_key, 0o600)?;
            identity_paths.push(path.to_string_lossy().into_owned());
        }
    }
    if let Some(cert) = auth.certificate.as_deref().filter(|c| !c.trim().is_empty()) {
        let path = file("cert.pub");
        write_secure(&path, cert, 0o600)?;
        ssh_options.push(format!("CertificateFile={}", config_path(&path)));
    }
    for id_path in auth.identity_file_paths.iter().filter(|p| !p.is_empty()) {
        identity_paths.push(if use_agent {
            public_selector(id_path)
        } else {
            id_path.clone()
        });
    }
    if auth.auth_method() == "auto" {
        for key_path in &env.default_identities {
            let key_path = key_path.to_string_lossy().into_owned();
            if !identity_paths.contains(&key_path) {
                identity_paths.push(key_path);
            }
        }
    }
    for id_path in &identity_paths {
        ssh_options.push(format!("IdentityFile={}", config_path(Path::new(id_path))));
    }
    let strict_target_auth = matches!(auth.auth_method(), "key" | "certificate");
    if strict_target_auth && identity_paths.is_empty() {
        ssh_options.push("IdentityFile=none".into());
    }
    if (auth.auth_method() != "auto"
        && !use_agent
        && (!identity_paths.is_empty() || strict_target_auth))
        || (use_agent && auth.identities_only)
    {
        ssh_options.push("IdentitiesOnly=yes".into());
    }

    // Password.
    let has_password = auth.has_password();
    if let Some(password) = auth.password.as_deref().filter(|p| !p.is_empty()) {
        let path = file("password.txt");
        write_secure(&path, &format!("{password}\n"), 0o600)?;
        add_askpass(
            &mut askpass,
            "password",
            password_prompt_matchers(&auth.hostname, auth.username.as_deref(), auth.port),
            &path,
        );
    }
    let preferred = et_preferred_authentications(
        auth.auth_method(),
        has_password,
        use_agent || !identity_paths.is_empty(),
    );
    if auth.auth_method() == "password" {
        ssh_options.push("PubkeyAuthentication=no".into());
    }
    if !preferred.is_empty() {
        if preferred.contains(',') {
            config_lines.push(format!("PreferredAuthentications {preferred}"));
        } else {
            ssh_options.push(format!("PreferredAuthentications={preferred}"));
        }
    }
    ssh_options.push("KbdInteractiveAuthentication=yes".into());
    ssh_options.push("NumberOfPasswordPrompts=1".into());
    if auth.legacy_algorithms {
        config_lines.extend(LEGACY_ALGORITHMS.iter().map(|l| l.to_string()));
    }

    // Jump host: ET's own --jumphost/--jport, per-hop settings in a Host block.
    let mut et_jump_args: Vec<String> = Vec::new();
    let mut jump_lines: Vec<String> = Vec::new();
    if let Some(jump) = jump_hosts.first() {
        let jump_user = jump
            .username
            .clone()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| env.local_username.clone());
        let jump_port = if jump.port == 0 { 22 } else { jump.port };
        et_jump_args = vec![
            "--jumphost".into(),
            format!("{jump_user}@{}", jump.hostname),
            "--jport".into(),
            DEFAULT_ET_PORT.to_string(),
        ];
        jump_lines.push(format!("Host {}", jump.hostname));
        jump_lines.push(format!("  User {jump_user}"));
        jump_lines.push(format!("  Port {jump_port}"));
        let jump_agent = jump.use_ssh_agent == Some(true);
        if jump.use_ssh_agent == Some(false) {
            jump_lines.push("  IdentityAgent none".into());
        } else if let Some(socket) = jump.agent_socket.as_deref().filter(|_| jump_agent) {
            jump_lines.push(format!("  IdentityAgent {}", quote_raw(socket)));
        }
        if jump_agent {
            for (index, public_key) in jump.agent_public_keys.iter().enumerate() {
                if public_key.trim().is_empty() {
                    continue;
                }
                let path = file(&format!("jump-agent-{index}.pub"));
                write_secure(&path, public_key, 0o600)?;
                jump_lines.push(format!("  IdentityFile {}", quote_config_path(&path)));
            }
        }
        if let Some(key) = jump.private_key.as_deref().filter(|k| !k.trim().is_empty()) {
            let path = file("jump-key");
            write_secure(&path, key, 0o600)?;
            jump_lines.push(format!("  IdentityFile {}", quote_config_path(&path)));
            jump_lines.push("  IdentitiesOnly yes".into());
            if let Some(passphrase) = jump.passphrase.as_deref().filter(|p| !p.is_empty()) {
                let pass_path = file("jump-passphrase.txt");
                write_secure(&pass_path, &format!("{passphrase}\n"), 0o600)?;
                add_askpass(
                    &mut askpass,
                    "passphrase",
                    passphrase_prompt_matchers(&config_path(&path)),
                    &pass_path,
                );
            }
        } else {
            let ids: Vec<String> = jump
                .identity_file_paths
                .iter()
                .filter(|p| !p.is_empty())
                .map(|p| {
                    if jump_agent {
                        public_selector(p)
                    } else {
                        p.clone()
                    }
                })
                .collect();
            for id in &ids {
                jump_lines.push(format!(
                    "  IdentityFile {}",
                    quote_config_path(Path::new(id))
                ));
            }
            if !ids.is_empty() && (!jump_agent || jump.identities_only) {
                jump_lines.push("  IdentitiesOnly yes".into());
            }
        }
        if jump_agent
            && jump.identities_only
            && !jump_lines.iter().any(|l| l == "  IdentitiesOnly yes")
        {
            jump_lines.push("  IdentitiesOnly yes".into());
        }
        let has_jump_identity = jump_lines.iter().any(|l| l.starts_with("  IdentityFile "));
        if matches!(jump.auth_method(), "key" | "certificate") && !has_jump_identity {
            jump_lines.push("  IdentityFile none".into());
            if !jump_lines.iter().any(|l| l == "  IdentitiesOnly yes") {
                jump_lines.push("  IdentitiesOnly yes".into());
            }
        }
        if jump.auth_method() == "auto" {
            for key_path in &env.default_identities {
                jump_lines.push(format!("  IdentityFile {}", quote_config_path(key_path)));
            }
        } else if jump.auth_method() == "password" {
            jump_lines.push("  PubkeyAuthentication no".into());
        }
        let jump_preferred = et_preferred_authentications(
            jump.auth_method(),
            jump.has_password(),
            jump_agent || jump_lines.iter().any(|l| l.starts_with("  IdentityFile ")),
        );
        if !jump_preferred.is_empty() {
            jump_lines.push(format!("  PreferredAuthentications {jump_preferred}"));
        }
        if let Some(cert) = jump.certificate.as_deref().filter(|c| !c.trim().is_empty()) {
            let path = file("jump-cert.pub");
            write_secure(&path, cert, 0o600)?;
            jump_lines.push(format!("  CertificateFile {}", quote_config_path(&path)));
        }
        if let Some(password) = jump.password.as_deref().filter(|p| !p.is_empty()) {
            let path = file("jump-password.txt");
            write_secure(&path, &format!("{password}\n"), 0o600)?;
            add_askpass(
                &mut askpass,
                "password",
                password_prompt_matchers(&jump.hostname, Some(&jump_user), jump_port),
                &path,
            );
        }
        if auth.verify_host_keys {
            if let Some(path) = &jump_authoritative {
                for value in host_key_options(true, Some(path), None, true) {
                    jump_lines.push(format!("  {}", value.replacen('=', " ", 1)));
                }
            } else {
                jump_lines.push(format!(
                    "  UserKnownHostsFile {}",
                    quote_config_path(&known_hosts_path)
                ));
                jump_lines.push("  StrictHostKeyChecking accept-new".into());
            }
        } else if let Some(path) = &empty_known_hosts {
            for value in host_key_options(false, None, Some(path), true) {
                jump_lines.push(format!("  {}", value.replacen('=', " ", 1)));
            }
        }
        jump_lines.push("  LogLevel ERROR".into());
        jump_lines.push("  KbdInteractiveAuthentication yes".into());
        jump_lines.push("  NumberOfPasswordPrompts 1".into());
        if auth.legacy_algorithms {
            jump_lines.extend(LEGACY_ALGORITHMS.iter().map(|l| format!("  {l}")));
        }
    }

    // Config file.
    let mut config_file_lines: Vec<String> = Vec::new();
    if let Some(jump) = jump_hosts.first() {
        config_file_lines.push(format!("Host {}", auth.hostname));
        config_file_lines.push(format!("  ProxyJump {}", jump.hostname));
        config_file_lines.extend(config_lines.iter().map(|l| format!("  {l}")));
        config_file_lines.extend(jump_lines);
    } else {
        config_file_lines.extend(config_lines);
    }
    let mut plan_env: Vec<(String, String)> = Vec::new();
    if !config_file_lines.is_empty() {
        if !env.include_configs.is_empty() {
            config_file_lines.push(String::new());
            config_file_lines.push("Match all".into());
            config_file_lines
                .push("# Preserve normal OpenSSH user/system configuration under -F.".into());
            for include in &env.include_configs {
                config_file_lines.push(format!("Include {}", quote_config_path(include)));
            }
        }
        let config = ssh_dir.join("config");
        write_secure(&config, &(config_file_lines.join("\n") + "\n"), 0o600)?;

        if let Some(real_ssh) = env.real_ssh.as_deref().filter(|p| p.is_absolute()) {
            let wrapper_dir = ssh_dir.join("bin");
            if env.windows {
                write_secure(
                    &wrapper_dir.join("ssh.cmd"),
                    &format!(
                        "@echo off\r\n\"{}\" -F \"{}\" %*\r\n",
                        real_ssh.to_string_lossy().replace('"', "\"\""),
                        config.to_string_lossy().replace('"', "\"\"")
                    ),
                    0o700,
                )?;
            } else {
                write_secure(
                    &wrapper_dir.join("ssh"),
                    &format!(
                        "#!/bin/sh\nexec {} -F {} \"$@\"\n",
                        crate::handshake::shell_quote(&real_ssh.to_string_lossy()),
                        crate::handshake::shell_quote(&config.to_string_lossy())
                    ),
                    0o700,
                )?;
            }
            let separator = if env.windows { ";" } else { ":" };
            let wrapper = wrapper_dir.to_string_lossy().into_owned();
            let path_value = match env.base_path.as_deref().filter(|p| !p.is_empty()) {
                Some(base) => format!("{wrapper}{separator}{base}"),
                None => wrapper,
            };
            plan_env.push((env.path_key.clone(), path_value));
        }
        let home = env.temp_home.to_string_lossy().into_owned();
        plan_env.push(("HOME".into(), home.clone()));
        plan_env.push(("USERPROFILE".into(), home));
    }

    // Askpass helper.
    if !askpass.is_empty() {
        if let Some(exe) = &env.askpass_exe {
            let map = ssh_dir.join("netcatty-et-askpass-map.json");
            write_secure(&map, &to_json(&askpass), 0o600)?;
            plan_env.push(("SSH_ASKPASS".into(), exe.to_string_lossy().into_owned()));
            plan_env.push(("SSH_ASKPASS_REQUIRE".into(), "force".into()));
            plan_env.push((
                "DISPLAY".into(),
                env.display.clone().unwrap_or_else(|| "netcatty:0".into()),
            ));
            plan_env.push((ASKPASS_MAP_ENV.into(), map.to_string_lossy().into_owned()));
            plan_env.push((ASKPASS_MARKER_ENV.into(), "1".into()));
        }
    }

    // et arguments.
    let mut args: Vec<String> = Vec::new();
    if let Some(port) = et_port.filter(|p| *p != 0 && *p != DEFAULT_ET_PORT) {
        args.push("-p".into());
        args.push(port.to_string());
    }
    if let Some(socket) = &auth.forwarding_socket {
        args.push("-f".into());
        args.push("--ssh-socket".into());
        args.push(socket.clone());
    }
    for opt in &ssh_options {
        args.push("--ssh-option".into());
        args.push(opt.clone());
    }
    args.extend(et_jump_args);
    let user = auth
        .username
        .clone()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| env.local_username.clone());
    let user_host = format!("{user}@{}", auth.hostname);
    args.push(user_host.clone());

    Ok(EtPlan {
        args,
        env: plan_env,
        identity_file_paths: identity_paths,
        user_host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::askpass::from_json;
    use crate::auth::KnownHostPin;

    fn env_in(dir: &Path) -> EtEnvironment {
        EtEnvironment {
            temp_home: dir.join("et-ssh-home-s1"),
            real_ssh_dir: dir.join("real-ssh"),
            default_identities: vec![dir.join("real-ssh/id_ed25519")],
            include_configs: vec![dir.join("real-ssh/config")],
            real_ssh: Some(PathBuf::from("/usr/bin/ssh")),
            base_path: Some("/usr/bin".into()),
            path_key: "PATH".into(),
            local_username: "me".into(),
            askpass_exe: Some(PathBuf::from("/Applications/Netcatty")),
            display: None,
            windows: false,
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nc-et-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn opts(plan: &EtPlan) -> Vec<String> {
        plan.args
            .windows(2)
            .filter(|w| w[0] == "--ssh-option")
            .map(|w| w[1].clone())
            .collect()
    }

    #[test]
    fn password_session() {
        let dir = tmp("pw");
        let auth = ExternalSshAuth {
            hostname: "host.example".into(),
            port: 2200,
            username: Some("alice".into()),
            auth_method: Some("password".into()),
            password: Some("s3cret".into()),
            verify_host_keys: true,
            ..Default::default()
        };
        let plan = plan_et(&auth, Some(3000), &[], &env_in(&dir), "s1").unwrap();
        assert_eq!(&plan.args[..2], &["-p", "3000"]);
        assert_eq!(plan.args.last().unwrap(), "alice@host.example");
        let o = opts(&plan);
        assert!(o.contains(&"StrictHostKeyChecking=accept-new".to_string()));
        assert!(o.contains(&"LogLevel=ERROR".to_string()));
        assert!(o.contains(&"Port=2200".to_string()));
        assert!(o.contains(&"PubkeyAuthentication=no".to_string()));
        assert!(o.iter().all(|v| !v.contains(',')), "{o:?}");
        let config = std::fs::read_to_string(dir.join("et-ssh-home-s1/.ssh/config")).unwrap();
        assert!(config.contains("PreferredAuthentications password,keyboard-interactive"));
        assert!(config.contains("Match all"));
        let wrapper = std::fs::read_to_string(dir.join("et-ssh-home-s1/.ssh/bin/ssh")).unwrap();
        assert!(wrapper.contains("'/usr/bin/ssh' -F"));
        let env: std::collections::HashMap<_, _> = plan.env.iter().cloned().collect();
        assert!(env["PATH"].ends_with(":/usr/bin"));
        assert_eq!(env["SSH_ASKPASS"], "/Applications/Netcatty");
        assert_eq!(env[ASKPASS_MARKER_ENV], "1");
        let map = from_json(&std::fs::read_to_string(&env[ASKPASS_MAP_ENV]).unwrap());
        assert_eq!(map.len(), 1);
        assert!(map[0]
            .matchers
            .contains(&"alice@host.example's password".to_string()));
        assert_eq!(
            std::fs::read_to_string(&map[0].secret_file).unwrap(),
            "s3cret\n"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn key_session_without_config() {
        let dir = tmp("key");
        let auth = ExternalSshAuth {
            hostname: "h".into(),
            port: 22,
            username: Some("bob".into()),
            auth_method: Some("key".into()),
            private_key: Some("KEY".into()),
            passphrase: Some("pp".into()),
            verify_host_keys: false,
            ..Default::default()
        };
        let plan = plan_et(&auth, None, &[], &env_in(&dir), "s/2").unwrap();
        assert!(!plan.args.contains(&"-p".to_string()));
        let o = opts(&plan);
        assert!(o.contains(&"StrictHostKeyChecking=no".to_string()));
        assert!(o
            .iter()
            .any(|v| v.starts_with("IdentityFile=") && v.ends_with("s_2-key")));
        assert!(o.contains(&"IdentitiesOnly=yes".to_string()));
        assert!(o.contains(&"PreferredAuthentications=publickey".to_string()));
        // Only comma-free options: no config file, no HOME override.
        assert!(!dir.join("et-ssh-home-s1/.ssh/config").exists());
        assert!(!plan.env.iter().any(|(k, _)| k == "HOME"));
        assert!(plan.env.iter().any(|(k, _)| k == "SSH_ASKPASS"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn vault_pin_and_jump_host() {
        let dir = tmp("jump");
        let auth = ExternalSshAuth {
            hostname: "target".into(),
            port: 22,
            username: Some("alice".into()),
            auth_method: Some("auto".into()),
            verify_host_keys: true,
            known_hosts: vec![KnownHostPin {
                hostname: "target".into(),
                port: 22,
                key_type: "ssh-ed25519".into(),
                public_key: "AAAA".into(),
            }],
            ..Default::default()
        };
        let jump = ExternalSshAuth {
            hostname: "bastion".into(),
            port: 2222,
            username: None,
            auth_method: Some("password".into()),
            password: Some("jpw".into()),
            ..Default::default()
        };
        let plan = plan_et(
            &auth,
            None,
            std::slice::from_ref(&jump),
            &env_in(&dir),
            "s3",
        )
        .unwrap();
        let o = opts(&plan);
        assert!(o.iter().any(|v| v.starts_with("GlobalKnownHostsFile=")));
        assert!(o.contains(&"KnownHostsCommand=none".to_string()));
        let jump_idx = plan.args.iter().position(|a| a == "--jumphost").unwrap();
        assert_eq!(plan.args[jump_idx + 1], "me@bastion");
        assert_eq!(plan.args[jump_idx + 3], "2022");
        let config = std::fs::read_to_string(dir.join("et-ssh-home-s1/.ssh/config")).unwrap();
        assert!(config.starts_with("Host target\n  ProxyJump bastion\n"));
        assert!(config.contains("Host bastion\n  User me\n  Port 2222\n"));
        assert!(config.contains("  PubkeyAuthentication no"));
        assert!(config.contains("  StrictHostKeyChecking accept-new"));
        assert!(
            plan_et(&auth, None, &[jump.clone(), jump], &env_in(&dir), "s4")
                .unwrap_err()
                .contains("at most one jump host")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn preferred_authentications() {
        assert_eq!(
            et_preferred_authentications("auto", false, false),
            "publickey,password,keyboard-interactive"
        );
        assert_eq!(
            et_preferred_authentications("key", false, true),
            "publickey"
        );
        assert_eq!(et_preferred_authentications("key", false, false), "");
    }
}
