//! What a launch command line asks for: the cold-start intents of this
//! process and the routing of a second instance's forwarded argv (Electron:
//! the `second-instance` handler and startup queues in `electron/main.cjs`).

use crate::deeplink::{collect_jms_deep_link_urls, collect_queue_items, QueueItem};
use crate::open_terminal::{has_launch_args, resolve_requests_from_args, OpenTerminalRequest, PathProbe};
use std::path::Path;

/// Intents found in the launch argv of this (primary) process.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ColdStartIntents {
    pub ssh: Vec<QueueItem>,
    pub telnet: Vec<QueueItem>,
    pub jms: Vec<String>,
    pub open_terminal: Vec<OpenTerminalRequest>,
}

pub fn cold_start_intents(
    argv: &[String],
    cwd: Option<&Path>,
    home: Option<&Path>,
    ssh_enabled: bool,
    jms_enabled: bool,
    fs: &dyn PathProbe,
) -> ColdStartIntents {
    let items = collect_queue_items(argv, ssh_enabled);
    let mut intents = ColdStartIntents {
        jms: if jms_enabled {
            collect_jms_deep_link_urls(argv)
        } else {
            Vec::new()
        },
        open_terminal: resolve_requests_from_args(argv, cwd, home, fs),
        ..Default::default()
    };
    let crate::deeplink::QueueItems { ssh, telnet } = items;
    intents.ssh = ssh;
    intents.telnet = telnet;
    intents
}

/// What to do with a second instance's argv; first match wins, like Electron.
#[derive(Debug, PartialEq, Eq)]
pub enum SecondInstanceRoute {
    /// `jms://` URLs (dropped when jms handling is disabled; no focus).
    Jms { urls: Vec<String>, enabled: bool },
    Telnet(Vec<QueueItem>),
    Ssh(Vec<QueueItem>),
    OpenTerminal(Vec<OpenTerminalRequest>),
    /// Open-terminal flags were present but nothing resolved: focus anyway
    /// (a silent no-op feels like a broken menu item).
    OpenTerminalInvalid,
    /// Plain relaunch: bring the main window forward.
    Focus,
}

pub fn route_second_instance(
    argv: &[String],
    cwd: Option<&Path>,
    home: Option<&Path>,
    ssh_enabled: bool,
    jms_enabled: bool,
    fs: &dyn PathProbe,
) -> SecondInstanceRoute {
    let jms = collect_jms_deep_link_urls(argv);
    let crate::deeplink::QueueItems { ssh, telnet } = collect_queue_items(argv, ssh_enabled);
    if !jms.is_empty() {
        return SecondInstanceRoute::Jms {
            urls: jms,
            enabled: jms_enabled,
        };
    }
    if !telnet.is_empty() {
        return SecondInstanceRoute::Telnet(telnet);
    }
    if !ssh.is_empty() {
        return SecondInstanceRoute::Ssh(ssh);
    }
    if has_launch_args(argv) {
        let requests = resolve_requests_from_args(argv, cwd, home, fs);
        return if requests.is_empty() {
            SecondInstanceRoute::OpenTerminalInvalid
        } else {
            SecondInstanceRoute::OpenTerminal(requests)
        };
    }
    SecondInstanceRoute::Focus
}

/// Overwrite every argv string in place and clear the list: the forwarded
/// launch line may carry a password (`-pw`, `/PASSWORD`, `ssh://u:p@h`).
pub fn scrub_argv(argv: &mut Vec<String>) {
    for arg in argv.iter_mut() {
        zeroize::Zeroize::zeroize(arg);
    }
    argv.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    struct Dirs;
    impl PathProbe for Dirs {
        fn kind(&self, _: &Path) -> Option<bool> {
            Some(true)
        }
    }

    fn route(items: &[&str], ssh_enabled: bool) -> SecondInstanceRoute {
        route_second_instance(&argv(items), Some(Path::new("/working-directory")), None, ssh_enabled, false, &Dirs)
    }

    #[test]
    fn putty_launch_keeps_the_real_password_whatever_the_ssh_switch() {
        for password in ["secret", "space :/@ password", "-flag-like-password"] {
            let SecondInstanceRoute::Ssh(items) = route(
                &["netcatty", "-ssh", "alice@localhost", "-P", "2222", "-pw", password],
                false,
            ) else {
                panic!("expected an ssh route");
            };
            assert_eq!(items.len(), 1);
            let expected = format!(
                "ssh://alice:{}@localhost:2222",
                crate::putty::encode_uri_component(password)
            );
            assert_eq!(items[0].raw_url, expected);
            assert!(items[0].via_command_line);
        }
    }

    #[test]
    fn failed_parse_focuses_the_window() {
        assert_eq!(route(&["netcatty", "-raw", "localhost", "-pw", "secret"], true), SecondInstanceRoute::Focus);
    }

    #[test]
    fn securecrt_4a_launch_reaches_the_bastion() {
        let SecondInstanceRoute::Ssh(items) = route(
            &[
                "netcatty", "/TITLEBAR", "192.0.2.10", "/N", "192.0.2.10", "/T", "/SSH2", "198.51.100.20", "/P",
                "2200", "/L", "alice", "/PASSWORD", "space :/@ password",
            ],
            false,
        ) else {
            panic!("expected an ssh route");
        };
        assert_eq!(items[0].raw_url, "ssh://alice:space%20%3A%2F%40%20password@198.51.100.20:2200");
        let SecondInstanceRoute::Ssh(items) = route(
            &["netcatty", "/SSH2", "/L", "-pw", "/TITLEBAR", "-pw", "/PASSWORD", "secret", "server.example.com"],
            false,
        ) else {
            panic!("expected an ssh route");
        };
        assert_eq!(items[0].raw_url, "ssh://-pw:secret@server.example.com");
    }

    #[cfg(unix)]
    #[test]
    fn open_terminal_routes_resolve_against_the_second_instance_cwd() {
        assert_eq!(
            route(&["netcatty", "--open-terminal-shell", "pwsh"], true),
            SecondInstanceRoute::OpenTerminal(vec![OpenTerminalRequest { path: None, shell: Some("pwsh".into()) }])
        );
        assert_eq!(
            route(&["netcatty", "--open-terminal-path", "proj"], true),
            SecondInstanceRoute::OpenTerminal(vec![OpenTerminalRequest {
                path: Some("/working-directory/proj".into()),
                shell: None
            }])
        );
        assert_eq!(
            route(&["netcatty", "--open-terminal-shell", "pwsh", "--open-terminal-path", "proj"], true),
            SecondInstanceRoute::OpenTerminal(vec![OpenTerminalRequest {
                path: Some("/working-directory/proj".into()),
                shell: Some("pwsh".into())
            }])
        );
        assert_eq!(
            route(&["netcatty", "--open-terminal-shell", "bad\0shell"], true),
            SecondInstanceRoute::OpenTerminalInvalid
        );
    }

    #[test]
    fn scheme_urls_route_by_kind_and_preference() {
        assert_eq!(
            route_second_instance(&argv(&["netcatty", "jms://payload"]), None, None, true, false, &Dirs),
            SecondInstanceRoute::Jms { urls: vec!["jms://payload".into()], enabled: false }
        );
        assert!(matches!(route(&["netcatty", "telnet://router"], true), SecondInstanceRoute::Telnet(_)));
        assert!(matches!(route(&["netcatty", "ssh://host"], true), SecondInstanceRoute::Ssh(_)));
        assert_eq!(route(&["netcatty", "ssh://host"], false), SecondInstanceRoute::Focus);
    }

    #[test]
    fn cold_start_collects_every_kind() {
        let intents = cold_start_intents(
            &argv(&["netcatty", "ssh://a@h", "jms://p", "--open-terminal-shell", "zsh"]),
            None,
            None,
            true,
            true,
            &Dirs,
        );
        assert_eq!(intents.ssh.len(), 1);
        assert_eq!(intents.jms, vec!["jms://p"]);
        assert_eq!(intents.open_terminal.len(), 1);
        let disabled = cold_start_intents(&argv(&["netcatty", "ssh://a@h", "jms://p"]), None, None, false, false, &Dirs);
        assert!(disabled.ssh.is_empty() && disabled.jms.is_empty());
    }

    #[test]
    fn scrubbing_clears_the_forwarded_argv() {
        let mut items = argv(&["netcatty", "-pw", "secret"]);
        scrub_argv(&mut items);
        assert!(items.is_empty());
    }
}
