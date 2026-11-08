//! `ssh://`, `telnet://` and JumpServer `jms://` deep links: argv scanning,
//! PuTTY / SecureCRT launch intents, the enable switches and their persisted
//! preferences (Electron: `electron/deepLink.cjs`).

use crate::putty::{parse_putty_command_line, LaunchProtocol};
use crate::securecrt::parse_secure_crt_tokens;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const SSH_DEEP_LINK_CHANNEL: &str = "netcatty:deepLink:ssh";
pub const TELNET_DEEP_LINK_CHANNEL: &str = "netcatty:deepLink:telnet";
pub const JMS_DEEP_LINK_CHANNEL: &str = "netcatty:deepLink:jms";
pub const SSH_DEEP_LINK_PREFERENCES_FILE: &str = "ssh-deep-link-preferences.json";
pub const JMS_DEEP_LINK_PREFERENCES_FILE: &str = "jms-deep-link-preferences.json";

/// URL schemes Netcatty handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Ssh,
    Telnet,
    Jms,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Ssh => "ssh",
            Scheme::Telnet => "telnet",
            Scheme::Jms => "jms",
        }
    }
}

/// `true` when `raw` (trimmed, case-insensitive) starts with `scheme://`.
pub fn is_deep_link_url(raw: &str, scheme: Scheme) -> bool {
    let trimmed = raw.trim();
    let prefix = format!("{}://", scheme.as_str());
    trimmed.len() >= prefix.len()
        && trimmed.is_char_boundary(prefix.len())
        && trimmed[..prefix.len()].eq_ignore_ascii_case(&prefix)
}

/// Classify a URL delivered by the OS (`open-url`): jms, then telnet,
/// anything else is offered to the ssh queue (which validates it).
pub fn classify_open_url(raw: &str) -> Scheme {
    if is_deep_link_url(raw, Scheme::Jms) {
        Scheme::Jms
    } else if is_deep_link_url(raw, Scheme::Telnet) {
        Scheme::Telnet
    } else {
        Scheme::Ssh
    }
}

/// Argv tokens that may be standalone scheme URLs: known SecureCRT option
/// operands never are, and on a successful SecureCRT parse neither are the
/// remaining launch tokens.
fn scheme_url_candidates(argv: &[String]) -> Vec<&String> {
    let Some(tokens) = parse_secure_crt_tokens(argv) else {
        return argv.iter().collect();
    };
    let mut filtered: BTreeSet<usize> = tokens.operands.clone();
    if tokens.result.is_some() {
        filtered.extend(tokens.consumed.iter().copied());
    }
    argv.iter()
        .enumerate()
        .filter(|(i, _)| !filtered.contains(i))
        .map(|(_, a)| a)
        .collect()
}

pub fn collect_deep_link_urls(argv: &[String], scheme: Scheme) -> Vec<String> {
    scheme_url_candidates(argv)
        .into_iter()
        .filter(|raw| is_deep_link_url(raw, scheme))
        .cloned()
        .collect()
}

pub fn collect_ssh_deep_link_urls(argv: &[String]) -> Vec<String> {
    collect_deep_link_urls(argv, Scheme::Ssh)
}

pub fn collect_telnet_deep_link_urls(argv: &[String]) -> Vec<String> {
    collect_deep_link_urls(argv, Scheme::Telnet)
}

pub fn collect_jms_deep_link_urls(argv: &[String]) -> Vec<String> {
    collect_deep_link_urls(argv, Scheme::Jms)
}

/// One queued ssh / telnet connection request.
#[derive(Clone, PartialEq, Eq)]
pub struct QueueItem {
    pub raw_url: String,
    /// From PuTTY / SecureCRT style argv: delivered regardless of the
    /// `ssh://` protocol-client preference.
    pub via_command_line: bool,
    pub tab_name: Option<String>,
}

impl std::fmt::Debug for QueueItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueueItem")
            .field("raw_url", &"<redacted>")
            .field("via_command_line", &self.via_command_line)
            .field("tab_name", &self.tab_name)
            .finish()
    }
}

impl Drop for QueueItem {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.raw_url);
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct QueueItems {
    pub ssh: Vec<QueueItem>,
    pub telnet: Vec<QueueItem>,
}

/// PuTTY / SecureCRT launch intents, unless the argv carries any scheme URL.
/// SecureCRT switches are tried first (disjoint from PuTTY dashes); once a
/// SecureCRT signal is present PuTTY parsing is never attempted.
pub fn collect_putty_style_intents(argv: &[String]) -> QueueItems {
    if !collect_ssh_deep_link_urls(argv).is_empty()
        || !collect_telnet_deep_link_urls(argv).is_empty()
        || !collect_jms_deep_link_urls(argv).is_empty()
    {
        return QueueItems::default();
    }
    let parsed = match parse_secure_crt_tokens(argv) {
        Some(tokens) => tokens.result,
        None => parse_putty_command_line(argv),
    };
    let mut items = QueueItems::default();
    let Some(parsed) = parsed else {
        return items;
    };
    let item = QueueItem {
        raw_url: parsed.url.clone(),
        via_command_line: true,
        tab_name: parsed.tab_name.clone(),
    };
    match parsed.protocol {
        LaunchProtocol::Telnet => items.telnet.push(item),
        LaunchProtocol::Ssh => items.ssh.push(item),
    }
    items
}

/// Queue items for the ssh / telnet connections requested by `argv`. Scheme
/// URLs are included only when `include_scheme_urls` (the protocol-client
/// preference); command-line launches always are.
pub fn collect_queue_items(argv: &[String], include_scheme_urls: bool) -> QueueItems {
    let cli = collect_putty_style_intents(argv);
    let mut items = QueueItems::default();
    if include_scheme_urls {
        for raw_url in collect_ssh_deep_link_urls(argv) {
            items.ssh.push(QueueItem {
                raw_url,
                via_command_line: false,
                tab_name: None,
            });
        }
        for raw_url in collect_telnet_deep_link_urls(argv) {
            items.telnet.push(QueueItem {
                raw_url,
                via_command_line: false,
                tab_name: None,
            });
        }
    }
    let QueueItems { ssh, telnet } = cli;
    items.ssh.extend(ssh);
    items.telnet.extend(telnet);
    items
}

// ---------------------------------------------------------------------------
// Preferences
// ---------------------------------------------------------------------------

pub fn preference_path(data_dir: &Path, file: &str) -> PathBuf {
    data_dir.join(file)
}

fn read_enabled_json(path: &Path) -> Option<serde_json::Value> {
    if !path.exists() {
        return None;
    }
    match std::fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).map_err(|e| e.to_string()))
    {
        Ok(value) => Some(value),
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "failed to read deep link preference");
            Some(serde_json::Value::Null)
        }
    }
}

/// `ssh://` handling defaults to enabled; only an explicit `false` disables.
pub fn read_ssh_enabled(data_dir: &Path) -> bool {
    match read_enabled_json(&preference_path(data_dir, SSH_DEEP_LINK_PREFERENCES_FILE)) {
        None | Some(serde_json::Value::Null) => true,
        Some(value) => value.get("enabled") != Some(&serde_json::Value::Bool(false)),
    }
}

/// `jms://` handling defaults to disabled; only an explicit `true` enables.
pub fn read_jms_enabled(data_dir: &Path) -> bool {
    match read_enabled_json(&preference_path(data_dir, JMS_DEEP_LINK_PREFERENCES_FILE)) {
        None | Some(serde_json::Value::Null) => false,
        Some(value) => value.get("enabled") == Some(&serde_json::Value::Bool(true)),
    }
}

/// Write `{ "enabled": bool }` (pretty, like Electron).
pub fn write_enabled(data_dir: &Path, file: &str, enabled: bool) -> bool {
    let path = preference_path(data_dir, file);
    let result = std::fs::create_dir_all(data_dir).and_then(|()| {
        let text = serde_json::to_string_pretty(&serde_json::json!({ "enabled": enabled }))
            .unwrap_or_else(|_| format!("{{\"enabled\":{enabled}}}"));
        std::fs::write(&path, text)
    });
    if let Err(err) = &result {
        tracing::warn!(path = %path.display(), %err, "failed to write deep link preference");
    }
    result.is_ok()
}

/// Outcome of a preference toggle (`{ enabled, success }` on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ToggleResult {
    pub enabled: bool,
    pub success: bool,
}

/// Electron `updateDeepLinkEnabledPreference`: apply the OS change, persist,
/// roll back the OS change when persisting fails, and clear queued links
/// whenever the final state is disabled.
pub fn update_enabled_preference(
    current: bool,
    requested: bool,
    mut apply: impl FnMut(bool) -> bool,
    write: impl FnOnce(bool) -> bool,
    clear_pending: impl FnOnce(),
) -> ToggleResult {
    if requested == current {
        return ToggleResult {
            enabled: current,
            success: true,
        };
    }
    if !apply(requested) {
        return ToggleResult {
            enabled: current,
            success: false,
        };
    }
    if !write(requested) {
        let rolled_back = apply(current);
        let final_enabled = if rolled_back { current } else { requested };
        if !final_enabled {
            clear_pending();
        }
        return ToggleResult {
            enabled: final_enabled,
            success: false,
        };
    }
    if !requested {
        clear_pending();
    }
    ToggleResult {
        enabled: requested,
        success: true,
    }
}

/// Electron `applyInitialDeepLinkPreference`: apply the saved preference at
/// startup; a failure leaves handling disabled (and clears queued scheme
/// links when it was meant to be enabled).
pub fn apply_initial_preference(
    enabled: bool,
    apply: impl FnOnce(bool) -> bool,
    clear_pending: impl FnOnce(),
    label: &str,
    warn_on_failure: bool,
) -> ToggleResult {
    if apply(enabled) {
        return ToggleResult {
            enabled,
            success: true,
        };
    }
    if warn_on_failure && enabled {
        tracing::warn!("failed to apply saved {label} deep link preference");
    }
    if enabled {
        clear_pending();
    }
    ToggleResult {
        enabled: false,
        success: false,
    }
}

/// Electron `applySshProtocolClientPreference`: the ssh and telnet handlers
/// follow one switch; ssh decides success, and a telnet change is undone
/// when ssh failed.
pub fn apply_ssh_and_telnet(enabled: bool, mut set_handler: impl FnMut(Scheme, bool) -> bool) -> bool {
    let ssh = set_handler(Scheme::Ssh, enabled);
    let telnet = set_handler(Scheme::Telnet, enabled);
    if !ssh && telnet {
        set_handler(Scheme::Telnet, !enabled);
    }
    ssh
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn item(url: &str, cli: bool, tab: Option<&str>) -> QueueItem {
        QueueItem {
            raw_url: url.to_owned(),
            via_command_line: cli,
            tab_name: tab.map(str::to_owned),
        }
    }

    fn items(ssh: Vec<QueueItem>, telnet: Vec<QueueItem>) -> QueueItems {
        QueueItems { ssh, telnet }
    }

    fn urls(found: &QueueItems) -> (Vec<String>, Vec<String>) {
        (
            found.ssh.iter().map(|i| i.raw_url.clone()).collect(),
            found.telnet.iter().map(|i| i.raw_url.clone()).collect(),
        )
    }

    #[test]
    fn scheme_detection() {
        assert!(is_deep_link_url("ssh://alice@example.com:2200", Scheme::Ssh));
        assert!(is_deep_link_url("SSH://alice@example.com", Scheme::Ssh));
        assert!(is_deep_link_url("ssh://example.com:99999", Scheme::Ssh));
        assert!(!is_deep_link_url("https://example.com", Scheme::Ssh));
        assert!(!is_deep_link_url("--flag", Scheme::Ssh));
        assert!(is_deep_link_url("TELNET://example.com:2001", Scheme::Telnet));
        assert!(!is_deep_link_url("ssh://alice@example.com", Scheme::Telnet));
        assert!(is_deep_link_url("JMS://payload", Scheme::Jms));
        assert!(!is_deep_link_url("ssh://x", Scheme::Jms));
        assert_eq!(classify_open_url("jms://x"), Scheme::Jms);
        assert_eq!(classify_open_url("telnet://x"), Scheme::Telnet);
        assert_eq!(classify_open_url("ssh://x"), Scheme::Ssh);
    }

    #[test]
    fn collects_scheme_urls_from_argv() {
        assert_eq!(
            collect_ssh_deep_link_urls(&argv(&[
                "/Applications/Netcatty.app/Contents/MacOS/Netcatty",
                "--flag",
                "ssh://alice@example.com",
                "file:///tmp/example",
                "ssh://bob@example.net:2222",
            ])),
            vec!["ssh://alice@example.com", "ssh://bob@example.net:2222"]
        );
        assert_eq!(
            collect_telnet_deep_link_urls(&argv(&[
                "/Applications/Netcatty.app/Contents/MacOS/Netcatty",
                "telnet://example.com:2001",
                "telnet://router.local:23",
            ])),
            vec!["telnet://example.com:2001", "telnet://router.local:23"]
        );
    }

    #[test]
    fn putty_argv_becomes_a_cli_intent_unless_a_scheme_url_is_present() {
        let found = collect_putty_style_intents(&argv(&[
            r"C:\Program Files\Netcatty\Netcatty.exe", "-ssh", "alice@10.0.0.8", "-P", "2222", "-pw",
            "s3cret",
        ]));
        assert_eq!(urls(&found).0, vec!["ssh://alice:s3cret@10.0.0.8:2222"]);
        let with_url = collect_putty_style_intents(&argv(&[
            "Netcatty.exe", "-url", "ssh://alice@example.com", "-ssh", "ignored@host",
        ]));
        assert_eq!(with_url, QueueItems::default());
    }

    #[test]
    fn queue_items_keep_tab_names() {
        assert_eq!(
            collect_queue_items(
                &argv(&["Netcatty.exe", "-newtab", "Production", "-ssh", "root@192.168.1.122", "-P", "22"]),
                false
            ),
            items(vec![item("ssh://root@192.168.1.122:22", true, Some("Production"))], vec![])
        );
        assert_eq!(
            collect_queue_items(
                &argv(&["Netcatty.exe", "-ssh", "alice@192.0.2.10@198.51.100.20", "-P", "2200", "-pw", "example"]),
                false
            ),
            items(
                vec![item("ssh://alice%40192.0.2.10:example@198.51.100.20:2200", true, Some("192.0.2.10"))],
                vec![]
            )
        );
        assert_eq!(
            collect_queue_items(
                &argv(&["Netcatty.exe", "/SSH2", "/L", "root", "/P", "22", "/N", "Production", "192.168.1.122"]),
                false
            ),
            items(vec![item("ssh://root@192.168.1.122:22", true, Some("Production"))], vec![])
        );
    }

    #[test]
    fn cli_launches_ignore_the_scheme_switch() {
        for line in [
            vec![r"C:\Program Files\Netcatty\Netcatty.exe", "-ssh", "alice@10.0.0.8", "-P", "2222", "-pw", "s3cret"],
            vec!["Netcatty.exe", "/SSH2", "/L", "alice", "/P", "2222", "/PASSWORD", "s3cret", "10.0.0.8"],
        ] {
            assert_eq!(
                collect_queue_items(&argv(&line), false),
                items(vec![item("ssh://alice:s3cret@10.0.0.8:2222", true, None)], vec![])
            );
        }
        let telnet = collect_putty_style_intents(&argv(&["Netcatty.exe", "/TELNET", "old.example.com", "/P", "2323"]));
        assert_eq!(urls(&telnet).1, vec!["telnet://old.example.com:2323"]);
    }

    #[test]
    fn scheme_shaped_securecrt_operands_are_never_links() {
        let line = argv(&["Netcatty.exe", "/SSH2", "/L", "alice", "/PASSWORD", "ssh://s3cret", "10.0.0.8"]);
        assert_eq!(
            collect_queue_items(&line, true),
            items(vec![item("ssh://alice:ssh%3A%2F%2Fs3cret@10.0.0.8", true, None)], vec![])
        );
        let failed = argv(&["Netcatty.exe", "/SSH2", "/PASSWORD", "ssh://s3cret", "/P", "99999", "10.0.0.8"]);
        assert_eq!(collect_queue_items(&failed, true), QueueItems::default());
        let genuine = argv(&[
            "Netcatty.exe", "/SSH2", "/PASSWORD", "s3cret", "/P", "99999", "10.0.0.8", "ssh://bob@example.com",
        ]);
        assert_eq!(
            collect_queue_items(&genuine, true),
            items(vec![item("ssh://bob@example.com", false, None)], vec![])
        );
    }

    #[test]
    fn standalone_scheme_links_never_inherit_securecrt_credentials() {
        for url in ["ssh://bob@example.com", "ssh://example.com", "telnet://example.com", " ssh://bob@example.com "] {
            let line = argv(&["Netcatty.exe", "/SSH2", "/L", "alice", "/PASSWORD", "secret", "10.0.0.8", url]);
            let expected = if url.contains("telnet") {
                items(vec![], vec![item(url, false, None)])
            } else {
                items(vec![item(url, false, None)], vec![])
            };
            assert_eq!(collect_queue_items(&line, true), expected);
            assert_eq!(collect_queue_items(&line, false), QueueItems::default());
        }
    }

    #[test]
    fn scheme_urls_follow_the_preference() {
        let line = argv(&["/Applications/Netcatty.app/Contents/MacOS/Netcatty", "ssh://alice@example.com"]);
        assert_eq!(
            collect_queue_items(&line, true),
            items(vec![item("ssh://alice@example.com", false, None)], vec![])
        );
        assert_eq!(collect_queue_items(&line, false), QueueItems::default());
    }

    #[test]
    fn malformed_securecrt_operands_are_filtered_for_every_scheme() {
        for flag in [
            "/L", "/P", "/PASSWORD", "/PASSPHRASE", "/AUTH", "/I", "/S", "/N", "/TITLEBAR", "/LOG",
            "/LOGAPPEND", "/FIREWALL", "/FWFIREWALL", "/PROXY",
        ] {
            for scheme in ["ssh", "telnet", "jms"] {
                let value = format!("{scheme}://option-value");
                let line = argv(&["Netcatty.exe", "/SSH2", "/P", "99999", flag, &value, "real.example.com"]);
                assert_eq!(collect_queue_items(&line, true), QueueItems::default());
                assert!(collect_jms_deep_link_urls(&line).is_empty());
            }
        }
    }

    #[test]
    fn securecrt_and_putty_edge_cases() {
        assert_eq!(
            collect_queue_items(
                &argv(&["Netcatty.exe", "/SSH2", "/L", "alice", "/P", "99999", "/PASSWORD", "-ssh", "server.example.com"]),
                true
            ),
            QueueItems::default()
        );
        for password in ["/SSH2", "/TELNET", "/PASSWORD", "/PASSPHRASE"] {
            let expected = format!(
                "ssh://alice:{}@server.example.com:2222",
                crate::putty::encode_uri_component(password)
            );
            assert_eq!(
                collect_queue_items(
                    &argv(&["Netcatty.exe", "-ssh", "-l", "alice", "-P", "2222", "-pw", password, "server.example.com"]),
                    true
                ),
                items(vec![item(&expected, true, None)], vec![])
            );
        }
        assert_eq!(
            collect_queue_items(&argv(&["Netcatty.exe", "/SSH2", "/PASSWORD", "/L", "ssh://bob@example.com"]), true),
            items(vec![item("ssh://bob@example.com", false, None)], vec![])
        );
        for names in [["Device", "bastion"], ["device.example.com", "bastion"]] {
            assert_eq!(
                collect_queue_items(
                    &argv(&["Netcatty.exe", "/T", names[0], "/SSH2", names[1], "/L", "alice", "/PASSWORD", "secret"]),
                    true
                ),
                QueueItems::default()
            );
        }
        for flag in ["-serial", "-raw", "-telnet", "-ssh", "-unknown"] {
            assert_eq!(
                collect_queue_items(
                    &argv(&["Netcatty.exe", "/SSH2", flag, "host", "/L", "alice", "/PASSWORD", "secret"]),
                    true
                ),
                QueueItems::default()
            );
        }
        assert_eq!(
            collect_queue_items(
                &argv(&[
                    "Netcatty.exe", "--original-process-start-time=1", "/SSH2", "host", "/TITLEBAR", "-serial",
                    "/L", "-raw", "/PASSWORD", "-telnet",
                ]),
                true
            ),
            items(vec![item("ssh://-raw:-telnet@host", true, None)], vec![])
        );
    }

    #[test]
    fn preferences_round_trip_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_ssh_enabled(dir.path()));
        assert!(!read_jms_enabled(dir.path()));
        assert!(write_enabled(dir.path(), SSH_DEEP_LINK_PREFERENCES_FILE, false));
        assert!(!read_ssh_enabled(dir.path()));
        assert!(write_enabled(dir.path(), SSH_DEEP_LINK_PREFERENCES_FILE, true));
        assert!(read_ssh_enabled(dir.path()));
        assert!(write_enabled(dir.path(), JMS_DEEP_LINK_PREFERENCES_FILE, true));
        assert!(read_jms_enabled(dir.path()));
        // Corrupt files fall back to the defaults.
        std::fs::write(dir.path().join(SSH_DEEP_LINK_PREFERENCES_FILE), "{").unwrap();
        assert!(read_ssh_enabled(dir.path()));
    }

    #[test]
    fn update_keeps_state_when_the_os_change_fails() {
        let mut writes = Vec::new();
        let result = update_enabled_preference(true, false, |_| false, |v| {
            writes.push(v);
            true
        }, || {});
        assert_eq!(result, ToggleResult { enabled: true, success: false });
        assert!(writes.is_empty());
    }

    #[test]
    fn update_clears_queue_after_disabling() {
        let mut cleared = false;
        let result = update_enabled_preference(true, false, |_| true, |_| true, || cleared = true);
        assert_eq!(result, ToggleResult { enabled: false, success: true });
        assert!(cleared);
    }

    #[test]
    fn update_rolls_back_when_saving_fails() {
        let mut applied = Vec::new();
        let result = update_enabled_preference(true, false, |v| {
            applied.push(v);
            true
        }, |_| false, || {});
        assert_eq!(result, ToggleResult { enabled: true, success: false });
        assert_eq!(applied, vec![false, true]);

        // Save and rollback both fail while disabling: disabled, queue cleared.
        let mut cleared = false;
        let mut calls = 0;
        let result = update_enabled_preference(true, false, |_| {
            calls += 1;
            calls == 1
        }, |_| false, || cleared = true);
        assert_eq!(result, ToggleResult { enabled: false, success: false });
        assert!(cleared);
    }

    #[test]
    fn initial_preference_failure_disables_and_clears() {
        let mut cleared = false;
        let result = apply_initial_preference(true, |_| false, || cleared = true, "ssh://", true);
        assert_eq!(result, ToggleResult { enabled: false, success: false });
        assert!(cleared);
        let mut cleared = false;
        let result = apply_initial_preference(false, |_| false, || cleared = true, "jms://", false);
        assert_eq!(result, ToggleResult { enabled: false, success: false });
        assert!(!cleared);
    }

    #[test]
    fn ssh_and_telnet_handlers_move_together() {
        let mut calls = Vec::new();
        assert!(apply_ssh_and_telnet(true, |s, e| {
            calls.push((s, e));
            true
        }));
        assert_eq!(calls, vec![(Scheme::Ssh, true), (Scheme::Telnet, true)]);

        let mut calls = Vec::new();
        assert!(!apply_ssh_and_telnet(true, |s, e| {
            calls.push((s, e));
            s == Scheme::Telnet
        }));
        assert_eq!(
            calls,
            vec![(Scheme::Ssh, true), (Scheme::Telnet, true), (Scheme::Telnet, false)]
        );

        let mut calls = Vec::new();
        assert!(apply_ssh_and_telnet(false, |s, e| {
            calls.push((s, e));
            s == Scheme::Ssh
        }));
        assert_eq!(calls, vec![(Scheme::Ssh, false), (Scheme::Telnet, false)]);
    }
}
