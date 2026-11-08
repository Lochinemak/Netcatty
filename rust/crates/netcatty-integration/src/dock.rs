//! macOS Dock menu model (Electron: `buildDockMenuTemplate` in
//! `globalShortcutBridge.cjs`): "Open Main Window", a separator and a
//! "New Connection" submenu of the saved hosts the renderer synced for the
//! tray (pinned first, then most recently connected, then by label).

use serde_json::Value;
use std::cmp::Ordering;

pub const OPEN_MAIN_ACTION: &str = "open-main";
pub const HOST_ACTION_PREFIX: &str = "host:";

/// One host entry of the "New Connection" submenu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockHost {
    pub id: String,
    pub label: String,
}

/// The whole Dock menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockMenu {
    pub open_main_label: String,
    pub new_connection_label: String,
    pub empty_label: String,
    pub hosts: Vec<DockHost>,
}

fn label_of(host: &Value) -> String {
    let label = host.get("label").and_then(Value::as_str).map(str::trim).unwrap_or("");
    if !label.is_empty() {
        return label.to_owned();
    }
    let hostname = host.get("hostname").and_then(Value::as_str).map(str::trim).unwrap_or("");
    if hostname.is_empty() {
        "Untitled Host".to_owned()
    } else {
        hostname.to_owned()
    }
}

fn last_connected(host: &Value) -> f64 {
    let value = match host.get("lastConnectedAt") {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.trim().parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    };
    if value.is_finite() {
        value
    } else {
        0.0
    }
}

fn pinned(host: &Value) -> bool {
    match host.get("pinned") {
        Some(Value::Bool(b)) => *b,
        Some(Value::Null) | None => false,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|v| v != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// `localeCompare(..., { sensitivity: "base" })` approximation: case- and
/// accent-insensitive for ASCII, then a stable byte order.
fn base_compare(a: &str, b: &str) -> Ordering {
    a.to_lowercase().cmp(&b.to_lowercase())
}

/// Sorted host entries from the tray menu data (`hosts`). `locked` hides
/// them (App Lock), like Electron.
pub fn dock_hosts(hosts: &[Value], locked: bool) -> Vec<DockHost> {
    if locked {
        return Vec::new();
    }
    let mut valid: Vec<&Value> = hosts
        .iter()
        .filter(|h| h.get("id").and_then(Value::as_str).is_some_and(|id| !id.is_empty()))
        .collect();
    valid.sort_by(|a, b| {
        pinned(b)
            .cmp(&pinned(a))
            .then_with(|| {
                last_connected(b)
                    .partial_cmp(&last_connected(a))
                    .unwrap_or(Ordering::Equal)
            })
            .then_with(|| base_compare(&label_of(a), &label_of(b)))
    });
    valid
        .into_iter()
        .map(|h| DockHost {
            id: h.get("id").and_then(Value::as_str).unwrap_or_default().to_owned(),
            label: label_of(h),
        })
        .collect()
}

pub fn build_dock_menu(hosts: &[Value], locked: bool) -> DockMenu {
    DockMenu {
        open_main_label: "Open Main Window".to_owned(),
        new_connection_label: "New Connection".to_owned(),
        empty_label: "No Saved Hosts".to_owned(),
        hosts: dock_hosts(hosts, locked),
    }
}

/// Action id of a menu entry, parsed back by [`parse_action`].
pub fn host_action(id: &str) -> String {
    format!("{HOST_ACTION_PREFIX}{id}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockAction {
    OpenMain,
    ConnectHost(String),
}

pub fn parse_action(action: &str) -> Option<DockAction> {
    if action == OPEN_MAIN_ACTION {
        return Some(DockAction::OpenMain);
    }
    action
        .strip_prefix(HOST_ACTION_PREFIX)
        .filter(|id| !id.is_empty())
        .map(|id| DockAction::ConnectHost(id.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hosts_sort_pinned_then_recent_then_label() {
        let hosts = vec![
            json!({ "id": "b", "label": "beta" }),
            json!({ "id": "a", "label": "Alpha" }),
            json!({ "id": "r", "label": "recent", "lastConnectedAt": 50 }),
            json!({ "id": "p", "label": "pinned", "pinned": true }),
            json!({ "id": "", "label": "no id" }),
            json!({ "label": "missing id" }),
            json!({ "id": "h", "hostname": " host.example " }),
            json!({ "id": "u" }),
        ];
        let sorted = dock_hosts(&hosts, false);
        let ids: Vec<&str> = sorted.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, vec!["p", "r", "a", "b", "h", "u"]);
        assert_eq!(sorted[4].label, "host.example");
        assert_eq!(sorted[5].label, "Untitled Host");
    }

    #[test]
    fn locked_runtime_hides_hosts() {
        assert!(dock_hosts(&[json!({ "id": "a", "label": "A" })], true).is_empty());
    }

    #[test]
    fn menu_labels_match_electron() {
        let menu = build_dock_menu(&[], false);
        assert_eq!(menu.open_main_label, "Open Main Window");
        assert_eq!(menu.new_connection_label, "New Connection");
        assert_eq!(menu.empty_label, "No Saved Hosts");
    }

    #[test]
    fn actions_round_trip() {
        assert_eq!(parse_action(OPEN_MAIN_ACTION), Some(DockAction::OpenMain));
        assert_eq!(parse_action(&host_action("h1")), Some(DockAction::ConnectHost("h1".into())));
        assert_eq!(parse_action("host:"), None);
        assert_eq!(parse_action("other"), None);
    }
}
