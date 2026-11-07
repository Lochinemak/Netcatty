//! Output parsers from `electron/bridges/systemManager/tmuxOps.cjs`.

use super::env::is_tmux_diagnostic_line;
use super::js;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::LazyLock;

static PLAIN_SESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^([^:]+):\s*([0-9]+)\s+windows?\b").unwrap());
static ATTACHED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\battached\b").unwrap());
static WINDOW_WITH_PANES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^([0-9]+):\s*(.+?)(\*)?\s+\(([0-9]+)\s+panes?\)").unwrap());
static WINDOW_BARE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([0-9]+):\s*(.*?)(\*)?(?:\s+\[[^\]]+\]|\s*$)").unwrap());
static WINDOW_ALL_PLAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([^:]+):\s*([0-9]+):\s*(.+)$").unwrap());
static PANE_PLAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([0-9]+):\s*\[([0-9]+)x([0-9]+)\]").unwrap());
static ACTIVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bactive\b").unwrap());

fn lines(stdout: &str) -> impl Iterator<Item = &str> {
    stdout.split('\n').map(str::trim).filter(|l| !l.is_empty())
}

/// `-F` session rows (`name\twindows\tattached\tcreated[\tactivity[\tgroup]]`).
pub fn parse_tmux_sessions(stdout: &str) -> Vec<Value> {
    lines(stdout)
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            (parts.len() >= 4).then(|| {
                json!({
                    "name": parts[0],
                    "windows": js::num_or_zero(parts[1]),
                    "attached": parts[2] == "1",
                    "created": js::num_or_zero(parts[3]),
                    "activity": parts.get(4).copied().unwrap_or(""),
                    "group": parts.get(5).copied().unwrap_or(""),
                })
            })
        })
        .collect()
}

/// Default `tmux list-sessions` lines.
pub fn parse_tmux_sessions_plain(stdout: &str) -> Vec<Value> {
    lines(stdout)
        .filter_map(|line| {
            let m = PLAIN_SESSION.captures(line)?;
            Some(json!({
                "name": m[1].trim(),
                "windows": js::num_or_zero(&m[2]),
                "attached": ATTACHED.is_match(line),
                "created": 0,
                "activity": "",
                "group": "",
            }))
        })
        .collect()
}

/// One bare session name per line.
pub fn parse_tmux_session_names(stdout: &str) -> Vec<Value> {
    lines(stdout)
        .map(|name| {
            json!({"name": name, "windows": 0, "attached": false, "created": 0, "activity": "", "group": ""})
        })
        .collect()
}

/// "No tmux server" (or a stale socket) — not an error, just no sessions.
pub fn is_no_tmux_server_message(text: &str, code: Option<i32>) -> bool {
    if code != Some(1) {
        return false;
    }
    let msg = text.to_lowercase();
    if msg.contains("no server running") {
        return true;
    }
    msg.contains("error connecting to") && msg.contains("no such file or directory")
}

/// Split `-F` rows on real tabs, or literal `\t` when the remote printf failed.
pub fn split_tmux_fields(line: &str) -> Vec<String> {
    if line.contains('\t') {
        line.split('\t').map(str::to_string).collect()
    } else if line.contains("\\t") {
        line.split("\\t").map(str::to_string).collect()
    } else {
        vec![line.to_string()]
    }
}

fn window_row(index: Value, name: &str, panes: Value, active: bool, layout: &str) -> Value {
    json!({"index": index, "name": name, "panes": panes, "active": active, "layout": layout})
}

/// Default `tmux list-windows` lines, e.g. `0: bash* (2 panes) [80x24]`.
pub fn parse_tmux_windows_plain(stdout: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in lines(stdout) {
        if is_tmux_diagnostic_line(line) {
            continue;
        }
        if let Some(m) = WINDOW_WITH_PANES.captures(line) {
            out.push(window_row(
                js::num_json(js::number(&m[1])),
                m[2].trim(),
                js::num_or_zero(&m[4]),
                m.get(3).is_some(),
                "",
            ));
            continue;
        }
        if let Some(m) = WINDOW_BARE.captures(line) {
            out.push(window_row(
                js::num_json(js::number(&m[1])),
                m[2].trim(),
                json!(0),
                m.get(3).is_some(),
                "",
            ));
        }
    }
    out
}

/// `-F` window rows, falling back to the default layout.
pub fn parse_tmux_windows(stdout: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in lines(stdout) {
        if is_tmux_diagnostic_line(line) {
            continue;
        }
        let parts = split_tmux_fields(line);
        if parts.len() < 4 {
            continue;
        }
        out.push(window_row(
            js::num_json(js::number(&parts[0])),
            &parts[1],
            js::num_or_zero(&parts[2]),
            parts[3] == "1",
            parts.get(4).map(String::as_str).unwrap_or(""),
        ));
    }
    if out.is_empty() {
        parse_tmux_windows_plain(stdout)
    } else {
        out
    }
}

/// `list-windows -a -F` rows (session name first).
pub fn parse_tmux_windows_all(stdout: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in lines(stdout) {
        if is_tmux_diagnostic_line(line) {
            continue;
        }
        let parts = split_tmux_fields(line);
        if parts.len() < 5 {
            continue;
        }
        out.push(json!({
            "session": parts[0].trim(),
            "index": js::num_json(js::number(&parts[1])),
            "name": parts[2],
            "panes": js::num_or_zero(&parts[3]),
            "active": parts[4] == "1",
            "layout": parts.get(5).map(String::as_str).unwrap_or(""),
        }));
    }
    out
}

/// Plain `tmux list-windows -a` lines, e.g. `test-session: 0: bash* (2 panes)`.
pub fn parse_tmux_windows_all_plain(stdout: &str, session_name: &str) -> Vec<Value> {
    let name = session_name.trim();
    let mut out = Vec::new();
    for line in lines(stdout) {
        if is_tmux_diagnostic_line(line) {
            continue;
        }
        let Some(m) = WINDOW_ALL_PLAIN.captures(line) else {
            continue;
        };
        if m[1].trim() != name {
            continue;
        }
        if let Some(first) = parse_tmux_windows_plain(&format!("{}: {}", &m[2], &m[3]))
            .into_iter()
            .next()
        {
            out.push(first);
        }
    }
    out
}

/// Keep rows of `session_name` and drop their `session` key.
pub fn filter_windows_for_session(rows: Vec<Value>, session_name: &str) -> Vec<Value> {
    let name = session_name.trim();
    rows.into_iter()
        .filter(|row| row.get("session").and_then(Value::as_str) == Some(name))
        .map(|mut row| {
            if let Value::Object(map) = &mut row {
                map.remove("session");
            }
            row
        })
        .collect()
}

fn num_or(text: Option<&String>) -> Option<f64> {
    match text {
        Some(t) => js::number(t),
        None => None,
    }
}

fn nonzero(n: Option<f64>) -> Option<f64> {
    n.filter(|v| *v != 0.0 && !v.is_nan())
}

/// One `-F` pane row. Rows with extra fields (titles containing tabs) take
/// active / pid / size from the end.
pub fn parse_tmux_pane_row(parts: &[String]) -> Option<Value> {
    let len = parts.len();
    if len < 5 {
        return None;
    }
    let wide = len >= 7;
    let active = parts[3] == "1" || (wide && parts[len - 4] == "1");
    let pid = nonzero(js::number(&parts[4]))
        .or_else(|| {
            if wide {
                nonzero(js::number(&parts[len - 3]))
            } else {
                None
            }
        })
        .unwrap_or(0.0);
    let width = nonzero(num_or(parts.get(if wide { len - 2 } else { 5 }))).unwrap_or(0.0);
    let height = nonzero(num_or(parts.get(if wide { len - 1 } else { 6 }))).unwrap_or(0.0);
    let mut row = Map::new();
    row.insert("index".into(), js::num_json(js::number(&parts[0])));
    row.insert("title".into(), json!(parts[1]));
    row.insert("command".into(), json!(parts[2]));
    row.insert("active".into(), json!(active));
    row.insert("pid".into(), js::num_json(Some(pid)));
    row.insert("width".into(), js::num_json(Some(width)));
    row.insert("height".into(), js::num_json(Some(height)));
    Some(Value::Object(row))
}

/// Default `tmux list-panes` lines, e.g. `1: [80x24] (active)`.
pub fn parse_tmux_panes_plain(stdout: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in lines(stdout) {
        if is_tmux_diagnostic_line(line) {
            continue;
        }
        let Some(m) = PANE_PLAIN.captures(line) else {
            continue;
        };
        out.push(json!({
            "index": js::num_json(js::number(&m[1])),
            "title": "",
            "command": "",
            "active": ACTIVE.is_match(line) || line.contains('*'),
            "pid": 0,
            "width": js::num_or_zero(&m[2]),
            "height": js::num_or_zero(&m[3]),
        }));
    }
    out
}

/// `-F` pane rows, falling back to the default layout.
pub fn parse_tmux_panes(stdout: &str) -> Vec<Value> {
    let out: Vec<Value> = lines(stdout)
        .filter(|l| !is_tmux_diagnostic_line(l))
        .filter_map(|l| parse_tmux_pane_row(&split_tmux_fields(l)))
        .collect();
    if out.is_empty() {
        parse_tmux_panes_plain(stdout)
    } else {
        out
    }
}

/// `list-clients -F` rows, optionally limited to `session_name`.
pub fn parse_tmux_clients(stdout: &str, session_name: Option<&str>) -> Vec<Value> {
    lines(stdout)
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 4 {
                return None;
            }
            if let Some(name) = session_name.filter(|n| !n.is_empty()) {
                if parts[3] != name {
                    return None;
                }
            }
            Some(json!({"name": parts[0], "tty": parts[1], "activity": parts[2], "session": parts[3]}))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_server_message_matches_stale_socket_errors() {
        let stale = "error connecting to /tmp/tmux-0/default (No such file or directory)";
        assert!(is_no_tmux_server_message(stale, Some(1)));
        assert!(is_no_tmux_server_message(
            "no server running on /tmp/tmux-501/default",
            Some(1)
        ));
        assert!(!is_no_tmux_server_message(
            "test-session: 1 windows",
            Some(1)
        ));
        assert!(!is_no_tmux_server_message(stale, Some(0)));
    }

    #[test]
    fn windows_plain_default_output() {
        let windows = parse_tmux_windows_plain(
            "0: bash* (2 panes) [160x40] [b33d,1]\n1: zsh (1 pane) [160x40] [b33d,2]",
        );
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0]["name"], "bash");
        assert_eq!(windows[0]["panes"], 2);
        assert_eq!(windows[0]["active"], true);
        assert_eq!(windows[1]["name"], "zsh");
        assert_eq!(windows[1]["active"], false);
    }

    #[test]
    fn windows_fall_back_to_plain_when_tabs_missing() {
        let windows = parse_tmux_windows("0: main* (2 panes) [80x24]");
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0]["panes"], 2);
        assert_eq!(windows[0]["name"], "main");
        let windows = parse_tmux_windows("0\tmain\t2\t1\tlayout");
        assert_eq!(
            windows[0],
            json!({"index":0,"name":"main","panes":2,"active":true,"layout":"layout"})
        );
    }

    #[test]
    fn windows_all_plain_filters_by_session() {
        let windows = parse_tmux_windows_all_plain(
            "test-session: 0: bash* (2 panes) [80x24]\ntest-session: 1: zsh (1 pane) [80x24]\nother: 0: vim (1 pane) [80x24]",
            "test-session",
        );
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0]["name"], "bash");
        assert_eq!(windows[1]["index"], 1);
    }

    #[test]
    fn windows_all_formatted_filter() {
        let rows = parse_tmux_windows_all("demo\t0\tmain\t1\t1\tl\nother\t0\tx\t1\t0\tl");
        let filtered = filter_windows_for_session(rows, " demo ");
        assert_eq!(
            filtered,
            vec![json!({"index":0,"name":"main","panes":1,"active":true,"layout":"l"})]
        );
    }

    #[test]
    fn panes_split_literal_tab_when_printf_fails() {
        let panes = parse_tmux_panes("0\\tRainYun-0tWTeTRw\\tbash\\t\\t\\t2232702\\t80\\t24");
        assert_eq!(panes.len(), 1);
        assert_eq!(panes[0]["title"], "RainYun-0tWTeTRw");
        assert_eq!(panes[0]["command"], "bash");
        assert_eq!(panes[0]["pid"], 2232702);
        assert_eq!(panes[0]["width"], 80);
        assert_eq!(panes[0]["height"], 24);
        assert_eq!(panes[0]["active"], false);
    }

    #[test]
    fn panes_formatted_and_plain() {
        let panes = parse_tmux_panes("0\ttitle\tvim\t1\t42\t120\t40");
        assert_eq!(
            panes[0],
            json!({"index":0,"title":"title","command":"vim","active":true,"pid":42,"width":120,"height":40})
        );
        let panes = parse_tmux_panes_plain("0: [80x24]\n1: [80x24] (active)");
        assert_eq!(panes.len(), 2);
        assert_eq!(panes[0]["active"], false);
        assert_eq!(panes[1]["active"], true);
        assert_eq!(parse_tmux_panes("1: [100x30] (active)")[0]["width"], 100);
    }

    #[test]
    fn sessions_parsers() {
        let s = parse_tmux_sessions("a\t2\t0\t17\nbad\n");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0]["created"], 17);
        let s = parse_tmux_sessions_plain("dev: 3 windows (attached)\nnoise");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0]["attached"], true);
        assert_eq!(parse_tmux_session_names("a\n\nb\n").len(), 2);
    }

    #[test]
    fn clients_filter_by_session() {
        let out = "/dev/pts/1\t/dev/pts/1\t100\tdemo\n/dev/pts/2\t/dev/pts/2\t200\tother";
        assert_eq!(parse_tmux_clients(out, None).len(), 2);
        let only = parse_tmux_clients(out, Some("demo"));
        assert_eq!(
            only,
            vec![json!({"name":"/dev/pts/1","tty":"/dev/pts/1","activity":"100","session":"demo"})]
        );
    }
}
