//! `SSH_ASKPASS` helper used by EternalTerminal sessions.
//!
//! ET drives its own `ssh`, so saved passwords / passphrases are answered
//! through `SSH_ASKPASS`. Electron ships a Node script for that; here the
//! Netcatty executable itself is the helper: when started with
//! [`ASKPASS_MARKER_ENV`] and [`ASKPASS_MAP_ENV`] set it prints the matching
//! secret for the prompt in `argv[1..]` and exits (see `main.rs`). The
//! matching rules are a port of `pickEntry` in `etSession.cjs`.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Set (to `1`) in the environment of the helper invocation.
pub const ASKPASS_MARKER_ENV: &str = "NETCATTY_ASKPASS";
/// Path of the JSON entry map.
pub const ASKPASS_MAP_ENV: &str = "NETCATTY_ET_ASKPASS_MAP";

/// One secret the helper may hand out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    /// `password` | `passphrase`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Lower-case substrings identifying the prompt.
    pub matchers: Vec<String>,
    pub secret_file: String,
}

/// Serialise the entry map (`NETCATTY_ET_ASKPASS_MAP` file contents).
pub fn to_json(entries: &[Entry]) -> String {
    serde_json::to_string_pretty(entries).unwrap_or_else(|_| "[]".into()) + "\n"
}

/// Parse the entry map; malformed input yields no entries.
pub fn from_json(text: &str) -> Vec<Entry> {
    serde_json::from_str(text).unwrap_or_default()
}

fn second_factor_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"one[\s-]?time|\botp\b|verification|passcode|\btoken\b|2fa|two[\s-]?factor|multi[\s-]?factor|\bmfa\b|second\s+factor|secondary(?:\s+\w+){0,3}\s+passw|second(?:\s+\w+){0,3}\s+passw|additional(?:\s+\w+){0,3}\s+passw|re[-\s]?enter\s+passw|confirm\s+passw|\bedr\b|duo|动态|一次性|验证码|验证信息|令牌|双因素|多因素|短信验证|手机验证|二次|安全密码|挑战码")
            .expect("valid regex")
    })
}

fn password_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"passw(or)?d|密\s*码|口\s*令").expect("valid regex"))
}

fn match_score(entry: &Entry, prompt: &str) -> usize {
    entry
        .matchers
        .iter()
        .map(|m| m.to_lowercase())
        .filter(|m| !m.is_empty() && prompt.contains(m.as_str()))
        .map(|m| m.len())
        .max()
        .unwrap_or(0)
}

/// Choose the entry answering `prompt` (`pickEntry`). Second-factor prompts
/// are never answered with the saved password.
pub fn pick_entry<'a>(entries: &'a [Entry], prompt: &str) -> Option<&'a Entry> {
    let prompt = prompt.to_lowercase();
    let wants_passphrase = prompt.contains("passphrase");
    let matches_known_login_prompt = entries.iter().any(|e| {
        e.kind == "password"
            && e.matchers.iter().any(|m| {
                let m = m.to_lowercase();
                m.ends_with("'s password") && prompt.contains(&m)
            })
    });
    let wants_second_factor = !matches_known_login_prompt && second_factor_re().is_match(&prompt);
    let wants_password = !wants_second_factor && password_re().is_match(&prompt);
    if !wants_passphrase && !wants_password {
        return None;
    }
    let kind = if wants_passphrase {
        "passphrase"
    } else {
        "password"
    };
    let scoped: Vec<&Entry> = entries.iter().filter(|e| e.kind == kind).collect();
    let best = scoped
        .iter()
        .enumerate()
        .map(|(i, e)| (i, *e, match_score(e, &prompt)))
        .filter(|(_, _, score)| *score > 0)
        .max_by(|a, b| a.2.cmp(&b.2).then(b.0.cmp(&a.0)))
        .map(|(_, e, _)| e);
    if best.is_some() {
        return best;
    }
    if wants_password && scoped.len() == 1 {
        return Some(scoped[0]);
    }
    None
}

/// `createPasswordPromptMatchers`.
pub fn password_prompt_matchers(hostname: &str, username: Option<&str>, port: u16) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    let host = hostname.to_lowercase();
    if host.is_empty() {
        return values;
    }
    let mut add = |v: String| {
        if !values.contains(&v) {
            values.push(v);
        }
    };
    add(host.clone());
    if let Some(user) = username.filter(|u| !u.is_empty()) {
        let user = user.to_lowercase();
        add(format!("{user}@{host}"));
        add(format!("{user}@{host}'s password"));
        if port != 0 {
            add(format!("{user}@{host}:{port}"));
        }
    }
    values
}

/// `createPassphrasePromptMatchers`: the key path and its file name.
pub fn passphrase_prompt_matchers(key_path: &str) -> Vec<String> {
    let lower = key_path.replace('\\', "/").to_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower).to_string();
    let mut out = vec![lower];
    if !out.contains(&base) {
        out.push(base);
    }
    out
}

/// Helper entry point: the secret (with trailing newline) to print for the
/// prompt, read from the entry map file.
pub fn answer(map_path: &str, prompt: &str) -> Option<String> {
    let raw = std::fs::read_to_string(map_path).ok()?;
    let entries = from_json(&raw);
    let entry = pick_entry(&entries, prompt)?;
    let secret = std::fs::read_to_string(&entry.secret_file).ok()?;
    let secret = secret
        .strip_suffix("\r\n")
        .or_else(|| secret.strip_suffix('\n'))
        .unwrap_or(&secret);
    Some(format!("{secret}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: &str, matchers: &[&str], file: &str) -> Entry {
        Entry {
            kind: kind.into(),
            matchers: matchers.iter().map(|s| s.to_string()).collect(),
            secret_file: file.into(),
        }
    }

    #[test]
    fn json_round_trip() {
        let entries = vec![
            entry("password", &["alice@h's password", "h"], "/tmp/p \"x\".txt"),
            entry("passphrase", &[], "C:\\keys\\k.txt"),
        ];
        assert_eq!(from_json(&to_json(&entries)), entries);
        assert!(from_json("garbage").is_empty());
        assert!(from_json("[]").is_empty());
    }

    #[test]
    fn picks_password_and_passphrase() {
        let entries = vec![
            entry(
                "password",
                &password_prompt_matchers("Host.example", Some("Alice"), 22)
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                "/p1",
            ),
            entry(
                "password",
                &password_prompt_matchers("jump.example", Some("bob"), 22)
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                "/p2",
            ),
            entry(
                "passphrase",
                &passphrase_prompt_matchers("/tmp/s/sess-key")
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                "/k1",
            ),
        ];
        assert_eq!(
            pick_entry(&entries, "alice@host.example's password: ").map(|e| e.secret_file.as_str()),
            Some("/p1")
        );
        assert_eq!(
            pick_entry(&entries, "bob@jump.example's password: ").map(|e| e.secret_file.as_str()),
            Some("/p2")
        );
        assert_eq!(
            pick_entry(&entries, "Enter passphrase for key '/tmp/s/sess-key': ")
                .map(|e| e.secret_file.as_str()),
            Some("/k1")
        );
        // Ambiguous password prompt with two entries: no answer.
        assert!(pick_entry(&entries, "Password: ").is_none());
        // Second factor is never answered.
        assert!(pick_entry(&entries, "Verification code: ").is_none());
    }

    #[test]
    fn single_password_entry_answers_generic_prompt() {
        let entries = vec![entry("password", &["h"], "/p")];
        assert!(pick_entry(&entries, "Password: ").is_some());
        assert!(pick_entry(&entries, "密码：").is_some());
        assert!(pick_entry(&entries, "One-time password: ").is_none());
        assert!(pick_entry(&entries, "Are you sure (yes/no)?").is_none());
    }

    #[test]
    fn answer_reads_secret_file() {
        let dir = std::env::temp_dir().join(format!("nc-askpass-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("pw.txt");
        std::fs::write(&secret, "s3cret\n").unwrap();
        let map = dir.join("map.json");
        std::fs::write(
            &map,
            to_json(&[entry("password", &["h"], &secret.to_string_lossy())]),
        )
        .unwrap();
        assert_eq!(
            answer(&map.to_string_lossy(), "alice@h's password:").as_deref(),
            Some("s3cret\n")
        );
        assert!(answer(&map.to_string_lossy(), "Enter PIN:").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
