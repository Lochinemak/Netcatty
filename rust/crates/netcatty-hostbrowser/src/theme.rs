//! Theme token validation (Electron: `validThemeTokens`). The renderer sends
//! its CSS HSL variables so the browser chrome can match the app theme; only
//! the known names with a `H S% L%` value are accepted.

use regex::Regex;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const THEME_TOKEN_NAMES: &[&str] = &[
    "background",
    "foreground",
    "secondary",
    "muted",
    "muted-foreground",
    "border",
    "primary",
    "primary-foreground",
];

fn hsl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*\d+(\.\d+)?\s+\d+(\.\d+)?%\s+\d+(\.\d+)?%\s*$").unwrap())
}

/// Keep the known tokens whose value is an HSL triple, trimmed.
pub fn valid_theme_tokens(input: Option<&Value>) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let Some(Value::Object(map)) = input else {
        return result;
    };
    for name in THEME_TOKEN_NAMES {
        if let Some(Value::String(value)) = map.get(*name) {
            if hsl_re().is_match(value) {
                result.insert((*name).to_string(), value.trim().to_string());
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keeps_only_known_hsl_tokens() {
        let tokens = valid_theme_tokens(Some(&json!({
            "background": " 216 33% 96% ",
            "foreground": "0 0% 100%",
            "primary": "red",
            "border": 12,
            "unknown": "1 2% 3%",
            "muted": "210.5 10.25% 50.75%"
        })));
        assert_eq!(tokens.get("background").map(String::as_str), Some("216 33% 96%"));
        assert_eq!(tokens.get("foreground").map(String::as_str), Some("0 0% 100%"));
        assert_eq!(tokens.get("muted").map(String::as_str), Some("210.5 10.25% 50.75%"));
        assert!(!tokens.contains_key("primary"));
        assert!(!tokens.contains_key("border"));
        assert!(!tokens.contains_key("unknown"));
        assert!(valid_theme_tokens(None).is_empty());
        assert!(valid_theme_tokens(Some(&json!("nope"))).is_empty());
    }
}
