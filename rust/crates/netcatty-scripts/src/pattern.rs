//! Wait patterns of the script API (`screen.waitFor*`), compiled with the
//! ECMAScript regex engine (`regress`) so user scripts keep JavaScript
//! semantics. Port of the pattern helpers in
//! `electron/scripts/sessionOutputBuffer.cjs`.
//!
//! Offsets are byte offsets into the UTF-8 buffer text (Electron uses UTF-16
//! code units; every comparison is relative, so the semantics carry over).

use serde::{Deserialize, Serialize};
use std::fmt;

/// A pattern as the script passed it: a string, or a `RegExp` object
/// (`source` + `flags`) serialized by the script worker shim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WaitPattern {
    Text(String),
    Regex {
        #[serde(rename = "__nctRegExp")]
        marker: bool,
        source: String,
        #[serde(default)]
        flags: String,
    },
}

impl WaitPattern {
    pub fn text(value: impl Into<String>) -> Self {
        WaitPattern::Text(value.into())
    }

    pub fn regex(source: impl Into<String>, flags: impl Into<String>) -> Self {
        WaitPattern::Regex {
            marker: true,
            source: source.into(),
            flags: flags.into(),
        }
    }

    pub fn is_regex(&self) -> bool {
        matches!(self, WaitPattern::Regex { .. })
    }

    /// Label shown in run status (`pattern.source` for a RegExp,
    /// `String(pattern)` otherwise).
    pub fn label(&self) -> String {
        match self {
            WaitPattern::Text(text) => text.clone(),
            WaitPattern::Regex { source, .. } => source.clone(),
        }
    }

    /// Parse one script argument: strings stay strings, serialized RegExp
    /// markers become regexes, anything else is `None` (a TypeError for the
    /// caller to raise).
    pub fn from_json(value: &serde_json::Value) -> Option<WaitPattern> {
        match value {
            serde_json::Value::String(s) => Some(WaitPattern::Text(s.clone())),
            serde_json::Value::Object(map) => {
                if map.get("__nctRegExp") != Some(&serde_json::Value::Bool(true)) {
                    return None;
                }
                let source = map.get("source")?.as_str()?.to_string();
                let flags = map
                    .get("flags")
                    .and_then(|f| f.as_str())
                    .unwrap_or("")
                    .to_string();
                Some(WaitPattern::regex(source, flags))
            }
            _ => None,
        }
    }
}

/// Errors raised while compiling a pattern. Messages match the JavaScript
/// runtime's (`TypeError` / `SyntaxError` text).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    #[error("{0}")]
    Type(String),
    #[error("Invalid regular expression: /{pattern}/{flags}: {message}")]
    Syntax {
        pattern: String,
        flags: String,
        message: String,
    },
}

/// A compiled ECMAScript regular expression.
#[derive(Clone)]
pub struct JsRegex {
    regex: std::sync::Arc<regress::Regex>,
    pub source: String,
    pub flags: String,
}

impl fmt::Debug for JsRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}/{}", self.source, self.flags)
    }
}

impl JsRegex {
    pub fn new(source: &str, flags: &str) -> Result<Self, PatternError> {
        // `g` / `y` / `d` do not change matching here (`exec` always starts at 0).
        let engine_flags: String = flags
            .chars()
            .filter(|c| matches!(c, 'i' | 'm' | 's' | 'u' | 'v'))
            .collect();
        let regex = regress::Regex::with_flags(source, engine_flags.as_str()).map_err(|err| {
            PatternError::Syntax {
                pattern: source.to_string(),
                flags: flags.to_string(),
                message: err.to_string(),
            }
        })?;
        Ok(Self {
            regex: std::sync::Arc::new(regex),
            source: source.to_string(),
            flags: flags.to_string(),
        })
    }

    /// First match in `text` as a byte range (`RegExp.prototype.exec` with
    /// `lastIndex = 0`).
    pub fn exec(&self, text: &str) -> Option<(usize, usize)> {
        self.regex.find(text).map(|m| (m.start(), m.end()))
    }

    /// Every match in `text` in order (the `g` flag loop, advancing past
    /// zero-length matches).
    pub fn exec_all(&self, text: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos <= text.len() {
            let Some(m) = self.regex.find_from(text, pos).next() else {
                break;
            };
            out.push((m.start(), m.end()));
            pos = if m.end() > m.start() {
                m.end()
            } else {
                next_char_boundary(text, m.end() + 1)
            };
        }
        out
    }
}

/// Smallest char boundary `>= index` (clamped to `text.len()`).
pub fn next_char_boundary(text: &str, index: usize) -> usize {
    let mut i = index.min(text.len());
    while i < text.len() && !text.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Largest char boundary `<= index` (clamped to `text.len()`).
pub fn prev_char_boundary(text: &str, index: usize) -> usize {
    let mut i = index.min(text.len());
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// `escapeRegExp`: quote every regex metacharacter.
pub fn escape_regexp(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        if ".*+?^${}()|[]\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `/^\/(.+)\/([gimsuy]*)$/` — a slash-delimited regex literal in a string.
fn slash_regex_parts(pattern: &str) -> Option<(&str, &str)> {
    let rest = pattern.strip_prefix('/')?;
    // Flags are the trailing [gimsuy]* after the last `/`; the body must be
    // non-empty (`.+`), and `.` does not match newlines in the JS regex.
    let last_slash = rest.rfind('/')?;
    let (body, flags) = (&rest[..last_slash], &rest[last_slash + 1..]);
    if body.is_empty() || body.contains('\n') || body.contains('\r') {
        return None;
    }
    if !flags.chars().all(|c| "gimsuy".contains(c)) {
        return None;
    }
    Some((body, flags))
}

/// `compilePattern`: RegExp as-is; `"/body/flags"` strings become regexes;
/// any other string is matched literally.
pub fn compile_pattern(pattern: &WaitPattern) -> Result<JsRegex, PatternError> {
    match pattern {
        WaitPattern::Regex { source, flags, .. } => JsRegex::new(source, flags),
        WaitPattern::Text(text) => match slash_regex_parts(text) {
            Some((body, flags)) => JsRegex::new(body, flags),
            None => JsRegex::new(&escape_regexp(text), ""),
        },
    }
}

/// `compileTextPattern`: strings only, always literal.
pub fn compile_text_pattern(pattern: &WaitPattern) -> Result<JsRegex, PatternError> {
    match pattern {
        WaitPattern::Text(text) => JsRegex::new(&escape_regexp(text), ""),
        WaitPattern::Regex { .. } => Err(PatternError::Type(
            "waitForText pattern must be a string".into(),
        )),
    }
}

/// `compileRegexPattern`: RegExp as-is; strings are regex sources with the
/// `s` flag added (slash form keeps its flags, plus `s`).
pub fn compile_regex_pattern(pattern: &WaitPattern) -> Result<JsRegex, PatternError> {
    match pattern {
        WaitPattern::Regex { source, flags, .. } => JsRegex::new(source, flags),
        WaitPattern::Text(text) => match slash_regex_parts(text) {
            Some((body, flags)) => {
                let flags = if flags.contains('s') {
                    flags.to_string()
                } else {
                    format!("{flags}s")
                };
                JsRegex::new(body, &flags)
            }
            None => JsRegex::new(text, "s"),
        },
    }
}

fn has_unescaped_char_at(source: &[u8], index: usize, ch: u8) -> bool {
    if index >= source.len() || source[index] != ch {
        return false;
    }
    let mut backslashes = 0;
    let mut cursor = index;
    while cursor > 0 && source[cursor - 1] == b'\\' {
        backslashes += 1;
        cursor -= 1;
    }
    backslashes % 2 == 0
}

fn edge_dot_repeat_token_length_at(source: &[u8], index: usize) -> usize {
    if index >= source.len() || source[index] != b'.' {
        return 0;
    }
    let quantifier = source.get(index + 1).copied();
    if quantifier != Some(b'*') && quantifier != Some(b'+') {
        return 0;
    }
    if !has_unescaped_char_at(source, index, b'.') {
        return 0;
    }
    if source.get(index + 2).copied() == Some(b'?') {
        3
    } else {
        2
    }
}

/// `stripEdgeDotRepeats`: drop leading `^`, trailing `$` and the `.*` /
/// `.+` / `.*?` / `.+?` wildcards at either edge of a regex source.
pub fn strip_edge_dot_repeats(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut start = 0;
    let mut end = bytes.len();
    if has_unescaped_char_at(bytes, start, b'^') {
        start += 1;
    }
    if end > start && has_unescaped_char_at(bytes, end - 1, b'$') {
        end -= 1;
    }
    while start < end {
        let token = edge_dot_repeat_token_length_at(bytes, start);
        if token == 0 {
            break;
        }
        start += token;
    }
    while end >= start + 2 {
        if end >= 3 && edge_dot_repeat_token_length_at(bytes, end - 3) == 3 {
            end -= 3;
            continue;
        }
        if edge_dot_repeat_token_length_at(bytes, end - 2) != 2 {
            break;
        }
        end -= 2;
    }
    // Token boundaries are ASCII, so the slice is on char boundaries.
    source[start..end].to_string()
}

/// `compileRegexFreshnessPattern`: the regex without its edge wildcards, used
/// to locate the "core" of a match for stale-output protection. `None` when
/// the source has no edge wildcards (or the stripped source is invalid).
pub fn compile_regex_freshness_pattern(pattern: &WaitPattern) -> Option<JsRegex> {
    let regex = compile_regex_pattern(pattern).ok()?;
    let stripped = strip_edge_dot_repeats(&regex.source);
    if stripped.is_empty() || stripped == regex.source {
        return None;
    }
    let flags: String = regex.flags.chars().filter(|c| *c != 'y').collect();
    let flags = if flags.contains('g') {
        flags
    } else {
        format!("{flags}g")
    };
    JsRegex::new(&stripped, &flags).ok()
}

/// A match with its byte range in the text it was searched in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchEnd {
    pub value: String,
    pub end_offset: usize,
}

/// `tryMatchWithEnd`.
pub fn try_match_with_end(
    text: &str,
    pattern: &WaitPattern,
    compiler: fn(&WaitPattern) -> Result<JsRegex, PatternError>,
) -> Result<Option<MatchEnd>, PatternError> {
    let regex = compiler(pattern)?;
    Ok(regex.exec(text).map(|(start, end)| MatchEnd {
        value: text[start..end].to_string(),
        end_offset: end,
    }))
}

/// `tryMatch`: the matched text of `compilePattern(pattern)` in `text`.
pub fn try_match(text: &str, pattern: &WaitPattern) -> Result<Option<String>, PatternError> {
    Ok(try_match_with_end(text, pattern, compile_pattern)?.map(|m| m.value))
}

/// A regex match annotated with the fresh "core" range (edge wildcards
/// excluded) for stale-output protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexMatch {
    pub value: String,
    pub start_offset: usize,
    pub end_offset: usize,
    pub fresh_start_offset: usize,
    pub fresh_end_offset: usize,
}

/// `tryRegexMatchWithEnd`.
pub fn try_regex_match_with_end(
    text: &str,
    pattern: &WaitPattern,
) -> Result<Option<RegexMatch>, PatternError> {
    let regex = compile_regex_pattern(pattern)?;
    let Some((start, end)) = regex.exec(text) else {
        return Ok(None);
    };
    let value = &text[start..end];
    let mut fresh_start = start;
    let mut fresh_end = end;
    if let Some(freshness) = compile_regex_freshness_pattern(pattern) {
        let mut latest_start: Option<usize> = None;
        let mut latest_end: Option<usize> = None;
        for (s, e) in freshness.exec_all(value) {
            if latest_end.is_none_or(|latest| e >= latest) {
                latest_start = Some(s);
            }
            latest_end = Some(latest_end.map_or(e, |latest| latest.max(e)));
        }
        if let (Some(s), Some(e)) = (latest_start, latest_end) {
            fresh_start = start + s;
            fresh_end = start + e;
        }
    }
    Ok(Some(RegexMatch {
        value: value.to_string(),
        start_offset: start,
        end_offset: end,
        fresh_start_offset: fresh_start,
        fresh_end_offset: fresh_end,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_match_finds_substring_patterns() {
        assert_eq!(
            try_match("hello world", &WaitPattern::text("world")).unwrap(),
            Some("world".to_string())
        );
    }

    #[test]
    fn try_match_supports_slash_delimited_regex_patterns() {
        assert_eq!(
            try_match("user@host:~$ ", &WaitPattern::text("/\\$\\s*$/")).unwrap(),
            Some("$ ".to_string())
        );
    }

    #[test]
    fn try_match_keeps_wildcard_looking_strings_literal() {
        assert_eq!(
            try_match("ready", &WaitPattern::text("rea.y")).unwrap(),
            None
        );
        assert_eq!(
            try_match("rea.y", &WaitPattern::text("rea.y")).unwrap(),
            Some("rea.y".to_string())
        );
    }

    #[test]
    fn try_match_accepts_regexp_objects() {
        assert_eq!(
            try_match("ok READY", &WaitPattern::regex("READY$", "")).unwrap(),
            Some("READY".to_string())
        );
    }

    #[test]
    fn invalid_regex_reports_syntax_error() {
        let err = compile_pattern(&WaitPattern::text("/[abc/")).unwrap_err();
        assert!(matches!(err, PatternError::Syntax { .. }));
        // Not a slash literal: matched literally.
        assert!(compile_pattern(&WaitPattern::text("[abc")).is_ok());
    }

    #[test]
    fn strips_edge_dot_repeats() {
        assert_eq!(strip_edge_dot_repeats(".*READY.*"), "READY");
        assert_eq!(strip_edge_dot_repeats("^.*?READY.+?$"), "READY");
        assert_eq!(strip_edge_dot_repeats(".+READY.+"), "READY");
        assert_eq!(strip_edge_dot_repeats("READY"), "READY");
        assert_eq!(strip_edge_dot_repeats("\\.*READY"), "\\.*READY");
    }

    #[test]
    fn freshness_pattern_only_for_edge_wildcards() {
        assert!(compile_regex_freshness_pattern(&WaitPattern::text("READY")).is_none());
        let fresh = compile_regex_freshness_pattern(&WaitPattern::text(".*READY.*")).unwrap();
        assert_eq!(fresh.source, "READY");
        assert!(fresh.flags.contains('g'));
    }

    #[test]
    fn regex_match_reports_fresh_core() {
        let m = try_regex_match_with_end("old READY\nfoo READY tail", &WaitPattern::text(".*READY.*"))
            .unwrap()
            .unwrap();
        // The `s` flag makes `.*` span lines: the whole text matches and the
        // latest `READY` is the fresh core.
        assert_eq!(m.start_offset, 0);
        assert_eq!(m.value, "old READY\nfoo READY tail");
        assert_eq!(&m.value[m.fresh_start_offset..m.fresh_end_offset], "READY");
        assert_eq!(m.fresh_start_offset, 14);
    }

    #[test]
    fn exec_all_handles_zero_length_matches() {
        let regex = JsRegex::new("", "g").unwrap();
        assert_eq!(regex.exec_all("ab").len(), 3);
    }

    #[test]
    fn multibyte_text_is_safe() {
        let regex = JsRegex::new("é+", "g").unwrap();
        assert_eq!(regex.exec_all("aééb").len(), 1);
        assert_eq!(next_char_boundary("aé", 2), 3);
        assert_eq!(prev_char_boundary("aé", 2), 1);
    }
}
