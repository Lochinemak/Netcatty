//! Permission grant matching (Electron `electron/shared/permissionGrants.cjs`).
//!
//! A grant approves a capability (optionally for one saved host, one
//! command pattern and argument patterns). Command grants apply only when
//! *every* executable segment of the shell command matches, so a grant for
//! `ls *` cannot approve `ls; rm -rf /` (comments, here-doc bodies,
//! background `&`, `cd` with expansions and arithmetic are handled).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PermissionGrant {
    pub id: String,
    pub capability_id: String,
    pub session_pattern: String,
    pub created_at: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_pattern: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Context of a permission check.
#[derive(Debug, Clone, Default)]
pub struct GrantContext<'a> {
    pub capability_id: &'a str,
    pub chat_session_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub host_id: Option<&'a str>,
    pub args: Option<&'a Map<String, Value>>,
}

fn js_regex(body: &str, flags: &str) -> Option<fancy_regex::Regex> {
    let mut prefix = String::new();
    if flags.contains('i') {
        prefix.push_str("(?i)");
    }
    if flags.contains('s') {
        prefix.push_str("(?s)");
    }
    if flags.contains('m') {
        prefix.push_str("(?m)");
    }
    fancy_regex::Regex::new(&format!("{prefix}{body}")).ok()
}

fn glob_or_regex_match(pattern: &str, value: &str) -> bool {
    if pattern.starts_with('/') {
        if let Some(last) = pattern.rfind('/').filter(|i| *i > 0) {
            let body = &pattern[1..last];
            let flags = &pattern[last + 1..];
            return js_regex(body, flags).is_some_and(|re| re.is_match(value).unwrap_or(false));
        }
    }
    if !pattern.contains('*') && !pattern.contains('?') {
        return value == pattern;
    }
    let mut escaped = String::new();
    for c in pattern.chars() {
        match c {
            '*' => escaped.push_str(".*"),
            '?' => escaped.push('.'),
            '.' | '+' | '^' | '$' | '{' | '}' | '(' | ')' | '|' | '[' | ']' | '\\' => {
                escaped.push('\\');
                escaped.push(c);
            }
            c => escaped.push(c),
        }
    }
    if let Some(stripped) = escaped.strip_suffix(" .*") {
        escaped = format!("{stripped}( .*)?");
    }
    regex::Regex::new(&format!("(?s)^{escaped}$")).is_ok_and(|re| re.is_match(value))
}

pub fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    if let Some(host) = pattern.strip_prefix("host:") {
        return glob_or_regex_match(host, value);
    }
    glob_or_regex_match(pattern, value)
}

fn value_to_js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

fn args_pattern_matches(args_pattern: Option<&Map<String, Value>>, args: Option<&Map<String, Value>>) -> bool {
    let Some(pattern) = args_pattern else {
        return true;
    };
    let Some(args) = args else {
        return false;
    };
    for (key, p) in pattern {
        let Some(value) = args.get(key) else {
            return false;
        };
        if !pattern_matches(&value_to_js_string(p), &value_to_js_string(value)) {
            return false;
        }
    }
    true
}

fn rule_matches_target(rule: &PermissionGrant, ctx: &GrantContext<'_>) -> bool {
    if let Some(host_id) = rule.session_pattern.strip_prefix("host:") {
        let opens_this_host = ctx.capability_id == "vault.host.open"
            && ctx.args.and_then(|a| a.get("hostId")).and_then(Value::as_str) == Some(host_id);
        return !host_id.is_empty()
            && ctx.host_id == Some(host_id)
            && (ctx.session_id.is_some_and(|s| !s.is_empty()) || opens_this_host);
    }
    rule.capability_id != "*" && rule.session_pattern != "host:"
}

fn rule_matches_capability(rule: &PermissionGrant, ctx: &GrantContext<'_>) -> bool {
    (rule.capability_id == ctx.capability_id || rule.capability_id == "*") && rule_matches_target(rule, ctx)
}

const CWD_COMMANDS: [&str; 6] = ["cd", "chdir", "popd", "pushd", "push-location", "set-location"];

fn unquote_shell_token(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() >= 2 {
        let (first, last) = (chars[0], chars[chars.len() - 1]);
        if (first == '"' || first == '\'') && first == last {
            return chars[1..chars.len() - 1].iter().collect();
        }
    }
    token.to_string()
}

fn tokenize_shell_command(command: &str) -> Vec<String> {
    let re = regex::Regex::new(r#"(?:[^\s"']+|"[^"]*"|'[^']*')+"#).unwrap();
    re.find_iter(command).map(|m| unquote_shell_token(m.as_str())).collect()
}

fn last_non_whitespace_char(value: &[char]) -> Option<char> {
    value.iter().rev().find(|c| !c.is_whitespace()).copied()
}

fn read_arithmetic_expansion_end(seg: &[char], start: usize) -> Option<usize> {
    if seg.get(start) != Some(&'$') || seg.get(start + 1) != Some(&'(') || seg.get(start + 2) != Some(&'(') {
        return None;
    }
    let mut depth = 1;
    let mut quote: Option<char> = None;
    let mut i = start + 3;
    while i < seg.len() {
        let c = seg[i];
        let next = seg.get(i + 1).copied();
        if let Some(q) = quote {
            if c == '\\' && q != '\'' && next.is_some() {
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if c == '\\' && next.is_some() {
            i += 2;
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            quote = Some(c);
            i += 1;
            continue;
        }
        if c == '(' {
            depth += 1;
            i += 1;
            continue;
        }
        if c == ')' {
            if depth == 1 && next == Some(')') {
                return Some(i + 2);
            }
            if depth > 1 {
                depth -= 1;
            }
        }
        i += 1;
    }
    Some(seg.len())
}

fn has_executable_shell_expansion(segment: &str) -> bool {
    let seg: Vec<char> = segment.chars().collect();
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < seg.len() {
        let c = seg[i];
        let next = seg.get(i + 1).copied();
        if let Some(q) = quote {
            if c == '\\' && q == '"' && next.is_some() {
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
                i += 1;
                continue;
            }
            if q == '"' && c == '$' && next == Some('(') {
                return true;
            }
            if q == '"' && c == '`' {
                return true;
            }
            i += 1;
            continue;
        }
        if c == '\\' && next.is_some() {
            i += 2;
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            i += 1;
            continue;
        }
        if c == '`' {
            return true;
        }
        if c == '$' && next == Some('(') {
            return true;
        }
        if (c == '<' || c == '>') && next == Some('(') {
            return true;
        }
        i += 1;
    }
    false
}

fn read_escape_digits(v: &[char], start: usize, max_len: usize, radix: u32) -> Option<(String, usize)> {
    let mut end = start;
    while end < v.len() && end < start + max_len && v[end].is_digit(radix) {
        end += 1;
    }
    if end == start {
        return None;
    }
    Some((v[start..end].iter().collect(), end - 1))
}

fn code_point(n: u32) -> String {
    char::from_u32(n).map(String::from).unwrap_or_default()
}

/// `(text, end_index)` of an ANSI-C escape at `backslash`.
fn read_ansi_c_escape(v: &[char], backslash: usize) -> (String, usize) {
    let ei = backslash + 1;
    let Some(&c) = v.get(ei) else {
        return ("\\".into(), backslash);
    };
    let simple = match c {
        'a' => Some("\x07"),
        'b' => Some("\x08"),
        'e' | 'E' => Some("\x1b"),
        'f' => Some("\x0c"),
        'n' => Some("\n"),
        'r' => Some("\r"),
        't' => Some("\t"),
        'v' => Some("\x0b"),
        '\\' => Some("\\"),
        '\'' => Some("'"),
        '"' => Some("\""),
        '?' => Some("?"),
        _ => None,
    };
    if let Some(s) = simple {
        return (s.into(), ei);
    }
    if c == 'x' {
        return match read_escape_digits(v, ei + 1, 2, 16) {
            None => ("\\x".into(), ei),
            Some((d, end)) => (code_point(u32::from_str_radix(&d, 16).unwrap_or(0)), end),
        };
    }
    if c == 'u' || c == 'U' {
        let max = if c == 'u' { 4 } else { 8 };
        return match read_escape_digits(v, ei + 1, max, 16) {
            None => (format!("\\{c}"), ei),
            Some((d, end)) => (code_point(u32::from_str_radix(&d, 16).unwrap_or(0)), end),
        };
    }
    if c.is_digit(8) {
        let (d, end) = read_escape_digits(v, ei, 3, 8).unwrap();
        return (code_point(u32::from_str_radix(&d, 8).unwrap_or(0)), end);
    }
    (format!("\\{c}"), ei)
}

fn read_here_doc_delimiter_word(seg: &[char], start: usize) -> Option<(String, usize)> {
    let mut i = start;
    while i < seg.len() && seg[i].is_whitespace() {
        i += 1;
    }
    let mut text = String::new();
    let mut quote: Option<char> = None;
    let mut ansi = false;
    while i < seg.len() {
        let c = seg[i];
        let next = seg.get(i + 1).copied();
        if let Some(q) = quote {
            if ansi && c == '\\' {
                let (t, end) = read_ansi_c_escape(seg, i);
                text.push_str(&t);
                i = end + 1;
                continue;
            }
            if let (true, Some(n)) = (c == '\\' && q != '\'', next) {
                text.push(n);
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
                ansi = false;
                i += 1;
                continue;
            }
            text.push(c);
            i += 1;
            continue;
        }
        if c.is_whitespace() || c == ';' || c == '|' || c == '&' {
            break;
        }
        if let (true, Some(n)) = (c == '\\', next) {
            text.push(n);
            i += 2;
            continue;
        }
        if c == '$' && (next == Some('\'') || next == Some('"')) {
            quote = next;
            ansi = next == Some('\'');
            i += 2;
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            quote = Some(c);
            ansi = false;
            i += 1;
            continue;
        }
        text.push(c);
        i += 1;
    }
    if text.is_empty() {
        None
    } else {
        Some((text, i))
    }
}

struct Terminator {
    text: String,
    strip_leading_tabs: bool,
}

fn extract_here_doc_terminators(segment: &[char]) -> Vec<Terminator> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < segment.len() {
        let c = segment[i];
        let next = segment.get(i + 1).copied();
        if let Some(q) = quote {
            if c == '\\' && q != '\'' && next.is_some() {
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if let Some(end) = read_arithmetic_expansion_end(segment, i) {
            i = end;
            continue;
        }
        if c == '\\' && next.is_some() {
            i += 2;
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            quote = Some(c);
            i += 1;
            continue;
        }
        if c != '<' || next != Some('<') {
            i += 1;
            continue;
        }
        if segment.get(i + 2) == Some(&'<') {
            i += 3;
            continue;
        }
        let strip = segment.get(i + 2) == Some(&'-');
        let start = i + if strip { 3 } else { 2 };
        match read_here_doc_delimiter_word(segment, start) {
            None => i += 1,
            Some((text, end)) => {
                out.push(Terminator { text, strip_leading_tabs: strip });
                i = end;
            }
        }
    }
    out
}

fn skip_here_doc_bodies(command: &[char], start: usize, terminators: &[Terminator]) -> usize {
    let mut cursor = start;
    for t in terminators {
        while cursor < command.len() {
            let line_end = command[cursor..].iter().position(|c| *c == '\n').map(|p| cursor + p);
            let end = line_end.unwrap_or(command.len());
            let raw: String = command[cursor..end].iter().collect();
            let line = if t.strip_leading_tabs { raw.trim_start_matches('\t').to_string() } else { raw };
            cursor = line_end.map(|e| e + 1).unwrap_or(command.len());
            if line == t.text {
                break;
            }
        }
    }
    cursor
}

/// Executable segments of a shell command (`;`, `&&`, `||`, `|`, `&`,
/// newlines; comments and here-doc bodies dropped).
pub fn split_shell_command_segments(command: &str) -> Vec<String> {
    let cmd: Vec<char> = command.chars().collect();
    let mut segments: Vec<String> = Vec::new();
    let mut current: Vec<char> = Vec::new();
    let mut quote: Option<char> = None;
    let mut in_comment = false;
    let mut line_terminators: Vec<Terminator> = Vec::new();

    fn flush(current: &mut Vec<char>, segments: &mut Vec<String>) {
        let s: String = current.iter().collect();
        let t = s.trim();
        if !t.is_empty() {
            segments.push(t.to_string());
        }
        current.clear();
    }
    let flush_cmd = |current: &mut Vec<char>, segments: &mut Vec<String>, terms: &mut Vec<Terminator>| {
        terms.extend(extract_here_doc_terminators(current));
        flush(current, segments);
    };

    let mut i = 0;
    while i < cmd.len() {
        let c = cmd[i];
        let next = cmd.get(i + 1).copied();
        if in_comment {
            if c == '\n' {
                in_comment = false;
                flush_cmd(&mut current, &mut segments, &mut line_terminators);
                let terms = std::mem::take(&mut line_terminators);
                i = skip_here_doc_bodies(&cmd, i + 1, &terms);
                continue;
            }
            i += 1;
            continue;
        }
        if let Some(q) = quote {
            current.push(c);
            if let (true, Some(n)) = (c == '\\' && q != '\'', next) {
                current.push(n);
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if c == '\\' && next == Some('\n') {
            i += 2;
            continue;
        }
        if let (true, Some(n)) = (c == '\\', next) {
            current.push(c);
            current.push(n);
            i += 2;
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            quote = Some(c);
            current.push(c);
            i += 1;
            continue;
        }
        if let Some(end) = read_arithmetic_expansion_end(&cmd, i) {
            current.extend_from_slice(&cmd[i..end]);
            i = end;
            continue;
        }
        if c == '#' {
            let prev = current.last().copied();
            if prev.is_none_or(char::is_whitespace) {
                in_comment = true;
                i += 1;
                continue;
            }
        }
        if c == '\n' {
            flush_cmd(&mut current, &mut segments, &mut line_terminators);
            let terms = std::mem::take(&mut line_terminators);
            i = skip_here_doc_bodies(&cmd, i + 1, &terms);
            continue;
        }
        if c == ';' {
            flush_cmd(&mut current, &mut segments, &mut line_terminators);
            i += 1;
            continue;
        }
        if c == '&' && next == Some('&') {
            flush_cmd(&mut current, &mut segments, &mut line_terminators);
            i += 2;
            continue;
        }
        if c == '|' && next == Some('|') {
            flush_cmd(&mut current, &mut segments, &mut line_terminators);
            i += 2;
            continue;
        }
        if c == '&' {
            let prev = last_non_whitespace_char(&current);
            if next == Some('>') || prev == Some('>') || prev == Some('<') {
                current.push(c);
                i += 1;
                continue;
            }
            flush_cmd(&mut current, &mut segments, &mut line_terminators);
            i += 1;
            continue;
        }
        if c == '|' {
            flush_cmd(&mut current, &mut segments, &mut line_terminators);
            i += if next == Some('&') { 2 } else { 1 };
            continue;
        }
        current.push(c);
        i += 1;
    }
    flush(&mut current, &mut segments);
    segments
}

fn extract_grantable_segments(command: &str) -> Vec<String> {
    split_shell_command_segments(command)
        .into_iter()
        .filter(|seg| {
            let tokens = tokenize_shell_command(seg);
            let cmd = tokens.first().map(|t| t.to_lowercase());
            !tokens.is_empty()
                && !(cmd.as_deref().is_some_and(|c| CWD_COMMANDS.contains(&c)) && !has_executable_shell_expansion(seg))
        })
        .collect()
}

fn match_command_pattern_grants<'a>(
    rules: &'a [PermissionGrant],
    ctx: &GrantContext<'_>,
    command: &str,
) -> Option<&'a PermissionGrant> {
    let segments = extract_grantable_segments(command);
    if segments.is_empty() {
        return None;
    }
    let eligible: Vec<&PermissionGrant> = rules
        .iter()
        .filter(|r| rule_matches_capability(r, ctx) && r.command_pattern.is_some() && args_pattern_matches(r.args_pattern.as_ref(), ctx.args))
        .collect();
    if eligible.is_empty() {
        return None;
    }
    let mut first = None;
    for seg in &segments {
        let matched = eligible
            .iter()
            .find(|r| pattern_matches(r.command_pattern.as_deref().unwrap_or(""), seg))?;
        if first.is_none() {
            first = Some(*matched);
        }
    }
    first
}

/// The first grant approving `ctx`, if any.
pub fn match_permission_grant<'a>(rules: &'a [PermissionGrant], ctx: &GrantContext<'_>) -> Option<&'a PermissionGrant> {
    if rules.is_empty() {
        return None;
    }
    let command = ctx.args.and_then(|a| a.get("command")).and_then(Value::as_str).unwrap_or("");
    if !command.is_empty() {
        if let Some(rule) = match_command_pattern_grants(rules, ctx, command) {
            return Some(rule);
        }
    }
    rules.iter().find(|rule| {
        rule_matches_capability(rule, ctx) && rule.command_pattern.is_none() && args_pattern_matches(rule.args_pattern.as_ref(), ctx.args)
    })
}

/// Normalise grants synced from the renderer.
pub fn sanitize_permission_grants(raw: &Value, now_ms: f64) -> Vec<PermissionGrant> {
    let Some(entries) = raw.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let capability_id = obj.get("capabilityId").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if capability_id.is_empty() {
            continue;
        }
        let id = obj
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.chars().take(64).collect())
            .unwrap_or_else(|| format!("grant_{}_{index}", now_ms as i64));
        let session_pattern = obj
            .get("sessionPattern")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("*")
            .to_string();
        let created_at = obj.get("createdAt").and_then(Value::as_f64).filter(|v| v.is_finite()).unwrap_or(now_ms);
        let command_pattern = obj
            .get("commandPattern")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let args_pattern = obj.get("argsPattern").and_then(Value::as_object).and_then(|m| {
            let filtered: Map<String, Value> = m
                .iter()
                .filter_map(|(k, v)| v.as_str().map(str::trim).filter(|s| !s.is_empty()).map(|s| (k.clone(), Value::String(s.into()))))
                .collect();
            (!filtered.is_empty()).then_some(filtered)
        });
        let note = obj
            .get("note")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.chars().take(240).collect());
        out.push(PermissionGrant { id, capability_id, session_pattern, created_at, command_pattern, args_pattern, note });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn grant(cap: &str, pattern: Option<&str>) -> PermissionGrant {
        PermissionGrant {
            id: "g1".into(),
            capability_id: cap.into(),
            session_pattern: "*".into(),
            created_at: 0.0,
            command_pattern: pattern.map(str::to_string),
            args_pattern: None,
            note: None,
        }
    }

    fn check(rules: &[PermissionGrant], command: &str) -> bool {
        let args = json!({ "command": command });
        let ctx = GrantContext { capability_id: "terminal.execute", args: args.as_object(), ..Default::default() };
        match_permission_grant(rules, &ctx).is_some()
    }

    #[test]
    fn wildcard_semantics() {
        assert!(pattern_matches("ls *", "ls"));
        assert!(pattern_matches("ls *", "ls -la"));
        assert!(!pattern_matches("ls *", "lsof"));
        assert!(pattern_matches("/^git (status|log)$/", "git log"));
        assert!(pattern_matches("*", "anything"));
        assert!(!pattern_matches("", "x"));
    }

    #[test]
    fn command_grants_require_every_segment() {
        let rules = vec![grant("terminal.execute", Some("ls *"))];
        assert!(check(&rules, "ls -la"));
        assert!(check(&rules, "cd /tmp && ls"));
        assert!(!check(&rules, "ls; rm -rf /"));
        assert!(!check(&rules, "ls # comment\nrm -rf /"));
        assert!(!check(&rules, "ls & rm x"));
        assert!(!check(&rules, "cd $(rm -rf /) && ls"));
        assert!(check(&rules, "ls 2>&1"));
        assert!(!check(&rules, "ls $((1<<2)); rm x"));
    }

    #[test]
    fn here_doc_bodies_are_not_segments() {
        let rules = vec![grant("terminal.execute", Some("cat *"))];
        assert!(check(&rules, "cat <<EOF\nrm -rf /\nEOF"));
        assert!(!check(&rules, "cat <<EOF\nrm -rf /\nEOF\nrm x"));
        assert!(check(&rules, "cat <<'EOF'\nanything\nEOF"));
        assert!(check(&rules, "cat <<-\"E\"OF\n\tbody\n\tEOF"));
        assert!(!check(&rules, "cat <<$'E\\x4fF'\nx\nEOF\nrm y"));
        let rules = vec![grant("terminal.execute", Some("cat *")), grant("terminal.execute", Some("echo *"))];
        assert!(check(&rules, "cat <<$'E\\x4fF'\nx\nEOF\necho y"));
        assert!(!check(&rules, "echo '<<EOF'; rm x"));
    }

    #[test]
    fn host_grants_are_target_bound() {
        let mut g = grant("terminal.execute", None);
        g.session_pattern = "host:h1".into();
        let rules = vec![g];
        let args = json!({ "command": "ls" });
        let ctx = |host: Option<&'static str>| GrantContext {
            capability_id: "terminal.execute",
            session_id: Some("s1"),
            host_id: host,
            args: None,
            chat_session_id: None,
        };
        let _ = &args;
        assert!(match_permission_grant(&rules, &ctx(Some("h1"))).is_some());
        assert!(match_permission_grant(&rules, &ctx(Some("h2"))).is_none());
        let mut star = grant("*", None);
        star.session_pattern = "*".into();
        assert!(match_permission_grant(&[star], &ctx(None)).is_none());
    }

    #[test]
    fn sanitize_drops_invalid_entries() {
        let raw = json!([
            { "capabilityId": " terminal.execute ", "commandPattern": " ls * ", "argsPattern": { "a": "x", "b": 1 } },
            { "id": "x" },
            "junk"
        ]);
        let out = sanitize_permission_grants(&raw, 5.0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].capability_id, "terminal.execute");
        assert_eq!(out[0].session_pattern, "*");
        assert_eq!(out[0].command_pattern.as_deref(), Some("ls *"));
        assert_eq!(out[0].args_pattern.as_ref().unwrap().len(), 1);
    }
}
