//! Script source preparation and small text helpers shared by the runtime
//! and the bridge (`wrapScriptSource`, `formatScriptInputForLog`,
//! `truncateActivityLabel`, `resolveStartupSeedText`, ...).

use crate::buffer::strip_trailing_blank_lines;
use crate::pattern::JsRegex;

/// `wrapScriptSource`: wrap the user's script in an async IIFE so top-level
/// `await` works. Scripts that already are `(async () => ...` / `(async
/// function () {` are left alone; scripts with a `main` function get
/// `await main();` (a trailing one is removed first).
pub fn wrap_script_source(source: &str) -> Result<String, String> {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        return Err("Script content is empty".into());
    }
    let iife_arrow = JsRegex::new(r"^\(\s*async\s*\(\s*\)\s*=>", "m").expect("static regex");
    let iife_function =
        JsRegex::new(r"^\(\s*async\s+function\s*\(\s*\)\s*\{", "m").expect("static regex");
    if iife_arrow.exec(trimmed).is_some() || iife_function.exec(trimmed).is_some() {
        return Ok(trimmed.to_string());
    }
    let async_main = JsRegex::new(r"\basync\s+function\s+main\s*\(", "m").expect("static regex");
    let plain_main = JsRegex::new(r"\bfunction\s+main\s*\(", "m").expect("static regex");
    if async_main.exec(trimmed).is_some() || plain_main.exec(trimmed).is_some() {
        let trailing_call =
            JsRegex::new(r"\n\s*;?\s*await\s+main\s*\(\s*\)\s*;?\s*$", "m").expect("static regex");
        let body = match trailing_call.exec(trimmed) {
            Some((start, end)) => format!("{}{}", &trimmed[..start], &trimmed[end..]),
            None => trimmed.to_string(),
        };
        let body = body.trim_end();
        let invoke_main = if async_main.exec(body).is_some() {
            "await main();"
        } else {
            "await Promise.resolve(main());"
        };
        return Ok(format!("(async () => {{\n{body}\n{invoke_main}\n}})();"));
    }
    Ok(format!("(async () => {{\n{trimmed}\n}})();"))
}

/// `truncateActivityLabel`: at most `max` characters, ellipsis when cut.
pub fn truncate_activity_label(value: &str, max: usize) -> String {
    let count = value.chars().count();
    if count > max {
        let mut out: String = value.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    } else {
        value.to_string()
    }
}

/// `formatScriptInputForLog`: make control characters visible.
pub fn format_script_input_for_log(data: &str) -> String {
    data.replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\x03', "^C")
        .replace('\x1b', "\\e")
}

/// `normalizeNewlines`.
pub fn normalize_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// `resolveStartupSeedText`: prefer the viewport when it is the live screen
/// suffix (drops scrolled-off scrollback, #1821); prefer the live buffer when
/// the viewport is empty or a lagging / incomplete paint of what the tap
/// already saw (#1960).
pub fn resolve_startup_seed_text(viewport_text: &str, buffer_text: &str) -> String {
    let viewport_norm = normalize_newlines(viewport_text);
    let buffer_norm = normalize_newlines(buffer_text);
    let viewport_core = strip_trailing_blank_lines(&viewport_norm);
    let buffer_core = strip_trailing_blank_lines(&buffer_norm);

    if viewport_core.is_empty() {
        return buffer_text.to_string();
    }
    if buffer_core.is_empty() {
        return viewport_text.to_string();
    }
    if viewport_core == buffer_core {
        return viewport_text.to_string();
    }
    if buffer_core.ends_with(viewport_core) {
        return viewport_text.to_string();
    }
    if buffer_core.starts_with(viewport_core) || buffer_core.contains(viewport_core) {
        return buffer_text.to_string();
    }
    viewport_text.to_string()
}

/// `seedBufferFromScreen`: seed `buffer` with the startup screen, keeping
/// output that arrived while the snapshot was in flight.
pub fn seed_buffer_from_screen(
    buffer: &crate::buffer::OutputBuffer,
    screen_text: &str,
    sync_start_text: &str,
) {
    let current = buffer.text();
    let trailing_fresh = current
        .strip_prefix(sync_start_text)
        .unwrap_or("")
        .to_string();
    let seed_text = resolve_startup_seed_text(screen_text, sync_start_text);
    if seed_text.is_empty() && trailing_fresh.is_empty() {
        return;
    }
    buffer.replace_with_visible_screen(&seed_text, &trailing_fresh, sync_start_text);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_async_main_scripts_in_async_iife() {
        let wrapped = wrap_script_source(
            "\n// generated\nasync function main() {\n  await nct.log('hi');\n}\n\nawait main();\n",
        )
        .unwrap();
        assert!(wrapped.starts_with("(async () => {"));
        assert!(wrapped.ends_with("await main();\n})();"));
        // The user's own trailing `await main();` is not duplicated.
        assert_eq!(wrapped.matches("await main();").count(), 1);
    }

    #[test]
    fn wraps_sync_main_with_promise_resolve() {
        let wrapped = wrap_script_source("function main() { nct.log('x'); }").unwrap();
        assert!(wrapped.contains("await Promise.resolve(main());"));
    }

    #[test]
    fn wraps_bare_statements_in_async_iife() {
        let wrapped = wrap_script_source("await nct.log('hi');").unwrap();
        assert!(wrapped.contains("async () =>"));
        assert_eq!(wrapped, "(async () => {\nawait nct.log('hi');\n})();");
    }

    #[test]
    fn keeps_existing_iife() {
        let source = "(async () => {\n nct.log(1);\n})();";
        assert_eq!(wrap_script_source(source).unwrap(), source);
        assert_eq!(
            wrap_script_source("   ").unwrap_err(),
            "Script content is empty"
        );
    }

    #[test]
    fn formats_input_for_logs() {
        assert_eq!(
            format_script_input_for_log("ls\r\n\x03\x1b[A"),
            "ls\\r\\n^C\\e[A"
        );
        assert_eq!(truncate_activity_label("abcdef", 4), "abc…");
        assert_eq!(truncate_activity_label("abc", 4), "abc");
    }

    #[test]
    fn resolve_startup_seed_text_prefers_buffer_when_viewport_paint_lags_bastion_menu() {
        let buffer = "Welcome to SSHD\n\nuser login success\n\nSSH资源(5) :\n  [1] host\n";
        let lagging_viewport = "Welcome to SSHD\n\nuser login success\n";
        let seed = resolve_startup_seed_text(lagging_viewport, buffer);
        assert!(seed.contains("SSH资源(5)"));
        assert_eq!(resolve_startup_seed_text("", buffer), buffer);
    }

    #[test]
    fn resolve_startup_seed_text_prefers_viewport_when_buffer_only_adds_scrolled_off_prefix() {
        let viewport = "SSH资源(5) :\n  [1] host\n";
        let buffer = format!("old deployment READY marker\nuser@host:~$ \n{viewport}");
        let seed = resolve_startup_seed_text(viewport, &buffer);
        assert_eq!(seed, viewport);
        assert!(!seed.contains("READY marker"));
        assert_eq!(resolve_startup_seed_text(viewport, ""), viewport);
        assert_eq!(resolve_startup_seed_text("unrelated", &buffer), "unrelated");
    }
}
