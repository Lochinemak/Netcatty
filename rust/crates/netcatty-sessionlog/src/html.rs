//! Standalone HTML log page (Electron: `wrapTerminalHtmlContent` and friends
//! in `sessionLogsBridge.cjs`). The template is reproduced byte for byte.

use crate::naming::locale_date_string;
use crate::sanitizer::{escape_html, terminal_data_to_html_content};
use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

/// Light-theme overrides for extended / true-colour foregrounds: colours too
/// bright for the white background are darkened (one linear-light scale) to
/// reach 4.5:1 contrast. Returns `(light, dark)` CSS declaration blocks.
fn build_extended_foreground_palette(html_content: &str) -> (String, String) {
    static CUSTOM: OnceLock<Regex> = OnceLock::new();
    let re = CUSTOM.get_or_init(|| {
        Regex::new(r"var\(--term-custom-([a-f0-9]{6}), #[a-f0-9]{6}\)").expect("valid regex")
    });
    let mut seen = HashSet::new();
    let mut light = Vec::new();
    let mut dark = Vec::new();
    for caps in re.captures_iter(html_content) {
        let hex = &caps[1];
        if !seen.insert(hex.to_string()) {
            continue;
        }
        let channels: Vec<u32> = (0..3)
            .map(|i| u32::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect();
        let linear: Vec<f64> = channels
            .iter()
            .map(|&c| {
                let value = f64::from(c) / 255.0;
                if value <= 0.04045 {
                    value / 12.92
                } else {
                    ((value + 0.055) / 1.055).powf(2.4)
                }
            })
            .collect();
        let luminance = linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722;
        let max_luminance = 1.05 / 4.5 - 0.05;
        let adjusted: Vec<u32> = if luminance > max_luminance {
            let scale = max_luminance / luminance;
            linear
                .iter()
                .map(|channel| {
                    let value = channel * scale;
                    let srgb = if value <= 0.0031308 {
                        value * 12.92
                    } else {
                        1.055 * value.powf(1.0 / 2.4) - 0.055
                    };
                    (srgb * 255.0).floor().max(0.0) as u32
                })
                .collect()
        } else {
            channels
        };
        let light_hex: String = adjusted.iter().map(|c| format!("{c:02x}")).collect();
        light.push(format!("--term-custom-{hex}: #{light_hex};"));
        dark.push(format!("--term-custom-{hex}: #{hex};"));
    }
    (light.join("\n      "), dark.join("\n        "))
}

/// Wrap an HTML fragment into the log page. `timestamp_ms` is the session
/// start shown in the header (`None` renders `Invalid Date` like JS).
pub fn wrap_terminal_html_content(
    html_content: &str,
    host_label: &str,
    timestamp_ms: Option<i64>,
) -> String {
    let (light, dark) = build_extended_foreground_palette(html_content);
    let safe_host_label = escape_html(if host_label.is_empty() {
        "Unknown"
    } else {
        host_label
    });
    let safe_date = escape_html(&locale_date_string(timestamp_ms));

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="color-scheme" content="light dark">
  <title>Session Log - {safe_host_label}</title>
  <style>
    :root {{
      color-scheme: light dark;
      /* Day palette (default): readable on light browser/OS themes. */
      --term-default-bg: #ffffff;
      --term-default-fg: #24292f;
      --term-header-fg: #6a737d;
      --term-border: #d0d7de;
      /* ANSI palette (basic 0-7, bright 8-15) tuned for the light background. */
      --ansi-0: #000000;
      --ansi-1: #cd3131;
      --ansi-2: #008000;
      --ansi-3: #747700;
      --ansi-4: #0451a5;
      --ansi-5: #bc05bc;
      --ansi-6: #007c9b;
      --ansi-7: #555555;
      --ansi-8: #666666;
      --ansi-9: #cd3131;
      --ansi-10: #008500;
      --ansi-11: #797600;
      --ansi-12: #0451a5;
      --ansi-13: #bc05bc;
      --ansi-14: #007c9b;
      --ansi-15: #767676;
      {light}
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --term-default-bg: #1e1e1e;
        --term-default-fg: #d4d4d4;
        --term-header-fg: #888888;
        --term-border: #444444;
        --ansi-0: #000000;
        --ansi-1: #cd3131;
        --ansi-2: #0dbc79;
        --ansi-3: #e5e510;
        --ansi-4: #2472c8;
        --ansi-5: #bc3fbc;
        --ansi-6: #11a8cd;
        --ansi-7: #e5e5e5;
        --ansi-8: #666666;
        --ansi-9: #f14c4c;
        --ansi-10: #23d18b;
        --ansi-11: #f5f543;
        --ansi-12: #3b8eea;
        --ansi-13: #d670d6;
        --ansi-14: #29b8db;
        --ansi-15: #ffffff;
        {dark}
      }}
    }}
    body {{
      background: var(--term-default-bg);
      color: var(--term-default-fg);
      font-family: ui-monospace, 'Cascadia Mono', 'JetBrains Mono', 'SF Mono',
        Consolas, Monaco, Menlo, monospace;
      font-size: 13px;
      line-height: 1.5;
      padding: 20px;
      white-space: pre-wrap;
      word-wrap: break-word;
    }}
    .header {{
      border-bottom: 1px solid var(--term-border);
      padding-bottom: 10px;
      margin-bottom: 20px;
      color: var(--term-header-fg);
    }}
  </style>
</head>
<body>
  <div class="header">
    Host: {safe_host_label}<br>
    Date: {safe_date}
  </div>
  <div class="content">{html_content}</div>
</body>
</html>"#
    )
}

/// Replay terminal data and wrap it into the HTML page (`terminalDataToHtml`).
pub fn terminal_data_to_html(
    terminal_data: &str,
    host_label: &str,
    timestamp_ms: Option<i64>,
) -> String {
    wrap_terminal_html_content(
        &terminal_data_to_html_content(terminal_data),
        host_label,
        timestamp_ms,
    )
}

/// Already-rendered screen text as an HTML page (`terminalPlainTextToHtml`).
pub fn terminal_plain_text_to_html(
    plain_text: &str,
    host_label: &str,
    timestamp_ms: Option<i64>,
) -> String {
    wrap_terminal_html_content(&escape_html(plain_text), host_label, timestamp_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_adapts_to_light_and_dark_schemes() {
        let html = wrap_terminal_html_content("hello", "host-1", Some(0));
        assert!(html.contains("--term-default-bg: #ffffff"));
        assert!(html.contains("color-scheme: light dark"));
        assert!(html.contains("<meta name=\"color-scheme\" content=\"light dark\">"));
        assert!(html.contains("@media (prefers-color-scheme: dark)"));
        assert!(html.contains("--term-default-bg: #1e1e1e"));
        assert!(html.contains("font-family: ui-monospace,"));
        assert!(html.contains("<div class=\"content\">hello</div>"));
        assert!(html.starts_with("<!DOCTYPE html>\n<html>\n<head>\n  <meta charset=\"utf-8\">"));
        assert!(html.ends_with("</body>\n</html>"));
    }

    #[test]
    fn html_escapes_content_and_strips_controls() {
        let html =
            terminal_data_to_html("a < b\x1b[31m & c\x1b[0m\r\x1b[Kdone\n", "host<1>", Some(0));
        assert!(!html.contains('\x1b'));
        assert!(!html.contains("[31m"));
        assert!(html.contains("done"));
        assert!(!html.contains("a &lt; b"));
        assert!(html.contains("host&lt;1&gt;"));
        assert!(wrap_terminal_html_content("", "", None)
            .contains("Host: Unknown<br>\n    Date: Invalid Date"));
    }

    fn luminance(hex: &str) -> f64 {
        let hex = hex.trim_start_matches('#');
        let c: Vec<f64> = (0..3)
            .map(|i| {
                let v = f64::from(u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()) / 255.0;
                if v <= 0.04045 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            })
            .collect();
        c[0] * 0.2126 + c[1] * 0.7152 + c[2] * 0.0722
    }

    #[test]
    fn light_mode_foregrounds_remain_readable() {
        let mut data = String::new();
        for index in 0..256 {
            data.push_str(&format!("\x1b[38;5;{index}mcolor {index}\x1b[0m\n"));
        }
        data.push_str("\x1b[38;2;255;255;255mwhite\x1b[0m\n\x1b[38;2;255;255;0myellow\x1b[0m\n\x1b[38;2;18;52;86mdark\x1b[0m");
        let html = terminal_data_to_html(&data, "host", Some(0));
        let (light_css, dark_css) = html.split_once("@media").unwrap();
        let background = luminance("#ffffff");
        let re = Regex::new(r"--(ansi-\d+|term-custom-([a-f0-9]{6})):\s*(#[a-f0-9]{6})").unwrap();
        let mut count = 0;
        for caps in re.captures_iter(light_css) {
            count += 1;
            let color = &caps[3];
            let fg = luminance(color);
            let contrast = (background.max(fg) + 0.05) / (background.min(fg) + 0.05);
            assert!(
                contrast >= 4.5,
                "{} ({color}) contrast {contrast:.2}",
                &caps[1]
            );
            if let Some(hex) = caps.get(2) {
                let hex = hex.as_str();
                assert!(dark_css.contains(&format!("--term-custom-{hex}: #{hex};")));
                if 1.05 / (luminance(hex) + 0.05) >= 4.5 {
                    assert_eq!(color, format!("#{hex}"));
                }
            }
        }
        assert_eq!(count, 257);
        assert!(html.contains("color: var(--term-custom-ffffff, #ffffff)\">white"));
    }

    #[test]
    fn plain_text_html_escapes_markup() {
        let html = terminal_plain_text_to_html("<script>alert(1)</script>\n\n", "screen", Some(0));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;\n\n"));
        assert!(!html.contains("<script>"));
    }
}
