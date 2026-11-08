//! `scanTotpQrFromScreen` (Electron `totpBridge.cjs` `scanScreensForTotp`):
//! capture every display, decode QR codes, pick the first `otpauth://totp`
//! payload and return the same preview shape as `totp_preview`.
//!
//! Errors (`{ ok: false, error }`): `screen-permission-denied` (macOS
//! Screen Recording not granted; the system prompt is requested once),
//! `unavailable` (capture failed / unsupported platform), `not-found`, and
//! the parse errors `hotp` / `migration` when only such codes were found.
//!
//! Capture uses `xcap` on macOS and Windows. Linux is not supported in this
//! build (xcap needs PipeWire / XCB development libraries the Linux bundle
//! does not ship) and reports `unavailable`.

use crate::commands::totp::{parse_input, preview, TotpPreview};
use serde_json::Value;

/// A captured display: tightly packed RGBA rows.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// Decode every QR code in `frame` (luma conversion + `rqrr`).
pub fn decode_frame(frame: &Frame) -> Vec<String> {
    let (w, h) = (frame.width as usize, frame.height as usize);
    if w == 0 || h == 0 || frame.rgba.len() < w * h * 4 {
        return Vec::new();
    }
    let rgba = &frame.rgba;
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| {
        let i = (y * w + x) * 4;
        let (r, g, b) = (u32::from(rgba[i]), u32::from(rgba[i + 1]), u32::from(rgba[i + 2]));
        ((r * 299 + g * 587 + b * 114) / 1000) as u8
    });
    prepared
        .detect_grids()
        .into_iter()
        .filter_map(|grid| grid.decode().ok().map(|(_, content)| content))
        .collect()
}

/// `selectTotpFromQrPayloads`: first valid TOTP wins; otherwise report a
/// recognised-but-unsupported kind, else `not-found`.
pub fn select_totp(payloads: &[String]) -> Result<String, &'static str> {
    let (mut saw_hotp, mut saw_migration) = (false, false);
    for payload in payloads {
        match parse_input(payload) {
            Ok(_) => return Ok(payload.clone()),
            Err("hotp") => saw_hotp = true,
            Err("migration") => saw_migration = true,
            Err(_) => {}
        }
    }
    if saw_hotp {
        Err("hotp")
    } else if saw_migration {
        Err("migration")
    } else {
        Err("not-found")
    }
}

fn failure(code: &str) -> Value {
    serde_json::json!({ "ok": false, "error": code })
}

/// Pure part of the command, separated for tests.
pub fn scan_frames(frames: Result<Vec<Frame>, &'static str>, now_ms: u64) -> Value {
    let frames = match frames {
        Ok(frames) => frames,
        Err(code) => return failure(code),
    };
    if frames.is_empty() {
        return failure("not-found");
    }
    let payloads: Vec<String> = frames.iter().flat_map(decode_frame).collect();
    match select_totp(&payloads) {
        Ok(text) => {
            let result: TotpPreview = preview(&text, now_ms);
            serde_json::to_value(result).unwrap_or_else(|_| failure("not-found"))
        }
        Err(code) => failure(code),
    }
}

#[cfg(target_os = "macos")]
mod permission {
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGPreflightScreenCaptureAccess() -> bool;
        fn CGRequestScreenCaptureAccess() -> bool;
    }

    /// `true` when Screen Recording is granted. Otherwise ask macOS to
    /// show its permission prompt (once per app) and report `false`.
    pub fn ensure() -> bool {
        unsafe {
            if CGPreflightScreenCaptureAccess() {
                return true;
            }
            CGRequestScreenCaptureAccess();
            false
        }
    }
}

#[cfg(any(target_os = "macos", windows))]
fn capture() -> Result<Vec<Frame>, &'static str> {
    #[cfg(target_os = "macos")]
    if !permission::ensure() {
        return Err("screen-permission-denied");
    }
    let monitors = xcap::Monitor::all().map_err(|e| classify_capture_error(&e.to_string()))?;
    let mut frames = Vec::new();
    let mut last_error = None;
    for monitor in monitors {
        match monitor.capture_image() {
            Ok(image) => frames.push(Frame {
                width: image.width(),
                height: image.height(),
                rgba: image.into_raw(),
            }),
            Err(e) => last_error = Some(classify_capture_error(&e.to_string())),
        }
    }
    match (frames.is_empty(), last_error) {
        (true, Some(code)) => Err(code),
        _ => Ok(frames),
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn capture() -> Result<Vec<Frame>, &'static str> {
    Err("unavailable")
}

#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
fn classify_capture_error(message: &str) -> &'static str {
    let lower = message.to_lowercase();
    if ["denied", "permission", "not authorized", "not permitted"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        "screen-permission-denied"
    } else {
        "unavailable"
    }
}

#[tauri::command]
pub async fn totp_scan_screen() -> Value {
    let frames = tokio::task::spawn_blocking(capture)
        .await
        .unwrap_or(Err("unavailable"));
    scan_frames(frames, netcatty_core::ids::now_ms().max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    /// Render `text` as a QR code into an RGBA frame (black on white, with
    /// a quiet zone and a few pixels per module).
    fn qr_frame(text: &str) -> Frame {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let modules = code.width();
        let scale = 4usize;
        let quiet = 4usize;
        let side = (modules + quiet * 2) * scale;
        let mut rgba = vec![255u8; side * side * 4];
        for y in 0..modules {
            for x in 0..modules {
                if code[(x, y)] == qrcode::Color::Dark {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let px = (x + quiet) * scale + dx;
                            let py = (y + quiet) * scale + dy;
                            let i = (py * side + px) * 4;
                            rgba[i..i + 3].copy_from_slice(&[0, 0, 0]);
                        }
                    }
                }
            }
        }
        Frame {
            width: side as u32,
            height: side as u32,
            rgba,
        }
    }

    #[test]
    fn decodes_a_totp_qr() {
        let frame = qr_frame(URI);
        assert_eq!(decode_frame(&frame), vec![URI.to_string()]);
        let result = scan_frames(Ok(vec![frame]), 0);
        assert_eq!(result["ok"], true);
        assert_eq!(result["issuer"], "Example");
        assert_eq!(result["label"], "alice@example.com");
        assert_eq!(result["digits"], 6);
        assert_eq!(result["period"], 30);
        assert_eq!(result["code"].as_str().unwrap().len(), 6);
    }

    #[test]
    fn error_codes() {
        assert_eq!(scan_frames(Err("screen-permission-denied"), 0)["error"], "screen-permission-denied");
        assert_eq!(scan_frames(Ok(vec![]), 0)["error"], "not-found");
        let blank = Frame {
            width: 64,
            height: 64,
            rgba: vec![255; 64 * 64 * 4],
        };
        assert_eq!(scan_frames(Ok(vec![blank]), 0)["error"], "not-found");
        let hotp = qr_frame("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1");
        assert_eq!(scan_frames(Ok(vec![hotp]), 0)["error"], "hotp");
        let migration = qr_frame("otpauth-migration://offline?data=abc");
        assert_eq!(scan_frames(Ok(vec![migration]), 0)["error"], "migration");
    }

    #[test]
    fn first_valid_payload_wins() {
        let payloads = vec!["otpauth-migration://offline?data=x".to_string(), URI.to_string()];
        assert_eq!(select_totp(&payloads), Ok(URI.to_string()));
        assert_eq!(select_totp(&["nonsense!".to_string()]), Err("not-found"));
    }

    #[test]
    fn capture_errors_are_classified() {
        assert_eq!(classify_capture_error("Permission denied"), "screen-permission-denied");
        assert_eq!(classify_capture_error("boom"), "unavailable");
    }
}
