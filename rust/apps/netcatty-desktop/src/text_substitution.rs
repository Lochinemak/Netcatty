//! Stops macOS from rewriting what the user types into the webview.
//!
//! WKWebView runs the system text checker over every editable field: it
//! capitalises the first word, "corrects" spelling and shows the correction
//! bubble, so a host label typed as `ve-debian` is offered back as
//! `Ve-debian`. Hostnames, usernames, paths and commands are case-sensitive
//! identifiers, and nothing in an SSH manager wants that.
//!
//! WebKit takes these switches from the application's own `NSUserDefaults`
//! when the first webview is created, so they are written before the Tauri
//! builder runs. They live in this app's defaults domain only; the user's
//! system-wide keyboard settings are untouched. The renderer also marks its
//! fields (`infrastructure/textInputAutoCorrection.ts`); this is the layer that
//! does not depend on WebKit honouring per-element attributes on macOS.
//!
//! Continuous spell checking (the red underline) is left alone.

/// Substitutions switched off for this application.
#[cfg(any(target_os = "macos", test))]
const DISABLED_KEYS: [&std::ffi::CStr; 7] = [
    c"WebAutomaticSpellingCorrectionEnabled",
    c"WebAutomaticTextReplacementEnabled",
    c"WebAutomaticQuoteSubstitutionEnabled",
    c"WebAutomaticDashSubstitutionEnabled",
    c"NSAutomaticSpellingCorrectionEnabled",
    c"NSAutomaticCapitalizationEnabled",
    c"NSAutomaticPeriodSubstitutionEnabled",
];

/// Must run before the first webview exists.
#[cfg(target_os = "macos")]
pub fn disable() {
    use objc2::runtime::AnyObject;
    use objc2::{class, msg_send};

    // SAFETY: plain Foundation calls with valid, NUL-terminated keys; both
    // objects are autoreleased or process-lived and not retained here.
    unsafe {
        let defaults: *mut AnyObject = msg_send![class!(NSUserDefaults), standardUserDefaults];
        if defaults.is_null() {
            return;
        }
        for key in DISABLED_KEYS {
            let key: *mut AnyObject =
                msg_send![class!(NSString), stringWithUTF8String: key.as_ptr()];
            if !key.is_null() {
                let _: () = msg_send![defaults, setBool: false, forKey: key];
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn disable() {}

#[cfg(test)]
mod tests {
    use super::DISABLED_KEYS;

    #[test]
    fn keys_are_distinct_and_leave_spell_checking_on() {
        let mut names: Vec<&str> = DISABLED_KEYS.iter().map(|k| k.to_str().unwrap()).collect();
        assert!(names.iter().all(|n| !n.contains("ContinuousSpellChecking")));
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), DISABLED_KEYS.len());
    }
}
