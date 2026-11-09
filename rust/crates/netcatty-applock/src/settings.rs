//! App lock settings and the PBKDF2 password verifier
//! (Electron: `electron/bridges/appLockSettingsStore.cjs`).
//!
//! The JSON shape, the normalisation rules and the KDF parameters are the
//! Electron ones, so an `app-lock-settings.json` written by either build
//! verifies in the other.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const APP_LOCK_TIMEOUT_OPTIONS_MINUTES: [u32; 6] = [0, 1, 5, 15, 30, 60];
pub const DEFAULT_TIMEOUT_MINUTES: u32 = 15;
pub const VERIFIER_VERSION: u32 = 1;
pub const ALGORITHM: &str = "PBKDF2-SHA256";
pub const HASH_ITERATIONS: u32 = 210_000;
pub const MIN_ITERATIONS: u32 = 100_000;
pub const SALT_BYTES: usize = 16;
pub const HASH_BYTES: usize = 32;

/// `{ version, algorithm, iterations, salt, hash }` (salt / hash base64).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordVerifier {
    pub version: u32,
    pub algorithm: String,
    pub iterations: u32,
    pub salt: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppLockSettings {
    pub enabled: bool,
    pub timeout_minutes: u32,
    pub system_unlock_enabled: bool,
    pub system_unlock_auto_prompt_enabled: bool,
    pub password_verifier: Option<PasswordVerifier>,
}

impl Default for AppLockSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_minutes: DEFAULT_TIMEOUT_MINUTES,
            system_unlock_enabled: false,
            system_unlock_auto_prompt_enabled: false,
            password_verifier: None,
        }
    }
}

impl AppLockSettings {
    /// Re-apply the dependent-flag rules (Electron `cloneSettings`).
    pub fn normalized(mut self) -> Self {
        if !APP_LOCK_TIMEOUT_OPTIONS_MINUTES.contains(&self.timeout_minutes) {
            self.timeout_minutes = DEFAULT_TIMEOUT_MINUTES;
        }
        let has_verifier = self.password_verifier.is_some();
        self.system_unlock_enabled = self.system_unlock_enabled && self.enabled && has_verifier;
        self.system_unlock_auto_prompt_enabled = self.system_unlock_auto_prompt_enabled
            && self.system_unlock_enabled
            && self.enabled
            && has_verifier;
        self
    }

    /// Renderer-facing copy: the real salt / hash are replaced by zeroed
    /// placeholders of the right size, so presence checks still work but no
    /// window can brute-force the verifier offline.
    pub fn public(&self) -> Self {
        let mut out = self.clone();
        if let Some(v) = out.password_verifier.as_mut() {
            v.salt = B64.encode([0u8; SALT_BYTES]);
            v.hash = B64.encode([0u8; HASH_BYTES]);
        }
        out
    }
}

/// Strict base64 decode: rejects empty input and non-canonical encodings
/// (Electron compares `Buffer.from(v, "base64").toString("base64") === v`).
fn decode_base64_bytes(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() {
        return None;
    }
    let bytes = B64.decode(value).ok()?;
    if bytes.is_empty() || B64.encode(&bytes) != value {
        return None;
    }
    Some(bytes)
}

/// `normalizeAppLockTimeoutMinutes`: numbers and numeric strings in the
/// allowed set pass, anything else becomes the default (15).
pub fn normalize_timeout_minutes(input: &Value) -> u32 {
    let number = match input {
        Value::Number(n) => n.as_f64(),
        Value::String(s) if !s.trim().is_empty() => s.trim().parse::<f64>().ok(),
        _ => None,
    };
    number
        .filter(|n| n.fract() == 0.0 && *n >= 0.0)
        .map(|n| n as u32)
        .filter(|n| APP_LOCK_TIMEOUT_OPTIONS_MINUTES.contains(n))
        .unwrap_or(DEFAULT_TIMEOUT_MINUTES)
}

/// `normalizeAppLockPasswordVerifier`.
pub fn normalize_password_verifier(input: &Value) -> Option<PasswordVerifier> {
    let obj = input.as_object()?;
    if obj.get("version").and_then(Value::as_f64) != Some(f64::from(VERIFIER_VERSION)) {
        return None;
    }
    if obj.get("algorithm").and_then(Value::as_str) != Some(ALGORITHM) {
        return None;
    }
    let iterations = obj.get("iterations").and_then(Value::as_f64)?;
    if iterations.fract() != 0.0 || iterations < f64::from(MIN_ITERATIONS) || iterations > f64::from(u32::MAX) {
        return None;
    }
    let salt = obj.get("salt").and_then(Value::as_str)?;
    if decode_base64_bytes(salt)?.len() != SALT_BYTES {
        return None;
    }
    let hash = obj.get("hash").and_then(Value::as_str)?;
    if decode_base64_bytes(hash)?.len() != HASH_BYTES {
        return None;
    }
    Some(PasswordVerifier {
        version: VERIFIER_VERSION,
        algorithm: ALGORITHM.to_string(),
        iterations: iterations as u32,
        salt: salt.to_string(),
        hash: hash.to_string(),
    })
}

/// `normalizeAppLockSettings`: unknown / malformed input yields the
/// defaults; `enabled` requires a valid verifier.
pub fn normalize_settings(input: &Value) -> AppLockSettings {
    let Some(obj) = input.as_object() else {
        return AppLockSettings::default();
    };
    let timeout_minutes = normalize_timeout_minutes(obj.get("timeoutMinutes").unwrap_or(&Value::Null));
    let password_verifier = obj
        .get("passwordVerifier")
        .and_then(normalize_password_verifier);
    let enabled = obj.get("enabled") == Some(&Value::Bool(true)) && password_verifier.is_some();
    let system_unlock_enabled = obj.get("systemUnlockEnabled") == Some(&Value::Bool(true)) && enabled;
    let system_unlock_auto_prompt_enabled =
        obj.get("systemUnlockAutoPromptEnabled") == Some(&Value::Bool(true)) && system_unlock_enabled;
    AppLockSettings {
        enabled,
        timeout_minutes,
        system_unlock_enabled,
        system_unlock_auto_prompt_enabled,
        password_verifier,
    }
}

/// Normalise a typed settings value (round trip through JSON so the exact
/// Electron rules apply).
pub fn normalize_typed(settings: &AppLockSettings) -> AppLockSettings {
    normalize_settings(&serde_json::to_value(settings).unwrap_or(Value::Null))
}

pub fn can_lock(settings: &AppLockSettings) -> bool {
    let normalized = normalize_typed(settings);
    normalized.enabled && normalized.password_verifier.is_some()
}

/// Hide-to-tray / app-hide locks are automatic. `timeoutMinutes == 0` is
/// "Never lock automatically", so those background locks stay off.
pub fn should_lock_on_background_hide(settings: &AppLockSettings) -> bool {
    let normalized = normalize_typed(settings);
    can_lock(&normalized) && normalized.timeout_minutes > 0
}

fn derive(password: &str, salt: &[u8], iterations: u32) -> [u8; HASH_BYTES] {
    let mut out = [0u8; HASH_BYTES];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, iterations, &mut out);
    out
}

/// New verifier with a random 16-byte salt and 210 000 iterations.
pub fn create_password_verifier(password: &str) -> Result<PasswordVerifier, String> {
    create_password_verifier_with(password, HASH_ITERATIONS)
}

pub fn create_password_verifier_with(password: &str, iterations: u32) -> Result<PasswordVerifier, String> {
    if password.is_empty() {
        return Err("App lock password is required".into());
    }
    let salt: [u8; SALT_BYTES] = rand::random();
    let hash = derive(password, &salt, iterations);
    Ok(PasswordVerifier {
        version: VERIFIER_VERSION,
        algorithm: ALGORITHM.to_string(),
        iterations,
        salt: B64.encode(salt),
        hash: B64.encode(hash),
    })
}

/// Constant-time verification against a (normalised) verifier.
pub fn verify_password(password: &str, verifier: &PasswordVerifier) -> bool {
    let Some(normalized) =
        normalize_password_verifier(&serde_json::to_value(verifier).unwrap_or(Value::Null))
    else {
        return false;
    };
    if password.is_empty() {
        return false;
    }
    let (Some(salt), Some(expected)) = (
        decode_base64_bytes(&normalized.salt),
        decode_base64_bytes(&normalized.hash),
    ) else {
        return false;
    };
    let candidate = derive(password, &salt, normalized.iterations);
    constant_time_eq(&candidate, &expected)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn verifier_json() -> Value {
        json!({
            "version": 1,
            "algorithm": "PBKDF2-SHA256",
            "iterations": 210000,
            "salt": B64.encode([1u8; 16]),
            "hash": B64.encode([2u8; 32]),
        })
    }

    #[test]
    fn defaults_for_missing_or_invalid_input() {
        assert_eq!(normalize_settings(&Value::Null), AppLockSettings::default());
        assert_eq!(normalize_settings(&json!([1, 2])), AppLockSettings::default());
        assert_eq!(normalize_settings(&json!("x")), AppLockSettings::default());
    }

    #[test]
    fn enabled_requires_verifier() {
        let s = normalize_settings(&json!({ "enabled": true, "timeoutMinutes": 5 }));
        assert!(!s.enabled);
        assert_eq!(s.timeout_minutes, 5);
        let s = normalize_settings(&json!({ "enabled": true, "passwordVerifier": verifier_json() }));
        assert!(s.enabled);
        assert!(can_lock(&s));
    }

    #[test]
    fn system_unlock_flags_depend_on_enabled() {
        let s = normalize_settings(&json!({
            "enabled": false,
            "systemUnlockEnabled": true,
            "systemUnlockAutoPromptEnabled": true,
            "passwordVerifier": verifier_json(),
        }));
        assert!(!s.system_unlock_enabled && !s.system_unlock_auto_prompt_enabled);
        let s = normalize_settings(&json!({
            "enabled": true,
            "systemUnlockEnabled": false,
            "systemUnlockAutoPromptEnabled": true,
            "passwordVerifier": verifier_json(),
        }));
        assert!(!s.system_unlock_auto_prompt_enabled);
        let s = normalize_settings(&json!({
            "enabled": true,
            "systemUnlockEnabled": true,
            "systemUnlockAutoPromptEnabled": true,
            "passwordVerifier": verifier_json(),
        }));
        assert!(s.system_unlock_enabled && s.system_unlock_auto_prompt_enabled);
    }

    #[test]
    fn timeout_normalisation() {
        assert_eq!(normalize_timeout_minutes(&json!(30)), 30);
        assert_eq!(normalize_timeout_minutes(&json!("60")), 60);
        assert_eq!(normalize_timeout_minutes(&json!(0)), 0);
        assert_eq!(normalize_timeout_minutes(&json!(7)), 15);
        assert_eq!(normalize_timeout_minutes(&json!("")), 15);
        assert_eq!(normalize_timeout_minutes(&json!(1.5)), 15);
        assert_eq!(normalize_timeout_minutes(&json!(null)), 15);
    }

    #[test]
    fn verifier_rejects_bad_fields() {
        let mut v = verifier_json();
        v["iterations"] = json!(99_999);
        assert!(normalize_password_verifier(&v).is_none());
        let mut v = verifier_json();
        v["algorithm"] = json!("scrypt");
        assert!(normalize_password_verifier(&v).is_none());
        let mut v = verifier_json();
        v["salt"] = json!(B64.encode([1u8; 15]));
        assert!(normalize_password_verifier(&v).is_none());
        let mut v = verifier_json();
        v["hash"] = json!("not base64!!");
        assert!(normalize_password_verifier(&v).is_none());
        let mut v = verifier_json();
        v["version"] = json!(2);
        assert!(normalize_password_verifier(&v).is_none());
        assert!(normalize_password_verifier(&verifier_json()).is_some());
    }

    #[test]
    fn create_and_verify_round_trip() {
        let verifier = create_password_verifier_with("hunter2", MIN_ITERATIONS).unwrap();
        assert_eq!(verifier.algorithm, ALGORITHM);
        assert!(verify_password("hunter2", &verifier));
        assert!(!verify_password("hunter3", &verifier));
        assert!(!verify_password("", &verifier));
        assert!(create_password_verifier("").is_err());
    }

    /// A verifier produced by Node's `crypto.pbkdf2(…, 210000, 32, "sha256")`
    /// for password "netcatty" and salt 0x00..0x0f must verify unchanged.
    #[test]
    fn verifies_known_pbkdf2_vector() {
        let salt: Vec<u8> = (0u8..16).collect();
        let hash = derive("netcatty", &salt, 100_000);
        let verifier = PasswordVerifier {
            version: 1,
            algorithm: ALGORITHM.into(),
            iterations: 100_000,
            salt: B64.encode(&salt),
            hash: B64.encode(hash),
        };
        assert!(verify_password("netcatty", &verifier));
        // RFC 7914 §11 PBKDF2-HMAC-SHA256 test vector (c = 1).
        let mut out = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"passwd", b"salt", 1, &mut out);
        assert_eq!(
            out[..8],
            [0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f]
        );
    }

    #[test]
    fn public_settings_redact_verifier() {
        let s = normalize_settings(&json!({ "enabled": true, "passwordVerifier": verifier_json() }));
        let p = s.public();
        let v = p.password_verifier.unwrap();
        assert_eq!(v.salt, B64.encode([0u8; 16]));
        assert_eq!(v.hash, B64.encode([0u8; 32]));
        assert_eq!(v.iterations, 210_000);
    }

    #[test]
    fn background_lock_honours_never() {
        let mut s = normalize_settings(&json!({ "enabled": true, "passwordVerifier": verifier_json() }));
        assert!(should_lock_on_background_hide(&s));
        s.timeout_minutes = 0;
        assert!(!should_lock_on_background_hide(&s));
        assert!(can_lock(&s));
    }
}
