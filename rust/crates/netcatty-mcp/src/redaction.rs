//! External MCP privacy boundary (Electron `externalMcpPrivacyBoundary.cjs`).
//!
//! The redaction engine itself (Electron `externalMcpRedaction.cjs`: public
//! IPs, hostnames in host-like fields, credentials, PEM keys, vendor tokens,
//! custom RE2 patterns → `[NC_<nonce>_<IP|HOST|SECRET>_<n>]`) is
//! `netcatty_ai::privacy::redaction`, shared with the AI chat privacy
//! service; this module adapts it to the `&self` / `String`-error shape the
//! MCP transports use and pins the policy per client connection.

use netcatty_ai::privacy::redaction as engine;
use parking_lot::Mutex;
use serde_json::Value;

pub use engine::{RedactionConfig, CONFIG_ERROR, LIMIT_ERROR, TOKEN_ERROR, VALUE_ERROR};

pub const RECONNECT_MESSAGE: &str = "External MCP privacy settings changed. Reconnect the MCP client before continuing.";

/// Reject malformed policy rather than silently disabling a requested protection.
pub fn normalize_redaction_config(input: Option<&Value>) -> Result<RedactionConfig, String> {
    engine::normalize_redaction_config(input).map_err(|e| e.message().to_string())
}

/// The renderer / settings JSON shape of a policy.
pub fn config_value(config: &RedactionConfig) -> Value {
    serde_json::to_value(config).unwrap_or(Value::Null)
}

/// One reversible redaction session (one MCP client connection).
pub struct RedactionSession(Mutex<engine::RedactionSession>);

impl RedactionSession {
    /// Fails (closed) on a policy [`normalize_redaction_config`] rejects.
    pub fn new(config: RedactionConfig) -> Result<Self, String> {
        engine::RedactionSession::new(&config).map(|s| Self(Mutex::new(s))).map_err(|e| e.message().to_string())
    }

    pub fn enabled(&self) -> bool {
        self.0.lock().enabled()
    }

    /// Mask a value bound for the client. `preserve_root_keys` keeps the
    /// result object's own keys (RPC control fields) intact.
    pub fn redact(&self, value: &Value, preserve_root_keys: bool) -> Result<Value, String> {
        let options = engine::RedactOptions { preserve_root_keys, accept_existing_tokens: false };
        self.0.lock().redact(value, options).map_err(|e| e.message().to_string())
    }

    /// Restore tokens in a client request before dispatch.
    pub fn restore(&self, value: &Value) -> Result<Value, String> {
        self.0.lock().restore(value).map_err(|e| e.message().to_string())
    }
}

/// One boundary per stdio process / HTTP session (`createPrivacyBoundary`):
/// the configuration fingerprint is pinned at first use; any change asks
/// the client to reconnect.
pub struct PrivacyBoundary {
    get_config: Box<dyn Fn() -> Option<Value> + Send + Sync>,
    state: Mutex<Option<(String, Option<std::sync::Arc<RedactionSession>>)>>,
}

impl PrivacyBoundary {
    pub fn new(get_config: impl Fn() -> Option<Value> + Send + Sync + 'static) -> Self {
        Self { get_config: Box::new(get_config), state: Mutex::new(None) }
    }

    fn check(&self) -> Result<Option<std::sync::Arc<RedactionSession>>, String> {
        let config = normalize_redaction_config((self.get_config)().as_ref())
            .map_err(|_| "External MCP privacy configuration is unavailable or invalid. Check Settings and reconnect.".to_string())?;
        let fingerprint = config_value(&config).to_string();
        let mut state = self.state.lock();
        match &*state {
            Some((fp, _)) if *fp != fingerprint => Err(RECONNECT_MESSAGE.into()),
            Some((_, s)) => Ok(s.clone()),
            None => {
                let session = match config.enabled {
                    true => Some(std::sync::Arc::new(RedactionSession::new(config)?)),
                    false => None,
                };
                *state = Some((fingerprint, session.clone()));
                Ok(session)
            }
        }
    }

    pub fn restore(&self, params: Value) -> Result<(Value, Option<std::sync::Arc<RedactionSession>>), String> {
        let protection = self.check()?;
        let restored = match &protection {
            Some(p) => p.restore(&params)?,
            None => params,
        };
        Ok((restored, protection))
    }

    /// Mask a result (or error message) after dispatch.
    pub fn finish(&self, method: &str, outcome: Result<Value, String>, protection: Option<std::sync::Arc<RedactionSession>>) -> Result<Value, String> {
        self.check()?;
        let Some(p) = protection else {
            return outcome;
        };
        match outcome {
            Err(e) => Err(match p.redact(&Value::String(e), false)? {
                Value::String(s) => s,
                other => other.to_string(),
            }),
            Ok(mut v) => {
                if method == "netcatty/readAttachment" && v.get("text").is_some_and(Value::is_string) {
                    v.as_object_mut().map(|m| m.remove("base64Data"));
                }
                p.redact(&v, true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn session() -> RedactionSession {
        RedactionSession::new(normalize_redaction_config(Some(&json!({ "enabled": true }))).unwrap()).unwrap()
    }

    fn is_token(s: &str) -> bool {
        regex::Regex::new(r"^\[NC_[a-f0-9]{12}_(?:IP|HOST|SECRET)_\d+\]$").unwrap().is_match(s)
    }

    #[test]
    fn config_normalization_is_strict() {
        assert_eq!(normalize_redaction_config(None).unwrap(), RedactionConfig::default());
        for bad in [
            json!(null), json!([]), json!({ "enabled": "true" }), json!({ "surprise": 1 }), json!({ "cidrs": ["1.2.3.4/33"] }),
            json!({ "cidrs": ["::1%eth0/64"] }), json!({ "cidrs": ["10.0.0.0/08"] }), json!({ "patterns": ["(?=x)"] }),
            json!({ "patterns": ["a*"] }), json!({ "patterns": [""] }),
        ] {
            assert_eq!(normalize_redaction_config(Some(&bad)).unwrap_err(), CONFIG_ERROR, "{bad}");
        }
    }

    #[test]
    fn disabled_is_identity() {
        let s = RedactionSession::new(RedactionConfig::default()).unwrap();
        let v = json!({ "password": "x", "content": "8.8.8.8" });
        assert_eq!(s.redact(&v, false).unwrap(), v);
    }

    #[test]
    fn masks_public_ips_secrets_hosts_and_round_trips() {
        let s = session();
        let src = json!({
            "8.8.8.8": [{ "host": "build.example.test", "password": "synthetic-pass" }, null, 42, false],
            "note": "connect 10.0.0.1 and 203.0.113.14 with token=abc123def",
            "tokenCount": 123,
        });
        let r = s.redact(&src, false).unwrap();
        let text = r.to_string();
        assert!(!text.contains("synthetic-pass") && !text.contains("8.8.8.8") && !text.contains("203.0.113.14") && !text.contains("abc123def"));
        assert!(text.contains("10.0.0.1"), "private IPs kept by default");
        assert!(!text.contains("build.example.test"));
        assert_eq!(r["tokenCount"], 123);
        assert_eq!(s.restore(&r).unwrap(), src);
        let a = s.redact(&json!("8.8.8.8"), false).unwrap();
        assert!(is_token(a.as_str().unwrap()));
        assert_eq!(s.redact(&json!("8.8.8.8"), false).unwrap(), a);
        assert!(session().restore(&a).is_err(), "cross-session tokens fail closed");
        let mapped = s.redact(&json!("::ffff:8.8.8.8"), false).unwrap();
        assert!(is_token(mapped.as_str().unwrap()));
        assert_eq!(s.redact(&json!("::ffff:10.0.0.1"), false).unwrap(), json!("::ffff:10.0.0.1"));
    }

    #[test]
    fn root_keys_preserved_and_binary_fails_closed() {
        let s = session();
        let src = json!({ "stdout": "password=stdout\nimportant output", "exitCode": 0 });
        let r = s.redact(&src, true).unwrap();
        assert!(r["stdout"].as_str().unwrap().starts_with("password=[NC_"));
        assert!(r["stdout"].as_str().unwrap().ends_with("\nimportant output"));
        assert!(s.redact(&json!({ "type": "image", "data": "x" }), false).is_err());
        assert!(s.redact(&json!({ "base64Data": "aGk=" }), false).is_err());
        assert!(s.restore(&json!("[NC_000000000000_IP_9]")).is_err());
    }

    #[test]
    fn pem_bearer_and_custom_patterns() {
        let s = RedactionSession::new(normalize_redaction_config(Some(&json!({ "enabled": true, "patterns": ["synthetic-[0-9]+"] }))).unwrap()).unwrap();
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----";
        let r = s.redact(&json!(format!("key:\n{pem}\nAuthorization: Bearer abcdefgh123 id synthetic-42")), false).unwrap();
        let t = r.as_str().unwrap();
        assert!(!t.contains("BEGIN") && !t.contains("abcdefgh123") && !t.contains("synthetic-42"));
        assert!(t.contains("Bearer "));
    }

    #[test]
    fn boundary_requires_reconnect_on_change() {
        let cfg = std::sync::Arc::new(Mutex::new(json!({ "enabled": true })));
        let c = cfg.clone();
        let b = PrivacyBoundary::new(move || Some(c.lock().clone()));
        let (p, prot) = b.restore(json!({ "a": 1 })).unwrap();
        assert_eq!(p, json!({ "a": 1 }));
        let r = b.finish("x", Ok(json!({ "ip": "8.8.8.8" })), prot).unwrap();
        assert!(is_token(r["ip"].as_str().unwrap()));
        *cfg.lock() = json!({ "enabled": false });
        assert_eq!(b.restore(json!({})).err().unwrap(), RECONNECT_MESSAGE);
        let bad = PrivacyBoundary::new(|| Some(json!({ "bad": 1 })));
        assert!(bad.restore(json!({})).err().unwrap().contains("unavailable or invalid"));
    }
}
