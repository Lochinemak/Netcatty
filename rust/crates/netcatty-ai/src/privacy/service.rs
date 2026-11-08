//! Per-chat AI privacy state (Electron: `electron/shared/aiPrivacyService.cjs`).
//!
//! Only the validated policy is ever exposed; alias maps and retired chat
//! identities never leave the service. A chat is pinned to the policy it
//! first saw (even while privacy is disabled); any policy change retires all
//! pinned chats, so switching privacy off cannot leak an old turn. Retired
//! IDs are tombstoned forever, so a late callback cannot recreate a map.
//! Root object keys of a redacted value are control fields and stay intact.

use super::redaction::{normalize_redaction_config, RedactOptions, RedactionConfig, RedactionError, RedactionSession};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt;

pub const CONFIG_ERROR: &str = "Invalid AI privacy configuration";
pub const LOADING_ERROR: &str = "AI privacy settings are still loading; try again";
pub const SESSION_ERROR: &str = "AI privacy session is unavailable or its settings changed; start a new chat";
pub const SESSION_ID_ERROR: &str = "AI privacy requires a valid chat session";
pub const LIMIT_ERROR: &str = "AI privacy session limit reached; close a chat and try again";
pub const VALUE_ERROR: &str = "AI privacy could not safely process this value";
pub const TOKEN_ERROR: &str = "Unknown AI privacy token; start a new chat";
pub const VALUE_LIMIT_ERROR: &str = "AI privacy session limit reached; start a new chat";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiPrivacyError {
    Config,
    Loading,
    Session,
    SessionId,
    Limit,
    Value,
    Token,
    ValueLimit,
}

impl AiPrivacyError {
    pub fn message(self) -> &'static str {
        match self {
            AiPrivacyError::Config => CONFIG_ERROR,
            AiPrivacyError::Loading => LOADING_ERROR,
            AiPrivacyError::Session => SESSION_ERROR,
            AiPrivacyError::SessionId => SESSION_ID_ERROR,
            AiPrivacyError::Limit => LIMIT_ERROR,
            AiPrivacyError::Value => VALUE_ERROR,
            AiPrivacyError::Token => TOKEN_ERROR,
            AiPrivacyError::ValueLimit => VALUE_LIMIT_ERROR,
        }
    }
}

impl fmt::Display for AiPrivacyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for AiPrivacyError {}

type Result<T> = std::result::Result<T, AiPrivacyError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Redact,
    Restore,
}

impl Operation {
    /// `"redact"` / `"restore"`; anything else is rejected by the caller.
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value {
            Some("redact") => Some(Operation::Redact),
            Some("restore") => Some(Operation::Restore),
            _ => None,
        }
    }
}

/// Snapshot of the policy revision for delayed external effects
/// (`createPolicyGuard`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyGuard {
    revision: u64,
}

#[derive(Debug)]
pub struct AiPrivacyService {
    max_sessions: usize,
    config: RedactionConfig,
    invalid_configuration: bool,
    configuration_initialized: bool,
    policy_revision: u64,
    /// Only enabled chats allocate secret-bearing maps.
    sessions: HashMap<String, RedactionSession>,
    disabled_sessions: HashSet<String>,
    closed_sessions: HashSet<String>,
}

impl Default for AiPrivacyService {
    /// The production instance: the persisted policy arrives asynchronously
    /// from the renderer, and "not loaded yet" must never be treated as a
    /// disabled policy.
    fn default() -> Self {
        Self::new(64, false).expect("valid defaults")
    }
}

impl AiPrivacyService {
    pub fn new(max_sessions: usize, initialized: bool) -> Result<Self> {
        if !(1..=4096).contains(&max_sessions) {
            return Err(AiPrivacyError::Config);
        }
        Ok(Self {
            max_sessions,
            config: RedactionConfig::default(),
            invalid_configuration: false,
            configuration_initialized: initialized,
            policy_revision: 0,
            sessions: HashMap::new(),
            disabled_sessions: HashSet::new(),
            closed_sessions: HashSet::new(),
        })
    }

    fn validate_id(chat_session_id: &str) -> Result<()> {
        if chat_session_id.trim().is_empty()
            || chat_session_id.encode_utf16().count() > 512
            || chat_session_id.contains('\0')
        {
            return Err(AiPrivacyError::SessionId);
        }
        Ok(())
    }

    fn retire(&mut self, chat_session_id: &str) {
        self.sessions.remove(chat_session_id);
        self.disabled_sessions.remove(chat_session_id);
        // Keep only the ID, never its alias map.
        self.closed_sessions.insert(chat_session_id.to_owned());
    }

    fn retire_all(&mut self) {
        let ids: Vec<String> = self.sessions.keys().chain(self.disabled_sessions.iter()).cloned().collect();
        for id in ids {
            self.retire(&id);
        }
    }

    /// Block every path until a valid policy is configured again.
    pub fn invalidate_configuration(&mut self) {
        self.policy_revision += 1;
        self.invalid_configuration = true;
        self.retire_all();
    }

    fn require_valid_config(&self) -> Result<()> {
        if self.invalid_configuration {
            return Err(AiPrivacyError::Config);
        }
        if !self.configuration_initialized {
            return Err(AiPrivacyError::Loading);
        }
        Ok(())
    }

    /// Apply a policy (`None` = defaults). Invalid input invalidates the
    /// configuration; any change retires all pinned chats.
    pub fn configure(&mut self, input: Option<&Value>) -> Result<RedactionConfig> {
        let next = match normalize_redaction_config(input) {
            Ok(next) => next,
            Err(_) => {
                self.invalidate_configuration();
                return Err(AiPrivacyError::Config);
            }
        };
        if next != self.config {
            self.policy_revision += 1;
            self.retire_all();
        }
        self.config = next;
        self.invalid_configuration = false;
        self.configuration_initialized = true;
        self.get_config()
    }

    pub fn create_policy_guard(&self) -> Result<PolicyGuard> {
        self.require_valid_config()?;
        Ok(PolicyGuard { revision: self.policy_revision })
    }

    pub fn check_policy_guard(&self, guard: PolicyGuard) -> Result<()> {
        self.require_valid_config()?;
        if guard.revision != self.policy_revision {
            return Err(AiPrivacyError::Session);
        }
        Ok(())
    }

    pub fn get_config(&self) -> Result<RedactionConfig> {
        self.require_valid_config()?;
        Ok(self.config.clone())
    }

    pub fn is_enabled(&self) -> Result<bool> {
        self.require_valid_config()?;
        Ok(self.config.enabled)
    }

    pub fn has_session(&self, chat_session_id: &str) -> bool {
        self.configuration_initialized
            && !self.invalid_configuration
            && self.sessions.get(chat_session_id).is_some_and(RedactionSession::enabled)
    }

    /// `Some(session)` for an enabled chat, `None` for a (pinned) disabled one.
    fn get_session(&mut self, chat_session_id: &str, create: bool) -> Result<Option<&mut RedactionSession>> {
        self.require_valid_config()?;
        Self::validate_id(chat_session_id)?;
        if self.closed_sessions.contains(chat_session_id) {
            return Err(AiPrivacyError::Session);
        }
        if !self.config.enabled {
            if !create && !self.disabled_sessions.contains(chat_session_id) {
                return Err(AiPrivacyError::Session);
            }
            self.disabled_sessions.insert(chat_session_id.to_owned());
            return Ok(None);
        }
        if !self.sessions.contains_key(chat_session_id) {
            if !create {
                return Err(AiPrivacyError::Session);
            }
            if self.sessions.len() >= self.max_sessions {
                return Err(AiPrivacyError::Limit);
            }
            let session = RedactionSession::new(&self.config).map_err(|_| AiPrivacyError::Config)?;
            self.sessions.insert(chat_session_id.to_owned(), session);
        }
        Ok(self.sessions.get_mut(chat_session_id))
    }

    /// Pin the chat to the current policy; `true` when privacy is enabled for it.
    pub fn check_session(&mut self, chat_session_id: &str) -> Result<bool> {
        Ok(self.get_session(chat_session_id, true)?.is_some())
    }

    pub fn transform(&mut self, operation: Operation, chat_session_id: &str, value: &Value) -> Result<Value> {
        let Some(redactor) = self.get_session(chat_session_id, operation == Operation::Redact)? else {
            return Ok(value.clone());
        };
        let result = match operation {
            Operation::Restore => redactor.restore(value),
            Operation::Redact => {
                // Also validate aliases in preserved root keys. The restored value
                // is not used for redaction: whole-string numeric/boolean aliases
                // must keep their token and type across another model boundary.
                redactor.restore(value).and_then(|_| {
                    redactor.redact(value, RedactOptions { preserve_root_keys: true, accept_existing_tokens: true })
                })
            }
        };
        result.map_err(|err| match err {
            RedactionError::Token => AiPrivacyError::Token,
            RedactionError::Limit => AiPrivacyError::ValueLimit,
            _ => AiPrivacyError::Value,
        })
    }

    pub fn redact(&mut self, chat_session_id: &str, value: &Value) -> Result<Value> {
        self.transform(Operation::Redact, chat_session_id, value)
    }

    pub fn restore(&mut self, chat_session_id: &str, value: &Value) -> Result<Value> {
        self.transform(Operation::Restore, chat_session_id, value)
    }

    /// Tombstone the chat, even an unseen ID: a deleted chat may have an
    /// in-flight first model call which must not create its map afterwards.
    pub fn clear_session(&mut self, chat_session_id: &str) -> Result<()> {
        Self::validate_id(chat_session_id)?;
        self.retire(chat_session_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn is_token(value: &Value) -> bool {
        let text = value.as_str().unwrap_or("");
        regex::Regex::new(r"^\[NC_[a-f0-9]{12}_(?:IP|HOST|SECRET)_[0-9]+\]$").unwrap().is_match(text)
    }

    fn enabled_service(policy: Value, max_sessions: usize) -> AiPrivacyService {
        let mut service = AiPrivacyService::new(max_sessions, true).unwrap();
        let mut object = json!({ "enabled": true });
        for (k, v) in policy.as_object().unwrap() {
            object[k] = v.clone();
        }
        service.configure(Some(&object)).unwrap();
        service
    }

    fn ip() -> Value {
        json!("8.8.8.8")
    }

    #[test]
    fn factory_exposes_validated_disabled_by_default_configuration() {
        let mut service = AiPrivacyService::new(64, true).unwrap();
        assert_eq!(service.get_config().unwrap(), RedactionConfig::default());
        assert_eq!(service.is_enabled(), Ok(false));
        let source = json!({ "password": "synthetic-password" });
        assert_eq!(service.redact("disabled-chat", &source).unwrap(), source);
        assert_eq!(service.restore("disabled-chat", &source).unwrap(), source);
        assert_eq!(service.check_session("disabled-chat"), Ok(false));
        assert!(!service.has_session("disabled-chat"));
        service.configure(Some(&json!({ "enabled": true, "patterns": ["ACCOUNT-[0-9]+"], "cidrs": ["10.0.0.0/8"] }))).unwrap();
        assert_eq!(service.get_config().unwrap().patterns, vec!["ACCOUNT-[0-9]+"]);
        assert_eq!(service.is_enabled(), Ok(true));
    }

    #[test]
    fn production_instance_fails_closed_until_initialized() {
        let mut service = AiPrivacyService::default();
        assert_eq!(service.is_enabled(), Err(AiPrivacyError::Loading));
        assert_eq!(service.get_config(), Err(AiPrivacyError::Loading));
        assert_eq!(service.check_session("startup"), Err(AiPrivacyError::Loading));
        assert_eq!(service.redact("startup", &ip()), Err(AiPrivacyError::Loading));
        assert_eq!(service.restore("startup", &ip()), Err(AiPrivacyError::Loading));
        assert!(!service.has_session("startup"));
        assert_eq!(service.configure(Some(&json!({ "enabled": "corrupt-saved-value" }))), Err(AiPrivacyError::Config));
        assert_eq!(service.is_enabled(), Err(AiPrivacyError::Config));
        assert_eq!(service.redact("startup", &ip()), Err(AiPrivacyError::Config));
        service.configure(Some(&json!({ "enabled": true }))).unwrap();
        assert_eq!(service.is_enabled(), Ok(true));
        // Failed pre-initialization calls must not leave a disabled snapshot behind.
        assert!(is_token(&service.redact("startup", &ip()).unwrap()));
        service.invalidate_configuration();
        assert_eq!(service.is_enabled(), Err(AiPrivacyError::Config));
        service.configure(Some(&json!({ "enabled": false }))).unwrap();
        assert_eq!(service.is_enabled(), Ok(false));
        assert_eq!(service.redact("startup", &ip()), Err(AiPrivacyError::Session));
        assert_eq!(service.redact("loaded-disabled", &ip()).unwrap(), ip());
    }

    #[test]
    fn a_pending_service_can_initialize_a_disabled_policy() {
        let mut service = AiPrivacyService::new(64, false).unwrap();
        assert_eq!(service.check_session("waiting"), Err(AiPrivacyError::Loading));
        service.configure(Some(&json!({}))).unwrap();
        assert_eq!(service.check_session("waiting"), Ok(false));
        assert_eq!(service.redact("waiting", &ip()).unwrap(), ip());
    }

    #[test]
    fn maps_are_isolated_per_chat_and_per_service() {
        let mut service = enabled_service(json!({}), 64);
        assert!(!service.has_session("chat-one"));
        assert_eq!(service.check_session("chat-one"), Ok(true));
        assert!(service.has_session("chat-one"));
        let one = service.redact("chat-one", &ip()).unwrap();
        let two = service.redact("chat-two", &ip()).unwrap();
        assert!(is_token(&one) && is_token(&two));
        assert_ne!(one, two);
        assert_eq!(service.redact("chat-one", &ip()).unwrap(), one);
        assert_eq!(service.restore("chat-one", &one).unwrap(), ip());
        assert_eq!(service.restore("chat-two", &one), Err(AiPrivacyError::Token));
        assert_eq!(service.redact("chat-two", &one), Err(AiPrivacyError::Token));
        let mut other = enabled_service(json!({}), 64);
        other.check_session("chat-one").unwrap();
        assert_eq!(other.restore("chat-one", &one), Err(AiPrivacyError::Token));
    }

    #[test]
    fn multiple_model_boundaries_preserve_existing_aliases() {
        let mut service = enabled_service(json!({}), 64);
        let source = json!({ "host": "synthetic.example.test", "password": "synthetic-secret", "token": 123456, "secret": false });
        let first = service.redact("chat", &source).unwrap();
        assert_eq!(service.redact("chat", &first).unwrap(), first);
        let nested = json!({ "text": first["token"], "nested": [first["secret"], first["host"]] });
        assert_eq!(service.redact("chat", &nested).unwrap(), nested);
        assert_eq!(service.redact("chat", &first["token"]).unwrap(), first["token"]);
        assert_eq!(service.restore("chat", &first["token"]).unwrap(), json!(123456));
        assert_eq!(service.restore("chat", &first["secret"]).unwrap(), json!(false));
        assert_eq!(service.restore("chat", &first).unwrap(), source);
        let later = service
            .redact("chat", &json!(format!("{} with synthetic-secret and 1.1.1.1", first["host"].as_str().unwrap())))
            .unwrap();
        let text = later.as_str().unwrap();
        assert!(text.contains(first["host"].as_str().unwrap()));
        assert!(text.contains(first["password"].as_str().unwrap()));
        assert!(!text.contains("1.1.1.1"));
        assert_eq!(service.restore("chat", &later).unwrap(), json!("synthetic.example.test with synthetic-secret and 1.1.1.1"));
    }

    #[test]
    fn unknown_and_cross_chat_aliases_fail_closed() {
        let mut service = enabled_service(json!({}), 64);
        let token = service.redact("chat", &ip()).unwrap();
        let modified = token.as_str().unwrap().replace("_IP_", "_HOST_");
        for value in [json!("[NC_literal]"), json!("[NC_unclosed"), json!(modified), json!({ "[NC_unknown]": "ordinary" }), json!({ "text": "[NC_unknown]" })] {
            assert_eq!(service.redact("chat", &value), Err(AiPrivacyError::Token), "{value}");
            assert_eq!(service.restore("chat", &value), Err(AiPrivacyError::Token), "{value}");
        }
        assert_eq!(service.restore("unseen", &token), Err(AiPrivacyError::Session));
        assert!(!service.has_session("unseen"));
    }

    #[test]
    fn root_control_keys_stay_intact() {
        let mut service = enabled_service(json!({}), 64);
        let source = json!({ "stdout": "password=stdout\n8.8.8.8", "stderr": "", "exitCode": 0, "details": { "stdout": "nested key", "8.8.8.8": "address key" } });
        let masked = service.redact("chat", &source).unwrap();
        assert_eq!(masked.as_object().unwrap().keys().collect::<Vec<_>>(), source.as_object().unwrap().keys().collect::<Vec<_>>());
        assert!(!masked["details"].as_object().unwrap().contains_key("stdout"));
        assert!(!masked["details"].as_object().unwrap().contains_key("8.8.8.8"));
        assert_eq!(service.redact("chat", &masked).unwrap(), masked);
        assert_eq!(service.restore("chat", &masked).unwrap(), source);
    }

    #[test]
    fn hostnames_are_remembered_across_responses() {
        let mut service = enabled_service(json!({}), 64);
        let masked = service.redact("chat", &json!({ "text": "db responded", "host": "db" })).unwrap();
        let host = masked["host"].as_str().unwrap().to_owned();
        assert_eq!(masked["text"], json!(format!("{host} responded")));
        assert_eq!(service.redact("chat", &json!("ssh db; adb dbx db.internal")).unwrap(), json!(format!("ssh {host}; adb dbx db.internal")));
        assert_eq!(service.redact("chat", &masked["text"]).unwrap(), masked["text"]);
        assert_eq!(service.restore("chat", &masked["text"]).unwrap(), json!("db responded"));
    }

    #[test]
    fn equivalent_configuration_preserves_maps_and_changes_retire_chats() {
        let mut service = enabled_service(json!({}), 64);
        let token = service.redact("chat", &ip()).unwrap();
        service.configure(Some(&json!({ "patterns": [], "enabled": true, "cidrs": [], "redactPrivateIps": false }))).unwrap();
        assert!(service.has_session("chat"));
        assert_eq!(service.redact("chat", &token).unwrap(), token);
        service.configure(Some(&json!({ "enabled": false }))).unwrap();
        assert!(!service.has_session("chat"));
        assert_eq!(service.check_session("chat"), Err(AiPrivacyError::Session));
        assert_eq!(service.redact("chat", &ip()), Err(AiPrivacyError::Session));
        assert_eq!(service.restore("chat", &token), Err(AiPrivacyError::Session));
        service.configure(Some(&json!({ "enabled": true }))).unwrap();
        assert_eq!(service.redact("chat", &ip()), Err(AiPrivacyError::Session));
        assert_ne!(service.redact("new-chat", &ip()).unwrap(), token);
        service.configure(Some(&json!({ "enabled": true, "redactPrivateIps": true }))).unwrap();
        assert_eq!(service.check_session("new-chat"), Err(AiPrivacyError::Session));
    }

    #[test]
    fn disabled_chats_are_pinned() {
        let mut service = AiPrivacyService::new(64, true).unwrap();
        service.check_session("disabled").unwrap();
        service.configure(Some(&json!({ "enabled": true }))).unwrap();
        assert_eq!(service.redact("disabled", &ip()), Err(AiPrivacyError::Session));
        assert!(is_token(&service.redact("fresh", &ip()).unwrap()));
    }

    #[test]
    fn invalid_configuration_blocks_until_recovery() {
        let mut service = enabled_service(json!({}), 64);
        let token = service.redact("chat", &ip()).unwrap();
        assert_eq!(service.configure(Some(&json!({ "enabled": "sensitive-invalid-input" }))), Err(AiPrivacyError::Config));
        assert_eq!(service.is_enabled(), Err(AiPrivacyError::Config));
        assert_eq!(service.get_config(), Err(AiPrivacyError::Config));
        assert_eq!(service.check_session("chat"), Err(AiPrivacyError::Config));
        assert_eq!(service.redact("chat", &ip()), Err(AiPrivacyError::Config));
        assert_eq!(service.restore("chat", &token), Err(AiPrivacyError::Config));
        assert!(!service.has_session("chat"));
        service.configure(Some(&json!({ "enabled": true }))).unwrap();
        assert_eq!(service.check_session("chat"), Err(AiPrivacyError::Session));
        assert!(is_token(&service.redact("recovered", &ip()).unwrap()));
        service.invalidate_configuration();
        assert_eq!(service.is_enabled(), Err(AiPrivacyError::Config));
        service.configure(Some(&json!({}))).unwrap();
        assert_eq!(service.is_enabled(), Ok(false));
        assert_eq!(service.redact("recovered", &json!("text")), Err(AiPrivacyError::Session));
        // `null` is not a valid policy.
        assert_eq!(service.configure(Some(&Value::Null)), Err(AiPrivacyError::Config));
    }

    #[test]
    fn cleanup_is_idempotent_and_rejects_late_callbacks() {
        let mut service = enabled_service(json!({}), 64);
        let token = service.redact("chat", &ip()).unwrap();
        service.clear_session("chat").unwrap();
        service.clear_session("chat").unwrap();
        assert!(!service.has_session("chat"));
        assert_eq!(service.check_session("chat"), Err(AiPrivacyError::Session));
        assert_eq!(service.redact("chat", &ip()), Err(AiPrivacyError::Session));
        assert_eq!(service.restore("chat", &token), Err(AiPrivacyError::Session));
        service.clear_session("not-started").unwrap();
        assert_eq!(service.redact("not-started", &ip()), Err(AiPrivacyError::Session));
        assert!(is_token(&service.redact("fresh", &ip()).unwrap()));
    }

    #[test]
    fn enabled_maps_are_bounded_without_eviction() {
        let mut service = enabled_service(json!({}), 2);
        let first = service.redact("one", &ip()).unwrap();
        let second = service.redact("two", &json!("1.1.1.1")).unwrap();
        assert_eq!(service.redact("three", &json!("9.9.9.9")), Err(AiPrivacyError::Limit));
        assert_eq!(service.redact("one", &first).unwrap(), first);
        service.clear_session("one").unwrap();
        assert_eq!(service.redact("one", &ip()), Err(AiPrivacyError::Session));
        service.redact("three", &json!("9.9.9.9")).unwrap();
        service.clear_session("three").unwrap();
        assert!(is_token(&service.redact("four", &json!("9.9.9.9")).unwrap()));
        assert_eq!(service.restore("two", &second).unwrap(), json!("1.1.1.1"));
    }

    #[test]
    fn disabled_chats_have_no_cap() {
        let mut service = AiPrivacyService::new(1, true).unwrap();
        let source = json!({ "password": "synthetic-ordinary-value" });
        for index in 0..4100 {
            let id = format!("disabled-{index}");
            assert_eq!(service.check_session(&id), Ok(false));
            assert_eq!(service.redact(&id, &source).unwrap(), source);
        }
        for index in 0..4100 {
            service.clear_session(&format!("disabled-{index}")).unwrap();
        }
        assert_eq!(service.check_session("still-disabled"), Ok(false));
        assert_eq!(service.redact("disabled-0", &source), Err(AiPrivacyError::Session));
        service.configure(Some(&json!({ "enabled": true }))).unwrap();
        assert_eq!(service.redact("still-disabled", &source), Err(AiPrivacyError::Session));
        assert!(is_token(&service.redact("new-enabled", &ip()).unwrap()));
        assert_eq!(service.redact("enabled-over-limit", &json!("1.1.1.1")), Err(AiPrivacyError::Limit));
    }

    #[test]
    fn ids_and_unsupported_values_are_sanitized() {
        let mut service = enabled_service(json!({}), 64);
        for id in ["", " ", &"x".repeat(513), "unsafe\0id"] {
            assert_eq!(service.redact(id, &json!("sensitive-source")), Err(AiPrivacyError::SessionId));
        }
        for value in [json!({ "type": "image", "data": "sensitive-source" }), json!("text\0binary")] {
            assert_eq!(service.redact("chat", &value), Err(AiPrivacyError::Value));
        }
        assert!(AiPrivacyService::new(0, true).is_err());
        assert!(AiPrivacyService::new(5000, true).is_err());
    }

    #[test]
    fn policy_guards_reject_changes_even_when_changed_back() {
        let mut service = AiPrivacyService::new(64, true).unwrap();
        service.configure(Some(&json!({ "enabled": true }))).unwrap();
        let guard = service.create_policy_guard().unwrap();
        service.check_policy_guard(guard).unwrap();
        service.configure(Some(&json!({ "enabled": true }))).unwrap();
        service.check_policy_guard(guard).unwrap();
        service.configure(Some(&json!({ "enabled": false }))).unwrap();
        service.configure(Some(&json!({ "enabled": true }))).unwrap();
        assert_eq!(service.check_policy_guard(guard), Err(AiPrivacyError::Session));
        let current = service.create_policy_guard().unwrap();
        service.invalidate_configuration();
        assert_eq!(service.check_policy_guard(current), Err(AiPrivacyError::Config));
    }

    #[test]
    fn ipc_shaped_round_trip_and_clear() {
        // Port of electron/bridges/aiBridge.privacy.test.cjs.
        let mut service = enabled_service(json!({}), 64);
        let value = json!(["password=synthetic-secret", "192.0.2.1"]);
        let masked = service.redact("catty-chat", &value).unwrap();
        let text = masked.to_string();
        assert!(!text.contains("synthetic-secret") && !text.contains("192.0.2.1"), "{text}");
        assert_eq!(service.restore("catty-chat", &masked).unwrap(), value);
        service.clear_session("catty-chat").unwrap();
        assert!(service.restore("catty-chat", &masked).is_err());
        service.invalidate_configuration();
        assert!(service.is_enabled().is_err());
    }
}
