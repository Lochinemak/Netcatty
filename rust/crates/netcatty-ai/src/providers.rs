//! Provider registry synced from the renderer (Electron: `aiBridge.cjs`,
//! "Provider registry" section, and the `sync-providers` / `sync-web-search`
//! handlers).
//!
//! API keys stay encrypted in the renderer; it sends the placeholder
//! [`API_KEY_PLACEHOLDER`] in headers / URLs and the backend swaps in the
//! decrypted key right before the HTTP request. Web search works the same
//! way with [`WEB_SEARCH_KEY_PLACEHOLDER`].

use crate::allowlist::FetchAllowlist;
use percent_encoding::utf8_percent_encode;
use serde_json::Value;
use std::collections::BTreeMap;

/// Placeholder token used by the renderer to avoid sending real API keys over IPC.
pub const API_KEY_PLACEHOLDER: &str = "__IPC_SECURED__";
/// Placeholder for the web search API key — replaced before the HTTP request.
pub const WEB_SEARCH_KEY_PLACEHOLDER: &str = "__WEB_SEARCH_KEY__";

/// Encrypted-value prefixes (`enc:v1:` Electron safeStorage, `enc:v2:` the
/// Rust credential cipher).
pub const ENC_PREFIXES: &[&str] = &["enc:v1:", "enc:v2:"];

/// Is `value` an encrypted blob rather than plaintext?
pub fn is_encrypted(value: &str) -> bool {
    ENC_PREFIXES.iter().any(|p| value.starts_with(p))
}

/// Decrypts stored secret values. Returns the value unchanged when it is
/// plaintext or cannot be decrypted on this machine, and an empty string
/// when decryption fails (Electron `decryptApiKeyValue`).
pub type Decrypt<'a> = dyn Fn(&str) -> String + 'a;

/// Decryption used when no cipher is available: plaintext passes through,
/// encrypted blobs stay as they are ("cannot decrypt").
pub fn passthrough_decrypt(value: &str) -> String {
    value.to_owned()
}

/// One synced provider config (only the fields the backend needs; the
/// renderer sends the whole `ProviderConfig` object).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProviderConfig {
    pub id: String,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub skip_tls_verify: bool,
    pub custom_headers: BTreeMap<String, String>,
}

impl ProviderConfig {
    /// Lenient parse of a renderer provider object (unknown / mistyped fields
    /// are ignored, like Electron keeping the raw objects).
    pub fn from_value(value: &Value) -> Option<Self> {
        let obj = value.as_object()?;
        let str_field = |name: &str| obj.get(name).and_then(Value::as_str).map(str::to_owned);
        let custom_headers = obj
            .get("customHeaders")
            .and_then(Value::as_object)
            .map(|headers| {
                headers
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            id: str_field("id").unwrap_or_default(),
            api_key: str_field("apiKey"),
            base_url: str_field("baseURL").filter(|u| !u.is_empty()),
            skip_tls_verify: obj.get("skipTLSVerify").and_then(Value::as_bool) == Some(true),
            custom_headers,
        })
    }
}

/// Synced provider configs, web-search config and the derived allowlist.
#[derive(Debug)]
pub struct ProviderRegistry {
    configs: Vec<ProviderConfig>,
    web_search_api_key_encrypted: Option<String>,
    pub allowlist: FetchAllowlist,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self {
            configs: Vec::new(),
            web_search_api_key_encrypted: None,
            allowlist: FetchAllowlist::new(),
        }
    }
}

/// Header map as the renderer sends it (`Record<string, string>`; non-string
/// values are stringified).
pub type Headers = BTreeMap<String, String>;

/// Convert a renderer header object into [`Headers`].
pub fn headers_from_value(value: Option<&Value>) -> Headers {
    let mut headers = Headers::new();
    if let Some(obj) = value.and_then(Value::as_object) {
        for (k, v) in obj {
            match v {
                Value::String(s) => {
                    headers.insert(k.clone(), s.clone());
                }
                Value::Null => {}
                other => {
                    headers.insert(k.clone(), other.to_string());
                }
            }
        }
    }
    headers
}

impl ProviderRegistry {
    /// `aiSyncProviders`: replace the provider configs and rebuild the allowlist.
    pub fn sync_providers(&mut self, providers: &[Value]) {
        self.configs = providers.iter().filter_map(ProviderConfig::from_value).collect();
        let base_urls = self.configs.iter().filter_map(|c| c.base_url.clone()).collect();
        self.allowlist.set_provider_base_urls(base_urls);
    }

    /// `aiSyncWebSearch`: replace the web-search host and (encrypted) key.
    pub fn sync_web_search(&mut self, api_host: Option<String>, api_key: Option<String>) {
        self.web_search_api_key_encrypted = api_key;
        self.allowlist.set_web_search_api_host(api_host);
    }

    pub fn configs(&self) -> &[ProviderConfig] {
        &self.configs
    }

    pub fn provider(&self, provider_id: &str) -> Option<&ProviderConfig> {
        self.configs.iter().find(|c| c.id == provider_id)
    }

    /// Should TLS verification be skipped for this provider?
    pub fn should_skip_tls_verify(&self, provider_id: Option<&str>) -> bool {
        provider_id
            .and_then(|id| self.provider(id))
            .is_some_and(|c| c.skip_tls_verify)
    }

    /// Replace the API key placeholder in header values and the URL with the
    /// decrypted key, then apply the provider's custom headers
    /// (case-insensitively overriding existing ones). Errors when an
    /// encrypted custom header cannot be decrypted.
    pub fn inject_api_key(
        &self,
        url: &str,
        headers: &Headers,
        provider_id: Option<&str>,
        decrypt: &Decrypt<'_>,
    ) -> Result<(String, Headers), String> {
        let Some(provider) = provider_id.and_then(|id| self.provider(id)) else {
            return Ok((url.to_owned(), headers.clone()));
        };
        let real_key = provider.api_key.as_deref().map(decrypt).unwrap_or_default();
        // `String#replace` with a string pattern replaces the first occurrence only.
        let mut patched: Headers = headers
            .iter()
            .map(|(k, v)| (k.clone(), v.replacen(API_KEY_PLACEHOLDER, &real_key, 1)))
            .collect();
        let patched_url = if url.contains(API_KEY_PLACEHOLDER) {
            let encoded = utf8_percent_encode(&real_key, netcatty_sync::http::COMPONENT).to_string();
            url.replacen(API_KEY_PLACEHOLDER, &encoded, 1)
        } else {
            url.to_owned()
        };
        for (name, stored) in &provider.custom_headers {
            let value = decrypt(stored);
            if is_encrypted(stored) && (value.is_empty() || value == *stored) {
                return Err("Unable to decrypt custom HTTP headers".into());
            }
            // Replace case-insensitively, including SDK-generated authorization headers.
            patched.retain(|key, _| !key.eq_ignore_ascii_case(name));
            patched.insert(name.clone(), value);
        }
        Ok((patched_url, patched))
    }

    /// Replace the web search key placeholder in header values.
    pub fn inject_web_search_key(&self, headers: &Headers, decrypt: &Decrypt<'_>) -> Headers {
        let Some(encrypted) = self.web_search_api_key_encrypted.as_deref() else {
            return headers.clone();
        };
        let real_key = decrypt(encrypted);
        if real_key.is_empty() {
            return headers.clone();
        }
        headers
            .iter()
            .map(|(k, v)| (k.clone(), v.replacen(WEB_SEARCH_KEY_PLACEHOLDER, &real_key, 1)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn registry() -> ProviderRegistry {
        let mut registry = ProviderRegistry::default();
        registry.sync_providers(&[
            json!({ "id": "openai", "providerId": "openai", "apiKey": "enc:v2:sealed", "baseURL": "https://llm.example/v1", "enabled": true }),
            json!({ "id": "tls", "apiKey": "plain-key", "skipTLSVerify": true, "customHeaders": { "authorization": "enc:v2:hdr", "X-Tenant": "tenant" } }),
            json!("not an object"),
        ]);
        registry
    }

    fn decrypt(value: &str) -> String {
        match value {
            "enc:v2:sealed" => "real-key".into(),
            "enc:v2:hdr" => "Bearer tenant-secret".into(),
            other => other.to_owned(),
        }
    }

    #[test]
    fn parses_provider_objects_leniently() {
        let registry = registry();
        assert_eq!(registry.configs().len(), 2);
        assert_eq!(registry.provider("openai").unwrap().base_url.as_deref(), Some("https://llm.example/v1"));
        assert!(registry.should_skip_tls_verify(Some("tls")));
        assert!(!registry.should_skip_tls_verify(Some("openai")));
        assert!(!registry.should_skip_tls_verify(None));
        assert!(!registry.should_skip_tls_verify(Some("missing")));
    }

    #[test]
    fn injects_the_decrypted_key_into_headers_and_url() {
        let registry = registry();
        let headers: Headers = [
            ("Authorization".to_owned(), "Bearer __IPC_SECURED__".to_owned()),
            ("x-other".to_owned(), "keep".to_owned()),
        ]
        .into_iter()
        .collect();
        let (url, patched) = registry
            .inject_api_key("https://llm.example/v1?key=__IPC_SECURED__", &headers, Some("openai"), &decrypt)
            .unwrap();
        assert_eq!(url, "https://llm.example/v1?key=real-key");
        assert_eq!(patched["Authorization"], "Bearer real-key");
        assert_eq!(patched["x-other"], "keep");
        // Unknown provider: untouched.
        let (url, same) = registry.inject_api_key("u", &headers, Some("nope"), &decrypt).unwrap();
        assert_eq!(url, "u");
        assert_eq!(same, headers);
        let (_, same) = registry.inject_api_key("u", &headers, None, &decrypt).unwrap();
        assert_eq!(same, headers);
    }

    #[test]
    fn url_keys_are_component_encoded() {
        let mut registry = ProviderRegistry::default();
        registry.sync_providers(&[json!({ "id": "g", "apiKey": "a b&c/d" })]);
        let (url, _) = registry
            .inject_api_key("https://g.example/x?key=__IPC_SECURED__", &Headers::new(), Some("g"), &passthrough_decrypt)
            .unwrap();
        assert_eq!(url, "https://g.example/x?key=a%20b%26c%2Fd");
    }

    #[test]
    fn custom_headers_are_decrypted_and_override_case_insensitively() {
        let registry = registry();
        let headers: Headers = [
            ("Authorization".to_owned(), "Bearer __IPC_SECURED__".to_owned()),
            ("X-Other".to_owned(), "keep".to_owned()),
        ]
        .into_iter()
        .collect();
        let (_, patched) = registry.inject_api_key("https://x", &headers, Some("tls"), &decrypt).unwrap();
        assert!(!patched.contains_key("Authorization"));
        assert_eq!(patched["authorization"], "Bearer tenant-secret");
        assert_eq!(patched["X-Tenant"], "tenant");
        assert_eq!(patched["X-Other"], "keep");
        // Undecryptable encrypted custom header → error (never sent as a blob).
        let err = registry
            .inject_api_key("https://x", &headers, Some("tls"), &passthrough_decrypt)
            .unwrap_err();
        assert!(err.contains("Unable to decrypt"));
    }

    #[test]
    fn web_search_key_injection() {
        let mut registry = ProviderRegistry::default();
        let headers: Headers = [("X-API-Key".to_owned(), "__WEB_SEARCH_KEY__".to_owned())]
            .into_iter()
            .collect();
        assert_eq!(registry.inject_web_search_key(&headers, &decrypt), headers);
        registry.sync_web_search(Some("https://api.tavily.com".into()), Some("enc:v2:sealed".into()));
        assert_eq!(registry.inject_web_search_key(&headers, &decrypt)["X-API-Key"], "real-key");
        assert!(registry.allowlist.is_allowed("https://api.tavily.com/search", false));
    }

    #[test]
    fn header_values_are_stringified() {
        let headers = headers_from_value(Some(&json!({ "a": "x", "b": 1, "c": null, "d": true })));
        assert_eq!(headers["a"], "x");
        assert_eq!(headers["b"], "1");
        assert_eq!(headers["d"], "true");
        assert!(!headers.contains_key("c"));
        assert!(headers_from_value(None).is_empty());
    }
}
