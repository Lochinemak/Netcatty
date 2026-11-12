//! App-level HTTP proxy for the backend's HTTP calls (Electron:
//! `httpNetworkProxyBridge.cjs`). Not related to SSH proxies / jump hosts.
//!
//! * `system` (default): reqwest's system proxy (platform settings and the
//!   `HTTP(S)_PROXY` / `NO_PROXY` environment);
//! * `direct`: no proxy at all;
//! * `custom`: every request goes through `url`, except hosts matching
//!   `bypass` (Chromium bypass-list syntax; `<local>` = plain host names and
//!   loopback). An empty custom URL behaves like `system`.
//!
//! Credentials in the URL are stripped, as Electron does.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub const DEFAULT_BYPASS: &str = "<local>";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxySettings {
    pub mode: String,
    pub url: String,
    pub bypass: String,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            mode: "system".into(),
            url: String::new(),
            bypass: DEFAULT_BYPASS.into(),
        }
    }
}

/// Untyped renderer input (any field may be missing or of the wrong type).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RawProxySettings {
    pub mode: Option<serde_json::Value>,
    pub url: Option<serde_json::Value>,
    pub bypass: Option<serde_json::Value>,
}

static CURRENT: RwLock<Option<ProxySettings>> = RwLock::new(None);

/// Bumped by every [`set`]; clients built from [`configure`] elsewhere (the
/// AI proxy) compare it to know when to rebuild.
static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn generation() -> u64 {
    GENERATION.load(std::sync::atomic::Ordering::Acquire)
}

fn trimmed(value: Option<&serde_json::Value>) -> String {
    value
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

/// Drop `user:pass@` without otherwise rewriting the URL (drafts such as
/// `http://127.0.0.1:` must survive unchanged).
pub fn strip_userinfo(url: &str) -> String {
    let url = url.trim();
    let (scheme, rest) = match url.find("://") {
        Some(i)
            if url[..i]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c)) =>
        {
            (&url[..i + 3], &url[i + 3..])
        }
        _ => ("", url),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{scheme}{}", &rest[at + 1..]),
        None => url.to_owned(),
    }
}

/// Electron's `normalizeProxySettingsPayload`.
pub fn normalize(raw: &RawProxySettings) -> ProxySettings {
    let mode = trimmed(raw.mode.as_ref());
    match mode.as_str() {
        "direct" => ProxySettings {
            mode: "direct".into(),
            ..ProxySettings::default()
        },
        "custom" => {
            let bypass = trimmed(raw.bypass.as_ref());
            ProxySettings {
                mode: "custom".into(),
                url: strip_userinfo(&trimmed(raw.url.as_ref())),
                bypass: if bypass.is_empty() {
                    DEFAULT_BYPASS.into()
                } else {
                    bypass
                },
            }
        }
        _ => ProxySettings::default(),
    }
}

pub fn current() -> ProxySettings {
    CURRENT.read().clone().unwrap_or_default()
}

/// Store new settings; the shared HTTP client is rebuilt on next use.
pub fn set(settings: ProxySettings) {
    *CURRENT.write() = Some(settings);
    GENERATION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    crate::http::invalidate_client();
}

/// Chromium bypass list → `NO_PROXY` style list for reqwest.
fn no_proxy_list(bypass: &str) -> String {
    bypass
        .split([',', ';', ' ', '\n', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| match entry {
            "<local>" => "localhost,127.0.0.1,::1".to_owned(),
            other => other.trim_start_matches('*').to_owned(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Apply the current settings to a client builder.
pub fn configure(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    let settings = current();
    match settings.mode.as_str() {
        "direct" => builder.no_proxy(),
        "custom" if !settings.url.is_empty() => match reqwest::Proxy::all(&settings.url) {
            Ok(proxy) => builder.proxy(proxy.no_proxy(reqwest::NoProxy::from_string(
                &no_proxy_list(&settings.bypass),
            ))),
            Err(err) => {
                tracing::warn!(%err, "invalid custom HTTP proxy URL; using system proxy");
                builder
            }
        },
        _ => builder,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn raw(mode: &str, url: &str, bypass: &str) -> RawProxySettings {
        RawProxySettings {
            mode: Some(json!(mode)),
            url: Some(json!(url)),
            bypass: Some(json!(bypass)),
        }
    }

    #[test]
    fn normalizes_like_electron() {
        assert_eq!(
            normalize(&RawProxySettings::default()),
            ProxySettings::default()
        );
        assert_eq!(
            normalize(&raw("bogus", "http://x", "a")),
            ProxySettings::default()
        );
        assert_eq!(
            normalize(&raw("direct", "http://x", "a")),
            ProxySettings {
                mode: "direct".into(),
                url: String::new(),
                bypass: "<local>".into()
            }
        );
        assert_eq!(
            normalize(&raw(" custom ", " http://user:pw@proxy:8080/ ", "")),
            ProxySettings {
                mode: "custom".into(),
                url: "http://proxy:8080/".into(),
                bypass: "<local>".into()
            }
        );
    }

    #[test]
    fn strips_userinfo_only() {
        assert_eq!(strip_userinfo("http://127.0.0.1:"), "http://127.0.0.1:");
        assert_eq!(strip_userinfo("socks5://a:b@h:1080"), "socks5://h:1080");
        assert_eq!(strip_userinfo("a@h:3128"), "h:3128");
        assert_eq!(strip_userinfo("http://h/p@x"), "http://h/p@x");
    }

    #[test]
    fn converts_bypass_lists() {
        assert_eq!(
            no_proxy_list("<local>; *.corp.example, 10.0.0.0/8"),
            "localhost,127.0.0.1,::1,.corp.example,10.0.0.0/8"
        );
    }
}
