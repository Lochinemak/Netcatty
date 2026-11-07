//! Shared HTTP plumbing: the reqwest clients and the small helpers every
//! provider uses to shape errors the same way the Electron bridges do.

use netcatty_core::{CoreError, CoreResult};
use parking_lot::RwLock;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};

/// Characters `encodeURIComponent` leaves alone; everything else is escaped.
pub const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');
use std::time::Duration;

const USER_AGENT: &str = concat!("Netcatty/", env!("CARGO_PKG_VERSION"));
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

fn builder() -> reqwest::ClientBuilder {
    crate::proxy::configure(
        reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT),
    )
}

/// Shared client, rebuilt after the app proxy settings change.
static CLIENT: RwLock<Option<reqwest::Client>> = RwLock::new(None);

pub(crate) fn invalidate_client() {
    *CLIENT.write() = None;
}

/// The shared client (app proxy settings, platform certificate verification).
pub fn client() -> CoreResult<reqwest::Client> {
    if let Some(client) = CLIENT.read().as_ref() {
        return Ok(client.clone());
    }
    let client = builder()
        .build()
        .map_err(|err| CoreError::internal(format!("HTTP client init failed: {err}")))?;
    Ok(CLIENT.write().get_or_insert(client).clone())
}

/// Client for a user-configured endpoint. `allow_insecure` skips TLS
/// certificate verification (self-signed WebDAV / S3 servers), mirroring the
/// Electron `rejectUnauthorized: false` agent.
pub fn client_for(allow_insecure: bool) -> CoreResult<reqwest::Client> {
    if !allow_insecure {
        return client();
    }
    builder()
        .tls_danger_accept_invalid_certs(true)
        .build()
        .map_err(|err| CoreError::internal(format!("HTTP client init failed: {err}")))
}

/// Milliseconds since the Unix epoch (`Date.now()`).
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// First `max` characters of `text` (`text.slice(0, max)`).
pub fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// `JSON.parse` that yields `None` instead of throwing.
pub fn safe_json(text: &str) -> Option<serde_json::Value> {
    serde_json::from_str(text).ok()
}

/// Error message plus its source chain, like `describeNetworkError` in the
/// Electron bridges (`message (code): cause`).
pub fn describe_error(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if !text.is_empty() && !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = cause.source();
    }
    out
}

/// Non-empty after trimming (`isNonEmptyString`).
pub fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.trim().is_empty())
}

/// Require a non-empty string argument, failing with `message`.
pub fn require<'a>(value: Option<&'a str>, message: &str) -> CoreResult<&'a str> {
    non_empty(value).ok_or_else(|| CoreError::invalid(message))
}

/// Read a response body as text; transport failures while reading become
/// network errors prefixed with `context`.
pub async fn read_text(response: reqwest::Response, context: &str) -> CoreResult<String> {
    response
        .text()
        .await
        .map_err(|err| CoreError::network(format!("{context}: {}", describe_error(&err))))
}

/// A body that has already been read, together with its status.
pub struct TextResponse {
    pub status: reqwest::StatusCode,
    pub text: String,
}

impl TextResponse {
    pub fn ok(&self) -> bool {
        self.status.is_success()
    }

    pub fn code(&self) -> u16 {
        self.status.as_u16()
    }
}

/// Send `request` and read the body. `network_error` builds the message for
/// transport failures from the described error.
pub async fn send_text(
    request: reqwest::RequestBuilder,
    network_error: impl FnOnce(String) -> String,
) -> CoreResult<TextResponse> {
    let response = request
        .send()
        .await
        .map_err(|err| CoreError::network(network_error(describe_error(&err))))?;
    let status = response.status();
    let text = read_text(response, "Failed to read response").await?;
    Ok(TextResponse { status, text })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_counts_characters_not_bytes() {
        assert_eq!(truncate("héllo", 2), "hé");
        assert_eq!(truncate("ab", 10), "ab");
    }

    #[test]
    fn require_rejects_blank_values() {
        assert!(require(None, "missing").is_err());
        assert!(require(Some("  "), "missing").is_err());
        assert_eq!(require(Some("x"), "missing").unwrap(), "x");
    }
}
