//! Non-streaming provider proxy (`netcatty:ai:fetch`, Electron
//! `aiBridge/providerHandlers.cjs` `doFetch`): model listing, validation,
//! web search. Bounded body, inactivity timeout, optional manual redirect
//! following with re-validation of every target against the allowlist.

use crate::http::{client, describe_error, header_map, method};
use crate::providers::Headers;
use serde::Serialize;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Default response cap (`MAX_RESPONSE_SIZE`).
pub const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
/// Response cap for delegated (plugin agent) fetches.
pub const DELEGATED_MAX_RESPONSE_BYTES: usize = 131_072;
/// Socket inactivity timeout (`timeout: 30000`).
pub const FETCH_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Redirects followed when `followRedirects` is set.
pub const MAX_REDIRECTS: u32 = 5;

#[derive(Debug, Clone, Default)]
pub struct FetchRequest {
    /// Final URL (placeholders already replaced).
    pub url: String,
    pub method: Option<String>,
    /// Final headers (placeholders already replaced).
    pub headers: Headers,
    pub body: Option<String>,
    pub skip_tls_verify: bool,
    pub follow_redirects: bool,
    /// Cap for the response body; `None` → [`MAX_RESPONSE_BYTES`].
    pub max_response_bytes: Option<usize>,
}

/// `{ ok, status, data, error? }` — the renderer builds a `Response` from it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FetchResult {
    pub ok: bool,
    pub status: u16,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl FetchResult {
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            status: 0,
            data: String::new(),
            error: Some(error.into()),
        }
    }
}

/// Perform the request. `is_allowed` re-validates redirect targets (the
/// caller has already validated the initial URL). `cancel` aborts the
/// request (delegated fetches only; the result is then an `Aborted` error).
pub async fn ai_fetch<F>(request: FetchRequest, is_allowed: F, cancel: CancellationToken) -> FetchResult
where
    F: Fn(&str) -> bool,
{
    let http = match client(request.skip_tls_verify) {
        Ok(client) => client,
        Err(err) => return FetchResult::failure(err.message),
    };
    let method = method(request.method.as_deref(), reqwest::Method::GET);
    let headers = header_map(&request.headers);
    let max_bytes = request.max_response_bytes.unwrap_or(MAX_RESPONSE_BYTES);
    let mut url = request.url.clone();
    let mut redirects_left = if request.follow_redirects { MAX_REDIRECTS } else { 0 };

    loop {
        let mut builder = http.request(method.clone(), &url).headers(headers.clone());
        if let Some(body) = request.body.as_deref().filter(|b| !b.is_empty()) {
            builder = builder.body(body.to_owned());
        }
        let send = builder.send();
        let response = tokio::select! {
            biased;
            _ = cancel.cancelled() => return FetchResult::failure("Aborted"),
            _ = tokio::time::sleep(FETCH_IDLE_TIMEOUT) => return FetchResult::failure("Request timeout"),
            result = send => match result {
                Ok(response) => response,
                Err(err) => return FetchResult::failure(describe_error(&err)),
            },
        };

        let status = response.status();
        if redirects_left > 0 && status.is_redirection() {
            if let Some(location) = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
            {
                let target = url::Url::parse(&url)
                    .ok()
                    .and_then(|base| base.join(location).ok())
                    .map(|u| u.to_string());
                // Revalidate the redirect target hostname (blocks localhost/metadata etc.).
                let Some(target) = target.filter(|t| is_allowed(t)) else {
                    return FetchResult::failure("Redirect target is not allowed");
                };
                url = target;
                redirects_left -= 1;
                continue;
            }
        }

        let mut response = response;
        let mut data: Vec<u8> = Vec::new();
        loop {
            let next = tokio::select! {
                biased;
                _ = cancel.cancelled() => return FetchResult::failure("Aborted"),
                _ = tokio::time::sleep(FETCH_IDLE_TIMEOUT) => return FetchResult::failure("Request timeout"),
                chunk = response.chunk() => chunk,
            };
            match next {
                Ok(Some(bytes)) => {
                    if data.len() + bytes.len() > max_bytes {
                        return FetchResult::failure("Response body exceeded maximum size (10MB)");
                    }
                    data.extend_from_slice(&bytes);
                }
                Ok(None) => break,
                Err(err) => return FetchResult::failure(describe_error(&err)),
            }
        }
        return FetchResult {
            ok: status.is_success(),
            status: status.as_u16(),
            data: String::from_utf8_lossy(&data).into_owned(),
            error: None,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{serve_once, ScriptedResponse};

    #[tokio::test]
    async fn returns_status_and_body_and_sends_content_length() {
        let (base, received) = serve_once(vec![ScriptedResponse::text(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"data\":[1]}\n",
        )])
        .await;
        let result = ai_fetch(
            FetchRequest {
                url: format!("{base}/v1/models"),
                method: Some("POST".into()),
                headers: [("x-test".to_owned(), "yes".to_owned())].into_iter().collect(),
                body: Some("{\"q\":\"環境\"}".into()),
                ..FetchRequest::default()
            },
            |_| true,
            CancellationToken::new(),
        )
        .await;
        assert!(result.ok);
        assert_eq!(result.status, 200);
        assert_eq!(result.data, "{\"data\":[1]}\n");
        let request = received.await.unwrap();
        let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
        assert!(request_text.starts_with("post /v1/models http/1.1"));
        assert!(request_text.contains("x-test: yes"));
        // Content-Length counts bytes, not UTF-16 code units, and no chunked encoding is used.
        assert!(request_text.contains(&format!("content-length: {}", "{\"q\":\"環境\"}".len())), "{request_text}");
        assert!(!request_text.contains("transfer-encoding"));
    }

    #[tokio::test]
    async fn non_2xx_is_not_ok_but_carries_the_body() {
        let (base, _) = serve_once(vec![ScriptedResponse::text(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 5\r\nConnection: close\r\n\r\nnope!",
        )])
        .await;
        let result = ai_fetch(
            FetchRequest { url: format!("{base}/x"), ..FetchRequest::default() },
            |_| true,
            CancellationToken::new(),
        )
        .await;
        assert_eq!(result, FetchResult { ok: false, status: 401, data: "nope!".into(), error: None });
    }

    #[tokio::test]
    async fn redirects_are_only_followed_when_requested_and_allowed() {
        let (base, _) = serve_once(vec![ScriptedResponse::text(
            "HTTP/1.1 302 Found\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )])
        .await;
        // Not following: the 302 itself is the answer.
        let result = ai_fetch(
            FetchRequest { url: format!("{base}/x"), ..FetchRequest::default() },
            |_| true,
            CancellationToken::new(),
        )
        .await;
        assert_eq!(result.status, 302);

        let (base, _) = serve_once(vec![ScriptedResponse::text(
            "HTTP/1.1 302 Found\r\nLocation: https://metadata.google.internal/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )])
        .await;
        let result = ai_fetch(
            FetchRequest { url: format!("{base}/x"), follow_redirects: true, ..FetchRequest::default() },
            |target| !target.contains("metadata.google.internal"),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(result.error.as_deref(), Some("Redirect target is not allowed"));
        assert_eq!(result.status, 0);

        let (base, _) = serve_once(vec![
            ScriptedResponse::text(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
            ScriptedResponse::text("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"),
        ])
        .await;
        let result = ai_fetch(
            FetchRequest { url: format!("{base}/x"), follow_redirects: true, ..FetchRequest::default() },
            |target| target.ends_with("/final"),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(result, FetchResult { ok: true, status: 200, data: "ok".into(), error: None });
    }

    #[tokio::test]
    async fn oversized_bodies_are_rejected() {
        let (base, _) = serve_once(vec![ScriptedResponse::text(&format!(
            "HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\n{}",
            "x".repeat(64)
        ))])
        .await;
        let result = ai_fetch(
            FetchRequest { url: format!("{base}/x"), max_response_bytes: Some(32), ..FetchRequest::default() },
            |_| true,
            CancellationToken::new(),
        )
        .await;
        assert_eq!(result.error.as_deref(), Some("Response body exceeded maximum size (10MB)"));
    }

    #[tokio::test]
    async fn connection_errors_are_reported_not_thrown() {
        let result = ai_fetch(
            FetchRequest { url: "http://127.0.0.1:1/x".into(), ..FetchRequest::default() },
            |_| true,
            CancellationToken::new(),
        )
        .await;
        assert!(!result.ok);
        assert_eq!(result.status, 0);
        assert!(result.error.is_some());
    }
}
