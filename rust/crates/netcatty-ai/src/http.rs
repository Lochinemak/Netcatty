//! reqwest clients for the AI proxy. They honour the app-level HTTP proxy
//! (`netcatty_sync::proxy`, Electron `httpNetworkProxyAgent.cjs`), never
//! follow redirects on their own (Electron uses `http.request`, which does
//! not either; `aiFetch` re-validates every redirect target itself) and
//! apply no overall request timeout: idle / total deadlines are enforced by
//! the callers, chunk by chunk, so long reasoning streams are not cut off.

use netcatty_core::{CoreError, CoreResult};
use std::sync::Mutex;
use std::time::Duration;

const USER_AGENT: &str = concat!("Netcatty/", env!("CARGO_PKG_VERSION"));
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Cached clients, `[verify, skip_tls_verify]`, tagged with the proxy
/// generation they were built for. A cached client keeps its connection
/// pool, so a chat turn or model listing does not redo TCP + TLS each time.
static CLIENTS: Mutex<[Option<(u64, reqwest::Client)>; 2]> = Mutex::new([None, None]);

/// The client for `skip_tls_verify` (per-provider "skip TLS verification"
/// setting, Electron `rejectUnauthorized: false`), rebuilt after the app
/// proxy settings change.
pub fn client(skip_tls_verify: bool) -> CoreResult<reqwest::Client> {
    let generation = netcatty_sync::proxy::generation();
    let slot = usize::from(skip_tls_verify);
    if let Some((built_for, client)) = &CLIENTS.lock().unwrap_or_else(|e| e.into_inner())[slot] {
        if *built_for == generation {
            return Ok(client.clone());
        }
    }
    let client = build(skip_tls_verify)?;
    CLIENTS.lock().unwrap_or_else(|e| e.into_inner())[slot] = Some((generation, client.clone()));
    Ok(client)
}

#[cfg(test)]
fn cached_generation(skip_tls_verify: bool) -> Option<u64> {
    CLIENTS.lock().unwrap_or_else(|e| e.into_inner())[usize::from(skip_tls_verify)]
        .as_ref()
        .map(|(generation, _)| *generation)
}

fn build(skip_tls_verify: bool) -> CoreResult<reqwest::Client> {
    let mut builder = netcatty_sync::proxy::configure(
        reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none()),
    );
    if skip_tls_verify {
        builder = builder.tls_danger_accept_invalid_certs(true);
    }
    builder
        .build()
        .map_err(|err| CoreError::internal(format!("HTTP client init failed: {err}")))
}

/// Error message plus its source chain (Electron surfaces `err.message`,
/// which for Node network errors already names the cause).
pub fn describe_error(err: &reqwest::Error) -> String {
    netcatty_sync::http::describe_error(err)
}

/// Build a header map from renderer headers, skipping names / values that
/// are not valid HTTP tokens (`http.request` would throw for those; here the
/// request proceeds without the offending header).
pub fn header_map(headers: &crate::providers::Headers) -> reqwest::header::HeaderMap {
    let mut map = reqwest::header::HeaderMap::new();
    for (name, value) in headers {
        let Ok(name) = reqwest::header::HeaderName::from_bytes(name.as_bytes()) else {
            tracing::debug!(name, "skipping invalid header name");
            continue;
        };
        let Ok(value) = reqwest::header::HeaderValue::from_str(value) else {
            tracing::debug!(name = %name, "skipping header with invalid value");
            continue;
        };
        map.insert(name, value);
    }
    map
}

/// HTTP method from the renderer (`method || "GET"`), falling back to
/// `default` for empty / invalid input.
pub fn method(value: Option<&str>, default: reqwest::Method) -> reqwest::Method {
    value
        .filter(|m| !m.trim().is_empty())
        .and_then(|m| reqwest::Method::from_bytes(m.trim().to_ascii_uppercase().as_bytes()).ok())
        .unwrap_or(default)
}

/// Incremental UTF-8 decoder: multi-byte characters split across network
/// chunks are reassembled, invalid sequences become U+FFFD (Node
/// `res.setEncoding("utf8")`).
#[derive(Debug, Default)]
pub struct Utf8Decoder {
    pending: Vec<u8>,
}

impl Utf8Decoder {
    pub fn push(&mut self, chunk: &[u8]) -> String {
        self.pending.extend_from_slice(chunk);
        let mut out = String::new();
        let mut rest: &[u8] = &self.pending;
        loop {
            match std::str::from_utf8(rest) {
                Ok(text) => {
                    out.push_str(text);
                    rest = &[];
                    break;
                }
                Err(err) => {
                    let valid = err.valid_up_to();
                    // SAFETY-free: the prefix is valid UTF-8 by construction.
                    out.push_str(std::str::from_utf8(&rest[..valid]).unwrap_or(""));
                    match err.error_len() {
                        Some(len) => {
                            out.push('\u{FFFD}');
                            rest = &rest[valid + len..];
                        }
                        None => {
                            // Incomplete trailing sequence: keep for the next chunk.
                            rest = &rest[valid..];
                            break;
                        }
                    }
                }
            }
        }
        self.pending = rest.to_vec();
        out
    }

    /// Flush an incomplete trailing sequence (lossy).
    pub fn finish(&mut self) -> String {
        let out = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending.clear();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_decoder_reassembles_split_characters() {
        let text = "环境正常 ok";
        let bytes = text.as_bytes();
        let split = bytes.iter().position(|&b| b == b'\xe5').unwrap() + 1;
        let mut decoder = Utf8Decoder::default();
        let mut out = decoder.push(&bytes[..split]);
        out.push_str(&decoder.push(&bytes[split..]));
        out.push_str(&decoder.finish());
        assert_eq!(out, text);
    }

    #[test]
    fn utf8_decoder_replaces_invalid_bytes() {
        let mut decoder = Utf8Decoder::default();
        assert_eq!(decoder.push(b"a\xffb"), "a\u{FFFD}b");
        assert_eq!(decoder.push(b"\xe5"), "");
        assert_eq!(decoder.finish(), "\u{FFFD}");
    }

    #[test]
    fn clients_are_reused_until_the_proxy_settings_change() {
        client(true).unwrap();
        let first = cached_generation(true).unwrap();
        client(true).unwrap();
        assert_eq!(cached_generation(true), Some(first), "same generation: cached client reused");

        netcatty_sync::proxy::set(netcatty_sync::proxy::current());
        client(true).unwrap();
        assert!(cached_generation(true).unwrap() > first, "proxy change rebuilds the client");
    }

    #[test]
    fn methods_default_and_uppercase() {
        assert_eq!(method(None, reqwest::Method::GET), reqwest::Method::GET);
        assert_eq!(method(Some(" post "), reqwest::Method::GET), reqwest::Method::POST);
        assert_eq!(method(Some(""), reqwest::Method::POST), reqwest::Method::POST);
    }
}
