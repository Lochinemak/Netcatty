//! WebDAV transport for the sync file (WebDAV half of `cloudSyncBridge.cjs`).
//!
//! Only the handful of verbs sync needs are implemented: `PROPFIND` (exists),
//! `GET`, `PUT`, `MOVE` and `DELETE`, with Basic (UTF-8 credentials), Bearer
//! token and Digest authentication.

use crate::http::{self, describe_error};
use crate::{synced_file, SYNC_FILE_NAME};
use netcatty_core::{CoreError, CoreResult};
use parking_lot::Mutex;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Renderer `WebDAVConfig`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebDavConfig {
    #[serde(default)]
    pub endpoint: String,
    /// `basic` (default), `digest` or `token`.
    pub auth_type: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub allow_insecure: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceResult {
    pub resource_id: Option<String>,
}

pub use crate::google::SyncedFileResult;

/// Prefix `https://` when the endpoint has no scheme.
pub fn normalize_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    }
}

/// `Authorization: Basic` with UTF-8 credentials (RFC 7617). The npm
/// `webdav` package encodes Latin-1, which broke non-ASCII passwords (#891).
pub fn basic_auth_header(username: &str, password: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
    )
}

#[derive(Debug, Clone)]
struct DigestChallenge {
    realm: String,
    nonce: String,
    opaque: Option<String>,
    algorithm: String,
    qop_auth: bool,
    nc: u32,
}

/// Parse a `Digest` challenge (`realm="x", nonce="y", qop="auth"`).
fn parse_digest_challenge(header: &str) -> Option<DigestChallenge> {
    let rest = header.trim();
    if rest.len() < 6 || !rest[..6].eq_ignore_ascii_case("digest") {
        return None;
    }
    let mut params = std::collections::HashMap::new();
    let mut chars = rest[6..].trim_start().chars().peekable();
    loop {
        while matches!(chars.peek(), Some(c) if c.is_whitespace() || *c == ',') {
            chars.next();
        }
        let key: String = chars.by_ref().take_while(|c| *c != '=').collect();
        if key.trim().is_empty() {
            break;
        }
        let value = if chars.peek() == Some(&'"') {
            chars.next();
            let mut value = String::new();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        if let Some(next) = chars.next() {
                            value.push(next);
                        }
                    }
                    '"' => break,
                    _ => value.push(c),
                }
            }
            value
        } else {
            chars
                .by_ref()
                .take_while(|c| *c != ',')
                .collect::<String>()
                .trim()
                .to_owned()
        };
        params.insert(key.trim().to_ascii_lowercase(), value);
    }
    Some(DigestChallenge {
        realm: params.get("realm").cloned().unwrap_or_default(),
        nonce: params.get("nonce").cloned()?,
        opaque: params.get("opaque").cloned(),
        algorithm: params
            .get("algorithm")
            .cloned()
            .unwrap_or_else(|| "MD5".into()),
        qop_auth: params.get("qop").is_some_and(|qop| {
            qop.split(',')
                .any(|q| q.trim().eq_ignore_ascii_case("auth"))
        }),
        nc: 0,
    })
}

fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

/// Build the `Authorization: Digest` header for one request.
fn digest_header(
    challenge: &mut DigestChallenge,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    cnonce: &str,
) -> String {
    challenge.nc += 1;
    let nc = format!("{:08x}", challenge.nc);
    let mut ha1 = md5_hex(&format!("{username}:{}:{password}", challenge.realm));
    if challenge.algorithm.eq_ignore_ascii_case("MD5-sess") {
        ha1 = md5_hex(&format!("{ha1}:{}:{cnonce}", challenge.nonce));
    }
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let response = if challenge.qop_auth {
        md5_hex(&format!(
            "{ha1}:{}:{nc}:{cnonce}:auth:{ha2}",
            challenge.nonce
        ))
    } else {
        md5_hex(&format!("{ha1}:{}:{ha2}", challenge.nonce))
    };
    let mut header = format!(
        "Digest username=\"{username}\", realm=\"{}\", nonce=\"{}\", uri=\"{uri}\", algorithm={}, response=\"{response}\"",
        challenge.realm, challenge.nonce, challenge.algorithm
    );
    if challenge.qop_auth {
        header.push_str(&format!(", qop=auth, nc={nc}, cnonce=\"{cnonce}\""));
    }
    if let Some(opaque) = &challenge.opaque {
        header.push_str(&format!(", opaque=\"{opaque}\""));
    }
    header
}

enum Auth {
    Header(String),
    Digest {
        username: String,
        password: String,
        challenge: Mutex<Option<DigestChallenge>>,
    },
}

/// Minimal WebDAV client bound to one endpoint.
pub struct WebDavClient {
    http: reqwest::Client,
    base: String,
    auth: Auth,
}

struct DavResponse {
    status: StatusCode,
    body: Vec<u8>,
}

fn invalid_response(status: StatusCode) -> CoreError {
    CoreError::network(format!(
        "Invalid response: {} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    ))
}

impl WebDavClient {
    pub fn new(config: &WebDavConfig) -> CoreResult<Self> {
        let base = normalize_endpoint(&config.endpoint);
        if base.is_empty() {
            return Err(CoreError::invalid("Missing WebDAV endpoint"));
        }
        let username = config.username.clone().unwrap_or_default();
        let password = config.password.clone().unwrap_or_default();
        let auth = match config.auth_type.as_deref() {
            Some("token") => Auth::Header(format!(
                "Bearer {}",
                config.token.clone().unwrap_or_default()
            )),
            Some("digest") => Auth::Digest {
                username,
                password,
                challenge: Mutex::new(None),
            },
            _ => Auth::Header(basic_auth_header(&username, &password)),
        };
        Ok(Self {
            http: http::client_for(config.allow_insecure.unwrap_or(false))?,
            base: base.trim_end_matches('/').to_owned(),
            auth,
        })
    }

    /// Absolute URL of `path` (`/a/b.json`) under the endpoint.
    pub fn url(&self, path: &str) -> String {
        let encoded: Vec<String> = path
            .split('/')
            .map(|seg| percent_encoding::utf8_percent_encode(seg, http::COMPONENT).to_string())
            .collect();
        format!("{}{}", self.base, encoded.join("/"))
    }

    fn auth_header(&self, method: &Method, url: &str) -> Option<String> {
        match &self.auth {
            Auth::Header(value) => Some(value.clone()),
            Auth::Digest {
                username,
                password,
                challenge,
            } => {
                let mut guard = challenge.lock();
                let challenge = guard.as_mut()?;
                let uri = url::Url::parse(url)
                    .map(|u| match u.query() {
                        Some(q) => format!("{}?{q}", u.path()),
                        None => u.path().to_owned(),
                    })
                    .unwrap_or_else(|_| "/".into());
                let cnonce = uuid::Uuid::new_v4().simple().to_string();
                Some(digest_header(
                    challenge,
                    username,
                    password,
                    method.as_str(),
                    &uri,
                    &cnonce,
                ))
            }
        }
    }

    async fn send_once(
        &self,
        method: &Method,
        url: &str,
        headers: &HeaderMap,
        body: Option<&[u8]>,
    ) -> CoreResult<(StatusCode, HeaderMap, Vec<u8>)> {
        let mut request = self
            .http
            .request(method.clone(), url)
            .headers(headers.clone());
        if let Some(value) = self.auth_header(method, url) {
            request = request.header(AUTHORIZATION, value);
        }
        if let Some(body) = body {
            request = request.body(body.to_vec());
        }
        let response = request
            .send()
            .await
            .map_err(|err| CoreError::network(describe_error(&err)))?;
        let status = response.status();
        let response_headers = response.headers().clone();
        let bytes = response
            .bytes()
            .await
            .map_err(|err| CoreError::network(describe_error(&err)))?;
        Ok((status, response_headers, bytes.to_vec()))
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        headers: HeaderMap,
        body: Option<&[u8]>,
    ) -> CoreResult<DavResponse> {
        let url = self.url(path);
        let (status, response_headers, bytes) =
            self.send_once(&method, &url, &headers, body).await?;
        if status == StatusCode::UNAUTHORIZED {
            if let Auth::Digest { challenge, .. } = &self.auth {
                let parsed = response_headers
                    .get_all(WWW_AUTHENTICATE)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .find_map(parse_digest_challenge);
                if let Some(parsed) = parsed {
                    *challenge.lock() = Some(parsed);
                    let (status, _, bytes) = self.send_once(&method, &url, &headers, body).await?;
                    return Ok(DavResponse {
                        status,
                        body: bytes,
                    });
                }
            }
        }
        Ok(DavResponse {
            status,
            body: bytes,
        })
    }

    /// `PROPFIND Depth: 0`; `false` on 404.
    pub async fn exists(&self, path: &str) -> CoreResult<bool> {
        let mut headers = HeaderMap::new();
        headers.insert("Depth", HeaderValue::from_static("0"));
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml; charset=utf-8"),
        );
        let body = br#"<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/></d:prop></d:propfind>"#;
        let method = Method::from_bytes(b"PROPFIND").expect("valid method");
        let res = self.request(method, path, headers, Some(body)).await?;
        match res.status {
            StatusCode::NOT_FOUND => Ok(false),
            s if s.is_success() => Ok(true),
            s => Err(invalid_response(s)),
        }
    }

    /// `GET` the raw bytes; non-2xx is an error.
    pub async fn get_bytes(&self, path: &str) -> CoreResult<Vec<u8>> {
        let res = self
            .request(Method::GET, path, HeaderMap::new(), None)
            .await?;
        if !res.status.is_success() {
            return Err(invalid_response(res.status));
        }
        Ok(res.body)
    }

    /// `GET` as (lossy) UTF-8 text.
    pub async fn get_text(&self, path: &str) -> CoreResult<String> {
        Ok(String::from_utf8_lossy(&self.get_bytes(path).await?).into_owned())
    }

    /// `PUT` (overwrite).
    pub async fn put(&self, path: &str, body: &[u8]) -> CoreResult<()> {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        let res = self.request(Method::PUT, path, headers, Some(body)).await?;
        if !res.status.is_success() {
            return Err(invalid_response(res.status));
        }
        Ok(())
    }

    /// `MOVE` with `Overwrite: T`.
    pub async fn move_file(&self, from: &str, to: &str) -> CoreResult<()> {
        let mut headers = HeaderMap::new();
        let destination = HeaderValue::from_str(&self.url(to))
            .map_err(|_| CoreError::invalid("Invalid WebDAV destination"))?;
        headers.insert("Destination", destination);
        headers.insert("Overwrite", HeaderValue::from_static("T"));
        let method = Method::from_bytes(b"MOVE").expect("valid method");
        let res = self.request(method, from, headers, None).await?;
        if !res.status.is_success() {
            return Err(invalid_response(res.status));
        }
        Ok(())
    }

    /// `DELETE`.
    pub async fn delete(&self, path: &str) -> CoreResult<()> {
        let res = self
            .request(Method::DELETE, path, HeaderMap::new(), None)
            .await?;
        if !res.status.is_success() {
            return Err(invalid_response(res.status));
        }
        Ok(())
    }

    async fn safe_delete(&self, path: &str) {
        if matches!(self.exists(path).await, Ok(true)) {
            let _ = self.delete(path).await;
        }
    }

    async fn existing_len_strict(&self, path: &str) -> CoreResult<usize> {
        let exists = self.exists(path).await.map_err(|err| {
            CoreError::network(format!(
                "WebDAV replace aborted: could not check existing file ({})",
                err.message
            ))
        })?;
        if !exists {
            return Ok(0);
        }
        self.get_bytes(path).await.map(|b| b.len()).map_err(|err| {
            CoreError::network(format!(
                "WebDAV replace aborted: could not read existing file length ({})",
                err.message
            ))
        })
    }

    async fn try_atomic_replace(&self, path: &str, tmp: &str, body: &[u8]) -> CoreResult<bool> {
        let tmp_min = self.existing_len_strict(tmp).await.unwrap_or(0);
        self.put(tmp, &synced_file::pad_to_at_least(body, tmp_min))
            .await?;
        self.move_file(tmp, path).await?;
        let moved = self.get_text(path).await?;
        Ok(synced_file::remote_matches_body(&moved, body))
    }

    /// Replace `path` with `body` so that the remote is exactly `body`
    /// (possibly followed by whitespace), even on servers whose `PUT` does
    /// not truncate (#2223):
    ///
    /// 1. `PUT` a fixed-name temp file and `MOVE` it into place, then verify;
    /// 2. otherwise `PUT` in place padded with spaces to at least the previous
    ///    length, re-read and verify; grow the pad if a concurrent writer made
    ///    the file longer, up to three attempts.
    pub async fn put_replacing(&self, path: &str, body: &[u8]) -> CoreResult<()> {
        let tmp = format!("{path}.tmp");
        if let Ok(true) = self.try_atomic_replace(path, &tmp, body).await {
            return Ok(());
        }
        self.safe_delete(&tmp).await;

        let mut min_len = self.existing_len_strict(path).await?;
        for _ in 0..3 {
            self.put(path, &synced_file::pad_to_at_least(body, min_len))
                .await?;
            let remote = self.get_text(path).await.map_err(|err| {
                CoreError::network(format!(
                    "WebDAV upload verification failed: could not re-read file ({})",
                    err.message
                ))
            })?;
            if synced_file::remote_matches_body(&remote, body) {
                return Ok(());
            }
            min_len = min_len.max(remote.len()).max(body.len());
        }
        Err(CoreError::network(
            "WebDAV upload verification failed: remote file still does not match uploaded body after padded PUT",
        ))
    }
}

fn sync_path() -> String {
    format!("/{SYNC_FILE_NAME}")
}

fn wrap(operation: &str, err: CoreError) -> CoreError {
    CoreError::new(
        err.code,
        format!("WebDAV {operation} failed: {}", err.message),
    )
}

/// Check the endpoint is reachable and authorized.
pub async fn initialize(config: &WebDavConfig) -> CoreResult<ResourceResult> {
    let run = async {
        let client = WebDavClient::new(config)?;
        let path = sync_path();
        client.exists(&path).await?;
        Ok(ResourceResult {
            resource_id: Some(path),
        })
    };
    run.await.map_err(|err| wrap("initialize", err))
}

/// Upload the sync file (compact JSON).
pub async fn upload(config: &WebDavConfig, synced: &Value) -> CoreResult<ResourceResult> {
    let run = async {
        let client = WebDavClient::new(config)?;
        let path = sync_path();
        client
            .put_replacing(&path, &synced_file::serialize_compact(synced))
            .await?;
        Ok(ResourceResult {
            resource_id: Some(path),
        })
    };
    run.await.map_err(|err| wrap("upload", err))
}

/// Download the sync file; missing or empty yields `syncedFile: null`.
pub async fn download(config: &WebDavConfig) -> CoreResult<SyncedFileResult> {
    let run = async {
        let client = WebDavClient::new(config)?;
        let path = sync_path();
        if !client.exists(&path).await? {
            return Ok(SyncedFileResult { synced_file: None });
        }
        let text = client.get_text(&path).await?;
        Ok(SyncedFileResult {
            synced_file: synced_file::parse_recovering(&text)?,
        })
    };
    run.await.map_err(|err| wrap("download", err))
}

/// Delete the sync file if present.
pub async fn delete(config: &WebDavConfig) -> CoreResult<()> {
    let run = async {
        let client = WebDavClient::new(config)?;
        let path = sync_path();
        if client.exists(&path).await? {
            client.delete(&path).await?;
        }
        Ok(())
    };
    run.await.map_err(|err| wrap("delete", err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_uses_utf8() {
        // "user:pässwörd" in UTF-8, base64.
        assert_eq!(
            basic_auth_header("user", "pässwörd"),
            "Basic dXNlcjpww6Rzc3fDtnJk"
        );
    }

    #[test]
    fn endpoint_normalization() {
        assert_eq!(
            normalize_endpoint(" dav.example.com/remote "),
            "https://dav.example.com/remote"
        );
        assert_eq!(normalize_endpoint("HTTP://x"), "HTTP://x");
        assert_eq!(normalize_endpoint(""), "");
    }

    #[test]
    fn url_joins_and_encodes_segments() {
        let client = WebDavClient::new(&WebDavConfig {
            endpoint: "https://dav.example.com/remote.php/dav/".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            client.url("/netcatty-vault.json"),
            "https://dav.example.com/remote.php/dav/netcatty-vault.json"
        );
        assert_eq!(
            client.url("/a b/c.json"),
            "https://dav.example.com/remote.php/dav/a%20b/c.json"
        );
    }

    #[test]
    fn digest_matches_rfc2617_example() {
        // RFC 2617 §3.5 example.
        let mut challenge = parse_digest_challenge(
            r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#,
        )
        .unwrap();
        let header = digest_header(
            &mut challenge,
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            "0a4f113b",
        );
        assert!(
            header.contains(r#"response="6629fae49393a05397450978507c4ef1""#),
            "{header}"
        );
        assert!(header.contains("nc=00000001"));
        assert!(header.contains(r#"opaque="5ccc069c403ebaf9f0171e9517f40e41""#));
    }

    #[test]
    fn non_digest_challenges_are_ignored() {
        assert!(parse_digest_challenge(r#"Basic realm="x""#).is_none());
        assert!(
            parse_digest_challenge(r#"Digest realm="x""#).is_none(),
            "nonce is required"
        );
    }
}
