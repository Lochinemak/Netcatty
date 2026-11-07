//! S3-compatible object storage for the sync file (S3 half of
//! `cloudSyncBridge.cjs`). Requests are signed with AWS Signature Version 4;
//! only `HEAD`, `GET`, `PUT` and `DELETE` of a single object are needed.

use crate::http::{self, describe_error};
use crate::{synced_file, SYNC_FILE_NAME};
use hmac::{Hmac, KeyInit, Mac};
use netcatty_core::{CoreError, CoreResult, ErrorCode};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use crate::google::SyncedFileResult;
pub use crate::webdav::ResourceResult;

/// Renderer `S3Config`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct S3Config {
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub prefix: Option<String>,
    pub force_path_style: Option<bool>,
    pub allow_insecure: Option<bool>,
}

/// SigV4 URI encoding: everything but `A-Z a-z 0-9 - _ . ~`.
const S3_UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// `<prefix>/netcatty-vault.json`, prefix trimmed of slashes.
pub fn object_key(config: &S3Config) -> String {
    let prefix = config
        .prefix
        .as_deref()
        .unwrap_or("")
        .trim()
        .trim_matches('/');
    if prefix.is_empty() {
        SYNC_FILE_NAME.to_owned()
    } else {
        format!("{prefix}/{SYNC_FILE_NAME}")
    }
}

fn region(config: &S3Config) -> &str {
    let region = config.region.trim();
    if region.is_empty() {
        "us-east-1"
    } else {
        region
    }
}

fn encode_key(key: &str) -> String {
    key.split('/')
        .map(|seg| percent_encoding::utf8_percent_encode(seg, S3_UNRESERVED).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// Object URL, path-style (default, like the Electron client) or
/// virtual-hosted style.
pub fn object_url(config: &S3Config, key: &str) -> CoreResult<url::Url> {
    let endpoint = crate::webdav::normalize_endpoint(&config.endpoint);
    let endpoint = if endpoint.is_empty() {
        format!("https://s3.{}.amazonaws.com", region(config))
    } else {
        endpoint
    };
    let base = url::Url::parse(&endpoint)
        .map_err(|_| CoreError::invalid(format!("Invalid S3 endpoint: {endpoint}")))?;
    let bucket = config.bucket.trim();
    if bucket.is_empty() {
        return Err(CoreError::invalid("Missing S3 bucket"));
    }
    let base_path = base.path().trim_end_matches('/');
    let encoded_key = encode_key(key);
    let mut url = base.clone();
    if config.force_path_style.unwrap_or(true) {
        url.set_path(&format!("{base_path}/{}/{encoded_key}", encode_key(bucket)));
    } else {
        let host = base
            .host_str()
            .ok_or_else(|| CoreError::invalid(format!("Invalid S3 endpoint: {endpoint}")))?;
        url.set_host(Some(&format!("{bucket}.{host}")))
            .map_err(|_| CoreError::invalid(format!("Invalid S3 bucket host: {bucket}.{host}")))?;
        url.set_path(&format!("{base_path}/{encoded_key}"));
    }
    url.set_query(None);
    Ok(url)
}

fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Inputs of one SigV4 signature.
pub struct SigningParams<'a> {
    pub method: &'a str,
    /// Already URI-encoded path.
    pub canonical_uri: &'a str,
    /// `host` plus every `x-amz-*` (and any other) header to sign, lowercase
    /// names; sorted here.
    pub headers: Vec<(String, String)>,
    pub payload_hash: &'a str,
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub region: &'a str,
    /// `YYYYMMDDTHHMMSSZ`.
    pub amz_date: &'a str,
}

/// The `Authorization` header value for `params`.
pub fn authorization(params: &SigningParams<'_>) -> String {
    let mut headers: Vec<(String, String)> = params
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{}\n{}\n\n{canonical_headers}\n{signed_headers}\n{}",
        params.method, params.canonical_uri, params.payload_hash
    );
    let date = &params.amz_date[..8];
    let scope = format!("{date}/{}/s3/aws4_request", params.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        params.amz_date,
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac_sha256(format!("AWS4{}", params.secret_access_key).as_bytes(), date);
    let k_region = hmac_sha256(&k_date, params.region);
    let k_service = hmac_sha256(&k_region, "s3");
    let k_signing = hmac_sha256(&k_service, "aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, &string_to_sign));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        params.access_key_id
    )
}

struct S3Response {
    status: StatusCode,
    body: String,
}

async fn send(config: &S3Config, method: Method, body: Option<Vec<u8>>) -> CoreResult<S3Response> {
    let key = object_key(config);
    let url = object_url(config, &key)?;
    let host = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_owned(),
    };
    let payload_hash = match &body {
        Some(bytes) => sha256_hex(bytes),
        None => EMPTY_SHA256.to_owned(),
    };
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let mut signed = vec![
        ("host".to_owned(), host),
        ("x-amz-content-sha256".to_owned(), payload_hash.clone()),
        ("x-amz-date".to_owned(), amz_date.clone()),
    ];
    if let Some(token) = http::non_empty(config.session_token.as_deref()) {
        signed.push(("x-amz-security-token".to_owned(), token.to_owned()));
    }
    let auth = authorization(&SigningParams {
        method: method.as_str(),
        canonical_uri: url.path(),
        headers: signed.clone(),
        payload_hash: &payload_hash,
        access_key_id: &config.access_key_id,
        secret_access_key: &config.secret_access_key,
        region: region(config),
        amz_date: &amz_date,
    });

    let client = http::client_for(config.allow_insecure.unwrap_or(false))?;
    let mut request = client
        .request(method, url)
        .header(reqwest::header::AUTHORIZATION, auth);
    for (name, value) in signed.into_iter().filter(|(name, _)| name != "host") {
        request = request.header(name, value);
    }
    if let Some(bytes) = body {
        request = request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes);
    }
    let response = request
        .send()
        .await
        .map_err(|err| CoreError::network(describe_error(&err)))?;
    let status = response.status();
    let body = http::read_text(response, "Failed to read S3 response").await?;
    Ok(S3Response { status, body })
}

fn xml_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim()).filter(|s| !s.is_empty())
}

/// Error message from an S3 XML error body (`Message`, else `Code`).
fn error_message(res: &S3Response) -> String {
    xml_tag(&res.body, "Message")
        .or_else(|| xml_tag(&res.body, "Code"))
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "HTTP {} {}",
                res.status.as_u16(),
                res.status.canonical_reason().unwrap_or("")
            )
            .trim_end()
            .to_owned()
        })
}

fn wrap(operation: &str, err: CoreError) -> CoreError {
    CoreError::new(err.code, format!("S3 {operation} failed: {}", err.message))
}

fn status_error(operation: &str, res: &S3Response) -> CoreError {
    let code = if res.status == StatusCode::FORBIDDEN || res.status == StatusCode::UNAUTHORIZED {
        ErrorCode::AuthFailed
    } else {
        ErrorCode::Network
    };
    CoreError::new(
        code,
        format!("S3 {operation} failed: {}", error_message(res)),
    )
}

/// `HEAD` the object: a missing object is fine, 403 is "access denied".
pub async fn initialize(config: &S3Config) -> CoreResult<ResourceResult> {
    let res = send(config, Method::HEAD, None)
        .await
        .map_err(|e| wrap("initialize", e))?;
    if res.status == StatusCode::FORBIDDEN {
        return Err(CoreError::auth("S3 access denied"));
    }
    if !res.status.is_success() && res.status != StatusCode::NOT_FOUND {
        return Err(status_error("initialize", &res));
    }
    Ok(ResourceResult {
        resource_id: Some(object_key(config)),
    })
}

/// `PUT` the sync file (compact JSON).
pub async fn upload(config: &S3Config, synced: &Value) -> CoreResult<ResourceResult> {
    let res = send(
        config,
        Method::PUT,
        Some(synced_file::serialize_compact(synced)),
    )
    .await
    .map_err(|e| wrap("upload", e))?;
    if !res.status.is_success() {
        return Err(status_error("upload", &res));
    }
    Ok(ResourceResult {
        resource_id: Some(object_key(config)),
    })
}

/// `GET` the sync file; missing or empty yields `syncedFile: null`.
pub async fn download(config: &S3Config) -> CoreResult<SyncedFileResult> {
    let res = send(config, Method::GET, None)
        .await
        .map_err(|e| wrap("download", e))?;
    if res.status == StatusCode::NOT_FOUND {
        return Ok(SyncedFileResult { synced_file: None });
    }
    if !res.status.is_success() {
        return Err(status_error("download", &res));
    }
    if res.body.is_empty() {
        return Ok(SyncedFileResult { synced_file: None });
    }
    let data = synced_file::parse_strict(&res.body).map_err(|e| wrap("download", e))?;
    Ok(SyncedFileResult {
        synced_file: Some(data),
    })
}

/// `DELETE` the sync file; already-missing counts as deleted.
pub async fn delete(config: &S3Config) -> CoreResult<()> {
    let res = send(config, Method::DELETE, None)
        .await
        .map_err(|e| wrap("delete", e))?;
    if !res.status.is_success() && res.status != StatusCode::NOT_FOUND {
        return Err(status_error("delete", &res));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_matches_aws_get_object_example() {
        // AWS SigV4 documentation, "Example: GET Object".
        let auth = authorization(&SigningParams {
            method: "GET",
            canonical_uri: "/test.txt",
            headers: vec![
                ("host".into(), "examplebucket.s3.amazonaws.com".into()),
                ("range".into(), "bytes=0-9".into()),
                ("x-amz-content-sha256".into(), EMPTY_SHA256.into()),
                ("x-amz-date".into(), "20130524T000000Z".into()),
            ],
            payload_hash: EMPTY_SHA256,
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            amz_date: "20130524T000000Z",
        });
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    fn config(endpoint: &str, path_style: Option<bool>) -> S3Config {
        S3Config {
            endpoint: endpoint.into(),
            region: "auto".into(),
            bucket: "my-bucket".into(),
            prefix: Some("/team/netcatty/".into()),
            force_path_style: path_style,
            ..Default::default()
        }
    }

    #[test]
    fn object_key_trims_prefix_slashes() {
        assert_eq!(
            object_key(&config("x", None)),
            "team/netcatty/netcatty-vault.json"
        );
        assert_eq!(object_key(&S3Config::default()), "netcatty-vault.json");
    }

    #[test]
    fn urls_for_both_addressing_styles() {
        let key = "team/netcatty/netcatty-vault.json";
        assert_eq!(
            object_url(&config("minio.local:9000", None), key)
                .unwrap()
                .as_str(),
            "https://minio.local:9000/my-bucket/team/netcatty/netcatty-vault.json"
        );
        assert_eq!(
            object_url(&config("https://s3.example.com/base/", Some(false)), key)
                .unwrap()
                .as_str(),
            "https://my-bucket.s3.example.com/base/team/netcatty/netcatty-vault.json"
        );
        let mut aws = config("", None);
        aws.region = "eu-west-1".into();
        assert_eq!(
            object_url(&aws, "a b.json").unwrap().as_str(),
            "https://s3.eu-west-1.amazonaws.com/my-bucket/a%20b.json"
        );
    }

    #[test]
    fn xml_error_message_extraction() {
        let res = S3Response {
            status: StatusCode::NOT_FOUND,
            body: "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>".into(),
        };
        assert_eq!(error_message(&res), "The specified bucket does not exist");
        let empty = S3Response {
            status: StatusCode::BAD_GATEWAY,
            body: String::new(),
        };
        assert_eq!(error_message(&empty), "HTTP 502 Bad Gateway");
    }
}
