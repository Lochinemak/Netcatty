//! Google OAuth token endpoint and Drive `appDataFolder` storage
//! (`googleAuthBridge.cjs`).

use crate::http::{self, non_empty, require, TextResponse};
use crate::{synced_file, OAuthTokens, SYNC_FILE_NAME};
use netcatty_core::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Endpoints, overridable for tests.
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub token_url: String,
    pub userinfo_url: String,
    pub drive_api: String,
    pub drive_upload_api: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            token_url: "https://oauth2.googleapis.com/token".into(),
            userinfo_url: "https://www.googleapis.com/oauth2/v2/userinfo".into(),
            drive_api: "https://www.googleapis.com/drive/v3".into(),
            drive_upload_api: "https://www.googleapis.com/upload/drive/v3".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeRequest {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub code_verifier: Option<String>,
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileIdResult {
    pub file_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncedFileResult {
    pub synced_file: Option<Value>,
}

const NETWORK_HINT: &str = "Check your network/VPN and whether Google services are reachable.";

fn network_error(what: &str) -> impl FnOnce(String) -> String + '_ {
    move |err| format!("{what} network error. {NETWORK_HINT} ({err})")
}

/// `describeGoogleApiError`: `status - message` from a Google error body.
fn describe_api_error(res: &TextResponse) -> String {
    let data = http::safe_json(&res.text);
    let from_json = data.as_ref().and_then(|d| {
        d.pointer("/error/message")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                d.get("error_description")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .or_else(|| d.get("error").and_then(Value::as_str).map(str::to_owned))
    });
    let msg = from_json.unwrap_or_else(|| {
        let trimmed = res.text.trim();
        if trimmed.is_empty() {
            "Unknown error".to_owned()
        } else {
            trimmed.to_owned()
        }
    });
    format!("{} - {}", res.code(), http::truncate(&msg, 300))
}

fn token_error_detail(res: &TextResponse) -> String {
    let data = http::safe_json(&res.text).unwrap_or_else(|| Value::String(res.text.clone()));
    data.get("error_description")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            data.get("error")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        })
        .or_else(|| data.as_str().filter(|s| !s.is_empty()))
        .map(str::to_owned)
        .unwrap_or_else(|| res.code().to_string())
}

fn drive_status_error(res: &TextResponse, what: &str, not_enabled_on_403: bool) -> CoreError {
    if not_enabled_on_403 && res.code() == 403 {
        return CoreError::network(
            "Google Drive API not enabled. Please enable it in Google Cloud Console.",
        );
    }
    if res.code() == 401 {
        return CoreError::auth("Token expired or invalid. Please reconnect Google Drive.");
    }
    CoreError::network(format!("{what}: {}", describe_api_error(res)))
}

async fn token_request(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    form: &[(&str, &str)],
    label: &str,
) -> CoreResult<Value> {
    let res = http::send_text(
        client
            .post(&endpoints.token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(form),
        network_error(label),
    )
    .await?;
    if !res.ok() {
        return Err(CoreError::auth(format!(
            "{label} failed: {}",
            token_error_detail(&res)
        )));
    }
    serde_json::from_str(&res.text).map_err(|_| {
        CoreError::network(format!(
            "{label} invalid JSON: {}",
            http::truncate(&res.text, 200)
        ))
    })
}

/// Authorization-code + PKCE exchange.
pub async fn exchange_code(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    req: &ExchangeRequest,
) -> CoreResult<OAuthTokens> {
    let client_id = require(req.client_id.as_deref(), "Missing Google clientId")?;
    let code = require(req.code.as_deref(), "Missing authorization code")?;
    let verifier = require(req.code_verifier.as_deref(), "Missing codeVerifier")?;
    let redirect = require(req.redirect_uri.as_deref(), "Missing redirectUri")?;
    let mut form = vec![
        ("client_id", client_id),
        ("code", code),
        ("code_verifier", verifier),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect),
    ];
    if let Some(secret) = non_empty(req.client_secret.as_deref()) {
        form.push(("client_secret", secret));
    }
    let data = token_request(client, endpoints, &form, "Google token exchange").await?;
    Ok(OAuthTokens::from_token_response(&data))
}

/// Refresh-token grant. Google does not rotate refresh tokens, so the input
/// token is returned.
pub async fn refresh_token(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    req: &RefreshRequest,
) -> CoreResult<OAuthTokens> {
    let client_id = require(req.client_id.as_deref(), "Missing Google clientId")?;
    let refresh = require(req.refresh_token.as_deref(), "Missing refreshToken")?;
    let mut form = vec![
        ("client_id", client_id),
        ("refresh_token", refresh),
        ("grant_type", "refresh_token"),
    ];
    if let Some(secret) = non_empty(req.client_secret.as_deref()) {
        form.push(("client_secret", secret));
    }
    let data = token_request(client, endpoints, &form, "Google token refresh").await?;
    let mut tokens = OAuthTokens::from_token_response(&data);
    tokens.refresh_token = Some(refresh.to_owned());
    Ok(tokens)
}

/// `GET /oauth2/v2/userinfo`, returned as is.
pub async fn user_info(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    access_token: Option<&str>,
) -> CoreResult<Value> {
    let token = require(access_token, "Missing accessToken")?;
    let res = http::send_text(
        client.get(&endpoints.userinfo_url).bearer_auth(token),
        network_error("Google userinfo"),
    )
    .await?;
    if !res.ok() {
        return Err(CoreError::network(format!(
            "Google userinfo failed: {} - {}",
            res.code(),
            http::truncate(&res.text, 200)
        )));
    }
    serde_json::from_str(&res.text).map_err(|_| {
        CoreError::network(format!(
            "Google userinfo invalid JSON: {}",
            http::truncate(&res.text, 200)
        ))
    })
}

fn file_name(name: Option<&str>) -> &str {
    non_empty(name).unwrap_or(SYNC_FILE_NAME)
}

fn file_url(base: &str, file_id: &str) -> String {
    let encoded = percent_encoding::utf8_percent_encode(file_id, crate::http::COMPONENT);
    format!("{base}/files/{encoded}")
}

/// Find the sync file in `appDataFolder`.
pub async fn find_sync_file(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    access_token: Option<&str>,
    name: Option<&str>,
) -> CoreResult<FileIdResult> {
    let token = require(access_token, "Missing accessToken")?;
    let query = format!("name = '{}'", file_name(name));
    let res = http::send_text(
        client
            .get(format!("{}/files", endpoints.drive_api))
            .query(&[
                ("spaces", "appDataFolder"),
                ("q", query.as_str()),
                ("fields", "files(id, name, modifiedTime)"),
            ])
            .bearer_auth(token)
            .header(reqwest::header::ACCEPT, "application/json"),
        network_error("Google Drive"),
    )
    .await?;
    if !res.ok() {
        return Err(drive_status_error(&res, "Google Drive API error", true));
    }
    let file_id = http::safe_json(&res.text)
        .and_then(|d| {
            d.pointer("/files/0/id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .filter(|id| !id.is_empty());
    Ok(FileIdResult { file_id })
}

/// Create the sync file in `appDataFolder` (multipart upload).
pub async fn create_sync_file(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    access_token: Option<&str>,
    name: Option<&str>,
    synced: Option<&Value>,
) -> CoreResult<FileIdResult> {
    let token = require(access_token, "Missing accessToken")?;
    let synced = synced
        .filter(|v| !v.is_null())
        .ok_or_else(|| CoreError::invalid("Missing syncedFile"))?;
    let boundary = format!("----netcatty_{}", uuid::Uuid::new_v4());
    let metadata = serde_json::json!({ "name": file_name(name), "parents": ["appDataFolder"] });
    let content = String::from_utf8(synced_file::serialize_pretty(synced)).unwrap_or_default();
    let body = format!(
        "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n\
         --{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{content}\r\n\
         --{boundary}--\r\n"
    );
    let res = http::send_text(
        client
            .post(format!(
                "{}/files?uploadType=multipart",
                endpoints.drive_upload_api
            ))
            .bearer_auth(token)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(
                reqwest::header::CONTENT_TYPE,
                format!("multipart/related; boundary={boundary}"),
            )
            .body(body),
        network_error("Google Drive upload"),
    )
    .await?;
    if !res.ok() {
        return Err(drive_status_error(&res, "Google Drive upload error", true));
    }
    let file_id = http::safe_json(&res.text)
        .and_then(|d| d.get("id").and_then(Value::as_str).map(str::to_owned))
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| {
            CoreError::network(format!(
                "Google Drive upload invalid response: {}",
                http::truncate(&res.text, 200)
            ))
        })?;
    Ok(FileIdResult {
        file_id: Some(file_id),
    })
}

/// Replace the content of an existing sync file.
pub async fn update_sync_file(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    access_token: Option<&str>,
    file_id: Option<&str>,
    synced: Option<&Value>,
) -> CoreResult<()> {
    let token = require(access_token, "Missing accessToken")?;
    let file_id = require(file_id, "Missing fileId")?;
    let synced = synced
        .filter(|v| !v.is_null())
        .ok_or_else(|| CoreError::invalid("Missing syncedFile"))?;
    let res = http::send_text(
        client
            .patch(format!(
                "{}?uploadType=media",
                file_url(&endpoints.drive_upload_api, file_id)
            ))
            .bearer_auth(token)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(synced_file::serialize_pretty(synced)),
        network_error("Google Drive update"),
    )
    .await?;
    if !res.ok() {
        return Err(drive_status_error(&res, "Google Drive update error", true));
    }
    Ok(())
}

/// Download the sync file; a missing file yields `syncedFile: null`.
pub async fn download_sync_file(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    access_token: Option<&str>,
    file_id: Option<&str>,
) -> CoreResult<SyncedFileResult> {
    let token = require(access_token, "Missing accessToken")?;
    let file_id = require(file_id, "Missing fileId")?;
    let res = http::send_text(
        client
            .get(format!(
                "{}?alt=media",
                file_url(&endpoints.drive_api, file_id)
            ))
            .bearer_auth(token)
            .header(reqwest::header::ACCEPT, "application/json"),
        network_error("Google Drive download"),
    )
    .await?;
    if !res.ok() {
        if res.code() == 404 {
            return Ok(SyncedFileResult { synced_file: None });
        }
        return Err(drive_status_error(
            &res,
            "Google Drive download error",
            false,
        ));
    }
    let data = http::safe_json(&res.text).ok_or_else(|| {
        CoreError::network(format!(
            "Google Drive download invalid JSON: {}",
            http::truncate(&res.text, 200)
        ))
    })?;
    Ok(SyncedFileResult {
        synced_file: Some(data),
    })
}

/// Delete the sync file; already-missing files count as deleted.
pub async fn delete_sync_file(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    access_token: Option<&str>,
    file_id: Option<&str>,
) -> CoreResult<()> {
    let token = require(access_token, "Missing accessToken")?;
    let file_id = require(file_id, "Missing fileId")?;
    let res = http::send_text(
        client
            .delete(file_url(&endpoints.drive_api, file_id))
            .bearer_auth(token)
            .header(reqwest::header::ACCEPT, "application/json"),
        network_error("Google Drive delete"),
    )
    .await?;
    if !res.ok() && res.code() != 404 {
        return Err(drive_status_error(&res, "Google Drive delete error", false));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(code: u16, text: &str) -> TextResponse {
        TextResponse {
            status: reqwest::StatusCode::from_u16(code).unwrap(),
            text: text.into(),
        }
    }

    #[test]
    fn api_error_prefers_nested_message() {
        assert_eq!(
            describe_api_error(&res(400, r#"{"error":{"message":"Bad query"}}"#)),
            "400 - Bad query"
        );
        assert_eq!(describe_api_error(&res(500, "")), "500 - Unknown error");
        assert_eq!(describe_api_error(&res(502, " gateway ")), "502 - gateway");
    }

    #[test]
    fn drive_errors_map_like_electron() {
        assert_eq!(
            drive_status_error(&res(403, "{}"), "x", true).message,
            "Google Drive API not enabled. Please enable it in Google Cloud Console."
        );
        assert_eq!(
            drive_status_error(&res(401, "{}"), "x", true).message,
            "Token expired or invalid. Please reconnect Google Drive."
        );
        assert_eq!(
            drive_status_error(
                &res(403, r#"{"error":"denied"}"#),
                "Google Drive download error",
                false
            )
            .message,
            "Google Drive download error: 403 - denied"
        );
    }

    #[test]
    fn token_error_detail_falls_back_to_status() {
        assert_eq!(
            token_error_detail(&res(
                400,
                r#"{"error":"invalid_grant","error_description":"Bad Request"}"#
            )),
            "Bad Request"
        );
        assert_eq!(
            token_error_detail(&res(400, r#"{"error":"invalid_grant"}"#)),
            "invalid_grant"
        );
        assert_eq!(token_error_detail(&res(500, "oops")), "oops");
        assert_eq!(token_error_detail(&res(500, "")), "500");
    }
}
