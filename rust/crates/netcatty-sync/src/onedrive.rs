//! OneDrive OAuth (Microsoft identity platform, consumers tenant) and Graph
//! app-folder storage (`onedriveAuthBridge.cjs`).

use crate::http::{self, non_empty, require, TextResponse};
use crate::{synced_file, OAuthTokens, SYNC_FILE_NAME};
use base64::Engine;
use netcatty_core::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Endpoints, overridable for tests.
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub token_url: String,
    pub graph_api: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            token_url: "https://login.microsoftonline.com/consumers/oauth2/v2.0/token".into(),
            graph_api: "https://graph.microsoft.com/v1.0".into(),
        }
    }
}

const APP_FOLDER_PATH: &str = "/drive/special/approot";
pub const DEFAULT_SCOPE: &str = "https://graph.microsoft.com/Files.ReadWrite.AppFolder https://graph.microsoft.com/User.Read offline_access";

/// Prefixed onto refresh errors when the refresh token itself is dead. The
/// renderer keys off this marker to ask the user to reconnect.
pub const REAUTH_REQUIRED_MARKER: &str = "ONEDRIVE_REAUTH_REQUIRED";

/// OAuth2 error codes meaning the refresh token can no longer be used.
const REFRESH_REAUTH_ERROR_CODES: [&str; 4] = [
    "invalid_grant",
    "interaction_required",
    "consent_required",
    "login_required",
];

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeRequest {
    pub client_id: Option<String>,
    pub code: Option<String>,
    pub code_verifier: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub client_id: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub id: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_data_url: Option<String>,
}

pub use crate::google::{FileIdResult, SyncedFileResult};

const NETWORK_HINT: &str = "Check your network/VPN and whether Microsoft services are reachable.";

fn network_error(what: &str) -> impl FnOnce(String) -> String + '_ {
    move |err| format!("{what} network error. {NETWORK_HINT} ({err})")
}

fn token_error_parts(res: &TextResponse) -> (Option<String>, String) {
    let data = http::safe_json(&res.text);
    let error = data
        .as_ref()
        .and_then(|d| d.get("error"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let description = data
        .as_ref()
        .and_then(|d| d.get("error_description"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| error.clone().filter(|s| !s.is_empty()))
        .or_else(|| {
            // Non-JSON body: Electron wraps it as `{ error: text }`.
            data.is_none()
                .then(|| res.text.clone())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| res.code().to_string());
    (error, description)
}

async fn token_request(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    form: &[(&str, &str)],
    label: &str,
) -> CoreResult<Result<Value, TextResponse>> {
    let res = http::send_text(
        client
            .post(&endpoints.token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(form),
        network_error(label),
    )
    .await?;
    if !res.ok() {
        return Ok(Err(res));
    }
    let data = http::safe_json(&res.text).ok_or_else(|| {
        CoreError::network(format!(
            "{label} invalid JSON: {}",
            http::truncate(&res.text, 200)
        ))
    })?;
    Ok(Ok(data))
}

/// Authorization-code + PKCE exchange.
pub async fn exchange_code(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    req: &ExchangeRequest,
) -> CoreResult<OAuthTokens> {
    let client_id = require(req.client_id.as_deref(), "Missing OneDrive clientId")?;
    let code = require(req.code.as_deref(), "Missing authorization code")?;
    let verifier = require(req.code_verifier.as_deref(), "Missing codeVerifier")?;
    let redirect = require(req.redirect_uri.as_deref(), "Missing redirectUri")?;
    let scope = non_empty(req.scope.as_deref()).unwrap_or(DEFAULT_SCOPE);
    let form = [
        ("client_id", client_id),
        ("code", code),
        ("code_verifier", verifier),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect),
        ("scope", scope),
    ];
    match token_request(client, endpoints, &form, "OneDrive token exchange").await? {
        Ok(data) => Ok(OAuthTokens::from_token_response(&data)),
        Err(res) => {
            let (_, description) = token_error_parts(&res);
            Err(CoreError::auth(format!(
                "OneDrive token exchange failed: {description}"
            )))
        }
    }
}

/// Refresh-token grant. Microsoft rotates refresh tokens; the old one is kept
/// when the response carries none.
pub async fn refresh_token(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    req: &RefreshRequest,
) -> CoreResult<OAuthTokens> {
    let client_id = require(req.client_id.as_deref(), "Missing OneDrive clientId")?;
    let refresh = require(req.refresh_token.as_deref(), "Missing refreshToken")?;
    let scope = non_empty(req.scope.as_deref()).unwrap_or(DEFAULT_SCOPE);
    let form = [
        ("client_id", client_id),
        ("refresh_token", refresh),
        ("grant_type", "refresh_token"),
        ("scope", scope),
    ];
    match token_request(client, endpoints, &form, "OneDrive token refresh").await? {
        Ok(data) => {
            let mut tokens = OAuthTokens::from_token_response(&data);
            if tokens.refresh_token.as_deref().is_none_or(str::is_empty) {
                tokens.refresh_token = Some(refresh.to_owned());
            }
            Ok(tokens)
        }
        Err(res) => {
            let (error, description) = token_error_parts(&res);
            let reauth = error
                .as_deref()
                .is_some_and(|e| REFRESH_REAUTH_ERROR_CODES.contains(&e));
            Err(CoreError::auth(if reauth {
                format!(
                    "{REAUTH_REQUIRED_MARKER}: OneDrive session expired, please reconnect. ({description})"
                )
            } else {
                format!("OneDrive token refresh failed: {description}")
            }))
        }
    }
}

/// `GET /me` plus the profile photo as a data URL (best effort).
pub async fn user_info(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    access_token: Option<&str>,
) -> CoreResult<UserInfo> {
    let token = require(access_token, "Missing accessToken")?;
    let res = http::send_text(
        client
            .get(format!("{}/me", endpoints.graph_api))
            .bearer_auth(token),
        network_error("OneDrive userinfo"),
    )
    .await?;
    if !res.ok() {
        return Err(CoreError::network(format!(
            "OneDrive userinfo failed: {} - {}",
            res.code(),
            http::truncate(&res.text, 200)
        )));
    }
    let user = http::safe_json(&res.text).ok_or_else(|| {
        CoreError::network(format!(
            "OneDrive userinfo invalid JSON: {}",
            http::truncate(&res.text, 200)
        ))
    })?;
    let str_field = |name: &str| user.get(name).and_then(Value::as_str).map(str::to_owned);
    Ok(UserInfo {
        id: str_field("id"),
        email: str_field("mail")
            .filter(|s| !s.is_empty())
            .or_else(|| str_field("userPrincipalName")),
        name: str_field("displayName"),
        avatar_data_url: fetch_photo(client, endpoints, token).await,
    })
}

async fn fetch_photo(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    token: &str,
) -> Option<String> {
    let res = client
        .get(format!("{}/me/photo/$value", endpoints.graph_api))
        .bearer_auth(token)
        .send()
        .await
        .ok()?;
    if !res.status().is_success() {
        return None;
    }
    let content_type = res
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("image/jpeg")
        .to_owned();
    let bytes = res.bytes().await.ok()?;
    Some(format!(
        "data:{content_type};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

fn app_file_url(endpoints: &Endpoints, name: Option<&str>) -> String {
    let name = non_empty(name).unwrap_or(SYNC_FILE_NAME);
    let encoded = percent_encoding::utf8_percent_encode(name, crate::http::COMPONENT);
    format!("{}/me{APP_FOLDER_PATH}:/{encoded}", endpoints.graph_api)
}

/// Find the sync file in the app folder.
pub async fn find_sync_file(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    access_token: Option<&str>,
    name: Option<&str>,
) -> CoreResult<FileIdResult> {
    let token = require(access_token, "Missing accessToken")?;
    let res = http::send_text(
        client.get(app_file_url(endpoints, name)).bearer_auth(token),
        |err| format!("OneDrive find sync file failed: {err}"),
    )
    .await?;
    if res.code() == 404 {
        return Ok(FileIdResult { file_id: None });
    }
    if !res.ok() {
        return Err(CoreError::network(format!(
            "OneDrive find sync file failed: {} - {}",
            res.code(),
            http::truncate(&res.text, 200)
        )));
    }
    let item = http::safe_json(&res.text).ok_or_else(|| {
        CoreError::network(format!(
            "OneDrive find sync file invalid JSON: {}",
            http::truncate(&res.text, 200)
        ))
    })?;
    Ok(FileIdResult {
        file_id: item
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .filter(|s| !s.is_empty()),
    })
}

/// Upload (create or replace) the sync file.
pub async fn upload_sync_file(
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
    let res = http::send_text(
        client
            .put(format!("{}:/content", app_file_url(endpoints, name)))
            .bearer_auth(token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(synced_file::serialize_pretty(synced)),
        |err| format!("OneDrive upload failed: {err}"),
    )
    .await?;
    if !res.ok() {
        return Err(CoreError::network(format!(
            "OneDrive upload failed: {} - {}",
            res.code(),
            http::truncate(&res.text, 200)
        )));
    }
    let file_id = http::safe_json(&res.text)
        .and_then(|item| item.get("id").and_then(Value::as_str).map(str::to_owned))
        .filter(|s| !s.is_empty());
    Ok(FileIdResult { file_id })
}

/// Download the sync file by id, or by name when no id is known.
pub async fn download_sync_file(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    access_token: Option<&str>,
    file_id: Option<&str>,
    name: Option<&str>,
) -> CoreResult<SyncedFileResult> {
    let token = require(access_token, "Missing accessToken")?;
    let item_url = match non_empty(file_id) {
        Some(id) => format!("{}/me/drive/items/{id}", endpoints.graph_api),
        None => app_file_url(endpoints, name),
    };
    let item_res = http::send_text(client.get(item_url).bearer_auth(token), |err| {
        format!("OneDrive download item failed: {err}")
    })
    .await?;
    if item_res.code() == 404 {
        return Ok(SyncedFileResult { synced_file: None });
    }
    if !item_res.ok() {
        return Err(CoreError::network(format!(
            "OneDrive download item failed: {} - {}",
            item_res.code(),
            http::truncate(&item_res.text, 200)
        )));
    }
    let item = http::safe_json(&item_res.text).ok_or_else(|| {
        CoreError::network(format!(
            "OneDrive download item invalid JSON: {}",
            http::truncate(&item_res.text, 200)
        ))
    })?;
    let download_url = item
        .get("@microsoft.graph.downloadUrl")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            CoreError::network("OneDrive download item missing @microsoft.graph.downloadUrl")
        })?;
    // The download URL is pre-authenticated; no bearer token.
    let res = http::send_text(client.get(download_url), |err| {
        format!("OneDrive download content failed: {err}")
    })
    .await?;
    if !res.ok() {
        return Err(CoreError::network(format!(
            "OneDrive download content failed: {} - {}",
            res.code(),
            http::truncate(&res.text, 200)
        )));
    }
    let data = http::safe_json(&res.text).ok_or_else(|| {
        CoreError::network(format!(
            "OneDrive download invalid JSON: {}",
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
            .delete(format!("{}/me/drive/items/{file_id}", endpoints.graph_api))
            .bearer_auth(token),
        |err| format!("OneDrive delete failed: {err}"),
    )
    .await?;
    if !res.ok() && res.code() != 404 {
        return Err(CoreError::network(format!(
            "OneDrive delete failed: {} - {}",
            res.code(),
            http::truncate(&res.text, 200)
        )));
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
    fn token_error_parts_follow_electron_precedence() {
        assert_eq!(
            token_error_parts(&res(
                400,
                r#"{"error":"invalid_grant","error_description":"AADSTS70000"}"#
            )),
            (Some("invalid_grant".into()), "AADSTS70000".into())
        );
        assert_eq!(
            token_error_parts(&res(400, r#"{"error":"temporarily_unavailable"}"#)),
            (
                Some("temporarily_unavailable".into()),
                "temporarily_unavailable".into()
            )
        );
        assert_eq!(token_error_parts(&res(503, "down")), (None, "down".into()));
        assert_eq!(token_error_parts(&res(503, "")), (None, "503".into()));
    }

    #[test]
    fn app_folder_url_encodes_the_file_name() {
        let ep = Endpoints::default();
        assert_eq!(
            app_file_url(&ep, None),
            "https://graph.microsoft.com/v1.0/me/drive/special/approot:/netcatty-vault.json"
        );
        assert_eq!(
            app_file_url(&ep, Some("a b.json")),
            "https://graph.microsoft.com/v1.0/me/drive/special/approot:/a%20b.json"
        );
    }
}
