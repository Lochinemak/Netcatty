//! GitHub Device Flow and Gist raw downloads (`githubAuthBridge.cjs`).
//!
//! `github.com/login/*` sends no CORS headers, so the renderer cannot call it
//! from the WebView. The Gist REST API itself (`api.github.com`) does allow
//! CORS and stays in the renderer.

use crate::http::{self, require};
use netcatty_core::{CoreError, CoreResult};
use serde::Serialize;
use serde_json::Value;

/// Endpoints, overridable for tests.
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub device_code_url: String,
    pub access_token_url: String,
    /// Only raw URLs on this origin are fetched with the user's token.
    pub gist_raw_origin: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            device_code_url: "https://github.com/login/device/code".into(),
            access_token_url: "https://github.com/login/oauth/access_token".into(),
            gist_raw_origin: "https://gist.githubusercontent.com".into(),
        }
    }
}

pub const DEFAULT_SCOPE: &str = "gist read:user";

/// Result of starting the device flow, in the renderer's shape.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceFlowStart {
    pub device_code: Option<String>,
    pub user_code: Option<String>,
    pub verification_uri: Option<String>,
    pub expires_at: i64,
    pub interval: i64,
}

fn form_post(
    client: &reqwest::Client,
    url: &str,
    form: &[(&str, &str)],
) -> reqwest::RequestBuilder {
    client
        .post(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(form)
}

/// `POST /login/device/code`.
pub async fn start_device_flow(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    client_id: &str,
    scope: Option<&str>,
) -> CoreResult<DeviceFlowStart> {
    let scope = http::non_empty(scope).unwrap_or(DEFAULT_SCOPE);
    let res = http::send_text(
        form_post(
            client,
            &endpoints.device_code_url,
            &[("client_id", client_id), ("scope", scope)],
        ),
        |err| format!("GitHub device flow failed: {err}"),
    )
    .await?;
    if !res.ok() {
        return Err(CoreError::network(format!(
            "GitHub device flow failed: {} - {}",
            res.code(),
            res.text
        )));
    }
    let data: Value = serde_json::from_str(&res.text).map_err(|_| {
        CoreError::network(format!(
            "GitHub device flow invalid JSON: {}",
            http::truncate(&res.text, 200)
        ))
    })?;
    let str_field = |name: &str| data.get(name).and_then(Value::as_str).map(str::to_owned);
    let expires_in = data.get("expires_in").and_then(Value::as_i64).unwrap_or(0);
    let interval = data
        .get("interval")
        .and_then(Value::as_i64)
        .filter(|v| *v > 0)
        .unwrap_or(5);
    Ok(DeviceFlowStart {
        device_code: str_field("device_code"),
        user_code: str_field("user_code"),
        verification_uri: str_field("verification_uri"),
        expires_at: http::now_ms() + expires_in * 1000,
        interval,
    })
}

/// One `POST /login/oauth/access_token` poll. The JSON body is returned as is
/// (`access_token` on success, `error: authorization_pending` while waiting).
pub async fn poll_device_flow_token(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    client_id: &str,
    device_code: Option<&str>,
) -> CoreResult<Value> {
    let device_code = require(device_code, "Missing deviceCode")?;
    let res = http::send_text(
        form_post(
            client,
            &endpoints.access_token_url,
            &[
                ("client_id", client_id),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ],
        ),
        |err| format!("GitHub token polling failed: {err}"),
    )
    .await?;
    if !res.ok() {
        return Err(CoreError::network(format!(
            "GitHub token polling failed: {} - {}",
            res.code(),
            res.text
        )));
    }
    serde_json::from_str(&res.text).map_err(|_| {
        CoreError::network(format!(
            "GitHub token polling invalid JSON: {}",
            http::truncate(&res.text, 200)
        ))
    })
}

fn normalize_gist_raw_url(endpoints: &Endpoints, raw_url: Option<&str>) -> CoreResult<url::Url> {
    let url = raw_url
        .and_then(|raw| url::Url::parse(raw).ok())
        .ok_or_else(|| CoreError::invalid("Invalid GitHub Gist raw URL"))?;
    let origin = url::Url::parse(&endpoints.gist_raw_origin)
        .map_err(|_| CoreError::internal("Invalid gist origin"))?;
    if url.origin() != origin.origin() || url.scheme() != origin.scheme() {
        return Err(CoreError::invalid(
            "GitHub Gist raw URL must use gist.githubusercontent.com",
        ));
    }
    Ok(url)
}

/// Download the full content of a truncated gist file.
pub async fn download_gist_raw(
    client: &reqwest::Client,
    endpoints: &Endpoints,
    access_token: Option<&str>,
    raw_url: Option<&str>,
) -> CoreResult<String> {
    let access_token = require(access_token, "Missing GitHub access token")?;
    let url = normalize_gist_raw_url(endpoints, raw_url)?;
    let res = http::send_text(
        client
            .get(url)
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "application/vnd.github.raw"),
        |err| format!("Failed to download full gist content: {err}"),
    )
    .await?;
    if !res.ok() {
        return Err(CoreError::network(format!(
            "Failed to download full gist content: {} - {}",
            res.code(),
            http::truncate(&res.text, 200)
        )));
    }
    Ok(res.text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gist_raw_url_must_stay_on_the_gist_origin() {
        let ep = Endpoints::default();
        assert!(
            normalize_gist_raw_url(&ep, Some("https://gist.githubusercontent.com/u/1/raw/f"))
                .is_ok()
        );
        assert!(
            normalize_gist_raw_url(&ep, Some("http://gist.githubusercontent.com/u/1/raw/f"))
                .is_err()
        );
        assert!(normalize_gist_raw_url(&ep, Some("https://evil.example/u/1/raw/f")).is_err());
        assert!(normalize_gist_raw_url(&ep, Some("not a url")).is_err());
        assert!(normalize_gist_raw_url(&ep, None).is_err());
    }
}
