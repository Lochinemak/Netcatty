//! `netcatty-sync` — network side of cloud sync for the Rust build.
//!
//! The renderer owns sync itself (encryption, merge, conflict handling); the
//! backend only moves the encrypted `SyncedFile` and runs the OAuth flows that
//! a WebView cannot do because of CORS. This crate is the Rust counterpart of
//! the Electron bridges:
//!
//! | module       | Electron bridge                         |
//! |--------------|-----------------------------------------|
//! | [`github`]   | `githubAuthBridge.cjs` (device flow)    |
//! | [`google`]   | `googleAuthBridge.cjs` (OAuth + Drive)  |
//! | [`onedrive`] | `onedriveAuthBridge.cjs` (OAuth + Graph)|
//! | [`webdav`]   | `cloudSyncBridge.cjs` (WebDAV half)     |
//! | [`s3`]       | `cloudSyncBridge.cjs` (S3 half)         |
//! | [`oauth`]    | `oauthBridge.cjs` (loopback callback)   |
//!
//! Error messages match the Electron ones: the renderer only sees
//! `error.message` and some code paths key off it (for example the
//! `ONEDRIVE_REAUTH_REQUIRED` marker).

pub mod github;
pub mod google;
pub mod http;
pub mod oauth;
pub mod onedrive;
pub mod s3;
pub mod synced_file;
pub mod webdav;

pub use reqwest;

/// File name every provider stores the encrypted vault under.
pub const SYNC_FILE_NAME: &str = "netcatty-vault.json";

/// OAuth token set returned by the token exchange / refresh helpers, in the
/// renderer's camelCase shape.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthTokens {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Absolute expiry in milliseconds since the Unix epoch.
    pub expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl OAuthTokens {
    /// Build from a standard OAuth2 token endpoint response.
    pub(crate) fn from_token_response(data: &serde_json::Value) -> Self {
        let str_field = |name: &str| data.get(name).and_then(|v| v.as_str()).map(str::to_owned);
        let expires_in = data.get("expires_in").and_then(|v| v.as_i64()).unwrap_or(0);
        Self {
            access_token: str_field("access_token").unwrap_or_default(),
            refresh_token: str_field("refresh_token"),
            expires_at: http::now_ms() + expires_in * 1000,
            token_type: str_field("token_type"),
            scope: str_field("scope"),
        }
    }
}
