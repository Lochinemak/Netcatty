//! Cloud sync: session master password, OAuth loopback callback, GitHub
//! device flow, Google Drive, OneDrive, WebDAV and S3.
//!
//! The renderer keeps the sync engine (encryption, merge, conflicts); these
//! commands only move the encrypted `SyncedFile` and run the HTTP calls a
//! WebView cannot make because of CORS. Shapes and error messages follow the
//! Electron bridges (see `netcatty-sync`).

use super::CmdResult;
use crate::state::Ctx;
use netcatty_core::ipc::events;
use netcatty_core::CoreError;
use netcatty_sync::oauth::{CallbackResult, OAuthCallbackServer, PreparedCallback};
use netcatty_sync::{github, google, onedrive, s3, webdav, OAuthTokens};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// GitHub OAuth app client id baked in at build time (same variable the
/// renderer reads); used when the renderer does not pass one.
const GITHUB_CLIENT_ID: Option<&str> = option_env!("VITE_SYNC_GITHUB_CLIENT_ID");

/// File holding the session master password, encrypted with the credential
/// cipher (Electron: `safeStorage`).
const PASSWORD_FILE: &str = "cloud-sync-session.enc";

#[derive(Default)]
pub struct SyncState {
    pub oauth: OAuthCallbackServer,
    /// Cancellation tokens of in-flight device-flow polls keyed by `pollId`.
    pub github_polls: dashmap::DashMap<String, CancellationToken>,
    password: parking_lot::Mutex<Option<String>>,
}

/// `{ ok: true }` acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct OkResult {
    pub ok: bool,
}

const OK: OkResult = OkResult { ok: true };

fn http() -> CmdResult<netcatty_sync::reqwest::Client> {
    netcatty_sync::http::client()
}

// ---------------------------------------------------------------------------
// Session master password
// ---------------------------------------------------------------------------

fn password_path<R: tauri::Runtime>(state: &Ctx<'_, R>) -> PathBuf {
    state.paths.data_dir.join(PASSWORD_FILE)
}

fn read_persisted_password<R: tauri::Runtime>(state: &Ctx<'_, R>) -> Option<String> {
    let cipher = state.cipher();
    if !cipher.available() {
        return None;
    }
    let stored = std::fs::read_to_string(password_path(state)).ok()?;
    let stored = stored.trim();
    if !stored.starts_with(netcatty_store::ENC_PREFIX_V2) {
        return None;
    }
    match cipher.decrypt(stored) {
        Ok(password) if !password.is_empty() => Some(password),
        Ok(_) => None,
        Err(err) => {
            tracing::warn!(%err, "could not decrypt the persisted cloud sync password");
            None
        }
    }
}

fn persist_password<R: tauri::Runtime>(state: &Ctx<'_, R>, password: &str) {
    let cipher = state.cipher();
    if !cipher.available() {
        return;
    }
    let encrypted = match cipher.encrypt(password) {
        Ok(value) if value != password => value,
        Ok(_) => return,
        Err(err) => {
            tracing::warn!(%err, "could not encrypt the cloud sync password");
            return;
        }
    };
    let path = password_path(state);
    if let Err(err) = write_private(&path, encrypted.as_bytes()) {
        tracing::warn!(%err, path = %path.display(), "could not persist the cloud sync password");
    }
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

fn clear_persisted_password<R: tauri::Runtime>(state: &Ctx<'_, R>) {
    let path = password_path(state);
    if let Err(err) = std::fs::remove_file(&path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(%err, "could not remove the persisted cloud sync password");
        }
    }
}

/// Remember the master password for this session and persist it encrypted;
/// an empty / missing password clears it. Other windows are notified.
#[tauri::command]
pub fn cloudsync_password_set<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    password: Option<String>,
) -> bool {
    let password = password.filter(|p| !p.is_empty());
    *state.sync.password.lock() = password.clone();
    match password {
        Some(password) => {
            persist_password(&state, &password);
            crate::events::emit(&state.app, events::CLOUD_SYNC_PASSWORD_AVAILABLE, ());
        }
        None => clear_persisted_password(&state),
    }
    true
}

/// The session master password, falling back to the persisted copy.
#[tauri::command]
pub fn cloudsync_password_get<R: tauri::Runtime>(state: Ctx<'_, R>) -> Option<String> {
    if let Some(cached) = state.sync.password.lock().clone() {
        return Some(cached);
    }
    let persisted = read_persisted_password(&state);
    *state.sync.password.lock() = persisted.clone();
    persisted
}

#[tauri::command]
pub fn cloudsync_password_clear<R: tauri::Runtime>(state: Ctx<'_, R>) -> bool {
    *state.sync.password.lock() = None;
    clear_persisted_password(&state);
    true
}

// ---------------------------------------------------------------------------
// OAuth loopback callback
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn oauth_prepare_callback<R: tauri::Runtime>(
    state: Ctx<'_, R>,
) -> CmdResult<PreparedCallback> {
    state.sync.oauth.prepare().await
}

#[tauri::command]
pub async fn oauth_await_callback<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    expected_state: Option<String>,
    session_id: Option<String>,
) -> CmdResult<CallbackResult> {
    let oauth = state.sync.oauth.clone();
    oauth.await_callback(expected_state, session_id).await
}

#[tauri::command]
pub fn oauth_cancel_callback<R: tauri::Runtime>(state: Ctx<'_, R>, session_id: Option<String>) {
    state.sync.oauth.cancel(session_id.as_deref());
}

// ---------------------------------------------------------------------------
// GitHub device flow
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubStartPayload {
    pub client_id: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubPollPayload {
    pub client_id: Option<String>,
    pub device_code: Option<String>,
    pub poll_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GistRawPayload {
    pub access_token: Option<String>,
    pub raw_url: Option<String>,
}

fn github_client_id(explicit: Option<&str>) -> String {
    netcatty_sync::http::non_empty(explicit)
        .or(GITHUB_CLIENT_ID)
        .unwrap_or_default()
        .to_owned()
}

#[tauri::command]
pub async fn github_device_flow_start(
    payload: Option<GithubStartPayload>,
) -> CmdResult<github::DeviceFlowStart> {
    let payload = payload.unwrap_or_default();
    github::start_device_flow(
        &http()?,
        &github::Endpoints::default(),
        &github_client_id(payload.client_id.as_deref()),
        payload.scope.as_deref(),
    )
    .await
}

/// One token poll. A `pollId` makes it cancellable through
/// [`github_device_flow_cancel`]; a cancelled poll rejects with an
/// "aborted" message, which the renderer treats as an abort.
#[tauri::command]
pub async fn github_device_flow_poll<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: GithubPollPayload,
) -> CmdResult<Value> {
    let client_id = github_client_id(payload.client_id.as_deref());
    let client = http()?;
    let endpoints = github::Endpoints::default();
    let poll = github::poll_device_flow_token(
        &client,
        &endpoints,
        &client_id,
        payload.device_code.as_deref(),
    );
    let Some(poll_id) = payload.poll_id.filter(|id| !id.is_empty()) else {
        return poll.await;
    };
    let token = CancellationToken::new();
    state
        .sync
        .github_polls
        .insert(poll_id.clone(), token.clone());
    let result = tokio::select! {
        result = poll => result,
        _ = token.cancelled() => Err(CoreError::cancelled("The operation was aborted.")),
    };
    state.sync.github_polls.remove(&poll_id);
    result
}

#[tauri::command]
pub fn github_device_flow_cancel<R: tauri::Runtime>(state: Ctx<'_, R>, poll_id: Option<String>) {
    if let Some((_, token)) = poll_id.and_then(|id| state.sync.github_polls.remove(&id)) {
        token.cancel();
    }
}

#[tauri::command]
pub async fn github_gist_raw_content(payload: GistRawPayload) -> CmdResult<String> {
    github::download_gist_raw(
        &http()?,
        &github::Endpoints::default(),
        payload.access_token.as_deref(),
        payload.raw_url.as_deref(),
    )
    .await
}

// ---------------------------------------------------------------------------
// Google OAuth + Drive
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenPayload {
    pub access_token: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveFilePayload {
    pub access_token: Option<String>,
    pub file_id: Option<String>,
    pub file_name: Option<String>,
    pub synced_file: Option<Value>,
}

#[tauri::command]
pub async fn google_oauth_exchange(payload: google::ExchangeRequest) -> CmdResult<OAuthTokens> {
    google::exchange_code(&http()?, &google::Endpoints::default(), &payload).await
}

#[tauri::command]
pub async fn google_oauth_refresh(payload: google::RefreshRequest) -> CmdResult<OAuthTokens> {
    google::refresh_token(&http()?, &google::Endpoints::default(), &payload).await
}

#[tauri::command]
pub async fn google_oauth_userinfo(payload: AccessTokenPayload) -> CmdResult<Value> {
    google::user_info(
        &http()?,
        &google::Endpoints::default(),
        payload.access_token.as_deref(),
    )
    .await
}

#[tauri::command]
pub async fn google_drive_find_sync_file(
    payload: DriveFilePayload,
) -> CmdResult<google::FileIdResult> {
    google::find_sync_file(
        &http()?,
        &google::Endpoints::default(),
        payload.access_token.as_deref(),
        payload.file_name.as_deref(),
    )
    .await
}

#[tauri::command]
pub async fn google_drive_create_sync_file(
    payload: DriveFilePayload,
) -> CmdResult<google::FileIdResult> {
    google::create_sync_file(
        &http()?,
        &google::Endpoints::default(),
        payload.access_token.as_deref(),
        payload.file_name.as_deref(),
        payload.synced_file.as_ref(),
    )
    .await
}

#[tauri::command]
pub async fn google_drive_update_sync_file(payload: DriveFilePayload) -> CmdResult<OkResult> {
    google::update_sync_file(
        &http()?,
        &google::Endpoints::default(),
        payload.access_token.as_deref(),
        payload.file_id.as_deref(),
        payload.synced_file.as_ref(),
    )
    .await
    .map(|()| OK)
}

#[tauri::command]
pub async fn google_drive_download_sync_file(
    payload: DriveFilePayload,
) -> CmdResult<google::SyncedFileResult> {
    google::download_sync_file(
        &http()?,
        &google::Endpoints::default(),
        payload.access_token.as_deref(),
        payload.file_id.as_deref(),
    )
    .await
}

#[tauri::command]
pub async fn google_drive_delete_sync_file(payload: DriveFilePayload) -> CmdResult<OkResult> {
    google::delete_sync_file(
        &http()?,
        &google::Endpoints::default(),
        payload.access_token.as_deref(),
        payload.file_id.as_deref(),
    )
    .await
    .map(|()| OK)
}

// ---------------------------------------------------------------------------
// OneDrive OAuth + Graph
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn onedrive_oauth_exchange(payload: onedrive::ExchangeRequest) -> CmdResult<OAuthTokens> {
    onedrive::exchange_code(&http()?, &onedrive::Endpoints::default(), &payload).await
}

#[tauri::command]
pub async fn onedrive_oauth_refresh(payload: onedrive::RefreshRequest) -> CmdResult<OAuthTokens> {
    onedrive::refresh_token(&http()?, &onedrive::Endpoints::default(), &payload).await
}

#[tauri::command]
pub async fn onedrive_oauth_userinfo(payload: AccessTokenPayload) -> CmdResult<onedrive::UserInfo> {
    onedrive::user_info(
        &http()?,
        &onedrive::Endpoints::default(),
        payload.access_token.as_deref(),
    )
    .await
}

#[tauri::command]
pub async fn onedrive_find_sync_file(
    payload: DriveFilePayload,
) -> CmdResult<onedrive::FileIdResult> {
    onedrive::find_sync_file(
        &http()?,
        &onedrive::Endpoints::default(),
        payload.access_token.as_deref(),
        payload.file_name.as_deref(),
    )
    .await
}

#[tauri::command]
pub async fn onedrive_upload_sync_file(
    payload: DriveFilePayload,
) -> CmdResult<onedrive::FileIdResult> {
    onedrive::upload_sync_file(
        &http()?,
        &onedrive::Endpoints::default(),
        payload.access_token.as_deref(),
        payload.file_name.as_deref(),
        payload.synced_file.as_ref(),
    )
    .await
}

#[tauri::command]
pub async fn onedrive_download_sync_file(
    payload: DriveFilePayload,
) -> CmdResult<onedrive::SyncedFileResult> {
    onedrive::download_sync_file(
        &http()?,
        &onedrive::Endpoints::default(),
        payload.access_token.as_deref(),
        payload.file_id.as_deref(),
        payload.file_name.as_deref(),
    )
    .await
}

#[tauri::command]
pub async fn onedrive_delete_sync_file(payload: DriveFilePayload) -> CmdResult<OkResult> {
    onedrive::delete_sync_file(
        &http()?,
        &onedrive::Endpoints::default(),
        payload.access_token.as_deref(),
        payload.file_id.as_deref(),
    )
    .await
    .map(|()| OK)
}

// ---------------------------------------------------------------------------
// WebDAV / S3
// ---------------------------------------------------------------------------

fn require_synced(synced_file: Option<Value>) -> CmdResult<Value> {
    synced_file
        .filter(|v| !v.is_null())
        .ok_or_else(|| CoreError::invalid("Missing syncedFile"))
}

fn require_config<T>(config: Option<T>, what: &str) -> CmdResult<T> {
    config.ok_or_else(|| CoreError::invalid(format!("Missing {what} config")))
}

#[tauri::command]
pub async fn webdav_initialize(
    config: Option<webdav::WebDavConfig>,
) -> CmdResult<webdav::ResourceResult> {
    webdav::initialize(&require_config(config, "WebDAV")?).await
}

#[tauri::command]
pub async fn webdav_upload(
    config: Option<webdav::WebDavConfig>,
    synced_file: Option<Value>,
) -> CmdResult<webdav::ResourceResult> {
    webdav::upload(
        &require_config(config, "WebDAV")?,
        &require_synced(synced_file)?,
    )
    .await
}

#[tauri::command]
pub async fn webdav_download(
    config: Option<webdav::WebDavConfig>,
) -> CmdResult<webdav::SyncedFileResult> {
    webdav::download(&require_config(config, "WebDAV")?).await
}

#[tauri::command]
pub async fn webdav_delete(config: Option<webdav::WebDavConfig>) -> CmdResult<OkResult> {
    webdav::delete(&require_config(config, "WebDAV")?)
        .await
        .map(|()| OK)
}

#[tauri::command]
pub async fn s3_initialize(config: Option<s3::S3Config>) -> CmdResult<s3::ResourceResult> {
    s3::initialize(&require_config(config, "S3")?).await
}

#[tauri::command]
pub async fn s3_upload(
    config: Option<s3::S3Config>,
    synced_file: Option<Value>,
) -> CmdResult<s3::ResourceResult> {
    s3::upload(
        &require_config(config, "S3")?,
        &require_synced(synced_file)?,
    )
    .await
}

#[tauri::command]
pub async fn s3_download(config: Option<s3::S3Config>) -> CmdResult<s3::SyncedFileResult> {
    s3::download(&require_config(config, "S3")?).await
}

#[tauri::command]
pub async fn s3_delete(config: Option<s3::S3Config>) -> CmdResult<OkResult> {
    s3::delete(&require_config(config, "S3")?)
        .await
        .map(|()| OK)
}
