//! Install a published `.ncpkg` from a public GitHub repository's latest
//! stable release (ports of `domain/pluginGitHubRepository.cjs` and
//! `electron/plugins/githubInstallService.cjs`; the delivery contract is in
//! `docs/plugin-platform/github-install.md`).
//!
//! `prepare` resolves the repository, release, tag commit and the single
//! `.ncpkg` asset, downloads it from GitHub hosts only, and runs the package
//! validator, runtime admission, compatibility and source-binding checks. It
//! keeps the package in a private directory and returns a preview with a
//! one-time token. `install` installs exactly that reviewed package, disabled,
//! and fails if its digest or manifest changed. Nothing is executed.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::database::PluginDatabase;
use crate::error::{PluginError, PluginResult};
use crate::manager::{InstallRequest, PluginManager};
use crate::package::compat::assert_browser_only;
use crate::package::{archive, limits};
use crate::source::{github_source, GitHubReleasePin, Source};
use crate::store::{ExpectedPackage, PackageStore};

/// `Number.MAX_SAFE_INTEGER`: GitHub IDs arrive as JSON numbers.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
const JSON_LIMIT: usize = 2 * 1024 * 1024;
const PREVIEW_TTL: Duration = Duration::from_secs(10 * 60);
const PREPARE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_PENDING_OPERATIONS: usize = 8;
const DOWNLOAD_HOSTS: &[&str] = &[
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];
const REPOSITORY_INPUT_ERROR: &str =
    "Use https://github.com/owner/repo, github.com/owner/repo or owner/repo (repository only; no credentials, query, fragment or extra paths)";

/// A normalised public repository reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubRepository {
    pub owner: String,
    pub repo: String,
    /// `owner/repo`, lowercase.
    pub repository: String,
    /// `https://github.com/owner/repo`, lowercase.
    pub origin: String,
}

fn is_owner(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=39).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && !value.contains("--")
}

fn is_repo_name(value: &str) -> bool {
    (1..=100).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// `parsePluginGitHubRepository`. Matches the original text, before URL
/// normalisation could hide traversal, ports or credentials.
pub fn parse_github_repository(input: &str) -> PluginResult<GitHubRepository> {
    let fail = || PluginError::host(REPOSITORY_INPUT_ERROR);
    if input.encode_utf16().count() > 512 {
        return Err(fail());
    }
    let value = input.trim();
    let lower = value.to_ascii_lowercase();
    let rest = ["https://github.com/", "http://github.com/", "github.com/"]
        .iter()
        .find(|prefix| lower.starts_with(*prefix))
        .map_or(value, |prefix| &value[prefix.len()..]);
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (owner, repo) = rest.split_once('/').ok_or_else(fail)?;
    if !is_owner(owner) || !is_repo_name(repo) {
        return Err(fail());
    }
    let owner = owner.to_ascii_lowercase();
    let repo = repo.to_ascii_lowercase();
    let repo = repo.strip_suffix(".git").unwrap_or(&repo).to_string();
    if repo.is_empty() || repo == "." || repo == ".." || repo.ends_with(".git") {
        return Err(fail());
    }
    Ok(GitHubRepository {
        repository: format!("{owner}/{repo}"),
        origin: format!("https://github.com/{owner}/{repo}"),
        owner,
        repo,
    })
}

/// `encodeURIComponent`.
fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Response head the download policy looks at.
#[derive(Debug, Clone, Default)]
pub struct HttpHead {
    pub status: u16,
    pub location: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub rate_limit_remaining: Option<String>,
}

#[async_trait]
pub trait HttpBody: Send {
    /// Next body chunk, `None` at the end.
    async fn chunk(&mut self) -> Result<Option<Vec<u8>>, String>;
}

/// One unauthenticated GET that never follows redirects. The real transport
/// is [`ReqwestGitHubHttp`]; tests inject a fake. Neither the renderer nor a
/// plugin can choose the URL or the transport.
#[async_trait]
pub trait GitHubHttp: Send + Sync {
    async fn get(&self, url: &str, accept: &str) -> Result<(HttpHead, Box<dyn HttpBody>), String>;
}

pub struct ReqwestGitHubHttp {
    client: reqwest::Client,
}

impl ReqwestGitHubHttp {
    pub fn new() -> PluginResult<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("Netcatty-Plugin-Installer")
            .https_only(true)
            .build()
            .map_err(|e| PluginError::host(format!("GitHub client unavailable: {e}")))?;
        Ok(Self { client })
    }
}

/// `err` and its causes, for diagnostics (reqwest hides the cause in `source`).
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut text = err.to_string();
    let mut cause = err.source();
    while let Some(inner) = cause {
        text.push_str(": ");
        text.push_str(&inner.to_string());
        cause = inner.source();
    }
    text
}

struct ReqwestBody(reqwest::Response);

#[async_trait]
impl HttpBody for ReqwestBody {
    async fn chunk(&mut self) -> Result<Option<Vec<u8>>, String> {
        self.0
            .chunk()
            .await
            .map(|c| c.map(|b| b.to_vec()))
            .map_err(|e| error_chain(&e))
    }
}

#[async_trait]
impl GitHubHttp for ReqwestGitHubHttp {
    async fn get(&self, url: &str, accept: &str) -> Result<(HttpHead, Box<dyn HttpBody>), String> {
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, accept)
            .send()
            .await
            .map_err(|e| error_chain(&e))?;
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let head = HttpHead {
            status: response.status().as_u16(),
            location: header("location"),
            content_type: header("content-type"),
            content_length: header("content-length").and_then(|v| v.parse().ok()),
            rate_limit_remaining: header("x-ratelimit-remaining"),
        };
        Ok((head, Box::new(ReqwestBody(response))))
    }
}

// ---------------------------------------------------------------------------
// Download policy
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FetchError {
    message: String,
    status: Option<u16>,
}

impl FetchError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: None,
        }
    }
}

impl From<FetchError> for PluginError {
    fn from(err: FetchError) -> Self {
        PluginError::host(err.message)
    }
}

/// `assertGitHubUrl`: HTTPS to the GitHub API (`api`) or a GitHub download
/// host, no credentials, port or fragment.
fn assert_github_url(value: &str, api: bool) -> Result<String, FetchError> {
    let refuse = || FetchError::new("GitHub download redirected outside approved HTTPS hosts");
    if value
        .chars()
        .any(|c| (c as u32) <= 0x20 || c as u32 == 0x7f || c == '\\')
    {
        return Err(refuse());
    }
    let url = url::Url::parse(value).map_err(|_| refuse())?;
    let host = url.host_str().unwrap_or("");
    let host_ok = if api {
        host == "api.github.com"
    } else {
        DOWNLOAD_HOSTS.contains(&host)
    };
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
        || !host_ok
    {
        return Err(refuse());
    }
    Ok(url.to_string())
}

/// Content types that mean GitHub served a page, not a package or JSON.
fn is_markup(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    if lower.contains("text/html") {
        return true;
    }
    ["application/", "text/"].iter().any(|prefix| {
        lower.match_indices(prefix).any(|(index, _)| {
            let rest = &lower[index + prefix.len()..];
            let segment = rest.split(';').next().unwrap_or("");
            rest.starts_with("xml") || segment.contains("+xml")
        })
    })
}

/// `fetchGitHubBytes`.
async fn fetch_github_bytes(
    http: &dyn GitHubHttp,
    url: &str,
    limit: usize,
    api: bool,
) -> Result<Vec<u8>, FetchError> {
    let mut url = url.to_string();
    let mut redirects = 0;
    loop {
        let checked = assert_github_url(&url, api)?;
        let accept = if api {
            "application/vnd.github+json"
        } else {
            "application/octet-stream"
        };
        let (head, mut body) = http.get(&checked, accept).await.map_err(|cause| {
            tracing::debug!(%cause, "GitHub plugin request failed");
            FetchError::new("Cannot reach GitHub. Check your network connection and try again")
        })?;
        if matches!(head.status, 301 | 302 | 303 | 307 | 308) {
            if api {
                return Err(FetchError::new(
                    "GitHub repository moved. Enter its current repository URL",
                ));
            }
            if redirects >= 3 {
                return Err(FetchError::new("Too many GitHub download redirects"));
            }
            let location = head
                .location
                .ok_or_else(|| FetchError::new("GitHub download redirect has no destination"))?;
            let base = url::Url::parse(&checked)
                .map_err(|_| FetchError::new("Invalid GitHub download URL"))?;
            url = base
                .join(&location)
                .map_err(|_| {
                    FetchError::new("GitHub download redirected outside approved HTTPS hosts")
                })?
                .to_string();
            redirects += 1;
            continue;
        }
        if !(200..300).contains(&head.status) {
            let message = match head.status {
                429 => "GitHub API rate limit reached. Try again later".to_string(),
                403 if head.rate_limit_remaining.as_deref() == Some("0") => "GitHub API rate limit reached. Try again later".to_string(),
                404 => {
                    return Err(FetchError {
                        message: "GitHub repository or asset not found. Only accessible public repositories are supported; private repositories require local import".into(),
                        status: Some(404),
                    })
                }
                401 | 403 => "GitHub access denied. Private repositories and login are not supported".to_string(),
                status => format!("GitHub download failed (HTTP {status})"),
            };
            return Err(FetchError::new(message));
        }
        if head.content_length.is_some_and(|len| len > limit as u64) {
            return Err(FetchError::new("GitHub download exceeds size limit"));
        }
        if head.content_type.as_deref().is_some_and(is_markup) {
            return Err(FetchError::new(
                "GitHub returned HTML/XML instead of a plugin package or release metadata",
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = body.chunk().await.map_err(|cause| {
            tracing::debug!(%cause, "GitHub plugin download interrupted");
            FetchError::new("Cannot reach GitHub. Check your network connection and try again")
        })? {
            if bytes.len() + chunk.len() > limit {
                return Err(FetchError::new("GitHub download exceeds size limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        return Ok(bytes);
    }
}

async fn fetch_json(
    http: &dyn GitHubHttp,
    url: &str,
) -> Result<serde_json::Map<String, Value>, FetchError> {
    let bytes = fetch_github_bytes(http, url, JSON_LIMIT, true).await?;
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(FetchError::new(
            "GitHub returned invalid release metadata (expected JSON object)",
        )),
    }
}

fn safe_integer(value: Option<&Value>) -> Option<u64> {
    value
        .and_then(Value::as_u64)
        .filter(|n| *n <= MAX_SAFE_INTEGER)
}

// ---------------------------------------------------------------------------
// Release resolution
// ---------------------------------------------------------------------------

/// What the GitHub API said about the package to download.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedAsset {
    source: Source,
    asset_name: String,
    size: u64,
    download_url: String,
    digest: Option<String>,
}

async fn resolve_release(
    http: &dyn GitHubHttp,
    repository: &GitHubRepository,
) -> PluginResult<ResolvedAsset> {
    let api_root = format!("https://api.github.com/repos/{}", repository.repository);
    let repo = fetch_json(http, &api_root).await?;
    let full_name_ok = repo
        .get("full_name")
        .and_then(Value::as_str)
        .is_some_and(|n| n.to_lowercase() == repository.repository);
    if !full_name_ok || repo.get("private") != Some(&Value::Bool(false)) {
        return Err(PluginError::host(
            "GitHub did not return the selected public repository",
        ));
    }
    let release = match fetch_json(http, &format!("{api_root}/releases/latest")).await {
        Ok(release) => release,
        Err(err) if err.status == Some(404) => {
            return Err(PluginError::host(
                "This repository has no published stable release. Ask the author to publish a release with a .ncpkg asset, or import a built package locally",
            ))
        }
        Err(err) => return Err(err.into()),
    };
    let tag = release
        .get("tag_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    // JavaScript truthiness, as the Electron check reads these fields.
    let truthy = |key: &str| match release.get(key) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    };
    if truthy("draft")
        || truthy("prerelease")
        || tag.is_empty()
        || tag.encode_utf16().count() > 256
        || tag.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f)
    {
        return Err(PluginError::host(
            "Publish a stable GitHub release with a tag and a .ncpkg asset first",
        ));
    }
    let assets: Vec<&serde_json::Map<String, Value>> = release
        .get("assets")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_object)
                .filter(|a| {
                    a.get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|n| n.to_ascii_lowercase().ends_with(".ncpkg"))
                })
                .collect()
        })
        .unwrap_or_default();
    if assets.len() != 1 {
        return Err(PluginError::host(if assets.is_empty() {
            "Release has no .ncpkg asset. Ask the author to build and attach one; source repositories cannot be built by Netcatty"
        } else {
            "Release contains multiple .ncpkg assets. Import the intended package locally"
        }));
    }
    let asset = assets[0];
    let name = asset.get("name").and_then(Value::as_str).unwrap_or("");
    let stem = &name[..name.len() - ".ncpkg".len()];
    let name_ok = name.len() <= 200
        && stem
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    let asset_id = safe_integer(asset.get("id")).filter(|id| *id >= 1);
    if !name_ok
        || asset_id.is_none()
        || asset.get("state").and_then(Value::as_str) != Some("uploaded")
    {
        return Err(PluginError::host(
            "Invalid GitHub plugin artifact name or identity",
        ));
    }
    let download = asset
        .get("browser_download_url")
        .and_then(Value::as_str)
        .and_then(|u| url::Url::parse(u).ok())
        .ok_or_else(|| PluginError::host("GitHub release asset has no valid download URL"))?;
    let repository_path = format!("/{}/", repository.repository);
    let expected_path = format!(
        "/{}/releases/download/{}/{}",
        repository.repository,
        encode_uri_component(tag),
        name
    );
    let path = download.path();
    if download.origin().ascii_serialization() != "https://github.com"
        || !path.to_lowercase().starts_with(&repository_path)
        || path.get(repository_path.len()..) != expected_path.get(repository_path.len()..)
        || download.query().is_some()
        || download.fragment().is_some()
        || !download.username().is_empty()
        || download.password().is_some()
    {
        return Err(PluginError::host(
            "GitHub asset does not belong to the selected repository and release",
        ));
    }
    let commit = match fetch_json(
        http,
        &format!("{api_root}/commits/{}", encode_uri_component(tag)),
    )
    .await
    {
        Ok(commit) => commit,
        Err(err) if err.status == Some(404) => return Err(PluginError::host(
            "The release tag has no accessible commit. Ask the author to repair the release tag",
        )),
        Err(err) => return Err(err.into()),
    };
    let source = github_source(
        &repository.origin,
        Some(GitHubReleasePin {
            tag: tag.to_string(),
            commit: commit
                .get("sha")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            asset_id: asset_id.unwrap_or(0),
        }),
    )?;
    let size = safe_integer(asset.get("size"))
        .filter(|s| (1..=limits::ARCHIVE_BYTES as u64).contains(s))
        .ok_or_else(|| PluginError::host("GitHub package size is invalid or exceeds size limit"))?;
    let digest = match asset.get("digest") {
        None | Some(Value::Null) => None,
        Some(Value::String(d)) => Some(d.clone()),
        Some(_) => Some(String::new()),
    };
    Ok(ResolvedAsset {
        source,
        asset_name: name.to_string(),
        size,
        download_url: download.to_string(),
        digest,
    })
}

async fn download_package(
    http: &dyn GitHubHttp,
    asset: &ResolvedAsset,
) -> PluginResult<(Vec<u8>, String)> {
    let bytes = fetch_github_bytes(http, &asset.download_url, limits::ARCHIVE_BYTES, false).await?;
    if bytes.len() as u64 != asset.size {
        return Err(PluginError::host("GitHub package size mismatch"));
    }
    if !bytes.starts_with(&[0x50, 0x4b, 0x03, 0x04]) {
        return Err(PluginError::host(
            "Expected a .ncpkg ZIP package; GitHub returned another file (possibly HTML/XML)",
        ));
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    if asset
        .digest
        .as_ref()
        .is_some_and(|d| *d != format!("sha256:{sha256}"))
    {
        return Err(PluginError::host("GitHub package SHA-256 mismatch"));
    }
    Ok((bytes, sha256))
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// What the user reviews before installing.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GitHubPluginPreview {
    pub token: String,
    pub source: Source,
    pub manifest: Value,
    pub archive_sha256: String,
    pub asset_name: String,
    pub size: u64,
}

struct Pending {
    preview: GitHubPluginPreview,
    directory: PathBuf,
    archive: PathBuf,
}

#[derive(Default)]
struct State {
    /// One reviewed package per owner (window).
    previews: HashMap<String, Pending>,
    /// Owners with a prepare/install in flight.
    active: HashSet<String>,
}

/// `GitHubInstallService`. Owners are window labels.
pub struct GitHubInstallService {
    http: Arc<dyn GitHubHttp>,
    state: Mutex<State>,
}

/// Clears an owner's in-flight mark however the operation ends.
struct ActiveGuard<'a> {
    service: &'a GitHubInstallService,
    owner: String,
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.service.state.lock().active.remove(&self.owner);
    }
}

fn remove_dir_quietly(directory: &Path) {
    let _ = std::fs::remove_dir_all(directory);
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

impl GitHubInstallService {
    pub fn new(http: Arc<dyn GitHubHttp>) -> Arc<Self> {
        Arc::new(Self {
            http,
            state: Mutex::new(State::default()),
        })
    }

    fn begin(&self, owner: &str, for_install: bool) -> PluginResult<ActiveGuard<'_>> {
        let mut state = self.state.lock();
        if state.active.contains(owner) {
            return Err(PluginError::host(if for_install {
                "A GitHub plugin operation is already active"
            } else {
                "A GitHub plugin operation is already active. Close the preview and try again"
            }));
        }
        if !for_install && state.active.len() + state.previews.len() >= MAX_PENDING_OPERATIONS {
            return Err(PluginError::host(
                "A GitHub plugin operation is already active. Close the preview and try again",
            ));
        }
        state.active.insert(owner.to_string());
        Ok(ActiveGuard {
            service: self,
            owner: owner.to_string(),
        })
    }

    /// Drop the owner's preview (only if it is `token`, when given).
    pub fn discard(&self, owner: &str, token: Option<&str>) {
        let removed = {
            let mut state = self.state.lock();
            match state.previews.get(owner) {
                Some(p) if token.is_none_or(|t| t == p.preview.token) => {
                    state.previews.remove(owner)
                }
                _ => None,
            }
        };
        if let Some(pending) = removed {
            remove_dir_quietly(&pending.directory);
        }
    }

    /// Download and fully validate the latest release package of `input`.
    /// `temp_root` is Netcatty's temp directory; the package is kept in a
    /// private subdirectory until installed, discarded or expired.
    pub async fn prepare(
        self: &Arc<Self>,
        owner: &str,
        input: &str,
        temp_root: &Path,
        store: &PackageStore,
        database: &PluginDatabase,
    ) -> PluginResult<GitHubPluginPreview> {
        let repository = parse_github_repository(input)?;
        let _guard = self.begin(owner, false)?;
        self.discard(owner, None);

        let http = self.http.clone();
        let (asset, bytes, sha256) = tokio::time::timeout(PREPARE_TIMEOUT, async {
            let asset = resolve_release(http.as_ref(), &repository).await?;
            let (bytes, sha256) = download_package(http.as_ref(), &asset).await?;
            Ok::<_, PluginError>((asset, bytes, sha256))
        })
        .await
        .map_err(|_| PluginError::host("GitHub download timed out"))??;

        std::fs::create_dir_all(temp_root)?;
        let directory = temp_root.join(format!("plugin-github-{}", uuid::Uuid::new_v4()));
        create_private_dir(&directory)?;
        let archive_path = directory.join("package.ncpkg");
        let checked = (|| -> PluginResult<Value> {
            write_private_file(&archive_path, &bytes)?;
            let manifest = archive::validate_package(&archive_path)?.manifest;
            if !store.allow_advanced_plugins {
                assert_browser_only(&manifest)?;
            }
            let compatibility = store.compatibility(&manifest);
            if !compatibility.compatible {
                return Err(PluginError::host(format!(
                    "Plugin is incompatible: {}",
                    compatibility.errors.join("; ")
                )));
            }
            database.assert_install_source(manifest["id"].as_str().unwrap_or(""), &asset.source)?;
            Ok(manifest)
        })();
        let manifest = match checked {
            Ok(manifest) => manifest,
            Err(err) => {
                remove_dir_quietly(&directory);
                return Err(err);
            }
        };

        let preview = GitHubPluginPreview {
            token: uuid::Uuid::new_v4().to_string(),
            source: asset.source,
            manifest,
            archive_sha256: sha256,
            asset_name: asset.asset_name,
            size: bytes.len() as u64,
        };
        self.state.lock().previews.insert(
            owner.to_string(),
            Pending {
                preview: preview.clone(),
                directory,
                archive: archive_path,
            },
        );
        let service = Arc::downgrade(self);
        let (expiring_owner, token) = (owner.to_string(), preview.token.clone());
        tokio::spawn(async move {
            tokio::time::sleep(PREVIEW_TTL).await;
            if let Some(service) = service.upgrade() {
                service.discard(&expiring_owner, Some(&token));
            }
        });
        Ok(preview)
    }

    /// Install the reviewed package, disabled. The preview is consumed
    /// whether or not the install succeeds.
    pub async fn install(
        &self,
        owner: &str,
        token: &str,
        manager: &PluginManager,
    ) -> PluginResult<Option<crate::database::PluginRecord>> {
        let (archive_path, preview) = {
            let state = self.state.lock();
            match state.previews.get(owner) {
                Some(p) if p.preview.token == token => (p.archive.clone(), p.preview.clone()),
                _ => {
                    return Err(PluginError::host(
                        "GitHub package preview expired. Download and review it again",
                    ))
                }
            }
        };
        let guard = self.begin(owner, true)?;
        let result = manager
            .install(InstallRequest {
                archive_path,
                enable: Some(false),
                source: preview.source,
                catalog: None,
                expected: Some(ExpectedPackage {
                    sha256: preview.archive_sha256,
                    manifest: preview.manifest,
                }),
            })
            .await;
        drop(guard);
        self.discard(owner, Some(token));
        result
    }

    #[cfg(test)]
    fn pending_directory(&self, owner: &str) -> Option<PathBuf> {
        self.state
            .lock()
            .previews
            .get(owner)
            .map(|p| p.directory.clone())
    }
}

#[cfg(test)]
mod tests;
