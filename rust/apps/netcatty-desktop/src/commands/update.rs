//! Auto-update (Electron: `autoUpdateBridge.cjs`) on `tauri-plugin-updater`.
//!
//! The renderer drives a "prompt" model: it asks to *check*, then explicitly
//! *downloads* and *installs*. Updates are signed bundles published next to a
//! `latest.json` manifest on GitHub Releases (see `.github/workflows/build-tauri.yml`
//! and `rust/docs/ipc-update.md`).
//!
//! * The status snapshot (`update_get_status`) and every event keep the
//!   Electron shapes and channel names so `application/state/useUpdateCheck.ts`
//!   is unchanged.
//! * The `autoUpdate` preference lives in the KV store (Electron:
//!   `auto-update-pref.json`). When it is on, an update found by any check is
//!   downloaded right away and one automatic check runs 5 s after startup
//!   (2 s after the preference is re-enabled); the renderer owns the hourly
//!   cadence on top of that, as under Electron.
//! * Where the updater cannot work — debug builds, a missing signing key,
//!   Linux packages without a known bundle type (snap, tarballs, …) — checks
//!   report `supported: false` plus the GitHub releases URL and the renderer
//!   offers its manual download link, like Electron's unmarked Linux builds.
//! * Install first asks every main window about unsaved editors
//!   (`app:query-dirty-editors` / `app_report_dirty_editors`, Electron's
//!   `dirtyEditorGuard.cjs`); if any has unsaved work the install is aborted
//!   and `netcatty:update:needs-save` is broadcast. Otherwise the app commits
//!   to the quit (close-to-tray off, Electron's `quittingForUpdate`), installs
//!   and relaunches; a failed install rolls the flags back, and a watchdog
//!   does the same if the process is somehow still alive a minute later.

use super::CmdResult;
use netcatty_core::CoreError;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tauri_plugin_updater::{Update, UpdaterExt};

// ---------------------------------------------------------------------------
// Contract constants
// ---------------------------------------------------------------------------

/// Event channel names (Electron's).
pub mod events {
    /// `{ version, releaseNotes, releaseDate }`.
    pub const UPDATE_AVAILABLE: &str = "netcatty:update:update-available";
    /// `{}`.
    pub const UPDATE_NOT_AVAILABLE: &str = "netcatty:update:update-not-available";
    /// `{ percent, bytesPerSecond, transferred, total }`.
    pub const DOWNLOAD_PROGRESS: &str = "netcatty:update:download-progress";
    /// No payload.
    pub const DOWNLOADED: &str = "netcatty:update:downloaded";
    /// `{ error }`.
    pub const ERROR: &str = "netcatty:update:error";
    /// No payload — an install was blocked by unsaved editors.
    pub const NEEDS_SAVE: &str = "netcatty:update:needs-save";
    /// `{ requestId, deadline }` — sent to one window; it answers with
    /// `app_report_dirty_editors`.
    pub const QUERY_DIRTY_EDITORS: &str = "app:query-dirty-editors";
}

/// KV store key of the persisted preference (`"true"` / `"false"`).
pub const AUTO_UPDATE_PREF_KEY: &str = "auto-update.enabled";

/// GitHub releases page offered for manual downloads
/// (`infrastructure/services/updateService.ts` uses the same repository).
pub const RELEASES_URL: &str = "https://github.com/Lochinemak/Netcatty/releases";

/// Electron: `startAutoCheck(5000)` after the main window is created.
const STARTUP_CHECK_DELAY: Duration = Duration::from_secs(5);
/// Electron: `startAutoCheck(2000)` when the preference is re-enabled.
const REENABLE_CHECK_DELAY: Duration = Duration::from_secs(2);
/// Electron: `INSTALL_DIRTY_CHECK_TIMEOUT_MS`.
const DIRTY_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
/// Electron: `QUITTING_FOR_UPDATE_WATCHDOG_MS`.
const QUITTING_WATCHDOG: Duration = Duration::from_secs(60);
/// Minimum interval between two `download-progress` events.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(150);

// ---------------------------------------------------------------------------
// Renderer-facing payloads
// ---------------------------------------------------------------------------

/// `getUpdateStatus()` snapshot (Electron `_lastStatus`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    pub status: Phase,
    pub percent: u8,
    pub error: Option<String>,
    pub version: Option<String>,
    pub is_checking: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Idle,
    Available,
    Downloading,
    Ready,
    Error,
}

/// `checkForUpdate()` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub available: bool,
    pub supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checking: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downloading: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Where to download manually; always present when `supported` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub releases_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DownloadResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutoUpdatePref {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuccessResult {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AvailableEvent {
    version: String,
    release_notes: String,
    release_date: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressEvent {
    percent: f64,
    bytes_per_second: u64,
    transferred: u64,
    total: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ErrorEvent {
    error: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DirtyQuery {
    request_id: String,
    /// Unix milliseconds, like Electron's `Date.now() + timeoutMs`.
    deadline: u64,
}

/// `reportDirtyEditorsResult(hasDirty, reason, { requestId, pending })`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirtyReport {
    pub request_id: Option<String>,
    #[serde(default)]
    pub has_dirty: bool,
    pub reason: Option<String>,
    #[serde(default)]
    pub pending: bool,
}

// ---------------------------------------------------------------------------
// Platform support (Electron: `isAutoUpdateSupported`, `getLinuxPackageType`)
// ---------------------------------------------------------------------------

/// Why the updater cannot run in this build, if it cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsupported {
    /// `cargo run` / `tauri dev`: nothing to replace, and a login item or
    /// installer must never point at a transient binary.
    DevBuild,
    /// The updater plugin failed to initialise (no `plugins.updater` config).
    PluginUnavailable,
    /// `plugins.updater.pubkey` is still the placeholder.
    SigningKeyMissing,
    /// Linux build without a known package type (snap, tarball, …).
    LinuxPackage,
}

impl Unsupported {
    pub fn message(&self) -> &'static str {
        match self {
            Self::DevBuild => "Auto-update is not available in development builds.",
            Self::PluginUnavailable => "Update module failed to load.",
            Self::SigningKeyMissing => {
                "Auto-update is disabled in this build (no update signing key)."
            }
            Self::LinuxPackage => "Auto-update is not supported on this platform/package format.",
        }
    }
}

/// Linux package format the running binary was installed from, when known.
/// `tauri-plugin-updater` handles AppImage (in-place), deb (`dpkg -i`) and
/// rpm (`rpm -U`) — the same set Electron's package-manager path covers.
pub fn linux_package_type() -> Option<&'static str> {
    use tauri::utils::config::BundleType;
    if std::env::var_os("APPIMAGE").is_some() {
        return Some("AppImage");
    }
    match tauri::utils::platform::bundle_type() {
        Some(BundleType::AppImage) => Some("AppImage"),
        Some(BundleType::Deb) => Some("deb"),
        Some(BundleType::Rpm) => Some("rpm"),
        _ => None,
    }
}

/// Pure part of the support check (unit tested).
pub fn support_for(
    debug_build: bool,
    plugin_ready: bool,
    pubkey_configured: bool,
    linux: bool,
    linux_package: Option<&str>,
) -> Result<(), Unsupported> {
    if debug_build {
        return Err(Unsupported::DevBuild);
    }
    if !plugin_ready {
        return Err(Unsupported::PluginUnavailable);
    }
    if !pubkey_configured {
        return Err(Unsupported::SigningKeyMissing);
    }
    if linux && linux_package.is_none() {
        return Err(Unsupported::LinuxPackage);
    }
    Ok(())
}

/// A minisign public key as produced by `tauri signer generate`: base64 of
/// `untrusted comment: …\n<key>`. The placeholder in `tauri.conf.json` is not.
pub fn pubkey_looks_valid(pubkey: &str) -> bool {
    use base64::Engine;
    let trimmed = pubkey.trim();
    if trimmed.is_empty() {
        return false;
    }
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(trimmed) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let mut lines = text.lines();
    lines.next().is_some_and(|l| l.starts_with("untrusted comment:"))
        && lines.next().is_some_and(|l| !l.trim().is_empty())
}

fn configured_pubkey<R: Runtime>(app: &AppHandle<R>) -> Option<String> {
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|v| v.get("pubkey"))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------
// State machine (pure; unit tested)
// ---------------------------------------------------------------------------

/// Electron's `_lastStatus` + `_isChecking` / `_isDownloading` /
/// `_isInstalling` flags, with the transitions `autoUpdateBridge.cjs` makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    pub phase: Phase,
    pub percent: u8,
    pub error: Option<String>,
    pub version: Option<String>,
    pub checking: bool,
    pub downloading: bool,
    pub installing: bool,
}

impl Default for Machine {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            percent: 0,
            error: None,
            version: None,
            checking: false,
            downloading: false,
            installing: false,
        }
    }
}

/// What `check` should answer without contacting the server, if anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckShortcut {
    Checking,
    Downloading { version: Option<String> },
    Ready { version: Option<String> },
}

impl Machine {
    pub fn snapshot(&self) -> UpdateStatus {
        UpdateStatus {
            status: self.phase,
            percent: self.percent,
            error: self.error.clone(),
            version: self.version.clone(),
            is_checking: self.checking,
        }
    }

    /// A check may not overlap another check, a download or a ready update
    /// (electron-updater errors out and corrupts the download, #522).
    pub fn check_shortcut(&self) -> Option<CheckShortcut> {
        if self.checking {
            return Some(CheckShortcut::Checking);
        }
        if self.downloading {
            return Some(CheckShortcut::Downloading {
                version: self.version.clone(),
            });
        }
        if self.phase == Phase::Ready {
            return Some(CheckShortcut::Ready {
                version: self.version.clone(),
            });
        }
        None
    }

    pub fn check_started(&mut self) {
        self.checking = true;
    }

    /// `update-not-available`: reset stale `ready` / `error` snapshots.
    pub fn not_available(&mut self) {
        *self = Machine {
            installing: self.installing,
            ..Machine::default()
        };
    }

    /// `update-available`; `will_download` is the auto-update preference.
    pub fn available(&mut self, version: &str, will_download: bool) {
        self.checking = false;
        self.downloading = will_download;
        self.phase = if will_download {
            Phase::Downloading
        } else {
            Phase::Available
        };
        self.percent = 0;
        self.error = None;
        self.version = Some(version.to_owned());
    }

    /// A check that failed before producing a result (not broadcast).
    pub fn check_failed(&mut self) {
        self.checking = false;
    }

    /// `downloadUpdate()` was called; `true` when a download actually starts.
    pub fn download_started(&mut self) -> bool {
        if self.downloading {
            return false;
        }
        self.downloading = true;
        self.phase = Phase::Downloading;
        self.percent = 0;
        self.error = None;
        true
    }

    pub fn progress(&mut self, percent: f64) {
        self.percent = percent.round().clamp(0.0, 100.0) as u8;
    }

    pub fn downloaded(&mut self) {
        self.downloading = false;
        self.phase = Phase::Ready;
        self.percent = 100;
    }

    /// Download or install failure (broadcast as `netcatty:update:error`).
    pub fn failed(&mut self, message: &str) {
        self.checking = false;
        self.downloading = false;
        self.installing = false;
        self.phase = Phase::Error;
        self.error = Some(message.to_owned());
    }

    /// Returns `false` when another install already committed the quit.
    pub fn install_started(&mut self) -> bool {
        if self.installing {
            return false;
        }
        self.installing = true;
        true
    }

    pub fn install_cancelled(&mut self) {
        self.installing = false;
    }
}

// ---------------------------------------------------------------------------
// Dirty-editor guard (Electron: `dirtyEditorGuard.cjs`)
// ---------------------------------------------------------------------------

/// Outcome of asking a renderer about unsaved work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirtyOutcome {
    Clean,
    /// Unsaved editor tabs.
    Editors,
    /// Unfinished transfers the user declined to abandon (or that are still
    /// being paused when the deadline passes).
    Transfers,
}

impl DirtyOutcome {
    pub fn blocks(self) -> bool {
        self != DirtyOutcome::Clean
    }
}

struct PendingQuery {
    /// Only the queried window may answer (Electron: `evt.sender` check).
    label: String,
    transfers_pending: AtomicBool,
    reply: Mutex<Option<tokio::sync::oneshot::Sender<DirtyOutcome>>>,
}

/// One-shot request / response round trip with the renderer: emit
/// `app:query-dirty-editors` to a window, resolve on the matching
/// `app_report_dirty_editors`, fail open on timeout (unless the renderer
/// acknowledged pending transfers, which silence must not discard).
#[derive(Default)]
pub struct DirtyEditorGuard {
    pending: dashmap::DashMap<String, Arc<PendingQuery>>,
}

impl DirtyEditorGuard {
    /// Pure classification of a renderer reply (unit tested).
    pub fn classify(report: &DirtyReport) -> Option<DirtyOutcome> {
        if report.pending && report.has_dirty && report.reason.as_deref() == Some("transfers") {
            return None;
        }
        Some(match (report.has_dirty, report.reason.as_deref()) {
            (true, Some("transfers")) => DirtyOutcome::Transfers,
            (true, _) => DirtyOutcome::Editors,
            (false, _) => DirtyOutcome::Clean,
        })
    }

    /// Ask the window labelled `label`; resolves within `timeout`.
    pub async fn query<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        label: &str,
        timeout: Duration,
    ) -> DirtyOutcome {
        let request_id = uuid_v4();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let pending = Arc::new(PendingQuery {
            label: label.to_owned(),
            transfers_pending: AtomicBool::new(false),
            reply: Mutex::new(Some(tx)),
        });
        self.pending.insert(request_id.clone(), pending.clone());
        let deadline = unix_millis() + timeout.as_millis() as u64;
        let sent = app.get_webview_window(label).is_some()
            && app
                .emit_to(
                    label,
                    events::QUERY_DIRTY_EDITORS,
                    DirtyQuery {
                        request_id: request_id.clone(),
                        deadline,
                    },
                )
                .is_ok();
        let outcome = if !sent {
            // No renderer to ask: fail open, like a destroyed webContents.
            DirtyOutcome::Clean
        } else {
            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(outcome)) => outcome,
                _ if pending.transfers_pending.load(Ordering::SeqCst) => DirtyOutcome::Transfers,
                _ => DirtyOutcome::Clean,
            }
        };
        self.pending.remove(&request_id);
        outcome
    }

    /// Deliver a renderer reply. Returns `false` when it matched no pending
    /// query of that window (unknown id, wrong window, already settled).
    pub fn report(&self, window_label: &str, report: &DirtyReport) -> bool {
        let Some(id) = report.request_id.as_deref() else {
            return false;
        };
        let Some(pending) = self.pending.get(id).map(|p| p.clone()) else {
            return false;
        };
        if pending.label != window_label {
            return false;
        }
        match Self::classify(report) {
            None => {
                pending.transfers_pending.store(true, Ordering::SeqCst);
                true
            }
            Some(outcome) => match pending.reply.lock().take() {
                Some(tx) => tx.send(outcome).is_ok(),
                None => false,
            },
        }
    }
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ---------------------------------------------------------------------------
// Managed state
// ---------------------------------------------------------------------------

/// Managed by `setup`; runtime independent so commands take
/// `tauri::State<'_, UpdateState>` directly.
pub struct UpdateState {
    machine: Mutex<Machine>,
    /// `update_check` result awaiting download.
    pending_update: Mutex<Option<Arc<Update>>>,
    /// Verified bytes of the downloaded bundle awaiting install.
    downloaded: Mutex<Option<Arc<Vec<u8>>>>,
    /// Scheduled automatic check (startup / re-enable), cancelled by a
    /// manual check so two checks never overlap.
    auto_check: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    /// Quit-for-update watchdog (clears the flags if the app did not quit).
    watchdog: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    /// Close-to-tray value to restore when an install does not quit.
    close_to_tray_before_install: Mutex<Option<bool>>,
    /// In-memory copy of the persisted preference.
    auto_update: AtomicBool,
    plugin_ready: AtomicBool,
    pub dirty_guard: DirtyEditorGuard,
}

impl Default for UpdateState {
    fn default() -> Self {
        Self {
            machine: Mutex::new(Machine::default()),
            pending_update: Mutex::new(None),
            downloaded: Mutex::new(None),
            auto_check: Mutex::new(None),
            watchdog: Mutex::new(None),
            close_to_tray_before_install: Mutex::new(None),
            auto_update: AtomicBool::new(true),
            plugin_ready: AtomicBool::new(false),
            dirty_guard: DirtyEditorGuard::default(),
        }
    }
}

impl UpdateState {
    pub fn snapshot(&self) -> UpdateStatus {
        self.machine.lock().snapshot()
    }

    pub fn auto_update_enabled(&self) -> bool {
        self.auto_update.load(Ordering::SeqCst)
    }

    fn cancel_auto_check(&self) {
        if let Some(handle) = self.auto_check.lock().take() {
            handle.abort();
        }
    }

    fn cancel_watchdog(&self) {
        if let Some(handle) = self.watchdog.lock().take() {
            handle.abort();
        }
    }
}

fn update_state<R: Runtime>(app: &AppHandle<R>) -> tauri::State<'_, UpdateState> {
    app.state::<UpdateState>()
}

/// Register the updater plugin and the managed state; schedule the startup
/// check. The plugin needs `plugins.updater` in the Tauri config: without it
/// (headless tests, stripped configs) the updater simply reports
/// `supported: false` instead of failing the app build.
pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    let handle = app.handle().clone();
    let plugin_ready = match handle.plugin(tauri_plugin_updater::Builder::new().build()) {
        Ok(()) => true,
        Err(err) => {
            tracing::warn!(%err, "updater unavailable");
            false
        }
    };
    let state = UpdateState::default();
    state.plugin_ready.store(plugin_ready, Ordering::SeqCst);
    app.manage(state);

    tauri::async_runtime::spawn(async move {
        let app_state = handle.state::<crate::state::AppState<R>>();
        let enabled = read_auto_update_pref(&app_state.store).await;
        update_state(&handle).auto_update.store(enabled, Ordering::SeqCst);
        if enabled {
            schedule_auto_check(&handle, STARTUP_CHECK_DELAY);
        }
    });
}

async fn read_auto_update_pref(store: &netcatty_store::KvStore) -> bool {
    match store.get(AUTO_UPDATE_PREF_KEY).await {
        Ok(Some(value)) => value.trim() != "false",
        // Default to enabled, like Electron when the file is missing.
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Support / availability
// ---------------------------------------------------------------------------

fn support<R: Runtime>(app: &AppHandle<R>) -> Result<(), Unsupported> {
    let st = update_state(app);
    let pubkey_ok = configured_pubkey(app).is_some_and(|k| pubkey_looks_valid(&k));
    support_for(
        cfg!(debug_assertions),
        st.plugin_ready.load(Ordering::SeqCst),
        pubkey_ok,
        cfg!(target_os = "linux"),
        linux_package_type(),
    )
}

fn unsupported_result(reason: &Unsupported) -> CheckResult {
    CheckResult {
        available: false,
        supported: false,
        error: Some(reason.message().to_owned()),
        releases_url: Some(RELEASES_URL.to_owned()),
        ..CheckResult::default()
    }
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

/// Electron: `startAutoCheck(delay)` — one automatic check unless the
/// preference was switched off in the meantime.
fn schedule_auto_check<R: Runtime>(app: &AppHandle<R>, delay: Duration) {
    if support(app).is_err() {
        tracing::debug!("auto-update unsupported here; automatic check skipped");
        return;
    }
    let st = update_state(app);
    st.cancel_auto_check();
    let handle = app.clone();
    let task = tauri::async_runtime::spawn(async move {
        tokio::time::sleep(delay).await;
        {
            let st = update_state(&handle);
            *st.auto_check.lock() = None;
            if !st.auto_update_enabled() {
                tracing::debug!("automatic update check skipped: auto-update disabled");
                return;
            }
        }
        tracing::info!("starting automatic update check");
        let result = run_check(&handle).await;
        if let Some(err) = result.error {
            tracing::warn!(error = %err, "automatic update check failed");
        }
    });
    *st.auto_check.lock() = Some(task);
}

fn release_date(update: &Update) -> Option<String> {
    update
        .raw_json
        .get("pub_date")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

/// The shared check: contacts the endpoint, updates the machine, broadcasts
/// `update-available` / `update-not-available`, starts the download when
/// auto-update is on. Check-phase errors are returned, not broadcast.
async fn run_check<R: Runtime>(app: &AppHandle<R>) -> CheckResult {
    if let Err(reason) = support(app) {
        return unsupported_result(&reason);
    }
    let st = update_state(app);
    {
        let mut machine = st.machine.lock();
        match machine.check_shortcut() {
            Some(CheckShortcut::Checking) => {
                return CheckResult {
                    available: false,
                    supported: true,
                    checking: Some(true),
                    ..CheckResult::default()
                };
            }
            Some(CheckShortcut::Downloading { version }) => {
                return CheckResult {
                    available: true,
                    supported: true,
                    downloading: Some(true),
                    version,
                    ..CheckResult::default()
                };
            }
            Some(CheckShortcut::Ready { version }) => {
                return CheckResult {
                    available: true,
                    supported: true,
                    ready: Some(true),
                    version,
                    ..CheckResult::default()
                };
            }
            None => machine.check_started(),
        }
    }

    let checked = match app.updater() {
        Ok(updater) => updater.check().await.map_err(|e| e.to_string()),
        Err(err) => Err(err.to_string()),
    };

    match checked {
        Ok(Some(update)) => {
            let will_download = st.auto_update_enabled();
            let version = update.version.clone();
            let notes = update.body.clone().unwrap_or_default();
            let date = release_date(&update);
            let update = Arc::new(update);
            *st.pending_update.lock() = Some(update.clone());
            st.machine.lock().available(&version, will_download);
            crate::events::emit(
                app,
                events::UPDATE_AVAILABLE,
                AvailableEvent {
                    version: version.clone(),
                    release_notes: notes.clone(),
                    release_date: date.clone(),
                },
            );
            if will_download {
                spawn_download(app.clone(), update);
            }
            CheckResult {
                available: true,
                supported: true,
                version: Some(version),
                release_notes: Some(notes),
                release_date: date,
                ..CheckResult::default()
            }
        }
        Ok(None) => {
            st.machine.lock().not_available();
            *st.pending_update.lock() = None;
            crate::events::emit(app, events::UPDATE_NOT_AVAILABLE, serde_json::json!({}));
            CheckResult {
                available: false,
                supported: true,
                ..CheckResult::default()
            }
        }
        Err(message) => {
            st.machine.lock().check_failed();
            tracing::warn!(error = %message, "update check failed");
            CheckResult {
                available: false,
                supported: true,
                error: Some(message),
                ..CheckResult::default()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

/// Download `update` in the background (auto-download after a check).
fn spawn_download<R: Runtime>(app: AppHandle<R>, update: Arc<Update>) {
    tauri::async_runtime::spawn(async move {
        // Failures are already broadcast as `netcatty:update:error`.
        let _ = download_update(&app, update).await;
    });
}

/// Download and verify; the machine is already in the downloading phase.
/// Emits progress, then `downloaded` or `error`.
async fn download_update<R: Runtime>(app: &AppHandle<R>, update: Arc<Update>) -> Result<(), String> {
    let started = Instant::now();
    let mut transferred: u64 = 0;
    let mut last_emit: Option<Instant> = None;
    let mut last_percent: Option<u8> = None;
    let progress_app = app.clone();
    let on_chunk = |chunk: usize, total: Option<u64>| {
        transferred += chunk as u64;
        let total = total.unwrap_or(0);
        let percent = if total > 0 {
            (transferred as f64 / total as f64 * 100.0).min(100.0)
        } else {
            0.0
        };
        let rounded = percent.round() as u8;
        let due = last_emit.is_none_or(|t| t.elapsed() >= PROGRESS_INTERVAL)
            || last_percent != Some(rounded)
            || (total > 0 && transferred >= total);
        if !due {
            return;
        }
        last_emit = Some(Instant::now());
        last_percent = Some(rounded);
        let elapsed = started.elapsed().as_secs_f64();
        let bytes_per_second = if elapsed > 0.0 {
            (transferred as f64 / elapsed) as u64
        } else {
            0
        };
        update_state(&progress_app).machine.lock().progress(percent);
        crate::events::emit(
            &progress_app,
            events::DOWNLOAD_PROGRESS,
            ProgressEvent {
                percent,
                bytes_per_second,
                transferred,
                total,
            },
        );
    };

    let result = update.download(on_chunk, || {}).await;
    let st = update_state(app);
    match result {
        Ok(bytes) => {
            *st.downloaded.lock() = Some(Arc::new(bytes));
            st.machine.lock().downloaded();
            crate::events::emit(app, events::DOWNLOADED, ());
            Ok(())
        }
        Err(err) => {
            let message = err.to_string();
            st.machine.lock().failed(&message);
            tracing::error!(error = %message, "update download failed");
            crate::events::emit(
                app,
                events::ERROR,
                ErrorEvent {
                    error: message.clone(),
                },
            );
            Err(message)
        }
    }
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

/// Electron's `setQuittingForUpdate(true)`: commit to a real quit so
/// close-to-tray cannot keep the process alive while the installer waits for
/// it to exit. The previous value is kept for the rollback paths.
fn set_quitting_for_update<R: Runtime>(app: &AppHandle<R>, quitting: bool) {
    let st = update_state(app);
    if quitting {
        let previous = super::tray::tray_is_close_to_tray(app.clone()).enabled;
        *st.close_to_tray_before_install.lock() = Some(previous);
        if previous {
            super::tray::tray_set_close_to_tray(app.clone(), false);
        }
    } else if let Some(previous) = st.close_to_tray_before_install.lock().take() {
        if previous {
            super::tray::tray_set_close_to_tray(app.clone(), true);
        }
    }
}

fn rollback_install<R: Runtime>(app: &AppHandle<R>) {
    let st = update_state(app);
    st.cancel_watchdog();
    st.machine.lock().install_cancelled();
    set_quitting_for_update(app, false);
}

fn schedule_quitting_watchdog<R: Runtime>(app: &AppHandle<R>) {
    let st = update_state(app);
    st.cancel_watchdog();
    let handle = app.clone();
    let task = tauri::async_runtime::spawn(async move {
        tokio::time::sleep(QUITTING_WATCHDOG).await;
        *update_state(&handle).watchdog.lock() = None;
        tracing::warn!("app still running after the update install; clearing quitting-for-update state");
        rollback_install(&handle);
    });
    *st.watchdog.lock() = Some(task);
}

fn install_failed<R: Runtime>(app: &AppHandle<R>, message: String) {
    tracing::error!(error = %message, "update install failed");
    rollback_install(app);
    update_state(app).machine.lock().failed(&message);
    crate::events::emit(app, events::ERROR, ErrorEvent { error: message });
}

/// Labels of the windows that own editor tabs (Electron:
/// `getDirtyEditorWindows`): the main window only; the settings and tray
/// panel windows do not take part in the protocol.
fn dirty_editor_windows<R: Runtime>(app: &AppHandle<R>) -> Vec<String> {
    app.webview_windows()
        .keys()
        .filter(|label| label.as_str() == super::window::MAIN_LABEL)
        .cloned()
        .collect()
}

async fn install_update<R: Runtime>(app: &AppHandle<R>) {
    let st = update_state(app);
    let (update, bytes) = {
        let update = st.pending_update.lock().clone();
        let bytes = st.downloaded.lock().clone();
        match (update, bytes) {
            (Some(update), Some(bytes)) if st.machine.lock().phase == Phase::Ready => {
                (update, bytes)
            }
            _ => {
                crate::events::emit(
                    app,
                    events::ERROR,
                    ErrorEvent {
                        error: "No downloaded update to install.".to_owned(),
                    },
                );
                return;
            }
        }
    };
    if st.machine.lock().installing {
        return;
    }

    // Ask every main window about unsaved work BEFORE committing to a quit.
    for label in dirty_editor_windows(app) {
        let outcome = st
            .dirty_guard
            .query(app, &label, DIRTY_CHECK_TIMEOUT)
            .await;
        if outcome.blocks() {
            tracing::info!(?outcome, "update install blocked by unsaved work");
            crate::events::emit(app, events::NEEDS_SAVE, ());
            return;
        }
    }

    // Another request may have finished its dirty check meanwhile.
    if !st.machine.lock().install_started() {
        return;
    }
    set_quitting_for_update(app, true);

    let installer = update.clone();
    let payload = bytes.clone();
    let installed = tokio::task::spawn_blocking(move || installer.install(payload.as_slice()))
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r.map_err(|e| e.to_string()));
    match installed {
        Ok(()) => {
            // Windows: the installer already exited the process. macOS /
            // Linux: the bundle was replaced in place; relaunch it.
            schedule_quitting_watchdog(app);
            tracing::info!(version = %update.version, "update installed; restarting");
            app.request_restart();
        }
        Err(message) => install_failed(app, message),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn update_check<R: Runtime>(app: AppHandle<R>) -> CheckResult {
    // Cancel a queued automatic check so two never run concurrently.
    update_state(&app).cancel_auto_check();
    run_check(&app).await
}

#[tauri::command]
pub async fn update_download<R: Runtime>(app: AppHandle<R>) -> DownloadResult {
    let st = update_state(&app);
    let Some(update) = st.pending_update.lock().clone() else {
        return DownloadResult {
            success: false,
            error: Some("No update available to download; check for updates first.".to_owned()),
        };
    };
    if !st.machine.lock().download_started() {
        // Already downloading (auto-download or an earlier call).
        return DownloadResult {
            success: true,
            error: None,
        };
    }
    match download_update(&app, update).await {
        Ok(()) => DownloadResult {
            success: true,
            error: None,
        },
        Err(error) => DownloadResult {
            success: false,
            error: Some(error),
        },
    }
}

#[tauri::command]
pub async fn update_install<R: Runtime>(app: AppHandle<R>) {
    install_update(&app).await;
}

#[tauri::command]
pub fn update_get_status<R: Runtime>(app: AppHandle<R>) -> UpdateStatus {
    update_state(&app).snapshot()
}

#[tauri::command]
pub fn update_get_auto_update<R: Runtime>(app: AppHandle<R>) -> AutoUpdatePref {
    AutoUpdatePref {
        enabled: update_state(&app).auto_update_enabled(),
    }
}

#[tauri::command]
pub async fn update_set_auto_update<R: Runtime>(
    ctx: crate::state::Ctx<'_, R>,
    enabled: bool,
) -> CmdResult<SuccessResult> {
    let app = ctx.app.clone();
    let st = update_state(&app);
    let was_enabled = st.auto_update.swap(enabled, Ordering::SeqCst);
    if let Err(err) = ctx
        .store
        .set(AUTO_UPDATE_PREF_KEY, if enabled { "true" } else { "false" })
        .await
    {
        tracing::warn!(%err, "failed to persist the auto-update preference");
    }
    if !enabled {
        st.cancel_auto_check();
    } else if !was_enabled && !st.machine.lock().checking {
        schedule_auto_check(&app, REENABLE_CHECK_DELAY);
    }
    Ok(SuccessResult { success: true })
}

/// Renderer reply to `app:query-dirty-editors`. Only the window that was
/// asked may answer, so the reply is matched against the caller's label.
#[tauri::command]
pub fn app_report_dirty_editors<R: Runtime>(
    app: AppHandle<R>,
    window: tauri::Window<R>,
    payload: Option<DirtyReport>,
) -> CmdResult<()> {
    let report = payload.ok_or_else(|| CoreError::invalid("payload is required"))?;
    if !update_state(&app).dirty_guard.report(window.label(), &report) {
        tracing::debug!(label = window.label(), "dirty-editor reply matched no pending query");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_has_electron_shape() {
        let json = serde_json::to_value(Machine::default().snapshot()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "status": "idle", "percent": 0, "error": null, "version": null, "isChecking": false
            })
        );
    }

    #[test]
    fn prompt_flow_check_download_ready() {
        let mut m = Machine::default();
        assert_eq!(m.check_shortcut(), None);
        m.check_started();
        assert_eq!(m.check_shortcut(), Some(CheckShortcut::Checking));
        assert!(m.snapshot().is_checking);

        // Auto-update off: the update is only announced.
        m.available("1.3.0", false);
        assert_eq!(m.phase, Phase::Available);
        assert!(!m.downloading);
        assert_eq!(m.version.as_deref(), Some("1.3.0"));
        assert_eq!(m.check_shortcut(), None);

        assert!(m.download_started());
        assert!(!m.download_started(), "a second download request is a no-op");
        assert_eq!(
            m.check_shortcut(),
            Some(CheckShortcut::Downloading {
                version: Some("1.3.0".into())
            })
        );
        m.progress(42.4);
        assert_eq!(m.snapshot().percent, 42);
        m.progress(150.0);
        assert_eq!(m.snapshot().percent, 100);

        m.downloaded();
        assert_eq!(m.phase, Phase::Ready);
        assert_eq!(m.percent, 100);
        assert_eq!(
            m.check_shortcut(),
            Some(CheckShortcut::Ready {
                version: Some("1.3.0".into())
            })
        );

        assert!(m.install_started());
        assert!(!m.install_started());
        m.install_cancelled();
        assert!(m.install_started());
    }

    #[test]
    fn auto_download_marks_downloading_on_available() {
        let mut m = Machine::default();
        m.check_started();
        m.available("2.0.0", true);
        assert_eq!(m.phase, Phase::Downloading);
        assert!(m.downloading);
        assert!(!m.checking);
        assert_eq!(m.snapshot().status, Phase::Downloading);
    }

    #[test]
    fn not_available_resets_stale_snapshots_but_keeps_installing() {
        let mut m = Machine::default();
        m.available("1.1.0", true);
        m.failed("boom");
        assert_eq!(m.phase, Phase::Error);
        m.installing = true;
        m.not_available();
        assert_eq!(m.phase, Phase::Idle);
        assert_eq!(m.error, None);
        assert_eq!(m.version, None);
        assert!(m.installing);
    }

    #[test]
    fn failures_clear_flags_and_keep_version() {
        let mut m = Machine::default();
        m.available("1.1.0", true);
        m.failed("network down");
        let s = m.snapshot();
        assert_eq!(s.status, Phase::Error);
        assert_eq!(s.error.as_deref(), Some("network down"));
        assert_eq!(s.version.as_deref(), Some("1.1.0"));
        assert!(!m.downloading && !m.checking && !m.installing);
        // A check error before a result only clears the checking flag.
        m.check_started();
        m.check_failed();
        assert!(!m.checking);
        assert_eq!(m.phase, Phase::Error);
    }

    #[test]
    fn check_result_serialization_skips_absent_fields() {
        let json = serde_json::to_value(CheckResult {
            available: false,
            supported: true,
            checking: Some(true),
            ..CheckResult::default()
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "available": false, "supported": true, "checking": true })
        );
        let json = serde_json::to_value(unsupported_result(&Unsupported::LinuxPackage)).unwrap();
        assert_eq!(json["supported"], false);
        assert_eq!(json["releasesUrl"], RELEASES_URL);
        assert!(json["error"].as_str().unwrap().contains("not supported"));
        assert!(json.get("version").is_none());
    }

    #[test]
    fn support_matrix() {
        assert_eq!(
            support_for(true, true, true, false, None),
            Err(Unsupported::DevBuild)
        );
        assert_eq!(
            support_for(false, false, true, false, None),
            Err(Unsupported::PluginUnavailable)
        );
        assert_eq!(
            support_for(false, true, false, false, None),
            Err(Unsupported::SigningKeyMissing)
        );
        assert_eq!(
            support_for(false, true, true, true, None),
            Err(Unsupported::LinuxPackage)
        );
        for pkg in ["AppImage", "deb", "rpm"] {
            assert_eq!(support_for(false, true, true, true, Some(pkg)), Ok(()));
        }
        assert_eq!(support_for(false, true, true, false, None), Ok(()));
    }

    #[test]
    fn pubkey_placeholder_is_rejected() {
        use base64::Engine;
        assert!(!pubkey_looks_valid(""));
        assert!(!pubkey_looks_valid("REPLACE_WITH_TAURI_UPDATER_PUBLIC_KEY"));
        assert!(!pubkey_looks_valid("aGVsbG8=")); // "hello"
        let key = base64::engine::general_purpose::STANDARD
            .encode("untrusted comment: minisign public key: ABC\nRWQfake==\n");
        assert!(pubkey_looks_valid(&key));
    }

    #[test]
    fn dirty_reply_classification() {
        let report = |has_dirty, reason: Option<&str>, pending| DirtyReport {
            request_id: Some("r".into()),
            has_dirty,
            reason: reason.map(str::to_owned),
            pending,
        };
        assert_eq!(
            DirtyEditorGuard::classify(&report(false, None, false)),
            Some(DirtyOutcome::Clean)
        );
        assert_eq!(
            DirtyEditorGuard::classify(&report(true, Some("editors"), false)),
            Some(DirtyOutcome::Editors)
        );
        assert_eq!(
            DirtyEditorGuard::classify(&report(true, None, false)),
            Some(DirtyOutcome::Editors)
        );
        assert_eq!(
            DirtyEditorGuard::classify(&report(true, Some("transfers"), false)),
            Some(DirtyOutcome::Transfers)
        );
        // A pending transfers acknowledgement does not settle the query.
        assert_eq!(
            DirtyEditorGuard::classify(&report(true, Some("transfers"), true)),
            None
        );
        assert!(DirtyOutcome::Editors.blocks());
        assert!(!DirtyOutcome::Clean.blocks());
    }

    #[test]
    fn dirty_report_rejects_unknown_and_wrong_window() {
        let guard = DirtyEditorGuard::default();
        let report = DirtyReport {
            request_id: Some("missing".into()),
            has_dirty: true,
            reason: None,
            pending: false,
        };
        assert!(!guard.report("main", &report));
        assert!(!guard.report("main", &DirtyReport::default()));
    }

    #[tokio::test]
    async fn dirty_query_round_trip_with_mock_app() {
        use tauri::test::{mock_app, MockRuntime};
        let app = mock_app();
        let handle: AppHandle<MockRuntime> = app.handle().clone();
        tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .unwrap();
        let guard = Arc::new(DirtyEditorGuard::default());

        // Reply from the right window settles the query.
        let g = guard.clone();
        let replier = tauri::async_runtime::spawn(async move {
            let started = Instant::now();
            loop {
                let id = g.pending.iter().next().map(|e| e.key().clone());
                if let Some(id) = id {
                    let bad = DirtyReport {
                        request_id: Some(id.clone()),
                        has_dirty: true,
                        reason: Some("editors".into()),
                        pending: false,
                    };
                    // Wrong window: ignored.
                    assert!(!g.report("settings", &bad));
                    // Pending transfers ack: kept open.
                    assert!(g.report(
                        "main",
                        &DirtyReport {
                            request_id: Some(id.clone()),
                            has_dirty: true,
                            reason: Some("transfers".into()),
                            pending: true,
                        }
                    ));
                    assert!(g.report(
                        "main",
                        &DirtyReport {
                            request_id: Some(id),
                            has_dirty: false,
                            reason: None,
                            pending: false,
                        }
                    ));
                    return;
                }
                assert!(started.elapsed() < Duration::from_secs(5), "query never registered");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let outcome = guard
            .query(&handle, "main", Duration::from_secs(5))
            .await;
        replier.await.unwrap();
        assert_eq!(outcome, DirtyOutcome::Clean);
        assert!(guard.pending.is_empty());

        // Timeout fails open ...
        let outcome = guard
            .query(&handle, "main", Duration::from_millis(50))
            .await;
        assert_eq!(outcome, DirtyOutcome::Clean);

        // ... unless transfers were acknowledged as pending.
        let g = guard.clone();
        let replier = tauri::async_runtime::spawn(async move {
            loop {
                let id = g.pending.iter().next().map(|e| e.key().clone());
                if let Some(id) = id {
                    g.report(
                        "main",
                        &DirtyReport {
                            request_id: Some(id),
                            has_dirty: true,
                            reason: Some("transfers".into()),
                            pending: true,
                        },
                    );
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let outcome = guard
            .query(&handle, "main", Duration::from_millis(200))
            .await;
        replier.await.unwrap();
        assert_eq!(outcome, DirtyOutcome::Transfers);

        // No such window: fail open immediately.
        let outcome = guard
            .query(&handle, "nope", Duration::from_secs(5))
            .await;
        assert_eq!(outcome, DirtyOutcome::Clean);
    }
}
