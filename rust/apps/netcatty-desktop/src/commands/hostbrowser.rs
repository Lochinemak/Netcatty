//! In-app host browser (Electron: `electron/hostBrowser/hostBrowserManager.cjs`
//! and the `netcatty:host-browser:*` IPC handlers). See
//! `rust/docs/ipc-hostbrowser.md`.
//!
//! # Shape
//!
//! A *browser record* holds up to [`MAX_TABS`] tabs for one host. Every tab
//! that shows a page is its own borderless, parented `WebviewWindow`
//! (label `hb-tab-…`) positioned over a rectangle of an *owner* window:
//!
//! * **embedded** (`openHostBrowser({ embedded: true })`, the side panel next
//!   to a terminal): the owner is the renderer window that called; the
//!   rectangle comes from `setHostBrowserPanelLayout`. The renderer draws the
//!   tab strip and address bar itself.
//! * **standalone**: the owner is a browser window (label `host-browser-…`)
//!   showing the Electron chrome (`hostbrowser/browser.html`, served by the
//!   `netcatty-hostbrowser:` protocol); pages fill the area below it.
//!
//! Tauri's multi-webview windows (`unstable` feature, `Window::add_child`)
//! were evaluated first: on macOS a child webview renders fine, but the main
//! window stops being a `WebviewWindow` (`get_webview_window("main")` returns
//! `None`), which breaks every window / tray / settings command of the app.
//! Parented windows avoid that.
//!
//! # Network route
//!
//! Pages of SSH hosts go through a dynamic (SOCKS5) forward of a dedicated
//! connection (`netcatty-forward`, `reuseTransport: false`). A webview's proxy
//! can only be set when it is created, so page webviews exist only while the
//! route is connected; a reconnect (new SOCKS port) recreates them. Local
//! hosts browse directly. Per-platform support is described in
//! [`proxy_support`].
//!
//! # Threading
//!
//! Webview callbacks (navigation, page load, title, download) run on the
//! main thread. They never take the state lock: synchronous decisions use
//! per-record atomics, everything else is spawned. Commands are `async` (they
//! run on the async runtime and may block on main-thread window getters while
//! holding the lock, which is safe because the main thread never waits on it).

use super::CmdResult;
use crate::state::{AppState, Ctx};
use netcatty_core::CoreError;
use netcatty_hostbrowser::{
    icon_origin, image_mime, is_allowed_page_url, normalize_browser_url, reserve_download_file,
    valid_image_data_url, valid_theme_tokens, BookmarkStore, Download, DownloadStatus,
    DownloadStore, IconMode, SiteIconInput, SiteIconStore, CHROME_HEIGHT, DOWNLOAD_PANEL_WIDTH,
    MAX_TABS,
};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tauri::webview::{DownloadEvent, NewWindowResponse, PageLoadEvent};
use tauri::{
    AppHandle, Manager, PhysicalPosition, PhysicalSize, Runtime, UriSchemeContext, WebviewUrl,
    WebviewWindow, WebviewWindowBuilder, WindowEvent,
};

// ---------------------------------------------------------------------------
// Contract constants
// ---------------------------------------------------------------------------

/// Renderer events (Electron channel names).
pub const EVENT_PANEL: &str = "netcatty:host-browser:panel-event";
pub const EVENT_BOOKMARKS_CHANGED: &str = "netcatty:host-browser:bookmarks-changed";
pub const EVENT_REQUEST_PANEL: &str = "netcatty:host-browser:request-panel";
/// Browser chrome / downloads panel events (standalone windows only). Their
/// payload is `{ labels: string[], payload }`: Tauri delivers every event to
/// every `listen()` subscriber, so pages keep only events for their label.
pub const EVENT_STATE: &str = "netcatty:host-browser:state";
pub const EVENT_DOWNLOADS_CHANGED: &str = "netcatty:host-browser:downloads-changed";
pub const EVENT_SITE_ICONS_CHANGED: &str = "netcatty:host-browser:site-icons-changed";
pub const EVENT_SHORTCUT: &str = "netcatty:host-browser:shortcut";
pub const EVENT_THEME: &str = "netcatty:host-browser:theme";

/// Custom protocol serving the browser chrome assets.
pub const ASSET_SCHEME: &str = "netcatty-hostbrowser";
/// Page → backend keyboard shortcut channel: the injected script navigates
/// to `netcatty-hb://shortcut/<type>`, which the navigation handler cancels.
const SHORTCUT_SCHEME: &str = "netcatty-hb";
/// Label prefixes. `host-browser-*` windows (chrome, downloads panel) get
/// the `hostbrowser` capability; page windows get none.
const CHROME_PREFIX: &str = "host-browser-";
const DOWNLOADS_PREFIX: &str = "host-browser-dl-";
const TAB_PREFIX: &str = "hb-tab-";
const MAIN_LABEL: &str = "main";
const ICON_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const ICON_FETCH_LIMIT: usize = 64 * 1024;
/// Width of the standalone chrome's bookmark panel.
const BOOKMARK_PANEL_WIDTH: f64 = 360.0;

const SHORTCUT_SCRIPT: &str = r#"(function () {
  if (window.top !== window) return;
  window.addEventListener('keydown', function (event) {
    var mac = /Mac/.test(navigator.platform);
    if (!(mac ? event.metaKey : event.ctrlKey) || event.altKey) return;
    var type = { t: 'new-tab', w: 'close-tab', r: 'reload', l: 'focus-address' }[String(event.key || '').toLowerCase()];
    if (!type) return;
    event.preventDefault();
    event.stopPropagation();
    try { window.location.href = 'netcatty-hb://shortcut/' + type; } catch (_) {}
  }, true);
})();"#;

const ICON_LINKS_SCRIPT: &str = "JSON.stringify(Array.from(document.querySelectorAll('link[rel~=\"icon\" i], link[rel=\"apple-touch-icon\" i]')).map(function (l) { return l.href; }).filter(Boolean).slice(0, 8))";

fn internal(err: impl std::fmt::Display) -> CoreError {
    CoreError::internal(err.to_string())
}

fn invalid(message: &str) -> CoreError {
    CoreError::invalid(message.to_string())
}

fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(windows) {
        "win32"
    } else {
        "linux"
    }
}

// ---------------------------------------------------------------------------
// Proxy support per platform
// ---------------------------------------------------------------------------

/// Can page webviews be routed through a SOCKS5 proxy on this machine?
///
/// * **macOS**: WebKit `WKWebsiteDataStore.proxyConfigurations` (wry
///   `mac-proxy`), available from macOS 14. The `Network` framework is
///   weak-linked (`build.rs`) so older systems still launch; SSH routes are
///   refused there.
/// * **Windows**: WebView2 `--proxy-server=socks5://…` in a browser
///   environment of its own (separate data directory per browser).
/// * **Linux**: WebKitGTK network proxy settings on an ephemeral context.
pub fn proxy_support() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        if !cfg!(feature = "hostbrowser-proxy") {
            return Err("This build cannot route browser traffic through SSH".into());
        }
        if macos_major_version().is_some_and(|major| major < 14) {
            return Err("Browsing through SSH requires macOS 14 or later".into());
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_major_version() -> Option<u32> {
    static VERSION: OnceLock<Option<u32>> = OnceLock::new();
    *VERSION.get_or_init(|| {
        let output = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()?;
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .split('.')
            .next()?
            .parse()
            .ok()
    })
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Connecting,
    Connected,
    Disconnected,
}

impl Route {
    fn as_str(self) -> &'static str {
        match self {
            Route::Connecting => "connecting",
            Route::Connected => "connected",
            Route::Disconnected => "disconnected",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

struct Tab {
    id: String,
    label: String,
    url: String,
    title: String,
    loading: bool,
    /// Approximate back / forward list (wry exposes no history API).
    history: Vec<String>,
    index: usize,
    pending_step: Option<isize>,
    /// The page window exists (created with the current route's proxy).
    webview: bool,
    shown: bool,
}

impl Tab {
    fn new(url: Option<String>) -> Self {
        let id = netcatty_core::ids::new_id();
        Self {
            label: format!("{TAB_PREFIX}{}", id.replace('-', "")),
            id,
            url: url.unwrap_or_default(),
            title: "New tab".into(),
            loading: false,
            history: Vec::new(),
            index: 0,
            pending_step: None,
            webview: false,
            shown: false,
        }
    }

    fn can_go_back(&self) -> bool {
        self.index > 0 && !self.history.is_empty()
    }

    fn can_go_forward(&self) -> bool {
        self.index + 1 < self.history.len()
    }

    fn record_navigation(&mut self, url: &str) {
        if let Some(step) = self.pending_step.take() {
            let target = (self.index as isize + step).clamp(0, self.history.len() as isize - 1);
            if target >= 0 {
                self.index = target as usize;
                if self.history.get(self.index).map(String::as_str) != Some(url) {
                    self.history[self.index] = url.to_string();
                }
                return;
            }
        }
        if self.history.get(self.index).map(String::as_str) == Some(url) {
            return;
        }
        if !self.history.is_empty() {
            self.history.truncate(self.index + 1);
        }
        self.history.push(url.to_string());
        self.index = self.history.len() - 1;
    }
}

struct Record {
    id: String,
    host_id: String,
    label: String,
    embedded: bool,
    local: bool,
    theme: String,
    theme_tokens: BTreeMap<String, String>,
    /// Window the page windows are positioned in.
    owner_label: String,
    /// Window allowed to control this browser (renderer window or chrome).
    source_label: String,
    downloads_label: Option<String>,
    route: Route,
    /// Mirrors `route == Connected` for main-thread callbacks.
    connected: Arc<AtomicBool>,
    error: Option<String>,
    generation: u64,
    tunnel_id: Option<String>,
    proxy_port: Option<u16>,
    connection_options: Option<Value>,
    tabs: Vec<Tab>,
    active_tab_id: Option<String>,
    visible: bool,
    /// Page area in logical pixels relative to the owner's content area.
    bounds: Rect,
    overlay_open: bool,
    panel_open: bool,
    downloads_panel_open: bool,
    /// WebView2 user data folder of this browser (Windows only).
    #[cfg_attr(not(windows), allow(dead_code))]
    data_dir: PathBuf,
}

impl Record {
    fn tab(&self, id: Option<&str>) -> Option<usize> {
        let id = id.or(self.active_tab_id.as_deref())?;
        self.tabs.iter().position(|tab| tab.id == id)
    }

    fn tab_by_label(&self, label: &str) -> Option<usize> {
        self.tabs.iter().position(|tab| tab.label == label)
    }

    fn set_route(&mut self, route: Route) {
        self.route = route;
        self.connected
            .store(route == Route::Connected, Ordering::SeqCst);
    }

    fn chrome_labels(&self) -> Vec<String> {
        let mut labels = vec![self.owner_label.clone()];
        labels.extend(self.downloads_label.clone());
        labels
    }
}

struct Layout {
    owner: String,
    visible: bool,
    occluded: bool,
    bounds: Option<Rect>,
    pending_urls: Vec<String>,
    theme: Option<String>,
    theme_tokens: BTreeMap<String, String>,
}

#[derive(Default)]
struct Inner {
    records: HashMap<String, Record>,
    layouts: HashMap<String, Layout>,
    /// Windows whose move / resize / destroy events are already observed.
    hooked: HashSet<String>,
    tunnel_watch: bool,
}

struct ActiveDownload {
    browser_id: String,
    host_id: String,
    tab_label: String,
    url: String,
    path: PathBuf,
    cancelled: bool,
}

struct Stores {
    bookmarks: BookmarkStore,
    downloads: DownloadStore,
    icons: SiteIconStore,
}

/// Managed state (registered in `lib.rs`).
#[derive(Default)]
pub struct HostBrowserState {
    inner: Mutex<Inner>,
    stores: OnceLock<Arc<Stores>>,
    /// Running downloads by id. Separate from `inner`: the download
    /// callback runs on the main thread and must not wait for `inner`.
    active: Mutex<HashMap<String, ActiveDownload>>,
    counter: AtomicU64,
}

fn host_state<R: Runtime>(app: &AppHandle<R>) -> tauri::State<'_, HostBrowserState> {
    app.state::<HostBrowserState>()
}

fn stores<R: Runtime>(app: &AppHandle<R>) -> Arc<Stores> {
    let state = host_state(app);
    let stores = state.stores.get_or_init(|| {
        let dir = app.state::<AppState<R>>().paths.data_dir.clone();
        let bookmarks = BookmarkStore::open(&dir);
        let handle = app.clone();
        bookmarks.set_on_change(move || {
            let handle = handle.clone();
            tauri::async_runtime::spawn(async move { bookmarks_changed(&handle) });
        });
        Arc::new(Stores {
            bookmarks,
            downloads: DownloadStore::open(&dir),
            icons: SiteIconStore::open(&dir),
        })
    });
    stores.clone()
}

fn downloads_dir<R: Runtime>(app: &AppHandle<R>) -> PathBuf {
    app.path()
        .download_dir()
        .ok()
        .or_else(|| dirs::home_dir().map(|home| home.join("Downloads")))
        .unwrap_or_else(std::env::temp_dir)
}

// ---------------------------------------------------------------------------
// Snapshots and events
// ---------------------------------------------------------------------------

fn snapshot<R: Runtime>(app: &AppHandle<R>, record: &Record) -> Value {
    let icons = &stores(app).icons;
    let is_maximized = !record.embedded
        && app
            .get_webview_window(&record.owner_label)
            .and_then(|w| w.is_maximized().ok())
            .unwrap_or(false);
    let tabs: Vec<Value> = record
        .tabs
        .iter()
        .map(|tab| {
            let icon = icons.get(&record.host_id, &tab.url);
            json!({
                "id": tab.id,
                "url": tab.url,
                "title": tab.title,
                "loading": tab.loading,
                "canGoBack": tab.can_go_back(),
                "canGoForward": tab.can_go_forward(),
                "iconDataUrl": icon.as_ref().and_then(|i| i.data_url.clone()),
                "iconGlyph": icon.as_ref().map(|i| i.glyph.clone()).filter(|g| !g.is_empty()),
                "iconColor": icon.as_ref().map(|i| i.color.clone()),
            })
        })
        .collect();
    json!({
        "hostId": record.host_id,
        "label": record.label,
        "theme": record.theme,
        "themeTokens": record.theme_tokens,
        "platform": platform(),
        "isMaximized": is_maximized,
        "embedded": record.embedded,
        "downloadsPanelOpen": record.downloads_panel_open,
        "route": record.route.as_str(),
        "error": record.error,
        "activeTabId": record.active_tab_id,
        "tabs": tabs,
    })
}

/// Event for the renderer window that owns an embedded browser. The adapter
/// keeps events whose `ownerLabel` is its own window and strips the field.
fn panel_event<R: Runtime>(app: &AppHandle<R>, record: &Record, mut event: Value) {
    if let Value::Object(map) = &mut event {
        map.insert("browserId".into(), json!(record.id));
        map.insert("ownerLabel".into(), json!(record.source_label));
    }
    crate::events::emit(app, EVENT_PANEL, event);
}

fn chrome_event<R: Runtime>(app: &AppHandle<R>, labels: Vec<String>, event: &str, payload: Value) {
    crate::events::emit(app, event, json!({ "labels": labels, "payload": payload }));
}

fn send<R: Runtime>(app: &AppHandle<R>, record: &Record) {
    let state = snapshot(app, record);
    if record.embedded {
        panel_event(app, record, json!({ "type": "state", "state": state }));
    } else {
        chrome_event(app, vec![record.owner_label.clone()], EVENT_STATE, state);
    }
}

fn notify_downloads<R: Runtime>(
    app: &AppHandle<R>,
    inner: &Inner,
    host_id: &str,
    started: Option<(&str, &str)>,
) {
    let downloads = json!(stores(app).downloads.list(host_id));
    for record in inner.records.values().filter(|r| r.host_id == host_id) {
        if record.embedded {
            let started_id = started
                .filter(|(browser, _)| *browser == record.id)
                .map(|(_, id)| id.to_string());
            let mut event = json!({ "type": "downloads", "downloads": downloads });
            if let Some(id) = started_id {
                event["startedId"] = json!(id);
            }
            panel_event(app, record, event);
        } else {
            if record.downloads_panel_open {
                position_downloads_window(app, record);
            }
            chrome_event(app, record.chrome_labels(), EVENT_DOWNLOADS_CHANGED, downloads.clone());
        }
    }
}

fn notify_site_icon<R: Runtime>(app: &AppHandle<R>, record: &Record) {
    send(app, record);
    if record.embedded {
        panel_event(app, record, json!({ "type": "bookmarks" }));
    } else {
        chrome_event(app, vec![record.owner_label.clone()], EVENT_SITE_ICONS_CHANGED, Value::Null);
    }
}

fn bookmarks_changed<R: Runtime>(app: &AppHandle<R>) {
    let state = host_state(app);
    {
        let inner = state.inner.lock();
        for record in inner.records.values().filter(|r| r.embedded) {
            panel_event(app, record, json!({ "type": "bookmarks" }));
        }
    }
    crate::events::emit(app, EVENT_BOOKMARKS_CHANGED, Value::Null);
}

fn send_theme<R: Runtime>(app: &AppHandle<R>, record: &Record) {
    if let Some(label) = &record.downloads_label {
        chrome_event(
            app,
            vec![label.clone()],
            EVENT_THEME,
            json!({ "theme": record.theme, "themeTokens": record.theme_tokens }),
        );
    }
}

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/// Page area in physical pixels of the screen, or `None` when it cannot be
/// shown (owner gone, empty rectangle).
fn page_area<R: Runtime>(
    app: &AppHandle<R>,
    record: &Record,
) -> Option<(PhysicalPosition<i32>, PhysicalSize<u32>, f64)> {
    let owner = app.get_webview_window(&record.owner_label)?;
    let scale = owner.scale_factor().ok()?;
    let origin = owner.inner_position().ok()?;
    let size = owner.inner_size().ok()?;
    let (owner_w, owner_h) = (size.width as f64 / scale, size.height as f64 / scale);
    let rect = if record.embedded {
        let x = record.bounds.x.clamp(0.0, owner_w);
        let y = record.bounds.y.clamp(0.0, owner_h);
        let right = (record.bounds.x + record.bounds.width).clamp(0.0, owner_w);
        let bottom = (record.bounds.y + record.bounds.height).clamp(0.0, owner_h);
        Rect {
            x,
            y,
            width: right - x,
            height: bottom - y,
        }
    } else {
        let panel = if record.panel_open {
            owner_w.min(BOOKMARK_PANEL_WIDTH)
        } else {
            0.0
        };
        Rect {
            x: 0.0,
            y: CHROME_HEIGHT,
            width: (owner_w - panel).max(1.0),
            height: (owner_h - CHROME_HEIGHT).max(1.0),
        }
    };
    if rect.width < 1.0 || rect.height < 1.0 {
        return None;
    }
    Some((
        PhysicalPosition::new(
            origin.x + (rect.x * scale).round() as i32,
            origin.y + (rect.y * scale).round() as i32,
        ),
        PhysicalSize::new(
            (rect.width * scale).round().max(1.0) as u32,
            (rect.height * scale).round().max(1.0) as u32,
        ),
        owner_w,
    ))
}

/// Show only the active tab's page, positioned over the page area
/// (Electron `displayTab` + `resizeView`).
fn display<R: Runtime>(app: &AppHandle<R>, record: &mut Record) {
    let area = if record.embedded && !record.visible {
        None
    } else {
        page_area(app, record)
    };
    let narrow_panel = record.panel_open
        && area
            .as_ref()
            .map(|(_, _, owner_w)| *owner_w <= 540.0)
            .unwrap_or(false);
    let active = record.active_tab_id.clone();
    let route = record.route;
    let overlay = record.overlay_open;
    let mut focus_owner = false;
    for index in 0..record.tabs.len() {
        let wanted = {
            let tab = &record.tabs[index];
            area.is_some()
                && Some(&tab.id) == active.as_ref()
                && !tab.url.is_empty()
                && route == Route::Connected
                && !overlay
                && !narrow_panel
        };
        if wanted && !record.tabs[index].webview {
            let url = record.tabs[index].url.clone();
            if let Err(err) = create_page(app, record, index, &url) {
                tracing::warn!(%err, "host browser page could not be created");
                continue;
            }
        }
        let tab = &mut record.tabs[index];
        let Some(window) = tab
            .webview
            .then(|| app.get_webview_window(&tab.label))
            .flatten()
        else {
            continue;
        };
        if wanted {
            let (position, size, _) = area.expect("checked above");
            let _ = window.set_position(position);
            let _ = window.set_size(size);
            if !tab.shown {
                let _ = window.show();
                tab.shown = true;
                // `show` makes the page key on macOS; keep keyboard focus
                // where it was (Electron attaches views without focusing).
                focus_owner = true;
            }
        } else if tab.shown {
            let _ = window.hide();
            tab.shown = false;
        }
    }
    if focus_owner {
        if let Some(owner) = app.get_webview_window(&record.owner_label) {
            let _ = owner.set_focus();
        }
    }
    if record.downloads_panel_open {
        position_downloads_window(app, record);
    }
    send(app, record);
}

fn position_downloads_window<R: Runtime>(app: &AppHandle<R>, record: &Record) {
    let (Some(label), Some(owner)) = (
        record.downloads_label.as_ref(),
        app.get_webview_window(&record.owner_label),
    ) else {
        return;
    };
    let Some(window) = app.get_webview_window(label) else {
        return;
    };
    let (Ok(scale), Ok(origin), Ok(size)) =
        (owner.scale_factor(), owner.inner_position(), owner.inner_size())
    else {
        return;
    };
    let (width, height) = (size.width as f64 / scale, size.height as f64 / scale);
    let downloads = stores(app).downloads.list(&record.host_id);
    let rows = (downloads.len() as f64 * 66.0 + 8.0).min(348.0);
    let panel_height = if downloads.is_empty() {
        230.0
    } else {
        72.0 + rows
            + if downloads.iter().any(|d| !d.item.status.is_active()) {
                38.0
            } else {
                0.0
            }
    };
    let x = (width - (DOWNLOAD_PANEL_WIDTH + 8.0)).max(0.0);
    let w = DOWNLOAD_PANEL_WIDTH.min(width);
    let h = panel_height.min((height - CHROME_HEIGHT).max(1.0));
    let _ = window.set_position(PhysicalPosition::new(
        origin.x + (x * scale).round() as i32,
        origin.y + (CHROME_HEIGHT * scale).round() as i32,
    ));
    let _ = window.set_size(PhysicalSize::new(
        (w * scale).round() as u32,
        (h * scale).round().max(1.0) as u32,
    ));
}

// ---------------------------------------------------------------------------
// Page windows
// ---------------------------------------------------------------------------

/// Create the page window of `record.tabs[index]` loading `url`, with the
/// current route's proxy.
fn create_page<R: Runtime>(
    app: &AppHandle<R>,
    record: &mut Record,
    index: usize,
    url: &str,
) -> Result<(), String> {
    let owner = app
        .get_webview_window(&record.owner_label)
        .ok_or("Browser window is unavailable")?;
    let parsed: url::Url = url.parse().map_err(|_| "Enter a valid web address")?;
    let label = record.tabs[index].label.clone();
    let connected = record.connected.clone();
    let browser_id = record.id.clone();
    let host_id = record.host_id.clone();
    let (nav_app, load_app, title_app, window_app, download_app) =
        (app.clone(), app.clone(), app.clone(), app.clone(), app.clone());
    let (nav_id, load_id, title_id, window_id) = (
        browser_id.clone(),
        browser_id.clone(),
        browser_id.clone(),
        browser_id.clone(),
    );
    let (nav_label, title_label) = (label.clone(), label.clone());
    let nav_connected = connected.clone();

    let builder = WebviewWindowBuilder::new(app, &label, WebviewUrl::External(parsed))
        .title("Browser")
        .decorations(false)
        .resizable(false)
        .skip_taskbar(true)
        .shadow(false)
        .visible(false)
        .focused(false)
        .accept_first_mouse(true)
        .incognito(true)
        .devtools(false)
        .initialization_script(SHORTCUT_SCRIPT)
        .parent(&owner)
        .map_err(|e| e.to_string())?
        .on_navigation(move |url| {
            if url.scheme() == SHORTCUT_SCHEME {
                if url.host_str() == Some("shortcut") {
                    let kind = url.path().trim_start_matches('/').to_string();
                    let (app, id, label) = (nav_app.clone(), nav_id.clone(), nav_label.clone());
                    tauri::async_runtime::spawn(async move { page_shortcut(&app, &id, &label, &kind) });
                }
                return false;
            }
            nav_connected.load(Ordering::SeqCst) && is_allowed_page_url(url.as_str())
        })
        .on_new_window(move |url, _features| {
            if let Ok(url) = normalize_browser_url(url.as_str()) {
                let (app, id) = (window_app.clone(), window_id.clone());
                tauri::async_runtime::spawn(async move {
                    let state = host_state(&app);
                    let mut inner = state.inner.lock();
                    if let Some(record) = inner.records.get_mut(&id) {
                        let _ = add_tab(&app, record, Some(url));
                    }
                });
            }
            NewWindowResponse::Deny
        })
        .on_page_load(move |webview, payload| {
            let started = matches!(payload.event(), PageLoadEvent::Started);
            let url = payload.url().to_string();
            let (app, id, label) = (load_app.clone(), load_id.clone(), webview.label().to_string());
            tauri::async_runtime::spawn(async move { page_loaded(&app, &id, &label, &url, started) });
        })
        .on_document_title_changed(move |_webview, title| {
            let (app, id, label) = (title_app.clone(), title_id.clone(), title_label.clone());
            tauri::async_runtime::spawn(async move {
                let state = host_state(&app);
                let mut inner = state.inner.lock();
                if let Some(record) = inner.records.get_mut(&id) {
                    if let Some(index) = record.tab_by_label(&label) {
                        record.tabs[index].title = if title.is_empty() {
                            record.tabs[index].url.clone()
                        } else {
                            title
                        };
                        send(&app, record);
                    }
                }
            });
        })
        .on_download(move |webview, event| {
            download_event(
                &download_app,
                &browser_id,
                &host_id,
                webview.label(),
                &connected,
                event,
            )
        });
    let builder = match (record.local, record.proxy_port) {
        (false, Some(port)) => {
            let proxy: url::Url = format!("socks5://127.0.0.1:{port}")
                .parse()
                .map_err(|_| "Browser route is unavailable")?;
            builder.proxy_url(proxy)
        }
        (false, None) => return Err("Browser route is unavailable".into()),
        (true, _) => builder,
    };
    #[cfg(windows)]
    let builder = builder
        .data_directory(record.data_dir.clone())
        // The Tauri defaults, plus no WebRTC UDP outside the proxy and
        // Electron's "accept self-signed device certificates" policy (only
        // this browser's environment gets these switches).
        .additional_browser_args(
            "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection \
             --force-webrtc-ip-handling-policy=disable_non_proxied_udp --ignore-certificate-errors",
        );
    builder.build().map_err(|e| e.to_string())?;
    let tab = &mut record.tabs[index];
    tab.webview = true;
    tab.shown = false;
    Ok(())
}

fn destroy_page<R: Runtime>(app: &AppHandle<R>, tab: &mut Tab) {
    if tab.webview {
        if let Some(window) = app.get_webview_window(&tab.label) {
            let _ = window.destroy();
        }
    }
    tab.webview = false;
    tab.shown = false;
    tab.loading = false;
}

fn page_loaded<R: Runtime>(app: &AppHandle<R>, browser_id: &str, label: &str, url: &str, started: bool) {
    let state = host_state(app);
    let mut inner = state.inner.lock();
    let Some(record) = inner.records.get_mut(browser_id) else {
        return;
    };
    let Some(index) = record.tab_by_label(label) else {
        return;
    };
    let tab = &mut record.tabs[index];
    tab.loading = started;
    if started {
        if !url.is_empty() && url != "about:blank" {
            tab.url = url.to_string();
            tab.record_navigation(url);
        }
    } else if tab.title.is_empty() || tab.title == "New tab" {
        tab.title = tab.url.clone();
    }
    send(app, record);
    if !started && record.route == Route::Connected {
        request_favicon(app, record, index);
    }
}

fn page_shortcut<R: Runtime>(app: &AppHandle<R>, browser_id: &str, label: &str, kind: &str) {
    if !matches!(kind, "new-tab" | "close-tab" | "reload" | "focus-address") {
        return;
    }
    let state = host_state(app);
    let inner = state.inner.lock();
    let Some(record) = inner.records.get(browser_id) else {
        return;
    };
    let Some(index) = record.tab_by_label(label) else {
        return;
    };
    let shortcut = json!({ "type": kind, "tabId": record.tabs[index].id });
    if matches!(kind, "focus-address" | "new-tab") {
        if let Some(owner) = app.get_webview_window(&record.source_label) {
            let _ = owner.set_focus();
        }
    }
    if record.embedded {
        panel_event(app, record, json!({ "type": "shortcut", "shortcut": shortcut }));
    } else {
        chrome_event(app, vec![record.owner_label.clone()], EVENT_SHORTCUT, shortcut);
    }
}

// ---------------------------------------------------------------------------
// Website icons
// ---------------------------------------------------------------------------

fn request_favicon<R: Runtime>(app: &AppHandle<R>, record: &Record, index: usize) {
    let tab = &record.tabs[index];
    let Some(origin) = icon_origin(&tab.url) else {
        return;
    };
    let stored = stores(app).icons.get(&record.host_id, &tab.url);
    if stored.as_ref().is_some_and(|icon| icon.mode == IconMode::Custom) {
        return;
    }
    let Some(window) = app.get_webview_window(&tab.label) else {
        return;
    };
    let (app, browser_id, host_id, tab_url, generation, proxy) = (
        app.clone(),
        record.id.clone(),
        record.host_id.clone(),
        tab.url.clone(),
        record.generation,
        (!record.local).then_some(record.proxy_port).flatten(),
    );
    let has_icon = stored.is_some();
    let _ = window.eval_with_callback(ICON_LINKS_SCRIPT, move |result| {
        let mut urls: Vec<String> = serde_json::from_str::<String>(&result)
            .ok()
            .and_then(|inner| serde_json::from_str(&inner).ok())
            .or_else(|| serde_json::from_str(&result).ok())
            .unwrap_or_default();
        if urls.is_empty() && !has_icon {
            urls.push(format!("{origin}/favicon.ico"));
        }
        if urls.is_empty() {
            return;
        }
        let (app, browser_id, host_id, tab_url) =
            (app.clone(), browser_id.clone(), host_id.clone(), tab_url.clone());
        tauri::async_runtime::spawn(async move {
            for url in urls {
                let Some(data_url) = fetch_icon(&url, proxy).await else {
                    continue;
                };
                let state = host_state(&app);
                let inner = state.inner.lock();
                let Some(record) = inner.records.get(&browser_id) else {
                    return;
                };
                if record.route != Route::Connected || record.generation != generation {
                    return;
                }
                let _ = stores(&app).icons.set(
                    &host_id,
                    &tab_url,
                    SiteIconInput {
                        mode: IconMode::Auto,
                        data_url: Some(data_url),
                        glyph: Some(String::new()),
                        color: Some(netcatty_hostbrowser::DEFAULT_ICON_COLOR.into()),
                    },
                );
                notify_site_icon(&app, record);
                return;
            }
        });
    });
}

/// Fetch a favicon (through the browser's SOCKS route) as a data URL of at
/// most 64 KiB (Electron `fetchPageIcon`).
async fn fetch_icon(url: &str, proxy_port: Option<u16>) -> Option<String> {
    if valid_image_data_url(url) {
        return Some(url.to_string());
    }
    let parsed = url::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    let mut builder = reqwest::Client::builder()
        .timeout(ICON_FETCH_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .no_proxy();
    if let Some(port) = proxy_port {
        builder = builder.proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).ok()?);
    }
    let client = builder.build().ok()?;
    let mut response = client.get(parsed).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        bytes.extend_from_slice(&chunk);
        if bytes.len() > ICON_FETCH_LIMIT {
            return None;
        }
    }
    image_mime(&bytes)?;
    netcatty_hostbrowser::icons::image_data_url(&bytes)
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------

/// `on_download` callback (main thread): decide synchronously, update the
/// stores, then notify asynchronously.
fn download_event<R: Runtime>(
    app: &AppHandle<R>,
    browser_id: &str,
    host_id: &str,
    tab_label: &str,
    connected: &AtomicBool,
    event: DownloadEvent<'_>,
) -> bool {
    let state = host_state(app);
    let store = &stores(app).downloads;
    match event {
        DownloadEvent::Requested { url, destination } => {
            if !connected.load(Ordering::SeqCst) {
                return false;
            }
            let id = netcatty_core::ids::new_id();
            let suggested = destination
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "download".into());
            let now = netcatty_core::ids::now_ms();
            let reserved = match reserve_download_file(&downloads_dir(app), &suggested) {
                Ok(reserved) => reserved,
                Err(err) => {
                    tracing::warn!(%err, "host browser download could not reserve a file name");
                    let _ = store.upsert(
                        Download {
                            id: id.clone(),
                            host_id: host_id.into(),
                            filename: suggested,
                            url: url.to_string(),
                            save_path: String::new(),
                            status: DownloadStatus::Interrupted,
                            received: 0,
                            total: 0,
                            started_at: now,
                            ended_at: Some(now),
                        },
                        false,
                    );
                    spawn_notify_downloads(app, host_id, Some((browser_id, &id)), false);
                    return false;
                }
            };
            // WebKit refuses to download onto an existing file: the name is
            // reserved race-free above, then the empty placeholder is removed
            // just before the engine creates the real file.
            reserved.cleanup_empty();
            let path = reserved.save_path.clone();
            *destination = path.clone();
            let filename = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "download".into());
            let _ = store.upsert(
                Download {
                    id: id.clone(),
                    host_id: host_id.into(),
                    filename,
                    url: url.to_string(),
                    save_path: path.to_string_lossy().into_owned(),
                    status: DownloadStatus::Progressing,
                    received: 0,
                    total: 0,
                    started_at: now,
                    ended_at: None,
                },
                false,
            );
            state.active.lock().insert(
                id.clone(),
                ActiveDownload {
                    browser_id: browser_id.into(),
                    host_id: host_id.into(),
                    tab_label: tab_label.into(),
                    url: url.to_string(),
                    path,
                    cancelled: false,
                },
            );
            spawn_notify_downloads(app, host_id, Some((browser_id, &id)), true);
            true
        }
        DownloadEvent::Finished { url, path, success } => {
            let finished = {
                let mut active = state.active.lock();
                let id = active
                    .iter()
                    .find(|(_, d)| d.tab_label == tab_label && d.url == url.as_str())
                    .or_else(|| active.iter().find(|(_, d)| d.url == url.as_str()))
                    .map(|(id, _)| id.clone());
                id.and_then(|id| active.remove(&id).map(|d| (id, d)))
            };
            let Some((id, download)) = finished else {
                return true;
            };
            let final_path = path.unwrap_or_else(|| download.path.clone());
            let size = std::fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);
            let status = if download.cancelled {
                remove_partial(&final_path);
                DownloadStatus::Cancelled
            } else if success {
                DownloadStatus::Completed
            } else {
                remove_partial(&final_path);
                DownloadStatus::Interrupted
            };
            if let Some(previous) = store.get(&download.host_id, &id) {
                let _ = store.upsert(
                    Download {
                        filename: final_path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or(previous.filename.clone()),
                        save_path: final_path.to_string_lossy().into_owned(),
                        status,
                        received: size,
                        total: if status == DownloadStatus::Completed { size } else { previous.total },
                        ended_at: Some(netcatty_core::ids::now_ms()),
                        ..previous
                    },
                    false,
                );
            }
            let _ = download.browser_id;
            spawn_notify_downloads(app, &download.host_id, None, false);
            true
        }
        _ => true,
    }
}

/// Remove an empty or partial file left by a failed / cancelled download.
fn remove_partial(path: &Path) {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file()) {
        let _ = std::fs::remove_file(path);
    }
}

fn spawn_notify_downloads<R: Runtime>(
    app: &AppHandle<R>,
    host_id: &str,
    started: Option<(&str, &str)>,
    open_panel: bool,
) {
    let (app, host_id) = (app.clone(), host_id.to_string());
    let started = started.map(|(b, d)| (b.to_string(), d.to_string()));
    tauri::async_runtime::spawn(async move {
        let state = host_state(&app);
        let mut inner = state.inner.lock();
        notify_downloads(
            &app,
            &inner,
            &host_id,
            started.as_ref().map(|(b, d)| (b.as_str(), d.as_str())),
        );
        if open_panel {
            if let Some((browser_id, _)) = &started {
                if let Some(record) = inner.records.get_mut(browser_id) {
                    if !record.embedded {
                        let _ = set_downloads_panel(&app, record, true);
                    }
                }
            }
        }
    });
}

fn cancel_downloads_of<R: Runtime>(app: &AppHandle<R>, browser_id: &str) {
    let state = host_state(app);
    for download in state
        .active
        .lock()
        .values_mut()
        .filter(|d| d.browser_id == browser_id)
    {
        download.cancelled = true;
    }
}

fn set_downloads_panel<R: Runtime>(app: &AppHandle<R>, record: &mut Record, open: bool) -> CmdResult<()> {
    if record.embedded {
        return Ok(());
    }
    if !open {
        if record.downloads_panel_open {
            record.downloads_panel_open = false;
            if let Some(window) = record
                .downloads_label
                .as_ref()
                .and_then(|label| app.get_webview_window(label))
            {
                let _ = window.hide();
            }
            send(app, record);
        }
        return Ok(());
    }
    let window = match record
        .downloads_label
        .as_ref()
        .and_then(|label| app.get_webview_window(label))
    {
        Some(window) => window,
        None => {
            let owner = app
                .get_webview_window(&record.owner_label)
                .ok_or_else(|| invalid("Browser window is unavailable"))?;
            let label = format!(
                "{DOWNLOADS_PREFIX}{}",
                host_state(app).counter.fetch_add(1, Ordering::SeqCst)
            );
            let window = WebviewWindowBuilder::new(app, &label, asset_url("downloads.html"))
                .title("Downloads")
                .decorations(false)
                .resizable(false)
                .skip_taskbar(true)
                .visible(false)
                .focused(false)
                .accept_first_mouse(true)
                .parent(&owner)
                .map_err(internal)?
                .on_navigation(|url| is_asset_url(url))
                .build()
                .map_err(internal)?;
            record.downloads_label = Some(label);
            window
        }
    };
    record.downloads_panel_open = true;
    position_downloads_window(app, record);
    let _ = window.show();
    send_theme(app, record);
    let downloads = json!(stores(app).downloads.list(&record.host_id));
    chrome_event(app, record.chrome_labels(), EVENT_DOWNLOADS_CHANGED, downloads);
    send(app, record);
    Ok(())
}

// ---------------------------------------------------------------------------
// Route (SOCKS forward)
// ---------------------------------------------------------------------------

fn spawn_tunnel_watch<R: Runtime>(app: &AppHandle<R>, inner: &mut Inner) {
    if inner.tunnel_watch {
        return;
    }
    inner.tunnel_watch = true;
    let mut rx = app.state::<AppState<R>>().tunnels.subscribe();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        use netcatty_core::models::PortForwardingStatus;
        use netcatty_forward::TunnelEvent;
        loop {
            match rx.recv().await {
                Ok(TunnelEvent::Status(event))
                    if matches!(
                        event.status,
                        PortForwardingStatus::Inactive | PortForwardingStatus::Error
                    ) =>
                {
                    let browser = {
                        let state = host_state(&app);
                        let inner = state.inner.lock();
                        inner
                            .records
                            .values()
                            .find(|r| r.tunnel_id.as_deref() == Some(event.tunnel_id.as_str()))
                            .map(|r| r.id.clone())
                    };
                    if let Some(id) = browser {
                        demote(&app, &id, event.error.clone()).await;
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

async fn stop_tunnel<R: Runtime>(app: &AppHandle<R>, tunnel_id: Option<String>) {
    if let Some(tunnel_id) = tunnel_id {
        let state = app.state::<AppState<R>>();
        let _ = super::forward::portforward_stop(Ctx(state), tunnel_id).await;
    }
}

/// Drop every page window and stop loading (the route is gone).
fn tear_down_pages<R: Runtime>(app: &AppHandle<R>, record: &mut Record) {
    for tab in &mut record.tabs {
        destroy_page(app, tab);
    }
}

async fn demote<R: Runtime>(app: &AppHandle<R>, browser_id: &str, error: Option<String>) {
    let tunnel = {
        let state = host_state(app);
        let mut inner = state.inner.lock();
        let Some(record) = inner.records.get_mut(browser_id) else {
            return;
        };
        if record.route == Route::Disconnected {
            return;
        }
        record.generation += 1;
        record.set_route(Route::Disconnected);
        record.error = Some(error.unwrap_or_else(|| "Connection to the host was lost".into()));
        record.proxy_port = None;
        tear_down_pages(app, record);
        display(app, record);
        record.tunnel_id.take()
    };
    cancel_downloads_of(app, browser_id);
    stop_tunnel(app, tunnel).await;
}

/// Connect (or reconnect) the browser's route (Electron `startRoute`).
async fn start_route<R: Runtime>(app: &AppHandle<R>, browser_id: &str) -> CmdResult<()> {
    let (generation, options, local, old_tunnel) = {
        let state = host_state(app);
        let mut inner = state.inner.lock();
        spawn_tunnel_watch(app, &mut inner);
        let record = inner
            .records
            .get_mut(browser_id)
            .ok_or_else(|| CoreError::not_found("Browser was closed"))?;
        record.generation += 1;
        record.set_route(Route::Connecting);
        record.proxy_port = None;
        tear_down_pages(app, record);
        display(app, record);
        (
            record.generation,
            record.connection_options.clone(),
            record.local,
            record.tunnel_id.take(),
        )
    };
    stop_tunnel(app, old_tunnel).await;

    let outcome: Result<Option<(String, u16)>, String> = if local {
        Ok(None)
    } else {
        match proxy_support() {
            Err(message) => Err(message),
            Ok(()) => dial_route(app, options).await.map(Some),
        }
    };

    let current = host_state(app)
        .inner
        .lock()
        .records
        .get(browser_id)
        .is_some_and(|r| r.generation == generation);
    if !current {
        if let Ok(Some((tunnel_id, _))) = outcome {
            stop_tunnel(app, Some(tunnel_id)).await;
        }
        return Ok(());
    }
    let state = host_state(app);
    let mut inner = state.inner.lock();
    // The record may have changed between the two locks; re-check.
    if !inner
        .records
        .get(browser_id)
        .is_some_and(|r| r.generation == generation)
    {
        if let Ok(Some((tunnel_id, _))) = outcome {
            let app = app.clone();
            tauri::async_runtime::spawn(async move { stop_tunnel(&app, Some(tunnel_id)).await });
        }
        return Ok(());
    }
    match outcome {
        Ok(route) => {
            {
                let record = inner.records.get_mut(browser_id).expect("checked");
                if let Some((tunnel_id, port)) = route {
                    record.tunnel_id = Some(tunnel_id);
                    record.proxy_port = Some(port);
                }
                record.set_route(Route::Connected);
                record.error = None;
                display(app, record);
            }
            flush_panel_urls(app, &mut inner, browser_id);
            Ok(())
        }
        Err(message) => {
            let record = inner.records.get_mut(browser_id).expect("checked");
            record.generation += 1;
            record.set_route(Route::Disconnected);
            record.error = Some(message.clone());
            display(app, record);
            Err(CoreError::new(netcatty_core::ErrorCode::Network, message))
        }
    }
}

/// Start the dedicated dynamic forward; returns `(tunnelId, socksPort)`.
async fn dial_route<R: Runtime>(app: &AppHandle<R>, options: Option<Value>) -> Result<(String, u16), String> {
    let Some(Value::Object(mut options)) = options else {
        return Err("Invalid host browser request".into());
    };
    let tunnel_id = format!("host-browser-{}", netcatty_core::ids::new_id());
    options.remove("ruleId");
    options.insert("tunnelId".into(), json!(tunnel_id));
    options.insert("type".into(), json!("dynamic"));
    options.insert("localPort".into(), json!(0));
    options.insert("bindAddress".into(), json!("127.0.0.1"));
    options.insert("reuseTransport".into(), json!(false));
    let payload: netcatty_core::ipc::PortForwardOptions =
        serde_json::from_value(Value::Object(options)).map_err(|e| e.to_string())?;
    let state = app.state::<AppState<R>>();
    let result = super::forward::portforward_start(Ctx(state.clone()), payload)
        .await
        .map_err(|e| e.message)?;
    if !result.success {
        return Err(result.error.unwrap_or_else(|| "Could not connect to host".into()));
    }
    match state.tunnels.local_addr(&tunnel_id).map(|addr| addr.port()) {
        Some(port) if port > 0 => Ok((tunnel_id, port)),
        _ => {
            let _ = super::forward::portforward_stop(Ctx(state), tunnel_id).await;
            Err("Browser route is unavailable".into())
        }
    }
}

fn flush_panel_urls<R: Runtime>(app: &AppHandle<R>, inner: &mut Inner, browser_id: &str) {
    let Some(urls) = inner
        .layouts
        .get_mut(browser_id)
        .map(|layout| std::mem::take(&mut layout.pending_urls))
    else {
        return;
    };
    let Some(record) = inner.records.get_mut(browser_id) else {
        return;
    };
    if record.route != Route::Connected {
        if let Some(layout) = inner.layouts.get_mut(browser_id) {
            layout.pending_urls = urls;
        }
        return;
    }
    for url in urls {
        let active = record.tab(None);
        match active {
            Some(index) if record.tabs[index].url.is_empty() => {
                record.tabs[index].url = url;
                display(app, record);
            }
            _ if record.tabs.len() < MAX_TABS => {
                let _ = add_tab(app, record, Some(url));
            }
            _ => {}
        }
    }
}

fn add_tab<R: Runtime>(app: &AppHandle<R>, record: &mut Record, url: Option<String>) -> CmdResult<()> {
    if record.tabs.len() >= MAX_TABS {
        return Err(invalid("Too many open tabs"));
    }
    let tab = Tab::new(url);
    record.active_tab_id = Some(tab.id.clone());
    let has_url = !tab.url.is_empty();
    record.tabs.push(tab);
    if has_url && record.route == Route::Connected {
        let index = record.tabs.len() - 1;
        let url = record.tabs[index].url.clone();
        create_page(app, record, index, &url).map_err(|e| invalid(&e))?;
    }
    display(app, record);
    Ok(())
}

fn close_record<R: Runtime>(app: &AppHandle<R>, inner: &mut Inner, browser_id: &str) -> Option<String> {
    inner.layouts.remove(browser_id);
    let mut record = inner.records.remove(browser_id)?;
    record.generation += 1;
    record.set_route(Route::Disconnected);
    tear_down_pages(app, &mut record);
    if let Some(window) = record
        .downloads_label
        .as_ref()
        .and_then(|label| app.get_webview_window(label))
    {
        let _ = window.destroy();
    }
    if !record.embedded {
        if let Some(window) = app.get_webview_window(&record.owner_label) {
            let _ = window.destroy();
        }
    }
    #[cfg(windows)]
    {
        let dir = record.data_dir.clone();
        std::thread::spawn(move || {
            // WebView2 releases the folder a moment after its last webview.
            std::thread::sleep(Duration::from_secs(3));
            let _ = std::fs::remove_dir_all(dir);
        });
    }
    cancel_downloads_of(app, browser_id);
    record.tunnel_id.take()
}

/// Observe moves / resizes / destruction of a window that owns or controls
/// browsers.
fn hook_window<R: Runtime>(app: &AppHandle<R>, inner: &mut Inner, window: &WebviewWindow<R>) {
    let label = window.label().to_string();
    if !inner.hooked.insert(label.clone()) {
        return;
    }
    let app = app.clone();
    window.on_window_event(move |event| {
        let destroyed = matches!(event, WindowEvent::Destroyed);
        if !destroyed
            && !matches!(
                event,
                WindowEvent::Moved(_) | WindowEvent::Resized(_) | WindowEvent::ScaleFactorChanged { .. }
            )
        {
            return;
        }
        let (app, label) = (app.clone(), label.clone());
        tauri::async_runtime::spawn(async move {
            let tunnels = {
                let state = host_state(&app);
                let mut inner = state.inner.lock();
                if destroyed {
                    inner.hooked.remove(&label);
                    let ids: Vec<String> = inner
                        .records
                        .values()
                        .filter(|r| r.owner_label == label || r.source_label == label)
                        .map(|r| r.id.clone())
                        .collect();
                    inner.layouts.retain(|_, layout| layout.owner != label);
                    ids.iter()
                        .filter_map(|id| close_record(&app, &mut inner, id))
                        .collect::<Vec<_>>()
                } else {
                    for record in inner.records.values_mut().filter(|r| r.owner_label == label) {
                        display(&app, record);
                    }
                    Vec::new()
                }
            };
            for tunnel in tunnels {
                stop_tunnel(&app, Some(tunnel)).await;
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Chrome assets (`netcatty-hostbrowser:` protocol)
// ---------------------------------------------------------------------------

fn asset_url(path: &str) -> WebviewUrl {
    let url = if cfg!(windows) {
        format!("http://{ASSET_SCHEME}.localhost/{path}")
    } else {
        format!("{ASSET_SCHEME}://localhost/{path}")
    };
    WebviewUrl::CustomProtocol(url.parse().expect("static asset url"))
}

fn is_asset_url(url: &url::Url) -> bool {
    url.scheme() == ASSET_SCHEME
        || (url.scheme() == "http" && url.host_str() == Some(&format!("{ASSET_SCHEME}.localhost")))
}

fn asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    Some(match path {
        "browser.html" => (include_bytes!("../../hostbrowser/browser.html"), "text/html"),
        "browser.css" => (include_bytes!("../../hostbrowser/browser.css"), "text/css"),
        "browser.js" => (include_bytes!("../../hostbrowser/browser.js"), "text/javascript"),
        "downloads.html" => (include_bytes!("../../hostbrowser/downloads.html"), "text/html"),
        "downloads.css" => (include_bytes!("../../hostbrowser/downloads.css"), "text/css"),
        "downloads.js" => (include_bytes!("../../hostbrowser/downloads.js"), "text/javascript"),
        "tauri-adapter.js" => (
            include_bytes!("../../hostbrowser/tauri-adapter.js"),
            "text/javascript",
        ),
        _ => return None,
    })
}

/// Protocol handler registered in `lib.rs`.
pub fn asset_protocol<R: Runtime>(
    _ctx: UriSchemeContext<'_, R>,
    request: tauri::http::Request<Vec<u8>>,
) -> tauri::http::Response<Cow<'static, [u8]>> {
    let path = request.uri().path().trim_start_matches('/');
    match asset(path) {
        Some((body, mime)) => tauri::http::Response::builder()
            .status(200)
            .header("Content-Type", format!("{mime}; charset=utf-8"))
            .header("Cache-Control", "no-store")
            .body(Cow::Borrowed(body))
            .expect("static response"),
        None => tauri::http::Response::builder()
            .status(404)
            .body(Cow::Borrowed(&b"not found"[..]))
            .expect("static response"),
    }
}

// ---------------------------------------------------------------------------
// Caller ownership (Electron `getOwned` / `getBrowserOwned`)
// ---------------------------------------------------------------------------

fn owned_id(inner: &Inner, caller: &str, browser_id: Option<&str>, allow_downloads: bool) -> CmdResult<String> {
    if let Some(id) = browser_id {
        return match inner.records.get(id) {
            Some(record) if record.embedded && record.source_label == caller => Ok(id.to_string()),
            _ => Err(invalid("Untrusted browser control")),
        };
    }
    inner
        .records
        .values()
        .find(|r| {
            (!r.embedded && r.owner_label == caller)
                || (allow_downloads && r.downloads_label.as_deref() == Some(caller))
        })
        .map(|r| r.id.clone())
        .ok_or_else(|| {
            invalid(if allow_downloads {
                "Untrusted browser download control"
            } else {
                "Untrusted browser control"
            })
        })
}

fn valid_browser_id(id: &str) -> CmdResult<()> {
    if id.is_empty() || id.len() > 512 {
        return Err(invalid("Invalid browser identity"));
    }
    Ok(())
}

fn is_browser_window(label: &str) -> bool {
    label.starts_with(CHROME_PREFIX) || label.starts_with(TAB_PREFIX)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenPayload {
    #[serde(default)]
    pub browser_id: Option<String>,
    #[serde(default)]
    pub embedded: bool,
    #[serde(default)]
    pub local: bool,
    #[serde(default)]
    pub host_id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub theme_tokens: Option<Value>,
    #[serde(default)]
    pub connection_options: Option<Value>,
}

/// `openHostBrowser` → `{ reused }`.
#[tauri::command]
pub async fn hostbrowser_open<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    payload: OpenPayload,
) -> CmdResult<Value> {
    let caller = window.label().to_string();
    if is_browser_window(&caller) {
        return Err(invalid("Browser opener is unavailable"));
    }
    let label: String = payload.label.chars().take(120).collect();
    let options = payload.connection_options.as_ref();
    if payload.host_id.is_empty()
        || payload.host_id.len() > 256
        || label.is_empty()
        || (!payload.local
            && (options.and_then(|o| o.get("hostId")).and_then(Value::as_str)
                != Some(payload.host_id.as_str())
                || options.and_then(|o| o.get("type")).and_then(Value::as_str) != Some("dynamic")))
    {
        return Err(invalid("Invalid host browser request"));
    }
    let id = if payload.embedded {
        payload.browser_id.clone().unwrap_or_default()
    } else {
        payload.host_id.clone()
    };
    valid_browser_id(&id)?;
    let theme = if payload.theme.as_deref() == Some("light") { "light" } else { "dark" }.to_string();
    let tokens = valid_theme_tokens(payload.theme_tokens.as_ref());

    enum Opened {
        Reused { reconnect: bool },
        NotMounted,
        Created,
    }
    let opened = {
        let state = host_state(&app);
        let mut inner = state.inner.lock();
        if let Some(existing) = inner.records.get_mut(&id) {
            if existing.source_label != caller || existing.host_id != payload.host_id {
                return Err(invalid("Browser belongs to another terminal window"));
            }
            existing.theme = theme;
            existing.theme_tokens = tokens;
            send_theme(&app, existing);
            send(&app, existing);
            let reconnect = existing.route != Route::Connected;
            if reconnect {
                existing.connection_options = payload.connection_options.clone();
            }
            if !existing.embedded {
                if let Some(chrome) = app.get_webview_window(&existing.owner_label) {
                    let _ = chrome.show();
                    let _ = chrome.set_focus();
                }
            }
            Opened::Reused { reconnect }
        } else if payload.embedded && !inner.layouts.contains_key(&id) {
            Opened::NotMounted
        } else {
        let owner_label = if payload.embedded {
            caller.clone()
        } else {
            format!("{CHROME_PREFIX}{}", state.counter.fetch_add(1, Ordering::SeqCst))
        };
        let data_dir = app
            .state::<AppState<R>>()
            .paths
            .cache_dir
            .join("host-browser")
            .join(netcatty_core::ids::new_id());
        let mut record = Record {
            id: id.clone(),
            host_id: payload.host_id.clone(),
            label,
            embedded: payload.embedded,
            local: payload.local,
            theme: theme.clone(),
            theme_tokens: tokens,
            owner_label: owner_label.clone(),
            source_label: if payload.embedded { caller.clone() } else { owner_label.clone() },
            downloads_label: None,
            route: Route::Connecting,
            connected: Arc::new(AtomicBool::new(false)),
            error: None,
            generation: 0,
            tunnel_id: None,
            proxy_port: None,
            connection_options: payload.connection_options.clone(),
            tabs: Vec::new(),
            active_tab_id: None,
            visible: !payload.embedded,
            bounds: Rect::default(),
            overlay_open: false,
            panel_open: false,
            downloads_panel_open: false,
            data_dir,
        };
        if !payload.embedded {
            let builder = WebviewWindowBuilder::new(&app, &owner_label, asset_url("browser.html"))
                .title("Browser")
                .inner_size(1100.0, 760.0)
                .min_inner_size(720.0, 480.0)
                .visible(false)
                .disable_drag_drop_handler()
                .background_color(if theme == "light" {
                    tauri::window::Color(0xf1, 0xf4, 0xf8, 255)
                } else {
                    tauri::window::Color(0x0f, 0x12, 0x1a, 255)
                })
                .on_navigation(|url| is_asset_url(url));
            #[cfg(target_os = "macos")]
            let builder = builder
                .title_bar_style(tauri::TitleBarStyle::Overlay)
                .hidden_title(true)
                .traffic_light_position(tauri::LogicalPosition::new(12.0, 12.0));
            #[cfg(not(target_os = "macos"))]
            let builder = builder.decorations(false);
            let chrome = builder.build().map_err(internal)?;
            hook_window(&app, &mut inner, &chrome);
            let _ = chrome.show();
            let _ = chrome.set_focus();
        } else {
            hook_window(&app, &mut inner, &window);
        }
        add_tab(&app, &mut record, None).ok();
        inner.records.insert(id.clone(), record);
        if payload.embedded {
            apply_stored_layout(&app, &mut inner, &id);
        }
        Opened::Created
        }
    };
    match opened {
        Opened::Reused { reconnect } => {
            if reconnect {
                start_route(&app, &id).await?;
            }
            Ok(json!({ "reused": true }))
        }
        Opened::NotMounted => Ok(json!({ "reused": false })),
        Opened::Created => {
            // Keep the browser open for an in-browser retry on failure.
            let _ = start_route(&app, &id).await;
            Ok(json!({ "reused": false }))
        }
    }
}

fn apply_stored_layout<R: Runtime>(app: &AppHandle<R>, inner: &mut Inner, id: &str) {
    let Inner {
        records, layouts, ..
    } = inner;
    let (Some(record), Some(layout)) = (records.get_mut(id), layouts.get(id)) else {
        return;
    };
    apply_layout(app, record, layout);
}

/// Electron `applyPanelLayout`.
fn apply_layout<R: Runtime>(app: &AppHandle<R>, record: &mut Record, layout: &Layout) {
    if !record.embedded {
        return;
    }
    if let Some(theme) = &layout.theme {
        record.theme = theme.clone();
        record.theme_tokens = layout.theme_tokens.clone();
    }
    let visible = layout.owner == record.source_label && layout.visible && !layout.occluded;
    record.visible = visible;
    if let (true, Some(bounds)) = (visible, layout.bounds) {
        record.bounds = bounds;
    } else {
        record.visible = false;
    }
    display(app, record);
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LayoutPayload {
    pub browser_id: String,
    #[serde(default)]
    pub visible: bool,
    #[serde(default)]
    pub occluded: bool,
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub theme_tokens: Option<Value>,
    #[serde(default)]
    pub bounds: Option<Rect>,
}

/// `setHostBrowserPanelLayout` → `true`, or `{ layers: [] }` while covered
/// (Tauri cannot capture a webview, so no picture is returned; the page is
/// hidden while a menu or dialog covers it).
#[tauri::command]
pub async fn hostbrowser_panel_layout<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    payload: LayoutPayload,
) -> CmdResult<Value> {
    let caller = window.label().to_string();
    valid_browser_id(&payload.browser_id)?;
    let id = payload.browser_id.clone();
    let state = host_state(&app);
    let mut inner = state.inner.lock();
    if inner.records.get(&id).is_some_and(|r| r.source_label != caller)
        || inner.layouts.get(&id).is_some_and(|l| l.owner != caller)
    {
        return Err(invalid("Browser belongs to another terminal window"));
    }
    if payload.visible {
        let valid = payload.bounds.is_some_and(|b| {
            [b.x, b.y, b.width, b.height].iter().all(|v| v.is_finite()) && b.width >= 0.0 && b.height >= 0.0
        });
        if !valid {
            return Err(invalid("Invalid browser panel bounds"));
        }
    }
    let pending_urls = inner
        .layouts
        .remove(&id)
        .map(|l| l.pending_urls)
        .unwrap_or_default();
    let layout = Layout {
        owner: caller,
        visible: payload.visible,
        occluded: payload.occluded,
        bounds: payload.bounds,
        pending_urls,
        theme: payload
            .theme
            .filter(|t| t == "light" || t == "dark"),
        theme_tokens: valid_theme_tokens(payload.theme_tokens.as_ref()),
    };
    let covered = layout.visible && layout.occluded;
    inner.layouts.insert(id.clone(), layout);
    hook_window(&app, &mut inner, &window);
    apply_stored_layout(&app, &mut inner, &id);
    Ok(if covered && inner.records.contains_key(&id) {
        json!({ "layers": [] })
    } else {
        json!(true)
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PanelUrlPayload {
    pub browser_id: String,
    pub url: String,
}

/// `openHostBrowserUrl`: queue a page for a (possibly not yet mounted)
/// embedded browser.
#[tauri::command]
pub async fn hostbrowser_panel_url<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    payload: PanelUrlPayload,
) -> CmdResult<bool> {
    let caller = window.label().to_string();
    valid_browser_id(&payload.browser_id)?;
    let url = normalize_browser_url(&payload.url).map_err(|e| invalid(&e))?;
    let id = payload.browser_id;
    let state = host_state(&app);
    let mut inner = state.inner.lock();
    if inner.records.get(&id).is_some_and(|r| r.source_label != caller)
        || inner.layouts.get(&id).is_some_and(|l| l.owner != caller)
    {
        return Err(invalid("Browser belongs to another terminal window"));
    }
    let open_tabs = inner.records.get(&id).map(|r| r.tabs.len()).unwrap_or(0);
    let layout = inner.layouts.entry(id.clone()).or_insert_with(|| Layout {
        owner: caller,
        visible: false,
        occluded: false,
        bounds: None,
        pending_urls: Vec::new(),
        theme: None,
        theme_tokens: BTreeMap::new(),
    });
    if open_tabs + layout.pending_urls.len() >= MAX_TABS {
        return Err(invalid("Too many open tabs"));
    }
    layout.pending_urls.push(url);
    flush_panel_urls(&app, &mut inner, &id);
    Ok(true)
}

/// `closeHostBrowserPanel`.
#[tauri::command]
pub async fn hostbrowser_panel_close<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    browser_id: String,
) -> CmdResult<bool> {
    let caller = window.label();
    let tunnel = {
        let state = host_state(&app);
        let mut inner = state.inner.lock();
        if inner.records.get(&browser_id).is_some_and(|r| r.source_label != caller)
            || inner.layouts.get(&browser_id).is_some_and(|l| l.owner != caller)
        {
            return Err(invalid("Browser belongs to another terminal window"));
        }
        let tunnel = if inner.records.get(&browser_id).is_some_and(|r| r.embedded) {
            close_record(&app, &mut inner, &browser_id)
        } else {
            None
        };
        inner.layouts.remove(&browser_id);
        tunnel
    };
    stop_tunnel(&app, tunnel).await;
    Ok(true)
}

/// `focusHostBrowser(hostId)` → connected.
#[tauri::command]
pub async fn hostbrowser_focus<R: Runtime>(app: AppHandle<R>, host_id: String) -> bool {
    let state = host_state(&app);
    let inner = state.inner.lock();
    let Some(record) = inner.records.get(&host_id) else {
        return false;
    };
    let Some(window) = app.get_webview_window(&record.owner_label) else {
        return false;
    };
    let _ = window.show();
    let _ = window.set_focus();
    record.route == Route::Connected
}

/// `requestHostBrowserPanel`: hand the request to the main window's
/// terminal layer and bring it forward.
#[tauri::command]
pub async fn hostbrowser_request_panel<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    payload: Value,
) -> CmdResult<bool> {
    let main = app.get_webview_window(MAIN_LABEL);
    let valid = payload
        .get("host")
        .and_then(|h| h.get("id"))
        .and_then(Value::as_str)
        .is_some();
    let Some(main) = main.filter(|_| valid && !is_browser_window(window.label())) else {
        return Err(invalid("Browser opener is unavailable"));
    };
    crate::events::emit(
        &app,
        EVENT_REQUEST_PANEL,
        json!({ "targetLabel": MAIN_LABEL, "request": payload }),
    );
    let _ = main.unminimize();
    let _ = main.show();
    let _ = main.set_focus();
    super::tray::main_window_shown(&app);
    Ok(true)
}

/// `getHostBrowserPanelState` (embedded, with `browserId`) and the chrome's
/// `snapshot()` (standalone, no `browserId`).
#[tauri::command]
pub async fn hostbrowser_snapshot<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    browser_id: Option<String>,
) -> CmdResult<Value> {
    let state = host_state(&app);
    let inner = state.inner.lock();
    let id = owned_id(&inner, window.label(), browser_id.as_deref(), false)?;
    Ok(snapshot(&app, &inner.records[&id]))
}

/// `commandHostBrowserPanel(browserId, command)` and the chrome's `command`.
#[tauri::command]
pub async fn hostbrowser_command<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    command: Value,
    browser_id: Option<String>,
) -> CmdResult<Value> {
    let kind = command.get("type").and_then(Value::as_str).unwrap_or("").to_string();
    let str_field = |key: &str| command.get(key).and_then(Value::as_str).map(str::to_string);
    let open_flag = command.get("open").and_then(Value::as_bool) == Some(true);
    let state = host_state(&app);
    let id = {
        let inner = state.inner.lock();
        owned_id(&inner, window.label(), browser_id.as_deref(), false)?
    };

    // Commands that await the route run without the lock.
    if kind == "retry" {
        let disconnected = state
            .inner
            .lock()
            .records
            .get(&id)
            .is_some_and(|r| r.route == Route::Disconnected);
        if disconnected {
            start_route(&app, &id).await?;
        }
        let inner = state.inner.lock();
        return inner
            .records
            .get(&id)
            .map(|r| snapshot(&app, r))
            .ok_or_else(|| CoreError::not_found("Browser was closed"));
    }

    let mut inner = state.inner.lock();
    let record = inner
        .records
        .get_mut(&id)
        .ok_or_else(|| CoreError::not_found("Browser was closed"))?;
    if kind.starts_with("window-") {
        if record.embedded {
            return Ok(snapshot(&app, record));
        }
        let chrome = app.get_webview_window(&record.owner_label);
        match (kind.as_str(), chrome) {
            ("window-close", Some(chrome)) => {
                let _ = chrome.close();
                return Ok(Value::Null);
            }
            ("window-minimize", Some(chrome)) => {
                let _ = chrome.minimize();
            }
            ("window-maximize", Some(chrome)) => {
                if chrome.is_maximized().unwrap_or(false) {
                    let _ = chrome.unmaximize();
                } else {
                    let _ = chrome.maximize();
                }
            }
            ("window-drag", Some(chrome)) => {
                let _ = chrome.start_dragging();
            }
            (_, None) => return Ok(Value::Null),
            _ => return Err(invalid("Unknown browser command")),
        }
        return Ok(snapshot(&app, record));
    }
    let tab_index = record.tab(str_field("tabId").as_deref());
    match kind.as_str() {
        "set-overlay" => {
            record.overlay_open = open_flag;
            if open_flag {
                set_downloads_panel(&app, record, false)?;
            }
            display(&app, record);
        }
        "set-icon" | "reset-icon" => {
            let index = tab_index
                .filter(|i| !record.tabs[*i].url.is_empty())
                .ok_or_else(|| invalid("Open a page before changing its icon"))?;
            let url = record.tabs[index].url.clone();
            if kind == "set-icon" {
                stores(&app)
                    .icons
                    .set(
                        &record.host_id,
                        &url,
                        SiteIconInput {
                            mode: IconMode::Custom,
                            data_url: str_field("dataUrl"),
                            glyph: str_field("glyph"),
                            color: str_field("color"),
                        },
                    )
                    .map_err(|e| invalid(&e))?;
                notify_site_icon(&app, record);
            } else {
                stores(&app).icons.reset(&record.host_id, &url);
                notify_site_icon(&app, record);
                if record.route == Route::Connected {
                    request_favicon(&app, record, index);
                }
            }
        }
        "set-panel" => {
            record.panel_open = open_flag;
            display(&app, record);
        }
        "set-download-panel" => set_downloads_panel(&app, record, open_flag)?,
        "new-tab" => {
            let url = match str_field("url") {
                Some(url) if !url.is_empty() => Some(normalize_browser_url(&url).map_err(|e| invalid(&e))?),
                _ => None,
            };
            add_tab(&app, record, url)?;
        }
        "reorder" => {
            let from = record.tabs.iter().position(|t| Some(&t.id) == str_field("tabId").as_ref());
            let to_id = str_field("beforeTabId");
            let to = record.tabs.iter().position(|t| Some(&t.id) == to_id.as_ref());
            if let (Some(from), Some(to)) = (from, to) {
                if from != to {
                    let tab = record.tabs.remove(from);
                    let to = record
                        .tabs
                        .iter()
                        .position(|t| Some(&t.id) == to_id.as_ref())
                        .unwrap_or(record.tabs.len());
                    record.tabs.insert(to, tab);
                    send(&app, record);
                }
            }
        }
        "activate" => {
            if let Some(index) = tab_index {
                record.active_tab_id = Some(record.tabs[index].id.clone());
                display(&app, record);
                let tab = &record.tabs[index];
                if record.visible && !tab.url.is_empty() {
                    if let Some(page) = app.get_webview_window(&tab.label) {
                        let _ = page.set_focus();
                    }
                }
            }
        }
        "close-tab" => {
            if let Some(index) = tab_index {
                let mut tab = record.tabs.remove(index);
                destroy_page(&app, &mut tab);
                if record.active_tab_id.as_deref() == Some(tab.id.as_str()) {
                    record.active_tab_id = record
                        .tabs
                        .get(index)
                        .or_else(|| index.checked_sub(1).and_then(|i| record.tabs.get(i)))
                        .map(|t| t.id.clone());
                }
                if record.tabs.is_empty() {
                    add_tab(&app, record, None)?;
                } else {
                    display(&app, record);
                }
            }
        }
        "navigate" => {
            if record.route != Route::Connected {
                return Err(invalid("Reconnect to the host before opening a page"));
            }
            let url = normalize_browser_url(&str_field("url").unwrap_or_default()).map_err(|e| invalid(&e))?;
            if let Some(index) = tab_index {
                record.tabs[index].url = url.clone();
                let page = record.tabs[index]
                    .webview
                    .then(|| app.get_webview_window(&record.tabs[index].label))
                    .flatten();
                match page {
                    Some(page) => {
                        let _ = page.navigate(url.parse().map_err(|_| invalid("Enter a valid web address"))?);
                    }
                    None => {
                        record.tabs[index].webview = false;
                        create_page(&app, record, index, &url).map_err(|e| invalid(&e))?;
                    }
                }
                display(&app, record);
                let tab = &record.tabs[index];
                if record.visible && record.active_tab_id.as_deref() == Some(&tab.id) && !record.overlay_open {
                    if let Some(page) = app.get_webview_window(&tab.label) {
                        let _ = page.set_focus();
                    }
                }
            }
        }
        "back" | "forward" | "reload" | "stop" => {
            if let Some(index) = tab_index {
                let connected = record.route == Route::Connected;
                let tab = &mut record.tabs[index];
                let page = tab.webview.then(|| app.get_webview_window(&tab.label)).flatten();
                if let Some(page) = page {
                    match kind.as_str() {
                        "back" if connected && tab.can_go_back() => {
                            tab.pending_step = Some(-1);
                            let _ = page.eval("history.back()");
                        }
                        "forward" if connected && tab.can_go_forward() => {
                            tab.pending_step = Some(1);
                            let _ = page.eval("history.forward()");
                        }
                        "reload" if connected => {
                            let _ = page.reload();
                        }
                        "stop" => {
                            let _ = page.eval("window.stop()");
                            tab.loading = false;
                        }
                        _ => {}
                    }
                } else if kind == "reload" && connected && !tab.url.is_empty() {
                    display(&app, record);
                }
            }
        }
        _ => return Err(invalid("Unknown browser command")),
    }
    Ok(inner
        .records
        .get(&id)
        .map(|r| snapshot(&app, r))
        .unwrap_or(Value::Null))
}

fn bookmark_with_icon<R: Runtime>(app: &AppHandle<R>, host_id: &str, bookmark: &netcatty_hostbrowser::Bookmark) -> Value {
    let icon = stores(app).icons.get(host_id, &bookmark.url);
    let mut value = json!(bookmark);
    value["siteIconDataUrl"] = json!(icon.as_ref().and_then(|i| i.data_url.clone()));
    value["siteIconGlyph"] = json!(icon.as_ref().map(|i| i.glyph.clone()).filter(|g| !g.is_empty()));
    value["siteIconColor"] = json!(icon.as_ref().map(|i| i.color.clone()));
    value
}

/// Bookmarks visible to this browser's host, with their website icons.
#[tauri::command]
pub async fn hostbrowser_bookmarks_list<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    browser_id: Option<String>,
) -> CmdResult<Vec<Value>> {
    let host_id = {
        let state = host_state(&app);
        let inner = state.inner.lock();
        let id = owned_id(&inner, window.label(), browser_id.as_deref(), false)?;
        inner.records[&id].host_id.clone()
    };
    Ok(stores(&app)
        .bookmarks
        .list()
        .iter()
        .filter(|b| b.scope == "all-hosts" || b.host_id.as_deref() == Some(host_id.as_str()))
        .map(|b| bookmark_with_icon(&app, &host_id, b))
        .collect())
}

#[tauri::command]
pub async fn hostbrowser_bookmarks_upsert<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    bookmark: Value,
    browser_id: Option<String>,
) -> CmdResult<Value> {
    let host_id = {
        let state = host_state(&app);
        let inner = state.inner.lock();
        let id = owned_id(&inner, window.label(), browser_id.as_deref(), false)?;
        inner.records[&id].host_id.clone()
    };
    let store = &stores(&app).bookmarks;
    if let Some(previous) = bookmark.get("id").and_then(Value::as_str).and_then(|id| store.find(id)) {
        if previous.scope == "host" && previous.host_id.as_deref() != Some(host_id.as_str()) {
            return Err(invalid("Bookmark belongs to another host"));
        }
    }
    let mut input = if bookmark.is_object() { bookmark } else { json!({}) };
    input["hostId"] = if input.get("scope").and_then(Value::as_str) == Some("all-hosts") {
        Value::Null
    } else {
        json!(host_id)
    };
    store.upsert(&input).map(|b| json!(b)).map_err(|e| invalid(&e))
}

#[tauri::command]
pub async fn hostbrowser_bookmarks_remove<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    id: String,
    browser_id: Option<String>,
) -> CmdResult<bool> {
    let host_id = {
        let state = host_state(&app);
        let inner = state.inner.lock();
        let owned = owned_id(&inner, window.label(), browser_id.as_deref(), false)?;
        inner.records[&owned].host_id.clone()
    };
    let store = &stores(&app).bookmarks;
    match store.find(&id) {
        Some(previous) if previous.scope != "host" || previous.host_id.as_deref() == Some(host_id.as_str()) => {
            store.remove(&id).map_err(|e| internal(e))
        }
        _ => Ok(false),
    }
}

/// `getHostBrowserBookmarks` (cloud sync): app windows only.
#[tauri::command]
pub async fn hostbrowser_bookmarks_get_all<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
) -> CmdResult<Value> {
    if is_browser_window(window.label()) {
        return Err(invalid("Untrusted bookmark reader"));
    }
    Ok(json!(stores(&app).bookmarks.list()))
}

/// `applyHostBrowserBookmarks` (cloud sync): app windows only.
#[tauri::command]
pub async fn hostbrowser_bookmarks_apply<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    items: Value,
) -> CmdResult<bool> {
    if is_browser_window(window.label()) {
        return Err(invalid("Untrusted bookmark writer"));
    }
    stores(&app).bookmarks.apply(&items).map_err(|e| invalid(&e))?;
    Ok(true)
}

#[tauri::command]
pub async fn hostbrowser_downloads_list<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    browser_id: Option<String>,
) -> CmdResult<Value> {
    let state = host_state(&app);
    let inner = state.inner.lock();
    let id = owned_id(&inner, window.label(), browser_id.as_deref(), true)?;
    Ok(json!(stores(&app).downloads.list(&inner.records[&id].host_id)))
}

/// Theme of the standalone downloads panel.
#[tauri::command]
pub async fn hostbrowser_downloads_theme<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
) -> CmdResult<Value> {
    let state = host_state(&app);
    let inner = state.inner.lock();
    let id = owned_id(&inner, window.label(), None, true)?;
    let record = &inner.records[&id];
    Ok(json!({ "theme": record.theme, "themeTokens": record.theme_tokens }))
}

/// `commandHostBrowserPanelDownload` and the downloads panel's actions.
#[tauri::command]
pub async fn hostbrowser_downloads_command<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    command: Value,
    browser_id: Option<String>,
) -> CmdResult<bool> {
    use tauri_plugin_opener::OpenerExt;
    let kind = command.get("type").and_then(Value::as_str).unwrap_or("").to_string();
    let download_id = command.get("id").and_then(Value::as_str).unwrap_or("").to_string();
    let state = host_state(&app);
    let (browser, host_id) = {
        let inner = state.inner.lock();
        let id = owned_id(&inner, window.label(), browser_id.as_deref(), true)?;
        let host = inner.records[&id].host_id.clone();
        (id, host)
    };
    let store = &stores(&app).downloads;
    let item = store.get(&host_id, &download_id);
    match kind.as_str() {
        "close" => {
            let mut inner = state.inner.lock();
            if let Some(record) = inner.records.get_mut(&browser) {
                set_downloads_panel(&app, record, false)?;
            }
            Ok(true)
        }
        "open-folder" => {
            let dir = downloads_dir(&app);
            app.opener()
                .open_path(dir.to_string_lossy(), None::<&str>)
                .map_err(internal)?;
            Ok(true)
        }
        "clear" => {
            store.clear_finished(&host_id);
            let inner = state.inner.lock();
            notify_downloads(&app, &inner, &host_id, None);
            Ok(true)
        }
        "cancel" => {
            let mut active = state.active.lock();
            match item.and_then(|item| active.get_mut(&item.id)) {
                Some(download) if download.host_id == host_id => {
                    // The webview engines expose no cancel: the transfer runs
                    // to its end, then the file is removed and the download
                    // is recorded as cancelled.
                    download.cancelled = true;
                    Ok(true)
                }
                _ => Err(invalid("Download is no longer active")),
            }
        }
        "remove" => {
            if item.is_none() || !store.remove(&host_id, &download_id) {
                return Ok(false);
            }
            let inner = state.inner.lock();
            notify_downloads(&app, &inner, &host_id, None);
            Ok(true)
        }
        "open" | "save-as" | "reveal" => {
            let item = item
                .filter(|item| {
                    item.status == DownloadStatus::Completed
                        && !item.save_path.is_empty()
                        && Path::new(&item.save_path).exists()
                })
                .ok_or_else(|| invalid("File moved or deleted"))?;
            let path = PathBuf::from(&item.save_path);
            match kind.as_str() {
                "reveal" => app.opener().reveal_item_in_dir(&path).map_err(internal)?,
                "open" => app
                    .opener()
                    .open_path(path.to_string_lossy(), None::<&str>)
                    .map_err(internal)?,
                _ => {
                    use tauri_plugin_dialog::DialogExt;
                    let mut builder = app.dialog().file().set_file_name(&item.filename);
                    if let Some(parent) = path.parent() {
                        builder = builder.set_directory(parent);
                    }
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    builder.save_file(move |picked| {
                        let _ = tx.send(picked);
                    });
                    let Some(target) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else {
                        return Ok(false);
                    };
                    let same = std::fs::canonicalize(&target).ok() == std::fs::canonicalize(&path).ok();
                    if !same {
                        tokio::fs::copy(&path, &target).await.map_err(internal)?;
                    }
                }
            }
            Ok(true)
        }
        _ => Err(invalid("Unknown download action")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approximate_history_tracks_back_and_forward() {
        let mut tab = Tab::new(None);
        assert!(!tab.can_go_back() && !tab.can_go_forward());
        tab.record_navigation("https://a/");
        tab.record_navigation("https://b/");
        tab.record_navigation("https://b/");
        assert_eq!(tab.history, ["https://a/", "https://b/"]);
        assert!(tab.can_go_back() && !tab.can_go_forward());
        tab.pending_step = Some(-1);
        tab.record_navigation("https://a/");
        assert_eq!(tab.index, 0);
        assert!(!tab.can_go_back() && tab.can_go_forward());
        tab.record_navigation("https://c/");
        assert_eq!(tab.history, ["https://a/", "https://c/"]);
        assert!(tab.can_go_back() && !tab.can_go_forward());
    }

    #[test]
    fn tab_labels_are_valid_window_labels() {
        let tab = Tab::new(Some("https://example.com/".into()));
        assert!(tab.label.starts_with(TAB_PREFIX));
        assert!(tab
            .label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_eq!(tab.url, "https://example.com/");
    }

    #[test]
    fn assets_are_served_and_unknown_paths_are_not() {
        for path in [
            "browser.html",
            "browser.css",
            "browser.js",
            "downloads.html",
            "downloads.css",
            "downloads.js",
            "tauri-adapter.js",
        ] {
            assert!(asset(path).is_some(), "{path}");
        }
        assert!(asset("../Cargo.toml").is_none());
        assert!(is_asset_url(&format!("{ASSET_SCHEME}://localhost/browser.html").parse().unwrap()));
        assert!(is_asset_url(&format!("http://{ASSET_SCHEME}.localhost/browser.html").parse().unwrap()));
        assert!(!is_asset_url(&"https://example.com/".parse().unwrap()));
    }

    #[test]
    fn browser_windows_are_recognised() {
        assert!(is_browser_window("host-browser-3"));
        assert!(is_browser_window("host-browser-dl-1"));
        assert!(is_browser_window("hb-tab-abc"));
        assert!(!is_browser_window("main"));
        assert!(!is_browser_window("settings"));
    }
}
