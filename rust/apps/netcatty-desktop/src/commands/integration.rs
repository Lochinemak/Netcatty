//! OS shell integration (Electron: `deepLink.cjs`, `openTerminalPath.cjs`,
//! `explorerContextMenu.cjs`, `puttyCommandLine.cjs`,
//! `secureCrtCommandLine.cjs`, `mainWindowReuse.cjs`, `appIconManager.cjs`
//! and the `second-instance` / `open-url` / `open-file` / Dock handling in
//! `main.cjs`). Logic lives in `netcatty-integration`; this module holds the
//! state, the commands and the Tauri wiring.
//!
//! Launch intents (ssh / telnet / jms deep links, PuTTY / SecureCRT command
//! lines, open-terminal-at-path requests) are queued until the main window's
//! bridge attaches (`integration_renderer_attach`, called once per renderer
//! load after its listeners exist). The attach call returns the queued
//! cold-start intents and marks cold start settled; later intents are emitted
//! live on the Electron channel names to the main window, which is brought
//! forward (recreated when missing) first.
//!
//! * Windows / Linux: a second launch reaches the running instance through
//!   `tauri-plugin-single-instance` ([`on_second_instance`]); its argv is
//!   parsed in order and then scrubbed (it may carry a password).
//! * macOS: URLs and Finder folder drops arrive as Apple Events through
//!   `tauri-plugin-deep-link` (`RunEvent::Opened`).
//! * Protocol-client registration: Launch Services on macOS, the HKCU
//!   `Software\Classes\<scheme>` key on Windows (only removed when it points
//!   at this executable), the deep-link plugin (`xdg-mime`) on Linux. Debug
//!   builds skip the startup registration so a development binary never
//!   becomes the system ssh handler; explicit toggles still apply.

use super::tray::{bring_main_to_foreground, TRAY_ID};
use super::window::MAIN_LABEL;
use netcatty_integration::app_icon;
use netcatty_integration::deeplink::{
    self, apply_initial_preference, apply_ssh_and_telnet, classify_open_url, is_deep_link_url,
    update_enabled_preference, QueueItem, Scheme, ToggleResult, JMS_DEEP_LINK_CHANNEL,
    JMS_DEEP_LINK_PREFERENCES_FILE, SSH_DEEP_LINK_CHANNEL, SSH_DEEP_LINK_PREFERENCES_FILE,
    TELNET_DEEP_LINK_CHANNEL,
};
use netcatty_integration::explorer::{self, ExplorerContextMenu, ExplorerResult, LaunchSpec, Registry};
use netcatty_integration::launch::{cold_start_intents, route_second_instance, scrub_argv, SecondInstanceRoute};
use netcatty_integration::open_terminal::{
    resolve_path, OpenTerminalRequest, RealFs, OPEN_TERMINAL_PATH_CHANNEL,
};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Emitter, Manager, Runtime, WebviewWindow};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// A queued launch intent. URLs may embed a password; they are zeroized on
/// drop and never logged.
enum Intent {
    Ssh(QueueItem),
    Telnet(QueueItem),
    Jms(Zeroizing<String>),
    OpenTerminal(OpenTerminalRequest),
}

impl Intent {
    fn is_scheme_link(&self) -> bool {
        match self {
            Intent::Ssh(item) | Intent::Telnet(item) => !item.via_command_line,
            _ => false,
        }
    }

    fn channel(&self) -> &'static str {
        match self {
            Intent::Ssh(_) => SSH_DEEP_LINK_CHANNEL,
            Intent::Telnet(_) => TELNET_DEEP_LINK_CHANNEL,
            Intent::Jms(_) => JMS_DEEP_LINK_CHANNEL,
            Intent::OpenTerminal(_) => OPEN_TERMINAL_PATH_CHANNEL,
        }
    }

    /// The Electron payload: `{ url, tabName? }`, `{ url }`, `{ path?, shell? }`.
    fn payload(&self) -> Value {
        match self {
            Intent::Ssh(item) | Intent::Telnet(item) => {
                let mut payload = json!({ "url": item.raw_url });
                if let Some(tab) = item.tab_name.as_deref().filter(|t| !t.is_empty()) {
                    payload["tabName"] = Value::String(tab.to_owned());
                }
                payload
            }
            Intent::Jms(url) => json!({ "url": url.as_str() }),
            Intent::OpenTerminal(request) => serde_json::to_value(request).unwrap_or_default(),
        }
    }
}

struct Inner {
    ssh_enabled: bool,
    jms_enabled: bool,
    explorer_enabled: bool,
    pending: VecDeque<Intent>,
    /// The main window's bridge is listening (set by `integration_renderer_attach`).
    attached: bool,
    cold_start_settled: bool,
    /// Variant PNG for the Windows tray (`None`: the default artwork).
    tray_variant_png: Option<Vec<u8>>,
}

/// Managed integration state (registered by [`setup`]).
pub struct IntegrationState {
    data_dir: PathBuf,
    inner: Mutex<Inner>,
}

impl IntegrationState {
    fn new(data_dir: PathBuf) -> Self {
        Self {
            inner: Mutex::new(Inner {
                ssh_enabled: deeplink::read_ssh_enabled(&data_dir),
                jms_enabled: deeplink::read_jms_enabled(&data_dir),
                explorer_enabled: false,
                pending: VecDeque::new(),
                attached: false,
                cold_start_settled: false,
                tray_variant_png: None,
            }),
            data_dir,
        }
    }

    /// Electron `dropSchemePendingDeepLinks`: scheme-originated ssh / telnet
    /// links go, command-line launches stay.
    fn drop_scheme_pending(&self) {
        self.inner.lock().pending.retain(|i| !i.is_scheme_link());
    }

    fn drop_jms_pending(&self) {
        self.inner.lock().pending.retain(|i| !matches!(i, Intent::Jms(_)));
    }
}

fn state<R: Runtime>(app: &AppHandle<R>) -> Option<tauri::State<'_, IntegrationState>> {
    app.try_state::<IntegrationState>()
}

// ---------------------------------------------------------------------------
// Queueing and delivery
// ---------------------------------------------------------------------------

/// Gate an intent like Electron's `queue*` functions and deliver or queue it.
fn queue<R: Runtime>(app: &AppHandle<R>, intent: Intent) {
    let Some(state) = state(app) else {
        return;
    };
    let deliver_now = {
        let mut inner = state.inner.lock();
        let allowed = match &intent {
            Intent::Ssh(item) => {
                (item.via_command_line || inner.ssh_enabled) && is_deep_link_url(&item.raw_url, Scheme::Ssh)
            }
            Intent::Telnet(item) => {
                (item.via_command_line || inner.ssh_enabled)
                    && is_deep_link_url(&item.raw_url, Scheme::Telnet)
            }
            Intent::Jms(url) => inner.jms_enabled && is_deep_link_url(url, Scheme::Jms),
            Intent::OpenTerminal(_) => true,
        };
        if !allowed {
            return;
        }
        if inner.attached {
            Some(intent)
        } else {
            inner.pending.push_back(intent);
            None
        }
    };
    if let Some(intent) = deliver_now {
        deliver(app, intent);
    }
}

/// Bring the main window forward and emit the intent to it. A missing main
/// window is recreated and the intent waits for its bridge to attach.
fn deliver<R: Runtime>(app: &AppHandle<R>, intent: Intent) {
    if app.get_webview_window(MAIN_LABEL).is_none() {
        if let Some(state) = state(app) {
            let mut inner = state.inner.lock();
            inner.attached = false;
            inner.pending.push_back(intent);
        }
        spawn_ensure_main_window(app);
        return;
    }
    bring_main_to_foreground(app);
    if let Err(err) = app.emit_to(MAIN_LABEL, intent.channel(), intent.payload()) {
        tracing::warn!(channel = intent.channel(), %err, "launch intent delivery failed");
    }
}

/// Electron `getReusableMainWindow` + `createAndShowMainWindow`: reuse the
/// main window when it exists, otherwise build it again from the config.
pub(crate) fn ensure_main_window<R: Runtime>(app: &AppHandle<R>) -> Option<WebviewWindow<R>> {
    if let Some(existing) = app.get_webview_window(MAIN_LABEL) {
        return Some(existing);
    }
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == MAIN_LABEL)
        .cloned()?;
    match tauri::WebviewWindowBuilder::from_config(app, &config).and_then(|b| b.build()) {
        Ok(window) => Some(window),
        Err(err) => {
            tracing::error!(%err, "failed to recreate the main window");
            None
        }
    }
}

/// Off the event-loop thread (window creation from an event handler can
/// deadlock on Windows), then focus it.
fn spawn_ensure_main_window<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if ensure_main_window(&app).is_some() {
            bring_main_to_foreground(&app);
        }
    });
}

/// Focus the main window; recreate it when it is gone.
fn focus_or_recreate_main<R: Runtime>(app: &AppHandle<R>) {
    if !bring_main_to_foreground(app) {
        spawn_ensure_main_window(app);
    }
}

fn queue_items<R: Runtime>(app: &AppHandle<R>, items: Vec<QueueItem>, telnet: bool) {
    for item in items {
        queue(app, if telnet { Intent::Telnet(item) } else { Intent::Ssh(item) });
    }
}

/// `tauri-plugin-single-instance` callback: the forwarded argv of a second
/// launch, in its original order (no Chromium regrouping), routed like
/// Electron's `second-instance` handler and then scrubbed.
pub fn on_second_instance<R: Runtime>(app: &AppHandle<R>, mut argv: Vec<String>, cwd: String) {
    let (ssh_enabled, jms_enabled) = state(app)
        .map(|s| {
            let inner = s.inner.lock();
            (inner.ssh_enabled, inner.jms_enabled)
        })
        .unwrap_or((true, false));
    let cwd = (!cwd.is_empty()).then(|| PathBuf::from(&cwd));
    let home = dirs::home_dir();
    let route = route_second_instance(&argv, cwd.as_deref(), home.as_deref(), ssh_enabled, jms_enabled, &RealFs);
    scrub_argv(&mut argv);
    match route {
        SecondInstanceRoute::Jms { urls, enabled } => {
            if enabled {
                for url in urls {
                    queue(app, Intent::Jms(Zeroizing::new(url)));
                }
            }
        }
        SecondInstanceRoute::Telnet(items) => queue_items(app, items, true),
        SecondInstanceRoute::Ssh(items) => queue_items(app, items, false),
        SecondInstanceRoute::OpenTerminal(requests) => {
            for request in requests {
                queue(app, Intent::OpenTerminal(request));
            }
        }
        SecondInstanceRoute::OpenTerminalInvalid => {
            tracing::warn!("open-terminal launch arguments present but no valid request resolved");
            focus_or_recreate_main(app);
        }
        SecondInstanceRoute::Focus => focus_or_recreate_main(app),
    }
}

/// A URL delivered by the OS (macOS `open-url` / Finder `open-file`).
fn on_open_url<R: Runtime>(app: &AppHandle<R>, url: &tauri::Url) {
    if url.scheme() == "file" {
        let Ok(path) = url.to_file_path() else {
            return;
        };
        let home = dirs::home_dir();
        if let Some(resolved) = resolve_path(&path.to_string_lossy(), None, home.as_deref(), &RealFs) {
            queue(
                app,
                Intent::OpenTerminal(OpenTerminalRequest {
                    path: Some(resolved),
                    shell: None,
                }),
            );
        }
        return;
    }
    let raw = url.to_string();
    match classify_open_url(&raw) {
        Scheme::Jms => queue(app, Intent::Jms(Zeroizing::new(raw))),
        Scheme::Telnet => queue(
            app,
            Intent::Telnet(QueueItem {
                raw_url: raw,
                via_command_line: false,
                tab_name: None,
            }),
        ),
        Scheme::Ssh => queue(
            app,
            Intent::Ssh(QueueItem {
                raw_url: raw,
                via_command_line: false,
                tab_name: None,
            }),
        ),
    }
}

// ---------------------------------------------------------------------------
// Protocol-client registration
// ---------------------------------------------------------------------------

/// Electron `setAsDefaultProtocolClient` / `removeAsDefaultProtocolClient`.
fn set_protocol_client<R: Runtime>(app: &AppHandle<R>, scheme: Scheme, enabled: bool) -> bool {
    let name = scheme.as_str();
    #[cfg(target_os = "macos")]
    {
        let _ = app;
        if enabled {
            netcatty_integration::macos::set_default_url_handler(name)
        } else {
            netcatty_integration::macos::remove_default_url_handler(name)
        }
    }
    #[cfg(windows)]
    {
        let _ = app;
        windows_protocol::apply(name, enabled)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use tauri_plugin_deep_link::DeepLinkExt;
        let result = if enabled {
            app.deep_link().register(name)
        } else {
            app.deep_link().unregister(name)
        };
        if let Err(err) = &result {
            tracing::warn!(scheme = name, %err, "protocol handler registration failed");
        }
        result.is_ok()
    }
}

/// HKCU `Software\Classes\<scheme>` like Electron on Windows. Removal only
/// touches a registration that launches this executable.
#[cfg(windows)]
mod windows_protocol {
    use netcatty_integration::explorer::{Hive, Registry, WindowsRegistry};

    fn command() -> Option<String> {
        let exe = std::env::current_exe().ok()?;
        Some(format!("\"{}\" \"%1\"", exe.display()))
    }

    pub fn apply(scheme: &str, enabled: bool) -> bool {
        let reg = WindowsRegistry;
        let key = format!("Software\\Classes\\{scheme}");
        let command_key = format!("{key}\\shell\\open\\command");
        let Some(command) = command() else {
            return false;
        };
        if enabled {
            return reg.write_string(Hive::CurrentUser, &key, "", &format!("URL:{scheme}"))
                && reg.write_string(Hive::CurrentUser, &key, "URL Protocol", "")
                && reg.write_string(Hive::CurrentUser, &command_key, "", &command);
        }
        match reg.read_string(Hive::CurrentUser, &command_key, "") {
            Some(current) if current.eq_ignore_ascii_case(&command) => {
                reg.delete_key(Hive::CurrentUser, &key)
            }
            _ => true,
        }
    }
}

fn apply_ssh_protocol_clients<R: Runtime>(app: &AppHandle<R>, enabled: bool) -> bool {
    apply_ssh_and_telnet(enabled, |scheme, on| set_protocol_client(app, scheme, on))
}

// ---------------------------------------------------------------------------
// Explorer context menu
// ---------------------------------------------------------------------------

fn registry() -> Box<dyn Registry> {
    #[cfg(windows)]
    {
        Box::new(explorer::WindowsRegistry)
    }
    #[cfg(not(windows))]
    {
        Box::new(explorer::MemoryRegistry::default())
    }
}

fn explorer_launch_spec() -> LaunchSpec {
    let portable = std::env::var("PORTABLE_EXECUTABLE_FILE").ok();
    let exe = std::env::current_exe().unwrap_or_default();
    explorer::resolve_launch_spec(portable.as_deref(), &exe)
}

fn with_explorer<T>(data_dir: &Path, f: impl FnOnce(&ExplorerContextMenu<'_>) -> T) -> T {
    let reg = registry();
    let menu = ExplorerContextMenu {
        registry: reg.as_ref(),
        data_dir,
        supported: cfg!(windows),
    };
    f(&menu)
}

// ---------------------------------------------------------------------------
// App icon variants
// ---------------------------------------------------------------------------

fn load_icon_asset<R: Runtime>(app: &AppHandle<R>, candidates: &[String]) -> Option<Vec<u8>> {
    for candidate in candidates {
        if let Some(asset) = app.asset_resolver().get(format!("/{candidate}")) {
            if !asset.bytes.is_empty() {
                return Some(asset.bytes);
            }
        }
        // Development: the renderer's `public/` directory.
        if cfg!(debug_assertions) {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../public").join(candidate);
            if let Ok(bytes) = std::fs::read(path) {
                return Some(bytes);
            }
        }
    }
    None
}

/// Windows tray artwork for the current variant (`None`: the default).
pub(crate) fn tray_icon_override<R: Runtime>(app: &AppHandle<R>) -> Option<tauri::image::Image<'static>> {
    let png = state(app)?.inner.lock().tray_variant_png.clone()?;
    let scale = app
        .primary_monitor()
        .ok()
        .flatten()
        .map(|m| m.scale_factor())
        .unwrap_or(1.0);
    let rendition = app_icon::tray_rendition(&png, app_icon::small_icon_px(scale))?;
    Some(tauri::image::Image::new_owned(rendition.pixels, rendition.width, rendition.height))
}

fn apply_app_icon_variant<R: Runtime>(app: &AppHandle<R>, variant: &str) -> bool {
    let normalized = app_icon::normalize_variant(Some(variant));
    let is_mac = cfg!(target_os = "macos");
    let Some(bytes) = load_icon_asset(app, &app_icon::asset_candidates(normalized, is_mac)) else {
        return false;
    };
    if is_mac {
        #[cfg(target_os = "macos")]
        {
            let dock_bytes = bytes.clone();
            let _ = app.run_on_main_thread(move || {
                netcatty_integration::macos::set_dock_icon(&dock_bytes);
            });
        }
        return true;
    }
    // Window / taskbar icons.
    if let Ok(image) = tauri::image::Image::from_bytes(&bytes) {
        for window in app.webview_windows().values() {
            let _ = window.set_icon(image.clone());
        }
    }
    // Windows tray: the variant artwork (the packaged default for "original").
    if cfg!(windows) {
        if let Some(state) = state(app) {
            state.inner.lock().tray_variant_png = (normalized != app_icon::DEFAULT_VARIANT).then(|| bytes.clone());
        }
        if let Some(tray) = app.tray_by_id(TRAY_ID) {
            let image = tray_icon_override(app).or_else(super::tray::default_tray_image);
            let _ = tray.set_icon(image);
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Setup and run-loop hooks
// ---------------------------------------------------------------------------

/// Register the deep-link plugin and the integration state, collect this
/// launch's intents and reconcile the OS registrations with the saved
/// preferences. Wired in `lib.rs` after the tray.
pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    let handle = app.handle().clone();
    if let Err(err) = handle.plugin(tauri_plugin_deep_link::init()) {
        tracing::warn!(%err, "deep-link plugin unavailable");
    }
    let data_dir = netcatty_store::AppPaths::resolve().data_dir;
    let integration = IntegrationState::new(data_dir.clone());
    let (ssh_enabled, jms_enabled) = {
        let inner = integration.inner.lock();
        (inner.ssh_enabled, inner.jms_enabled)
    };
    app.manage(integration);

    // Cold-start intents from this process's argv.
    let mut argv: Vec<String> = std::env::args().collect();
    let cwd = std::env::current_dir().ok();
    let home = dirs::home_dir();
    let intents = cold_start_intents(&argv, cwd.as_deref(), home.as_deref(), ssh_enabled, jms_enabled, &RealFs);
    scrub_argv(&mut argv);
    queue_items(&handle, intents.ssh, false);
    queue_items(&handle, intents.telnet, true);
    for url in intents.jms {
        queue(&handle, Intent::Jms(Zeroizing::new(url)));
    }
    for request in intents.open_terminal {
        queue(&handle, Intent::OpenTerminal(request));
    }

    // Startup reconciliation of the OS registrations (release builds).
    let reconcile = !cfg!(debug_assertions);
    let Some(state) = state(&handle) else {
        return;
    };
    let ssh = apply_initial_preference(
        ssh_enabled,
        |enabled| !reconcile || apply_ssh_protocol_clients(&handle, enabled),
        || state.drop_scheme_pending(),
        "ssh://",
        true,
    );
    let jms = apply_initial_preference(
        jms_enabled,
        |enabled| !reconcile || set_protocol_client(&handle, Scheme::Jms, enabled),
        || state.drop_jms_pending(),
        "jms://",
        false,
    );
    let explorer_enabled = with_explorer(&state.data_dir, |menu| {
        if reconcile {
            menu.apply_initial(&explorer_launch_spec()).enabled
        } else {
            menu.resolve_enabled().0
        }
    });
    {
        let mut inner = state.inner.lock();
        inner.ssh_enabled = ssh.enabled;
        inner.jms_enabled = jms.enabled;
        inner.explorer_enabled = explorer_enabled;
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(deep_link) = handle.try_state::<tauri_plugin_deep_link::DeepLink<R>>() {
            let listener = handle.clone();
            deep_link.on_open_url(move |event| {
                for url in event.urls() {
                    on_open_url(&listener, &url);
                }
            });
        }
        let dock = handle.clone();
        let _ = handle.run_on_main_thread(move || install_dock_menu(dock));
    }
    #[cfg(not(target_os = "macos"))]
    let _ = on_open_url::<R>;
}

/// Run-loop hook (called from `tray::on_run_event`): a Dock click with the
/// main window gone recreates it (Electron `activate`).
pub fn on_run_event<R: Runtime>(app: &AppHandle<R>, event: &tauri::RunEvent) {
    #[cfg(target_os = "macos")]
    if let tauri::RunEvent::Reopen { .. } = event {
        if app.get_webview_window(MAIN_LABEL).is_none() {
            spawn_ensure_main_window(app);
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (app, event);
}

#[cfg(target_os = "macos")]
fn install_dock_menu<R: Runtime>(app: AppHandle<R>) {
    use netcatty_integration::dock::{build_dock_menu, DockAction};
    let provider_app = app.clone();
    let installed = netcatty_integration::macos::install_dock_menu(
        move || {
            let data = super::tray::tray_get_menu_data(provider_app.clone());
            build_dock_menu(&data.hosts, super::security::is_app_locked(&provider_app))
        },
        move |action| match action {
            DockAction::OpenMain => focus_or_recreate_main(&app),
            DockAction::ConnectHost(id) => {
                super::tray::tray_panel_connect_to_host(app.clone(), id);
            }
        },
    );
    if !installed {
        tracing::warn!("macOS Dock menu unavailable");
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireIntent {
    channel: &'static str,
    payload: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachResult {
    intents: Vec<WireIntent>,
    cold_start_settled: bool,
}

/// The main window's bridge is listening: hand over the queued intents and
/// settle cold start (Electron `drainColdStartLaunchIntents` +
/// `netcatty:startup:coldStartIntentsSettled`). Other windows get nothing.
#[tauri::command]
pub fn integration_renderer_attach<R: Runtime>(app: AppHandle<R>, window: WebviewWindow<R>) -> AttachResult {
    if window.label() != MAIN_LABEL {
        return AttachResult {
            intents: Vec::new(),
            cold_start_settled: true,
        };
    }
    let Some(state) = state(&app) else {
        return AttachResult {
            intents: Vec::new(),
            cold_start_settled: true,
        };
    };
    let drained: Vec<Intent> = {
        let mut inner = state.inner.lock();
        inner.attached = true;
        inner.cold_start_settled = true;
        inner.pending.drain(..).collect()
    };
    if !drained.is_empty() {
        bring_main_to_foreground(&app);
    }
    AttachResult {
        intents: drained
            .iter()
            .map(|intent| WireIntent {
                channel: intent.channel(),
                payload: intent.payload(),
            })
            .collect(),
        cold_start_settled: true,
    }
}

#[tauri::command]
pub fn integration_get_ssh_deep_link_enabled<R: Runtime>(app: AppHandle<R>) -> bool {
    state(&app).is_some_and(|s| s.inner.lock().ssh_enabled)
}

#[tauri::command]
pub fn integration_set_ssh_deep_link_enabled<R: Runtime>(app: AppHandle<R>, enabled: Option<bool>) -> ToggleResult {
    let Some(state) = state(&app) else {
        return ToggleResult {
            enabled: false,
            success: false,
        };
    };
    let current = state.inner.lock().ssh_enabled;
    let result = update_enabled_preference(
        current,
        enabled != Some(false),
        |next| apply_ssh_protocol_clients(&app, next),
        |next| deeplink::write_enabled(&state.data_dir, SSH_DEEP_LINK_PREFERENCES_FILE, next),
        || state.drop_scheme_pending(),
    );
    state.inner.lock().ssh_enabled = result.enabled;
    result
}

#[tauri::command]
pub fn integration_get_jms_deep_link_enabled<R: Runtime>(app: AppHandle<R>) -> bool {
    state(&app).is_some_and(|s| s.inner.lock().jms_enabled)
}

#[tauri::command]
pub fn integration_set_jms_deep_link_enabled<R: Runtime>(app: AppHandle<R>, enabled: Option<bool>) -> ToggleResult {
    let Some(state) = state(&app) else {
        return ToggleResult {
            enabled: false,
            success: false,
        };
    };
    let current = state.inner.lock().jms_enabled;
    let result = update_enabled_preference(
        current,
        enabled != Some(false),
        |next| set_protocol_client(&app, Scheme::Jms, next),
        |next| deeplink::write_enabled(&state.data_dir, JMS_DEEP_LINK_PREFERENCES_FILE, next),
        || state.drop_jms_pending(),
    );
    state.inner.lock().jms_enabled = result.enabled;
    result
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerStatus {
    enabled: bool,
    supported: bool,
}

#[tauri::command]
pub fn integration_get_explorer_context_menu_enabled<R: Runtime>(app: AppHandle<R>) -> ExplorerStatus {
    ExplorerStatus {
        enabled: state(&app).is_some_and(|s| s.inner.lock().explorer_enabled),
        supported: cfg!(windows),
    }
}

#[tauri::command]
pub fn integration_set_explorer_context_menu_enabled<R: Runtime>(
    app: AppHandle<R>,
    enabled: Option<bool>,
) -> ExplorerResult {
    let Some(state) = state(&app).filter(|_| cfg!(windows)) else {
        // Windows only: elsewhere nothing is applied or saved.
        return ExplorerResult {
            enabled: false,
            success: !cfg!(windows),
            supported: false,
        };
    };
    let spec = explorer_launch_spec();
    let current = state.inner.lock().explorer_enabled;
    let result = with_explorer(&state.data_dir, |menu| {
        explorer::update_enabled_preference(
            current,
            enabled != Some(false),
            |next| menu.apply(next, &spec),
            |next| menu.write_enabled_preference(next, &spec),
        )
    });
    state.inner.lock().explorer_enabled = result.enabled;
    result
}

/// Electron `netcatty:setAppIconVariant`: `true` when the variant artwork
/// exists and was applied.
#[tauri::command]
pub fn integration_set_app_icon_variant<R: Runtime>(app: AppHandle<R>, variant: Option<String>) -> bool {
    apply_app_icon_variant(&app, variant.as_deref().unwrap_or(app_icon::DEFAULT_VARIANT))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(url: &str, cli: bool) -> QueueItem {
        QueueItem {
            raw_url: url.to_owned(),
            via_command_line: cli,
            tab_name: Some("Prod".into()),
        }
    }

    #[test]
    fn payloads_match_the_electron_channels() {
        let ssh = Intent::Ssh(item("ssh://a@h", true));
        assert_eq!(ssh.channel(), "netcatty:deepLink:ssh");
        assert_eq!(ssh.payload(), json!({ "url": "ssh://a@h", "tabName": "Prod" }));
        let jms = Intent::Jms(Zeroizing::new("jms://x".into()));
        assert_eq!(jms.channel(), "netcatty:deepLink:jms");
        assert_eq!(jms.payload(), json!({ "url": "jms://x" }));
        let open = Intent::OpenTerminal(OpenTerminalRequest {
            path: None,
            shell: Some("pwsh".into()),
        });
        assert_eq!(open.channel(), "netcatty:openTerminalPath");
        assert_eq!(open.payload(), json!({ "shell": "pwsh" }));
        assert_eq!(Intent::Telnet(item("telnet://h", false)).channel(), "netcatty:deepLink:telnet");
    }

    #[test]
    fn disabling_drops_only_scheme_links() {
        let dir = tempfile::tempdir().unwrap();
        let state = IntegrationState::new(dir.path().to_path_buf());
        {
            let mut inner = state.inner.lock();
            inner.pending.push_back(Intent::Ssh(item("ssh://scheme", false)));
            inner.pending.push_back(Intent::Ssh(item("ssh://cli", true)));
            inner.pending.push_back(Intent::Telnet(item("telnet://scheme", false)));
            inner.pending.push_back(Intent::Jms(Zeroizing::new("jms://x".into())));
        }
        state.drop_scheme_pending();
        assert_eq!(state.inner.lock().pending.len(), 2);
        state.drop_jms_pending();
        let inner = state.inner.lock();
        assert_eq!(inner.pending.len(), 1);
        assert!(matches!(&inner.pending[0], Intent::Ssh(i) if i.raw_url == "ssh://cli"));
    }
}
