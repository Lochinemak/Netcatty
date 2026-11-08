//! Browser runtime host side (replaces `browserPluginRuntime.cjs`,
//! `browserPreload.cjs` and `pluginProtocol.cjs` for the Tauri webview).
//!
//! Each browser plugin runs in a hidden `<iframe sandbox="allow-scripts">`
//! in the main webview (opaque origin: no Tauri IPC, no storage, no access
//! to the app document). Its documents and modules are served by the
//! `netcatty-plugin` URI scheme under a per-runtime unguessable token:
//!
//! * `/<token>/index.html` — import map + preload shim + `browserRuntime.mjs`
//!   under a restrictive CSP (no network origins besides the scheme);
//! * `/<token>/__host/runtime/…` — `electron/plugins/runtime/*.mjs` and
//!   `config.json`;
//! * `/<token>/__host/modules/m<i>/…` — `@netcatty/plugin-sdk` / `-contract`;
//! * `/<token>/package/…` — the verified package root.
//!
//! The inline shim plays `browserPreload.cjs`: it relays the parent's
//! MessagePort into the plugin document (runtime-ready / connect /
//! runtime-connected handshake). The renderer relay
//! (`infrastructure/tauri/bridge/pluginRuntimeHost.ts`) forwards port
//! messages to Rust in order and Rust replies over a `Channel`, so the host
//! side of every RPC (router, capability checks) runs here.

use crate::constants::PLUGIN_ACTIVATION_TIMEOUT;
use crate::error::{PluginError, PluginResult};
use crate::runtime::{LaunchSpec, RuntimeLauncher, RuntimeTransport, TransportEvent};
use crate::source::is_path_inside;
use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub const SCHEME: &str = "netcatty-plugin";
pub const LAUNCH_EVENT: &str = "netcatty:plugins:runtime-launch";
pub const STOP_EVENT: &str = "netcatty:plugins:runtime-stop";

/// Host module served to plugin documents (`moduleResources.cjs`).
#[derive(Debug, Clone)]
pub struct ModuleResource {
    pub specifier: String,
    pub directory: PathBuf,
    pub entry: String,
}

/// Static resources of the browser runtime.
#[derive(Debug, Clone)]
pub struct BrowserResources {
    /// `electron/plugins/runtime` (browserRuntime.mjs, runtimePeer.mjs, …).
    pub runtime_dir: PathBuf,
    pub modules: Vec<ModuleResource>,
}

impl BrowserResources {
    /// Repository / bundle layout rooted at `app_root`.
    pub fn from_app_root(app_root: &Path) -> Self {
        let module = |specifier: &str, dir: &str| ModuleResource {
            specifier: specifier.into(),
            directory: std::fs::canonicalize(app_root.join("node_modules/@netcatty").join(dir).join("dist"))
                .unwrap_or_else(|_| app_root.join("node_modules/@netcatty").join(dir).join("dist")),
            entry: "index.js".into(),
        };
        Self {
            runtime_dir: app_root.join("electron/plugins/runtime"),
            modules: vec![module("@netcatty/plugin-sdk", "plugin-sdk"), module("@netcatty/plugin-contract", "plugin-contract")],
        }
    }
}

/// Renderer side of browser runtimes (Tauri events in the app).
pub trait RendererRuntimeHost: Send + Sync {
    /// Ask the renderer to create the iframe for `runtime_id` at `url`.
    fn launch(&self, runtime_id: &str, url: &str) -> bool;
    /// Ask the renderer to remove the iframe.
    fn stop(&self, runtime_id: &str);
}

/// Outbound sender installed when the renderer attaches its channel.
pub type ChannelSender = Box<dyn Fn(Value) -> bool + Send + Sync>;

struct Registration {
    token: String,
    package_root: PathBuf,
    config: Value,
    events: mpsc::UnboundedSender<TransportEvent>,
    attached: Option<oneshot::Sender<()>>,
    sender: Option<Arc<ChannelSender>>,
    closed: CancellationToken,
}

/// Registry of browser runtimes + the `netcatty-plugin` protocol.
pub struct BrowserRuntimeHost {
    resources: BrowserResources,
    renderer: Mutex<Option<Arc<dyn RendererRuntimeHost>>>,
    runtimes: Mutex<HashMap<String, Registration>>,
    tokens: Mutex<HashMap<String, String>>,
}

/// Base URL of the scheme for this platform.
pub fn scheme_origin() -> &'static str {
    if cfg!(windows) {
        "http://netcatty-plugin.localhost"
    } else {
        "netcatty-plugin://localhost"
    }
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref() {
        Some("css") => "text/css; charset=utf-8",
        Some("gif") => "image/gif",
        Some("html") => "text/html; charset=utf-8",
        Some("ico") => "image/x-icon",
        Some("jpeg" | "jpg") => "image/jpeg",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("wasm") => "application/wasm",
        Some("webp") => "image/webp",
        _ => "application/octet-stream",
    }
}

/// A protocol response.
#[derive(Debug, Clone)]
pub struct ProtocolResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

fn response(status: u16, content_type: &str, body: Vec<u8>, extra: Vec<(String, String)>) -> ProtocolResponse {
    let mut headers = vec![
        ("Cache-Control".into(), "no-store".into()),
        ("X-Content-Type-Options".into(), "nosniff".into()),
        ("X-DNS-Prefetch-Control".into(), "off".into()),
        // Opaque-origin iframe documents fetch modules in CORS mode.
        ("Access-Control-Allow-Origin".into(), "*".into()),
        ("Content-Type".into(), content_type.into()),
    ];
    headers.extend(extra);
    ProtocolResponse { status, headers, body }
}

fn not_found() -> ProtocolResponse {
    response(404, "text/plain; charset=utf-8", b"Not Found".to_vec(), vec![])
}

/// `decodeRequestPath`.
fn decode_segments(path: &str) -> Option<Vec<String>> {
    let decoded = percent_decode(path)?;
    if !decoded.starts_with('/') || decoded.contains('\0') || decoded.contains('\\') {
        return None;
    }
    let segments: Vec<String> = decoded[1..].split('/').map(str::to_string).collect();
    if segments.iter().any(|s| s.is_empty() || s == "." || s == "..") {
        return None;
    }
    Some(segments)
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `readContainedFile`: lexical + realpath containment, regular file only.
pub fn read_contained(root: &Path, segments: &[String], max_bytes: u64) -> PluginResult<(PathBuf, Vec<u8>)> {
    let candidate = segments.iter().fold(root.to_path_buf(), |p, s| p.join(s));
    if !is_path_inside(root, &candidate) {
        return Err(PluginError::host("Plugin resource escapes its root"));
    }
    let real_root = std::fs::canonicalize(root)?;
    let real = std::fs::canonicalize(&candidate)?;
    if !is_path_inside(&real_root, &real) {
        return Err(PluginError::host("Plugin resource follows a symlink outside its root"));
    }
    let meta = std::fs::symlink_metadata(&real)?;
    if !meta.is_file() || meta.len() > max_bytes {
        return Err(PluginError::host("Plugin resource is not a regular file"));
    }
    Ok((real.clone(), std::fs::read(&real)?))
}

/// Preload shim (`browserPreload.cjs` equivalent) run in the plugin
/// document before `browserRuntime.mjs`.
const PRELOAD_SHIM: &str = r#"(() => {
  const token = window.location.hostname;
  let port = null;
  let ready = false;
  const connect = () => {
    if (!port || !ready) return;
    const transferred = port;
    port = null;
    window.postMessage({ type: "netcatty-plugin:connect", runtimeToken: token }, "*", [transferred]);
  };
  window.addEventListener("message", (event) => {
    if (event.source === window.parent && event.data?.type === "netcatty-plugin:port" && event.ports?.[0]) {
      port = event.ports[0];
      connect();
      return;
    }
    if (event.source !== window || event.data?.runtimeToken !== token) return;
    if (event.data?.type === "netcatty-plugin:runtime-ready") { ready = true; connect(); }
    else if (event.data?.type === "netcatty-plugin:runtime-connected") {
      window.parent.postMessage({ type: "netcatty-plugin:runtime-connected" }, "*");
    }
  });
  window.parent.postMessage({ type: "netcatty-plugin:preload-ready" }, "*");
})();"#;

impl BrowserRuntimeHost {
    pub fn new(resources: BrowserResources) -> Arc<Self> {
        Arc::new(Self {
            resources,
            renderer: Mutex::new(None),
            runtimes: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
        })
    }

    pub fn set_renderer(&self, renderer: Arc<dyn RendererRuntimeHost>) {
        *self.renderer.lock() = Some(renderer);
    }

    fn base(&self, token: &str) -> String {
        format!("{}/{token}", scheme_origin())
    }

    fn html(&self, token: &str) -> String {
        let base = self.base(token);
        let imports: serde_json::Map<String, Value> = self
            .resources
            .modules
            .iter()
            .enumerate()
            .map(|(i, m)| (m.specifier.clone(), json!(format!("{base}/__host/modules/m{i}/{}", m.entry))))
            .collect();
        format!(
            "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Netcatty plugin runtime</title>\n<script type=\"importmap\" nonce=\"{token}\">{}</script>\n<script nonce=\"{token}\">{PRELOAD_SHIM}</script></head><body><script type=\"module\" src=\"{base}/__host/runtime/browserRuntime.mjs\"></script></body></html>",
            json!({ "imports": imports })
        )
    }

    /// Serve one `netcatty-plugin` request path (`/<token>/…`).
    pub fn serve(&self, method: &str, path: &str) -> ProtocolResponse {
        if method != "GET" {
            return response(405, "text/plain; charset=utf-8", b"Method Not Allowed".to_vec(), vec![]);
        }
        let Some(segments) = decode_segments(path) else { return not_found() };
        let Some(token) = segments.first().cloned() else { return not_found() };
        let Some(runtime_id) = self.tokens.lock().get(&token).cloned() else { return not_found() };
        let (package_root, config) = match self.runtimes.lock().get(&runtime_id) {
            Some(r) => (r.package_root.clone(), r.config.clone()),
            None => return not_found(),
        };
        let rest = &segments[1..];
        let origin = scheme_origin();
        let csp = format!(
            "default-src 'none'; script-src {origin} 'nonce-{token}'; connect-src {origin}; img-src {origin}; style-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; child-src 'none'; base-uri 'none'; form-action 'none'"
        );
        if rest.len() == 1 && rest[0] == "index.html" {
            return response(
                200,
                "text/html; charset=utf-8",
                self.html(&token).into_bytes(),
                vec![
                    ("Content-Security-Policy".into(), csp),
                    ("Permissions-Policy".into(), "camera=(), microphone=(), geolocation=(), display-capture=(), usb=(), serial=(), hid=(), payment=(), fullscreen=(), clipboard-read=(), clipboard-write=()".into()),
                ],
            );
        }
        if rest.join("/") == "__host/runtime/config.json" {
            return response(200, "application/json; charset=utf-8", config.to_string().into_bytes(), vec![]);
        }
        let (root, files, package) = match rest.first().map(String::as_str) {
            Some("package") => (package_root, &rest[1..], true),
            Some("__host") if rest.get(1).map(String::as_str) == Some("runtime") => (self.resources.runtime_dir.clone(), &rest[2..], false),
            Some("__host") if rest.get(1).map(String::as_str) == Some("modules") => {
                let Some(index) = rest.get(2).and_then(|r| r.strip_prefix('m')).and_then(|n| n.parse::<usize>().ok()) else { return not_found() };
                let Some(module) = self.resources.modules.get(index) else { return not_found() };
                (module.directory.clone(), &rest[3..], false)
            }
            _ => return not_found(),
        };
        if files.is_empty() || (!package && files.iter().any(|s| s.starts_with('.'))) {
            return not_found();
        }
        match read_contained(&root, files, u64::MAX) {
            Ok((path, body)) => response(200, content_type(&path), body, vec![]),
            Err(_) => not_found(),
        }
    }

    /// The renderer finished the port handshake: install the outbound
    /// sender and release the pending launch.
    pub fn attach(&self, runtime_id: &str, sender: ChannelSender) -> bool {
        let mut runtimes = self.runtimes.lock();
        let Some(registration) = runtimes.get_mut(runtime_id) else { return false };
        registration.sender = Some(Arc::new(sender));
        if let Some(tx) = registration.attached.take() {
            let _ = tx.send(());
        }
        true
    }

    /// Ordered batch of runtime → host messages from the renderer relay.
    pub fn deliver(&self, runtime_id: &str, messages: Vec<Value>) -> bool {
        let events = self.runtimes.lock().get(runtime_id).map(|r| r.events.clone());
        let Some(events) = events else { return false };
        for message in messages {
            if events.send(TransportEvent::Message(message)).is_err() {
                return false;
            }
        }
        true
    }

    /// The iframe or its port went away.
    pub fn exited(&self, runtime_id: &str, reason: &str) {
        let registration = self.runtimes.lock().remove(runtime_id);
        if let Some(registration) = registration {
            self.tokens.lock().remove(&registration.token);
            registration.closed.cancel();
            let _ = registration.events.send(TransportEvent::Exited { reason: reason.chars().take(512).collect() });
        }
    }

    /// Drop every runtime (renderer reloaded / window closed).
    pub fn renderer_reset(&self) {
        let ids: Vec<String> = self.runtimes.lock().keys().cloned().collect();
        for id in ids {
            self.exited(&id, "Plugin renderer closed");
        }
    }
}

struct BrowserTransport {
    host: Arc<BrowserRuntimeHost>,
    runtime_id: String,
}

#[async_trait]
impl RuntimeTransport for BrowserTransport {
    fn send(&self, message: Value) -> PluginResult<()> {
        let sender = self.host.runtimes.lock().get(&self.runtime_id).and_then(|r| r.sender.clone());
        match sender {
            Some(send) if send(message) => Ok(()),
            _ => Err(PluginError::unavailable("Plugin browser runtime is not connected")),
        }
    }

    async fn terminate(&self) -> PluginResult<()> {
        let renderer = self.host.renderer.lock().clone();
        if let Some(renderer) = renderer {
            renderer.stop(&self.runtime_id);
        }
        let registration = self.host.runtimes.lock().remove(&self.runtime_id);
        if let Some(r) = registration {
            self.host.tokens.lock().remove(&r.token);
            r.closed.cancel();
        }
        Ok(())
    }
}

/// [`RuntimeLauncher`] for browser plugins.
pub struct BrowserLauncher {
    pub host: Arc<BrowserRuntimeHost>,
}

#[async_trait]
impl RuntimeLauncher for BrowserLauncher {
    async fn launch(
        &self,
        spec: LaunchSpec,
        events: mpsc::UnboundedSender<TransportEvent>,
        cancel: CancellationToken,
    ) -> PluginResult<Arc<dyn RuntimeTransport>> {
        let renderer = self.host.renderer.lock().clone().ok_or_else(|| PluginError::unavailable("Plugin browser runtime host is not ready"))?;
        crate::runtime::resolve_entrypoint(&spec.package_root, &spec.entry)?;
        let token_bytes: [u8; 24] = rand::random();
        let token = hex::encode(token_bytes);
        let mut config = spec.config.clone();
        let entry_path: String = spec.entry.split('/').map(|s| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()).collect::<Vec<_>>().join("/");
        config["entryUrl"] = json!(format!("{}/package/{entry_path}", self.host.base(&token)));
        let (attached_tx, attached_rx) = oneshot::channel();
        let closed = CancellationToken::new();
        self.host.runtimes.lock().insert(
            spec.runtime_id.clone(),
            Registration {
                token: token.clone(),
                package_root: spec.package_root.clone(),
                config,
                events,
                attached: Some(attached_tx),
                sender: None,
                closed: closed.clone(),
            },
        );
        self.host.tokens.lock().insert(token.clone(), spec.runtime_id.clone());
        let transport: Arc<dyn RuntimeTransport> = Arc::new(BrowserTransport { host: self.host.clone(), runtime_id: spec.runtime_id.clone() });
        let url = format!("{}/index.html", self.host.base(&token));
        if !renderer.launch(&spec.runtime_id, &url) {
            let _ = transport.terminate().await;
            return Err(PluginError::unavailable("Plugin browser runtime host is not ready"));
        }
        let outcome = tokio::select! {
            r = attached_rx => r.map_err(|_| PluginError::host("Plugin browser runtime closed during startup")),
            _ = tokio::time::sleep(PLUGIN_ACTIVATION_TIMEOUT * 2) => Err(PluginError::host("Plugin browser runtime did not accept its message port")),
            _ = cancel.cancelled() => Err(PluginError::cancelled()),
            _ = closed.cancelled() => Err(PluginError::host("Plugin browser runtime closed during startup")),
        };
        if let Err(err) = outcome {
            let _ = transport.terminate().await;
            return Err(err);
        }
        Ok(transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_only_registered_tokens_and_contained_files() {
        let dir = tempfile::tempdir().unwrap();
        let runtime_dir = dir.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).unwrap();
        std::fs::write(runtime_dir.join("browserRuntime.mjs"), "export {}").unwrap();
        let package = dir.path().join("pkg");
        std::fs::create_dir_all(package.join("dist")).unwrap();
        std::fs::write(package.join("dist/index.js"), "export default {}").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "x").unwrap();
        let host = BrowserRuntimeHost::new(BrowserResources { runtime_dir, modules: vec![] });
        let (tx, _rx) = mpsc::unbounded_channel();
        host.runtimes.lock().insert(
            "r1".into(),
            Registration { token: "tok".into(), package_root: package, config: json!({ "a": 1 }), events: tx, attached: None, sender: None, closed: CancellationToken::new() },
        );
        host.tokens.lock().insert("tok".into(), "r1".into());
        let html = host.serve("GET", "/tok/index.html");
        assert_eq!(html.status, 200);
        assert!(String::from_utf8_lossy(&html.body).contains("netcatty-plugin:preload-ready"));
        assert!(html.headers.iter().any(|(k, v)| k == "Content-Security-Policy" && v.contains("'nonce-tok'")));
        assert_eq!(host.serve("GET", "/tok/__host/runtime/config.json").body, br#"{"a":1}"#);
        assert_eq!(host.serve("GET", "/tok/__host/runtime/browserRuntime.mjs").status, 200);
        assert_eq!(host.serve("GET", "/tok/package/dist/index.js").status, 200);
        assert_eq!(host.serve("GET", "/tok/package/../secret.txt").status, 404);
        assert_eq!(host.serve("GET", "/tok/package/%2e%2e/secret.txt").status, 404);
        assert_eq!(host.serve("GET", "/other/index.html").status, 404);
        assert_eq!(host.serve("POST", "/tok/index.html").status, 405);
        host.exited("r1", "gone");
        assert_eq!(host.serve("GET", "/tok/index.html").status, 404);
    }
}
