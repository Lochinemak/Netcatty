//! Runtime transports (replacing `browserPluginRuntime.cjs` /
//! `utilityPluginRuntime.cjs`).
//!
//! The supervisor talks to a running plugin through a [`RuntimeTransport`]
//! created by a [`RuntimeLauncher`]:
//!
//! * **browser** — implemented by the desktop app: a sandboxed iframe in the
//!   main webview (opaque origin, no Tauri IPC) whose MessagePort is relayed
//!   to Rust through `invoke` + a `Channel` (`commands/plugins.rs`,
//!   `infrastructure/tauri/bridge/pluginRuntimeHost.ts`).
//! * **utility** — [`NodeSidecarLauncher`]: a Node child process running
//!   `runtime/nodeStdioRuntime.mjs` (the `utilityRuntime.mjs` equivalent)
//!   with newline-delimited JSON over stdio. Node is found through
//!   `NETCATTY_PLUGIN_NODE` or `PATH`; a bundled sidecar binary can be
//!   dropped in later by pointing [`NodeRuntimeConfig::node`] at it.
//!
//! Both deliver the same JSON-RPC messages to the [`crate::rpc::RpcRouter`].

use crate::constants::{PLUGIN_ACTIVATION_TIMEOUT, PLUGIN_UTILITY_FORCE_EXIT_TIMEOUT, PLUGIN_UTILITY_TERMINATION_GRACE};
use crate::error::{PluginError, PluginResult};
use crate::package::compat::RuntimeKind;
use crate::source::is_path_inside;
use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Events a transport delivers to the supervisor's pump.
#[derive(Debug)]
pub enum TransportEvent {
    /// One runtime → host message (already unwrapped; stream transfers as
    /// `transferBase64`).
    Message(Value),
    /// Message on a virtual sub-port (terminal interceptor channel).
    PortMessage { port: String, message: Value },
    /// The runtime is gone.
    Exited { reason: String },
    /// Free-form diagnostic output (stderr / console).
    Diagnostic { level: &'static str, message: String },
}

#[async_trait]
pub trait RuntimeTransport: Send + Sync {
    /// Send one host → runtime message.
    fn send(&self, message: Value) -> PluginResult<()>;
    /// Send a message transferring virtual ports (interceptor attachment).
    fn send_with_ports(&self, message: Value, ports: Vec<String>) -> PluginResult<()> {
        let _ = ports;
        self.send(message)
    }
    /// Post on a virtual sub-port.
    fn send_port(&self, _port: &str, _message: Value) -> PluginResult<()> {
        Err(PluginError::unavailable("Plugin runtime has no sub-ports"))
    }
    /// Tear the runtime down and wait for it to be gone.
    async fn terminate(&self) -> PluginResult<()>;
    fn process_id(&self) -> Option<u32> {
        None
    }
}

/// What to launch.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    pub plugin_id: String,
    pub plugin_version: String,
    pub runtime_id: String,
    pub kind: RuntimeKind,
    pub package_root: PathBuf,
    /// Manifest entry path (`main.browser` / `main.node`).
    pub entry: String,
    /// Runtime config (`pluginId`, `pluginVersion`, `netcattyVersion`,
    /// `apiVersion`, `supportedFeatures`, `enabledFeatures`, `environment`).
    pub config: Value,
}

#[async_trait]
pub trait RuntimeLauncher: Send + Sync {
    /// Start the runtime and return once its transport is connected (the
    /// runtime peer is listening). Messages are delivered on `events`.
    async fn launch(
        &self,
        spec: LaunchSpec,
        events: mpsc::UnboundedSender<TransportEvent>,
        cancel: CancellationToken,
    ) -> PluginResult<Arc<dyn RuntimeTransport>>;
}

/// Error raised when no Node runtime is available for an advanced plugin.
pub const NODE_UNAVAILABLE_MESSAGE: &str =
    "Advanced (Node) plugins need a Node.js runtime: install Node 20+ on PATH or set NETCATTY_PLUGIN_NODE to the node executable";

/// Configuration of the Node sidecar.
#[derive(Debug, Clone)]
pub struct NodeRuntimeConfig {
    /// Explicit node executable (bundled sidecar or `NETCATTY_PLUGIN_NODE`).
    pub node: Option<PathBuf>,
    /// Directory holding `runtimePeer.mjs`, `pluginModuleLoader.mjs`, … (the
    /// Electron `electron/plugins/runtime` directory, shipped as a resource).
    pub runtime_dir: PathBuf,
    /// `runtime/nodeStdioRuntime.mjs` of this crate.
    pub bootstrap: PathBuf,
    /// Bare specifier → file URL (`@netcatty/plugin-sdk`, `@netcatty/plugin-contract`).
    pub module_mappings: HashMap<String, String>,
}

/// Locate a node executable: explicit config, `NETCATTY_PLUGIN_NODE`, `PATH`.
pub fn find_node(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit.filter(|p| p.is_file()) {
        return Some(path.to_path_buf());
    }
    if let Some(env) = std::env::var_os("NETCATTY_PLUGIN_NODE").map(PathBuf::from).filter(|p| p.is_file()) {
        return Some(env);
    }
    let exe = if cfg!(windows) { "node.exe" } else { "node" };
    std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths).map(|dir| dir.join(exe)).find(|p| p.is_file()))
}

pub fn file_url(path: &Path) -> String {
    url::Url::from_file_path(path).map(|u| u.to_string()).unwrap_or_default()
}

/// Resolve the entrypoint with realpath containment (`resolveUtilityEntrypoint`).
pub fn resolve_entrypoint(package_root: &Path, entry: &str) -> PluginResult<PathBuf> {
    let candidate = entry.split('/').fold(package_root.to_path_buf(), |p, s| p.join(s));
    let real_root = std::fs::canonicalize(package_root)?;
    let real = std::fs::canonicalize(&candidate)?;
    if !is_path_inside(&real_root, &real) {
        return Err(PluginError::host("Plugin entrypoint escapes its package"));
    }
    let meta = std::fs::symlink_metadata(&real)?;
    if !meta.is_file() {
        return Err(PluginError::host("Plugin entrypoint is not a regular file"));
    }
    Ok(real)
}

pub struct NodeSidecarLauncher {
    pub config: NodeRuntimeConfig,
}

struct NodeTransport {
    stdin: tokio::sync::mpsc::UnboundedSender<String>,
    child: Mutex<Option<tokio::process::Child>>,
    exited: CancellationToken,
    pid: Option<u32>,
}

#[async_trait]
impl RuntimeTransport for NodeTransport {
    fn send(&self, message: Value) -> PluginResult<()> {
        self.send_envelope(message, None, None)
    }
    fn send_with_ports(&self, message: Value, ports: Vec<String>) -> PluginResult<()> {
        self.send_envelope(message, Some(ports), None)
    }
    fn send_port(&self, port: &str, message: Value) -> PluginResult<()> {
        self.send_envelope(message, None, Some(port))
    }
    async fn terminate(&self) -> PluginResult<()> {
        let child = self.child.lock().take();
        let Some(mut child) = child else { return Ok(()) };
        #[cfg(unix)]
        if let Some(pid) = child.id() {
            // Graceful SIGTERM first (utilityProcess.kill()).
            let _ = std::process::Command::new("kill").arg("-TERM").arg(pid.to_string()).status();
        }
        if tokio::time::timeout(PLUGIN_UTILITY_TERMINATION_GRACE, child.wait()).await.is_ok() {
            return Ok(());
        }
        let _ = child.start_kill();
        match tokio::time::timeout(PLUGIN_UTILITY_FORCE_EXIT_TIMEOUT, child.wait()).await {
            Ok(_) => Ok(()),
            Err(_) => Err(PluginError::host("Plugin utility process did not exit after forced termination")),
        }
    }
    fn process_id(&self) -> Option<u32> {
        self.pid
    }
}

impl NodeTransport {
    fn send_envelope(&self, mut message: Value, ports: Option<Vec<String>>, port: Option<&str>) -> PluginResult<()> {
        if self.exited.is_cancelled() {
            return Err(PluginError::unavailable("Plugin runtime is closed"));
        }
        let mut envelope = json!({});
        if let Some(transfer) = message.as_object_mut().and_then(|m| m.remove("transferBase64")) {
            envelope["transferBase64"] = transfer;
        }
        envelope["data"] = message;
        if let Some(ports) = ports {
            envelope["ports"] = json!(ports);
        }
        if let Some(port) = port {
            envelope["port"] = json!(port);
        }
        self.stdin
            .send(serde_json::to_string(&envelope)?)
            .map_err(|_| PluginError::unavailable("Plugin runtime is closed"))
    }
}

#[async_trait]
impl RuntimeLauncher for NodeSidecarLauncher {
    async fn launch(
        &self,
        spec: LaunchSpec,
        events: mpsc::UnboundedSender<TransportEvent>,
        cancel: CancellationToken,
    ) -> PluginResult<Arc<dyn RuntimeTransport>> {
        let node = find_node(self.config.node.as_deref()).ok_or_else(|| PluginError::unavailable(NODE_UNAVAILABLE_MESSAGE))?;
        let entry = resolve_entrypoint(&spec.package_root, &spec.entry)?;
        let mut config = spec.config.clone();
        config["entryUrl"] = json!(file_url(&entry));
        config["moduleMappings"] = json!(self.config.module_mappings);
        let bootstrap = json!({
            "type": "netcatty-plugin:bootstrap",
            "config": config,
            "runtimePeerUrl": file_url(&self.config.runtime_dir.join("runtimePeer.mjs")),
            "loaderUrl": file_url(&self.config.runtime_dir.join("pluginModuleLoader.mjs")),
        });
        let mut command = tokio::process::Command::new(&node);
        command
            .arg(&self.config.bootstrap)
            .current_dir(&spec.package_root)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for key in ["LANG", "LC_ALL", "PATH", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let mut child = command.spawn().map_err(|e| PluginError::unavailable(format!("{NODE_UNAVAILABLE_MESSAGE} ({e})")))?;
        let pid = child.id();
        let mut stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let exited = CancellationToken::new();
        let (line_tx, mut line_rx) = mpsc::unbounded_channel::<String>();
        // Writer.
        let writer_exited = exited.clone();
        tokio::spawn(async move {
            while let Some(line) = line_rx.recv().await {
                if stdin.write_all(line.as_bytes()).await.is_err() || stdin.write_all(b"\n").await.is_err() {
                    break;
                }
                let _ = stdin.flush().await;
            }
            writer_exited.cancel();
        });
        // Stderr → diagnostics.
        let diag = events.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = diag.send(TransportEvent::Diagnostic { level: "warn", message: line.chars().take(8192).collect() });
            }
        });
        // Stdout → protocol.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
        let reader_events = events.clone();
        let reader_exited = exited.clone();
        tokio::spawn(async move {
            let mut ready_tx = Some(ready_tx);
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(envelope) = serde_json::from_str::<Value>(&line) else {
                    let _ = reader_events.send(TransportEvent::Diagnostic { level: "info", message: line.chars().take(8192).collect() });
                    continue;
                };
                let mut data = envelope.get("data").cloned().unwrap_or(Value::Null);
                if data.get("type").and_then(Value::as_str) == Some("netcatty-plugin:ready") {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }
                    continue;
                }
                if let Some(transfer) = envelope.get("transferBase64") {
                    if let Some(object) = data.as_object_mut() {
                        object.insert("transferBase64".into(), transfer.clone());
                    }
                }
                let event = match envelope.get("port").and_then(Value::as_str) {
                    Some(port) => TransportEvent::PortMessage { port: port.to_string(), message: data },
                    None => TransportEvent::Message(data),
                };
                if reader_events.send(event).is_err() {
                    break;
                }
            }
            reader_exited.cancel();
            let _ = reader_events.send(TransportEvent::Exited { reason: "Plugin utility process exited".into() });
        });
        let transport = Arc::new(NodeTransport { stdin: line_tx, child: Mutex::new(Some(child)), exited: exited.clone(), pid });
        transport.send_envelope(bootstrap, None, None)?;
        let outcome = tokio::select! {
            r = ready_rx => r.map_err(|_| PluginError::host("Plugin utility process exited during startup")),
            _ = tokio::time::sleep(PLUGIN_ACTIVATION_TIMEOUT) => Err(PluginError::host("Plugin utility process did not become ready")),
            _ = cancel.cancelled() => Err(PluginError::cancelled()),
        };
        if let Err(err) = outcome {
            let _ = transport.terminate().await;
            return Err(err);
        }
        Ok(transport)
    }
}

/// Default Node runtime layout for a repository / bundle root that contains
/// `electron/plugins/runtime` and `node_modules/@netcatty/*`.
pub fn default_node_runtime_config(app_root: &Path) -> NodeRuntimeConfig {
    let mut mappings = HashMap::new();
    for (specifier, dir) in [("@netcatty/plugin-sdk", "plugin-sdk"), ("@netcatty/plugin-contract", "plugin-contract")] {
        let path = app_root.join("node_modules").join("@netcatty").join(dir).join("dist").join("index.js");
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        mappings.insert(specifier.to_string(), file_url(&path));
    }
    NodeRuntimeConfig {
        node: None,
        runtime_dir: app_root.join("electron").join("plugins").join("runtime"),
        bootstrap: app_root.join("rust").join("crates").join("netcatty-plugins").join("runtime").join("nodeStdioRuntime.mjs"),
        module_mappings: mappings,
    }
}
