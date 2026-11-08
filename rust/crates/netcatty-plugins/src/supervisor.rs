//! Runtime supervisor (port of `runtimeSupervisor.cjs`): placement,
//! activation handshake, version-scoped crash quarantine, identity-checked
//! host → plugin requests, and ordered shutdown.

use crate::constants::{
    PLUGIN_ACTIVATION_TIMEOUT, PLUGIN_CRASH_QUARANTINE_THRESHOLD, PLUGIN_CRASH_WINDOW_MS, PLUGIN_DEACTIVATION_TIMEOUT,
};
use crate::database::{PluginDatabase, PluginRecord};
use crate::error::{PluginError, PluginResult};
use crate::logs::{LogIdentity, PluginLogService};
use crate::package::compat::{self, RuntimeKind};
use crate::permissions::{default_security_principal, AuthContext, AuthorizationRequest, PermissionEngine};
use crate::registry::{assert_host_method, HostRpcRegistry, RuntimeIdentity};
use crate::rpc::{OutgoingStream, RpcRouter};
use crate::runtime::{LaunchSpec, RuntimeLauncher, RuntimeTransport, TransportEvent};
use crate::store::PackageStore;
use futures::future::{BoxFuture, Shared};
use futures::FutureExt;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// `runtime-state` event (`onDidChangeRuntime`).
#[derive(Debug, Clone)]
pub struct RuntimeStateEvent {
    pub plugin_id: String,
    pub plugin_version: Option<String>,
    pub runtime_id: Option<String>,
    pub runtime_kind: Option<String>,
    pub status: String,
    pub error: Option<String>,
}

/// Sub-port message from a runtime (terminal interceptor channel).
pub type PortListener = Arc<dyn Fn(&str, &str, Value) + Send + Sync>;

struct RunningRuntime {
    identity: Arc<RuntimeIdentity>,
    router: Arc<RpcRouter>,
    transport: Arc<dyn RuntimeTransport>,
    stopping: CancellationToken,
}

type StartFuture = Shared<BoxFuture<'static, Result<Arc<RuntimeIdentity>, PluginError>>>;

pub struct SupervisorConfig {
    pub netcatty_version: String,
    pub api_version: String,
    pub supported_features: Vec<String>,
    pub allow_advanced_plugins: bool,
}

pub struct RuntimeSupervisor {
    pub database: Arc<PluginDatabase>,
    pub store: Arc<PackageStore>,
    pub registry: Arc<HostRpcRegistry>,
    pub permissions: Arc<PermissionEngine>,
    pub logs: Arc<PluginLogService>,
    pub config: SupervisorConfig,
    browser: Mutex<Option<Arc<dyn RuntimeLauncher>>>,
    utility: Mutex<Option<Arc<dyn RuntimeLauncher>>>,
    runtimes: Mutex<HashMap<String, Arc<RunningRuntime>>>,
    starting: Mutex<HashMap<String, (StartFuture, CancellationToken)>>,
    uncontained: Mutex<HashSet<String>>,
    listeners: Mutex<Vec<Arc<dyn Fn(&RuntimeStateEvent) + Send + Sync>>>,
    progress_listeners: Mutex<Vec<Arc<dyn Fn(&Arc<RuntimeIdentity>, Value) + Send + Sync>>>,
    port_listeners: Mutex<Vec<PortListener>>,
    /// Provides the activation environment snapshot (`getInitialEnvironment`).
    pub environment: Mutex<Option<Arc<dyn Fn() -> Option<Value> + Send + Sync>>>,
    /// Runtime cleanup hooks (byte streams, leases, interactions…).
    cleanup: Mutex<Vec<Arc<dyn Fn(&RuntimeIdentity) + Send + Sync>>>,
    shutting_down: Mutex<bool>,
    me: Mutex<std::sync::Weak<RuntimeSupervisor>>,
}

impl RuntimeSupervisor {
    pub fn new(
        database: Arc<PluginDatabase>,
        store: Arc<PackageStore>,
        registry: Arc<HostRpcRegistry>,
        permissions: Arc<PermissionEngine>,
        logs: Arc<PluginLogService>,
        config: SupervisorConfig,
    ) -> Arc<Self> {
        let supervisor = Arc::new(Self {
            database,
            store,
            registry,
            permissions,
            logs,
            config,
            browser: Mutex::new(None),
            utility: Mutex::new(None),
            runtimes: Mutex::new(HashMap::new()),
            starting: Mutex::new(HashMap::new()),
            uncontained: Mutex::new(HashSet::new()),
            listeners: Mutex::new(Vec::new()),
            progress_listeners: Mutex::new(Vec::new()),
            port_listeners: Mutex::new(Vec::new()),
            environment: Mutex::new(None),
            cleanup: Mutex::new(Vec::new()),
            shutting_down: Mutex::new(false),
            me: Mutex::new(std::sync::Weak::new()),
        });
        *supervisor.me.lock() = Arc::downgrade(&supervisor);
        supervisor
    }

    fn me(&self) -> Arc<Self> {
        self.me.lock().upgrade().expect("supervisor alive")
    }

    pub fn set_browser_launcher(&self, launcher: Arc<dyn RuntimeLauncher>) {
        *self.browser.lock() = Some(launcher);
    }

    pub fn set_utility_launcher(&self, launcher: Arc<dyn RuntimeLauncher>) {
        *self.utility.lock() = Some(launcher);
    }

    pub fn on_did_change_runtime(&self, listener: Arc<dyn Fn(&RuntimeStateEvent) + Send + Sync>) {
        self.listeners.lock().push(listener);
    }

    pub fn on_did_report_progress(&self, listener: Arc<dyn Fn(&Arc<RuntimeIdentity>, Value) + Send + Sync>) {
        self.progress_listeners.lock().push(listener);
    }

    pub fn on_port_message(&self, listener: PortListener) {
        self.port_listeners.lock().push(listener);
    }

    pub fn add_cleanup(&self, hook: Arc<dyn Fn(&RuntimeIdentity) + Send + Sync>) {
        self.cleanup.lock().push(hook);
    }

    fn emit_state(&self, event: RuntimeStateEvent) {
        let listeners = self.listeners.lock().clone();
        for listener in listeners {
            listener(&event);
        }
    }

    fn set_runtime_state(&self, identity: Option<&RuntimeIdentity>, plugin_id: &str, status: &str, error: Option<String>, quarantined_at: Option<i64>) {
        let version = identity.map(|i| i.plugin_version.clone());
        let installed = match &version {
            Some(v) => self.database.get_version(plugin_id, v).ok().flatten().is_some(),
            None => true,
        };
        if installed {
            let _ = self.database.set_runtime_state(
                plugin_id,
                status,
                version.as_deref(),
                identity.map(|i| i.runtime_kind.as_str()),
                error.as_deref(),
                quarantined_at,
            );
        }
        if let Some(identity) = identity {
            identity.logger.audit_call(&format!("runtime.{status}"), "not-required", !matches!(status, "error" | "quarantined"), None, &[], 0);
        }
        self.emit_state(RuntimeStateEvent {
            plugin_id: plugin_id.to_string(),
            plugin_version: version,
            runtime_id: identity.map(|i| i.runtime_id.clone()),
            runtime_kind: identity.map(|i| i.runtime_kind.clone()),
            status: status.to_string(),
            error,
        });
    }

    /// Start every enabled, non-quarantined, executable plugin.
    pub async fn start_enabled(&self) {
        for plugin in self.database.list_plugins().unwrap_or_default() {
            let data = plugin.manifest.as_ref().and_then(|m| m["main"].get("data")).is_some();
            if !plugin.enabled || plugin.runtime.quarantined_at.is_some() || data {
                continue;
            }
            let _ = self.start(&plugin.id).await;
        }
    }

    pub fn get_runtime_identity(&self, plugin_id: &str) -> Option<Arc<RuntimeIdentity>> {
        self.runtimes.lock().get(plugin_id).map(|r| r.identity.clone())
    }

    pub fn running_plugin_ids(&self) -> Vec<String> {
        self.runtimes.lock().keys().cloned().collect()
    }

    /// `start(pluginId)`: idempotent; concurrent callers share one start.
    pub async fn start(&self, plugin_id: &str) -> PluginResult<Arc<RuntimeIdentity>> {
        if *self.shutting_down.lock() {
            return Err(PluginError::host("Plugin runtime supervisor is shutting down"));
        }
        if self.uncontained.lock().contains(plugin_id) {
            return Err(PluginError::unavailable(format!(
                "Plugin runtime containment failed; restart Netcatty before starting it again: {plugin_id}"
            )));
        }
        let existing = self.runtimes.lock().get(plugin_id).cloned();
        if let Some(running) = existing {
            return self.assert_running(plugin_id, &running).map(|_| running.identity.clone());
        }
        let future = {
            let mut starting = self.starting.lock();
            if let Some((future, _)) = starting.get(plugin_id) {
                future.clone()
            } else {
                let cancel = CancellationToken::new();
                let me = self.me();
                let id = plugin_id.to_string();
                let token = cancel.clone();
                let future: StartFuture = async move {
                    let result = me.start_inner(&id, token).await;
                    me.starting.lock().remove(&id);
                    result
                }
                .boxed()
                .shared();
                starting.insert(plugin_id.to_string(), (future.clone(), cancel));
                future
            }
        };
        future.await
    }

    fn resolve_kind(&self, plugin: &PluginRecord) -> PluginResult<RuntimeKind> {
        let manifest = plugin.manifest.as_ref().ok_or_else(|| PluginError::host("Plugin is not installed"))?;
        if !self.config.allow_advanced_plugins {
            compat::assert_browser_only(manifest)?;
        }
        let kind = compat::describe_runtime(manifest).default_kind;
        let available_browser = manifest["main"].get("browser").is_some();
        let available_node = manifest["main"].get("node").is_some();
        let ok = match kind {
            RuntimeKind::Browser => available_browser,
            RuntimeKind::Utility => available_node,
            RuntimeKind::Data => false,
        };
        if !ok {
            return Err(PluginError::host(format!("Plugin runtime selection is unavailable: {}", kind.as_str())));
        }
        if !self.config.allow_advanced_plugins && kind != RuntimeKind::Browser {
            return Err(PluginError::host("Advanced plugin runtime requires developer mode"));
        }
        Ok(kind)
    }

    async fn start_inner(self: &Arc<Self>, plugin_id: &str, cancel: CancellationToken) -> PluginResult<Arc<RuntimeIdentity>> {
        let plugin = self
            .database
            .get_active_plugin(plugin_id)?
            .filter(|p| p.manifest.is_some() && p.package_relative_path.is_some())
            .ok_or_else(|| PluginError::host(format!("Plugin is not installed: {plugin_id}")))?;
        let source_owner = self.database.private_owner(plugin_id).ok();
        let manifest = plugin.manifest.clone().expect("checked");
        if !plugin.enabled {
            return Err(PluginError::host(format!("Plugin is disabled: {plugin_id}")));
        }
        if manifest["main"].get("data").is_some() {
            return Err(PluginError::host("Static theme packs have no executable runtime"));
        }
        if plugin.runtime.quarantined_at.is_some() {
            return Err(PluginError::host(format!("Plugin is quarantined: {plugin_id}")));
        }
        let compatibility = self.store.compatibility(&manifest);
        if !compatibility.compatible {
            return Err(PluginError::host(format!("Plugin is incompatible: {}", compatibility.errors.join("; "))));
        }
        let store = self.store.clone();
        let record = plugin.clone();
        let package_root = tokio::task::spawn_blocking(move || store.prepare_package_root(&record))
            .await
            .map_err(|e| PluginError::host(e.to_string()))??;
        if cancel.is_cancelled() {
            return Err(PluginError::cancelled());
        }
        let security_principal = default_security_principal(&manifest, plugin.archive_sha256.as_deref())?;
        let kind = self.resolve_kind(&plugin)?;
        let version = plugin.active_version.clone().unwrap_or_default();
        // Runtime-level authorization (required permissions; runtime.advanced
        // for the utility runtime).
        crate::permissions::normalize_declarations(&manifest)?;
        if kind == RuntimeKind::Utility {
            let context = AuthContext {
                plugin_id: plugin_id.to_string(),
                plugin_version: Some(version.clone()),
                runtime_id: None,
                runtime_kind: Some("utility".into()),
                manifest: Arc::new(manifest.clone()),
                security_principal: Some(security_principal.clone()),
                source_owner: source_owner.clone(),
                signal: Some(cancel.clone()),
                operation_key: None,
            };
            self.permissions
                .authorize(
                    &context,
                    &AuthorizationRequest {
                        permission: "runtime.advanced".into(),
                        resources: vec!["*".into()],
                        reason: Some("Start an advanced runtime with full Node, filesystem, and network authority".into()),
                        operation_id: Some(format!("runtime.advanced:{version}")),
                        ..Default::default()
                    },
                )
                .await?;
        }
        let current = self.database.get_active_plugin(plugin_id)?;
        if !current.as_ref().is_some_and(|c| {
            c.enabled
                && c.active_version == plugin.active_version
                && c.runtime.quarantined_at.is_none()
                && c.source.id == plugin.source.id
                && self.database.private_owner(plugin_id).ok() == source_owner
        }) {
            return Err(PluginError::unavailable("Plugin changed while runtime placement was resolved"));
        }
        let runtime_id = uuid::Uuid::new_v4().to_string();
        let log_identity = LogIdentity {
            plugin_id: plugin_id.to_string(),
            plugin_version: Some(version.clone()),
            runtime_id: Some(runtime_id.clone()),
            runtime_kind: Some(kind.as_str().into()),
        };
        let logger = Arc::new(self.logs.create_logger(log_identity.clone()));
        let weak = Arc::downgrade(self);
        let pid = plugin_id.to_string();
        let rid = runtime_id.clone();
        let expected_version = version.clone();
        let expected_source = plugin.source.id.clone();
        let expected_owner = source_owner.clone();
        let assert_current: Arc<dyn Fn() -> PluginResult<()> + Send + Sync> = Arc::new(move || {
            let stale = || PluginError::unavailable("Plugin runtime identity is stale or inactive");
            let supervisor = weak.upgrade().ok_or_else(stale)?;
            let owns = supervisor.runtimes.lock().get(&pid).is_some_and(|r| r.identity.runtime_id == rid)
                || supervisor.starting.lock().contains_key(&pid);
            let active = supervisor.database.get_active_plugin(&pid).ok().flatten().ok_or_else(stale)?;
            if !owns
                || !active.enabled
                || active.active_version.as_deref() != Some(expected_version.as_str())
                || active.source.id != expected_source
                || supervisor.database.private_owner(&pid).ok() != expected_owner
                || !matches!(active.runtime.status.as_str(), "starting" | "running")
            {
                return Err(stale());
            }
            Ok(())
        });
        let identity = Arc::new(RuntimeIdentity {
            plugin_id: plugin_id.to_string(),
            plugin_version: version.clone(),
            runtime_id: runtime_id.clone(),
            runtime_kind: kind.as_str().into(),
            security_principal,
            source_owner: source_owner.clone(),
            source_id: Some(plugin.source.id.clone()),
            manifest: Arc::new(manifest.clone()),
            package_root: package_root.clone(),
            enabled_features: compatibility.enabled_features.clone(),
            logger,
            log_identity,
            assert_current,
        });
        let launcher = match kind {
            RuntimeKind::Browser => self.browser.lock().clone(),
            _ => self.utility.lock().clone(),
        }
        .ok_or_else(|| PluginError::unavailable(format!("No {} plugin runtime is available in this host", kind.as_str())))?;
        let environment = self.environment.lock().clone().and_then(|f| f());
        let config = json!({
            "pluginId": plugin_id,
            "pluginVersion": version,
            "netcattyVersion": self.config.netcatty_version,
            "apiVersion": compatibility.api_version,
            "supportedFeatures": self.config.supported_features,
            "enabledFeatures": compatibility.enabled_features,
            "environment": environment,
        });
        let entry = match kind {
            RuntimeKind::Browser => manifest["main"]["browser"].as_str(),
            _ => manifest["main"]["node"].as_str(),
        }
        .unwrap_or("")
        .to_string();
        self.set_runtime_state(Some(&identity), plugin_id, "starting", None, None);
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let launched = launcher
            .launch(
                LaunchSpec {
                    plugin_id: plugin_id.to_string(),
                    plugin_version: version.clone(),
                    runtime_id: runtime_id.clone(),
                    kind,
                    package_root,
                    entry,
                    config: config.clone(),
                },
                events_tx,
                cancel.clone(),
            )
            .await;
        let transport = match launched {
            Ok(t) => t,
            Err(err) => {
                self.record_failure(&identity, err.message());
                return Err(err);
            }
        };
        let routes = self.registry.create_routes(identity.clone());
        let mut routes = routes;
        let progress_identity = identity.clone();
        let progress = self.progress_listeners.lock().clone();
        routes.on_progress = Some(Arc::new(move |params: Value| {
            if (progress_identity.assert_current)().is_ok() {
                for l in &progress {
                    l(&progress_identity, params.clone());
                }
            }
        }));
        let send_transport = transport.clone();
        let protocol_identity = identity.clone();
        let router = RpcRouter::new(
            plugin_id,
            Arc::new(move |message| send_transport.send(message)),
            routes,
            Some(Box::new(move |error: PluginError| {
                protocol_identity.logger.write("error", "Plugin protocol violation", Some(&json!({ "error": error.message() })));
            })),
        );
        let running = Arc::new(RunningRuntime {
            identity: identity.clone(),
            router: router.clone(),
            transport: transport.clone(),
            stopping: CancellationToken::new(),
        });
        self.runtimes.lock().insert(plugin_id.to_string(), running.clone());
        self.spawn_pump(running.clone(), events_rx);
        let handshake = async {
            let initialized = router
                .request(
                    "plugin.initialize",
                    Some(json!({
                        "netcattyVersion": self.config.netcatty_version,
                        "apiVersion": compatibility.api_version,
                        "supportedFeatures": self.config.supported_features,
                    })),
                    Some(PLUGIN_ACTIVATION_TIMEOUT),
                    Some(cancel.clone()),
                )
                .await?;
            let environment = self.environment.lock().clone().and_then(|f| f());
            router
                .request(
                    "plugin.activate",
                    Some(match environment {
                        Some(env) => json!({ "environment": env }),
                        None => json!({}),
                    }),
                    Some(PLUGIN_ACTIVATION_TIMEOUT),
                    Some(cancel.clone()),
                )
                .await?;
            let mut negotiated: Vec<String> = initialized["enabledFeatures"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
            negotiated.sort();
            let mut expected = compatibility.enabled_features.clone();
            expected.sort();
            if initialized["pluginId"] != json!(plugin_id)
                || initialized["pluginVersion"] != json!(version)
                || initialized["apiVersion"] != json!(compatibility.api_version)
                || negotiated != expected
            {
                return Err(PluginError::host("Plugin initialization identity or feature negotiation mismatch"));
            }
            (identity.assert_current)()?;
            Ok::<(), PluginError>(())
        };
        match handshake.await {
            Ok(()) => {
                self.set_runtime_state(Some(&identity), plugin_id, "running", None, None);
                Ok(identity)
            }
            Err(error) => {
                let owned = self.runtimes.lock().get(plugin_id).is_some_and(|r| Arc::ptr_eq(r, &running));
                if owned {
                    self.runtimes.lock().remove(plugin_id);
                    running.stopping.cancel();
                    router.close(error.clone());
                    let terminated = transport.terminate().await;
                    self.run_cleanup(&identity);
                    if let Err(containment) = terminated {
                        self.record_containment_failure(&identity, containment.message());
                        return Err(containment);
                    }
                    self.record_failure(&identity, error.message());
                }
                Err(error)
            }
        }
    }

    fn spawn_pump(self: &Arc<Self>, running: Arc<RunningRuntime>, mut events: mpsc::UnboundedReceiver<TransportEvent>) {
        let me = self.clone();
        tokio::spawn(async move {
            let closed = running.router.closed_token();
            loop {
                let event = tokio::select! {
                    e = events.recv() => e,
                    _ = closed.cancelled() => None,
                };
                match event {
                    Some(TransportEvent::Message(message)) => running.router.accept(message),
                    Some(TransportEvent::PortMessage { port, message }) => {
                        let listeners = me.port_listeners.lock().clone();
                        for l in listeners {
                            l(&running.identity.runtime_id, &port, message.clone());
                        }
                    }
                    Some(TransportEvent::Diagnostic { level, message }) => {
                        running.identity.logger.write(level, "runtime output", Some(&json!({ "output": message })));
                    }
                    Some(TransportEvent::Exited { reason }) => {
                        running.router.close(PluginError::unavailable(reason.clone()));
                        me.handle_exit(&running, &reason).await;
                        break;
                    }
                    None => {
                        // Router closed (protocol violation) or channel gone.
                        if !running.stopping.is_cancelled() {
                            me.handle_exit(&running, "Plugin runtime closed after a protocol violation").await;
                        }
                        break;
                    }
                }
            }
        });
    }

    async fn handle_exit(&self, running: &Arc<RunningRuntime>, reason: &str) {
        let owned = {
            let mut runtimes = self.runtimes.lock();
            let owned = runtimes.get(&running.identity.plugin_id).is_some_and(|r| Arc::ptr_eq(r, running));
            if owned {
                runtimes.remove(&running.identity.plugin_id);
            }
            owned
        };
        if !owned || running.stopping.is_cancelled() {
            return;
        }
        running.stopping.cancel();
        let terminated = running.transport.terminate().await;
        self.run_cleanup(&running.identity);
        if let Err(err) = terminated {
            self.record_containment_failure(&running.identity, err.message());
            return;
        }
        if *self.shutting_down.lock() {
            self.set_runtime_state(Some(&running.identity), &running.identity.plugin_id, "stopped", None, None);
            return;
        }
        self.record_failure(&running.identity, reason);
    }

    fn run_cleanup(&self, identity: &RuntimeIdentity) {
        let hooks = self.cleanup.lock().clone();
        for hook in hooks {
            hook(identity);
        }
    }

    fn record_failure(&self, identity: &RuntimeIdentity, error: &str) {
        let plugin_id = &identity.plugin_id;
        if self.database.get_version(plugin_id, &identity.plugin_version).ok().flatten().is_none() {
            self.emit_state(RuntimeStateEvent {
                plugin_id: plugin_id.clone(),
                plugin_version: Some(identity.plugin_version.clone()),
                runtime_id: Some(identity.runtime_id.clone()),
                runtime_kind: Some(identity.runtime_kind.clone()),
                status: "error".into(),
                error: Some(error.into()),
            });
            return;
        }
        match self.database.record_crash(plugin_id, &identity.plugin_version, PLUGIN_CRASH_WINDOW_MS, PLUGIN_CRASH_QUARANTINE_THRESHOLD) {
            Ok(crash) => self.set_runtime_state(
                Some(identity),
                plugin_id,
                if crash.quarantined { "quarantined" } else { "error" },
                Some(error.into()),
                crash.quarantined_at,
            ),
            Err(_) => self.set_runtime_state(Some(identity), plugin_id, "error", Some(error.into()), None),
        }
    }

    fn record_containment_failure(&self, identity: &RuntimeIdentity, error: &str) {
        self.uncontained.lock().insert(identity.plugin_id.clone());
        if let Ok(Some(active)) = self.database.get_active_plugin(&identity.plugin_id) {
            if active.active_version.as_deref() == Some(identity.plugin_version.as_str()) && active.enabled {
                let _ = self.database.set_enabled(&identity.plugin_id, false);
            }
        }
        self.set_runtime_state(Some(identity), &identity.plugin_id, "quarantined", Some(error.into()), Some(crate::constants::now_ms()));
    }

    /// `stop(pluginId)`: deactivate (2 s), close, terminate, cleanup.
    pub async fn stop(&self, plugin_id: &str) -> PluginResult<()> {
        let starting = self.starting.lock().get(plugin_id).cloned();
        if let Some((future, cancel)) = starting {
            cancel.cancel();
            let _ = future.await;
        }
        let running = self.runtimes.lock().remove(plugin_id);
        let Some(running) = running else {
            if let Ok(Some(plugin)) = self.database.get_active_plugin(plugin_id) {
                if plugin.runtime.quarantined_at.is_none() && plugin.runtime.status != "stopped" {
                    let _ = self.database.set_runtime_state(plugin_id, "stopped", None, plugin.runtime.kind.as_deref(), None, None);
                    self.emit_state(RuntimeStateEvent {
                        plugin_id: plugin_id.into(),
                        plugin_version: plugin.active_version.clone(),
                        runtime_id: None,
                        runtime_kind: plugin.runtime.kind.clone(),
                        status: "stopped".into(),
                        error: None,
                    });
                }
            }
            return Ok(());
        };
        running.stopping.cancel();
        let deactivate = running.router.request("plugin.deactivate", Some(json!({})), Some(PLUGIN_DEACTIVATION_TIMEOUT), None).await;
        running.router.close(PluginError::unavailable("Plugin runtime closed"));
        let terminated = running.transport.terminate().await;
        self.run_cleanup(&running.identity);
        match terminated {
            Err(err) => {
                self.record_containment_failure(&running.identity, err.message());
                Err(err)
            }
            Ok(()) => {
                self.set_runtime_state(Some(&running.identity), plugin_id, "stopped", deactivate.err().map(|e| e.message().to_string()), None);
                Ok(())
            }
        }
    }

    pub async fn restart(&self, plugin_id: &str) -> PluginResult<Arc<RuntimeIdentity>> {
        self.stop(plugin_id).await?;
        self.database.clear_quarantine(plugin_id, None)?;
        self.start(plugin_id).await
    }

    /// Disable and stop after a quota / policy violation.
    pub async fn enforce_policy_violation(&self, runtime_id: &str, error: &str) {
        let target = self.runtimes.lock().values().find(|r| r.identity.runtime_id == runtime_id).map(|r| r.identity.clone());
        let Some(identity) = target else { return };
        let _ = self.database.set_enabled(&identity.plugin_id, false);
        let _ = self.stop(&identity.plugin_id).await;
        self.set_runtime_state(Some(&identity), &identity.plugin_id, "error", Some(error.into()), None);
    }

    fn assert_running(&self, plugin_id: &str, running: &RunningRuntime) -> PluginResult<()> {
        let active = self.database.get_active_plugin(plugin_id)?;
        if !active.is_some_and(|a| {
            a.enabled && a.active_version.as_deref() == Some(running.identity.plugin_version.as_str()) && a.runtime.status == "running"
        }) {
            return Err(PluginError::unavailable(format!("Plugin runtime identity is stale or inactive: {plugin_id}")));
        }
        Ok(())
    }

    async fn running(&self, plugin_id: &str, expected: Option<&RuntimeIdentity>) -> PluginResult<Arc<RunningRuntime>> {
        let starting = self.starting.lock().get(plugin_id).map(|(f, _)| f.clone());
        if let Some(future) = starting {
            let _ = future.await;
        }
        let running = self
            .runtimes
            .lock()
            .get(plugin_id)
            .cloned()
            .ok_or_else(|| PluginError::unavailable(format!("Plugin runtime is unavailable: {plugin_id}")))?;
        self.assert_running(plugin_id, &running)?;
        if let Some(expected) = expected {
            if expected.runtime_id != running.identity.runtime_id || expected.plugin_version != running.identity.plugin_version {
                return Err(PluginError::unavailable(format!("Plugin runtime no longer matches the authorized activation: {plugin_id}")));
            }
        }
        Ok(running)
    }

    /// Identity-checked host → plugin request.
    pub async fn request(
        &self,
        plugin_id: &str,
        method: &str,
        params: Value,
        expected: Option<&RuntimeIdentity>,
        timeout: Option<Duration>,
        signal: Option<CancellationToken>,
    ) -> PluginResult<Value> {
        assert_host_method(method)?;
        let running = self.running(plugin_id, expected).await?;
        let result = running.router.request(method, Some(params), timeout, signal).await?;
        let current = self.running(plugin_id, None).await?;
        if current.identity.runtime_id != running.identity.runtime_id {
            return Err(PluginError::unavailable(format!("Plugin runtime changed while handling request: {plugin_id}")));
        }
        Ok(result)
    }

    pub async fn notify(&self, plugin_id: &str, method: &str, params: Value, expected: Option<&RuntimeIdentity>) -> PluginResult<()> {
        assert_host_method(method)?;
        let running = self.running(plugin_id, expected).await?;
        running.router.notify(method, Some(params))
    }

    pub async fn open_stream(
        &self,
        plugin_id: &str,
        stream_id: &str,
        window: u64,
        expected: Option<&RuntimeIdentity>,
        on_close: Option<Box<dyn FnOnce(Value) + Send>>,
    ) -> PluginResult<OutgoingStream> {
        let running = self.running(plugin_id, expected).await?;
        running.router.open_outgoing(stream_id, window, on_close)
    }

    /// Router of a running plugin (provider services that consume streams).
    pub async fn router(&self, plugin_id: &str) -> PluginResult<Arc<RpcRouter>> {
        Ok(self.running(plugin_id, None).await?.router.clone())
    }

    /// Transport of a running plugin (virtual sub-ports).
    pub async fn transport(&self, plugin_id: &str) -> PluginResult<(Arc<RuntimeIdentity>, Arc<dyn RuntimeTransport>)> {
        let running = self.running(plugin_id, None).await?;
        Ok((running.identity.clone(), running.transport.clone()))
    }

    pub async fn shutdown(&self) {
        *self.shutting_down.lock() = true;
        for (_, cancel) in self.starting.lock().values() {
            cancel.cancel();
        }
        let ids: Vec<String> = self.runtimes.lock().keys().cloned().collect();
        futures::future::join_all(ids.iter().map(|id| self.stop(id))).await;
    }
}
