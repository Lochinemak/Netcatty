//! Plugin host assembly (port of `electron/plugins/hostService.cjs`).
//!
//! [`PluginHost::new`] wires the database, package store, permission
//! engine, quotas, RPC registry, supervisor, contribution service and
//! lifecycle manager, plus every capability service. Renderer-facing events
//! go through [`HostEvents`] (the desktop app emits them as Tauri events
//! with the Electron channel names).

use crate::capabilities::{CredentialCatalog, FilesystemBroker, NetworkBroker, SecretLeaseStore, SecureCapabilities};
use crate::constants::PLUGIN_API_VERSION;
use crate::contributions::ContributionService;
use crate::database::PluginDatabase;
use crate::error::PluginResult;
use crate::interactions::InteractionService;
use crate::logs::PluginLogService;
use crate::manager::PluginManager;
use crate::permissions::PermissionEngine;
use crate::quota::{QuotaManager, Quotas};
use crate::registry::{register_default_capabilities, HostRpcRegistry};
use crate::runtime::{NodeRuntimeConfig, NodeSidecarLauncher, RuntimeLauncher};
use crate::secrets::{PluginSecretStore, SecretCipher};
use crate::source::PluginPaths;
use crate::store::PackageStore;
use crate::supervisor::{RuntimeSupervisor, SupervisorConfig};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

/// Renderer event sink.
pub trait HostEvents: Send + Sync {
    fn emit(&self, channel: &str, payload: Value);
}

/// No-op sink (tests, headless).
pub struct NullEvents;
impl HostEvents for NullEvents {
    fn emit(&self, _channel: &str, _payload: Value) {}
}

pub mod channels {
    pub const CONTRIBUTIONS_CHANGED: &str = "netcatty:plugins:contributions-changed";
    pub const THEMES_CHANGED: &str = "netcatty:plugins:themes-changed";
    pub const CATALOG_CHANGED: &str = "netcatty:plugins:catalog-changed";
    pub const PERMISSION_PROMPT: &str = "netcatty:plugins:permission-prompt";
    pub const INTERACTION: &str = "netcatty:plugins:host-interaction";
    pub const VIEW_UPDATE: &str = "netcatty:plugins:host-ui-update";
    pub const VIEW_CLOSED: &str = "netcatty:plugins:view-closed";
    pub const SCOPE_CATALOG_CHANGED: &str = "netcatty:plugins:scope-catalog-changed";
    pub const CONNECTION_DATA: &str = "netcatty:plugins:connection-data";
    pub const CONNECTION_CLOSED: &str = "netcatty:plugins:connection-closed";
    pub const IMPORTER_PROGRESS: &str = "netcatty:plugins:importer-progress";
    pub const AUTHENTICATION_CHALLENGE: &str = "netcatty:plugins:authentication-challenge";
    pub const AI_HOST_REQUEST: &str = "netcatty:plugins:ai-host-request";
    pub const AGENT_HOST_REQUEST: &str = "netcatty:plugins:agent-host-request";
    pub const RUNTIME_STATE: &str = "netcatty:plugins:runtime-state";
}

pub struct HostConfig {
    /// Application user-data directory (`<data>/netcatty`).
    pub user_data: PathBuf,
    pub netcatty_version: String,
    /// `NETCATTY_PLUGIN_DEV=1`: admit advanced (Node utility) plugins.
    pub allow_advanced_plugins: bool,
    /// Node sidecar layout; `None` disables the utility runtime.
    pub node: Option<NodeRuntimeConfig>,
    pub cipher: Arc<dyn SecretCipher>,
    pub events: Arc<dyn HostEvents>,
}

pub struct PluginHost {
    pub paths: PluginPaths,
    pub database: Arc<PluginDatabase>,
    pub store: Arc<PackageStore>,
    pub secrets: Arc<PluginSecretStore>,
    pub logs: Arc<PluginLogService>,
    pub quota: Arc<QuotaManager>,
    pub permissions: Arc<PermissionEngine>,
    pub registry: Arc<HostRpcRegistry>,
    pub supervisor: Arc<RuntimeSupervisor>,
    pub contributions: Arc<ContributionService>,
    pub manager: Arc<PluginManager>,
    pub capabilities: SecureCapabilities,
    pub interactions: Arc<InteractionService>,
    pub themes: Arc<crate::ui::ThemeService>,
    pub icons: Arc<crate::ui::IconService>,
    pub views: Arc<crate::ui::ViewHost>,
    pub terminal_providers: Arc<crate::providers::TerminalProviderService>,
    pub extensions: Arc<crate::providers::ExtensionProviderService>,
    pub sidecars: Arc<crate::sidecars::SidecarService>,
    pub events: Arc<dyn HostEvents>,
    pub supported_features: Vec<String>,
    pub allow_advanced_plugins: bool,
}

/// Features this host implements (advertised in `plugin.initialize`).
pub fn supported_features() -> Vec<String> {
    [
        "appearance.theme-packs",
        "metadata.brand-icon",
        "views.host-drawn",
        "views.vault-pages",
        "views.terminal-sidebar",
        "commands.interactive",
        "host.interactions",
        "terminal.input-drafts",
        "terminal.selection-sharing",
        "network.byte-streams",
        "network.credential-lease",
        "ai.model-invocation",
        "context.selected-read",
        "ai.agent-sessions",
        "vault.host-actions",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl PluginHost {
    pub fn new(config: HostConfig) -> PluginResult<Arc<Self>> {
        let paths = PluginPaths::new(&config.user_data);
        crate::package::archive::create_private_dir_all(&paths.root)?;
        let database = Arc::new(PluginDatabase::open(&paths.database)?);
        let logs = Arc::new(PluginLogService::new(&paths, Some(database.clone())));
        let features = supported_features();
        let store = Arc::new(PackageStore::new(
            paths.clone(),
            database.clone(),
            config.netcatty_version.clone(),
            PLUGIN_API_VERSION.into(),
            features.clone(),
            config.allow_advanced_plugins,
        ));
        let permissions = Arc::new(PermissionEngine::new(database.clone()));
        let quota = Arc::new(QuotaManager::new(Quotas::default()));
        let registry = Arc::new(HostRpcRegistry::new(quota.clone(), permissions.clone()));
        register_default_capabilities(&registry, database.clone())?;
        let secrets = Arc::new(PluginSecretStore::new(database.clone(), config.cipher.clone()));
        let catalog = Arc::new(CredentialCatalog::new(config.cipher.clone()));
        let capabilities = SecureCapabilities {
            secrets: secrets.clone(),
            leases: Arc::new(SecretLeaseStore::new(secrets.clone(), catalog.clone())),
            catalog,
            network: Arc::new(NetworkBroker::new(quota.clone())?),
            filesystem: Arc::new(FilesystemBroker::new(
                quota.clone(),
                vec![paths.logs.clone(), paths.root.join("agent-chats")],
                vec![paths.root.join("agent-chats")],
                vec![paths.root.join("local-logging.json"), paths.root.join("local-logging.json.tmp")],
            )),
        };
        crate::capabilities::register(&registry, &capabilities)?;
        let interactions = InteractionService::new(database.clone(), permissions.clone(), quota.clone());
        interactions.register(&registry)?;
        let supervisor = RuntimeSupervisor::new(
            database.clone(),
            store.clone(),
            registry.clone(),
            permissions.clone(),
            logs.clone(),
            SupervisorConfig {
                netcatty_version: config.netcatty_version.clone(),
                api_version: PLUGIN_API_VERSION.into(),
                supported_features: features.clone(),
                allow_advanced_plugins: config.allow_advanced_plugins,
            },
        );
        if let Some(node) = config.node.clone() {
            let launcher: Arc<dyn RuntimeLauncher> = Arc::new(NodeSidecarLauncher { config: node });
            supervisor.set_utility_launcher(launcher);
        }
        let contributions = ContributionService::new(database.clone(), secrets.clone(), supervisor.clone());
        contributions.register_rpc_capabilities(&registry)?;
        let manager = PluginManager::new(
            database.clone(),
            store.clone(),
            supervisor.clone(),
            contributions.clone(),
            permissions.clone(),
            secrets.clone(),
        );
        let themes = crate::ui::ThemeService::new(database.clone(), store.clone(), &contributions, config.events.clone());
        let icons = Arc::new(crate::ui::IconService::new(database.clone(), store.clone()));
        let views = crate::ui::ViewHost::new(contributions.clone(), icons.clone(), config.events.clone());
        let terminal_providers = Arc::new(crate::providers::TerminalProviderService::new(contributions.clone(), supervisor.clone(), permissions.clone()));
        let extensions = crate::providers::ExtensionProviderService::new(contributions.clone(), supervisor.clone(), permissions.clone(), capabilities.leases.clone(), &registry);
        let sidecars = Arc::new(crate::sidecars::SidecarService::new(database.clone(), contributions.clone()));
        // Wiring.
        let quota_for_cleanup = quota.clone();
        let leases = capabilities.leases.clone();
        let interactions_cleanup = interactions.clone();
        supervisor.add_cleanup(Arc::new(move |identity| {
            quota_for_cleanup.release_runtime(&identity.runtime_id);
            leases.revoke_runtime(&identity.runtime_id);
            interactions_cleanup.release_runtime(&identity.runtime_id);
        }));
        let interactions_commands = interactions.clone();
        *contributions.on_command_finished.lock() = Some(Arc::new(move |runtime_id: &str| {
            interactions_commands.cancel_runtime_requests(runtime_id, "Host command finished")
        }));
        let c = contributions.clone();
        let events = config.events.clone();
        supervisor.on_did_change_runtime(Arc::new(move |event| {
            c.on_runtime_state_changed(&event.plugin_id, &event.status);
            events.emit(
                channels::RUNTIME_STATE,
                json!({ "pluginId": event.plugin_id, "pluginVersion": event.plugin_version, "status": event.status, "error": event.error }),
            );
        }));
        let c = contributions.clone();
        *supervisor.environment.lock() = Some(Arc::new(move || c.get_environment()));
        let events = config.events.clone();
        contributions.on_did_change(Arc::new(move |event| events.emit(channels::CONTRIBUTIONS_CHANGED, event.clone())));
        // Revoking runtime.advanced stops the privileged activation.
        let weak_manager = Arc::downgrade(&manager);
        *permissions.on_policy_changed.lock() = Some(Arc::new(move |plugin_id: &str, permission: &str, mode: &str| {
            if permission == "runtime.advanced" && mode != "allow" {
                if let Some(manager) = weak_manager.upgrade() {
                    let id = plugin_id.to_string();
                    tokio::spawn(async move {
                        let _ = manager.set_enabled(&id, false, None).await;
                    });
                }
            }
        }));
        Ok(Arc::new(Self {
            paths,
            database,
            store,
            secrets,
            logs,
            quota,
            permissions,
            registry,
            supervisor,
            contributions,
            manager,
            capabilities,
            interactions,
            themes,
            icons,
            views,
            terminal_providers,
            extensions,
            sidecars,
            events: config.events,
            supported_features: features,
            allow_advanced_plugins: config.allow_advanced_plugins,
        }))
    }

    /// `getPluginRuntimeStatus` shape.
    pub fn runtime_status(&self) -> Value {
        json!({
            "available": self.manager.is_initialized(),
            "developmentMode": self.allow_advanced_plugins,
            "apiVersion": PLUGIN_API_VERSION,
        })
    }

    pub async fn shutdown(&self) {
        self.views.shutdown().await;
        self.extensions.shutdown();
        self.manager.shutdown().await;
        self.interactions.shutdown();
        self.permissions.shutdown();
        self.capabilities.leases.shutdown();
        self.capabilities.catalog.clear();
        self.quota.shutdown();
        self.logs.close();
    }
}
