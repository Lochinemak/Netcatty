//! Lifecycle manager (port of `electron/plugins/pluginManager.cjs`): one
//! serialized mutation queue for install / enable / disable / restart /
//! uninstall / source changes, so no request can race an active-version
//! switch or start two runtimes for one plugin.

use crate::contributions::ContributionService;
use crate::database::{PluginDatabase, PluginRecord};
use crate::error::{PluginError, PluginResult};
use crate::permissions::PermissionEngine;
use crate::secrets::PluginSecretStore;
use crate::source::Source;
use crate::store::{BeforeActivate, CatalogExpectation, InstallOptions, PackageStore};
use crate::supervisor::RuntimeSupervisor;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};

pub struct PluginManager {
    pub database: Arc<PluginDatabase>,
    pub store: Arc<PackageStore>,
    pub supervisor: Arc<RuntimeSupervisor>,
    pub contributions: Arc<ContributionService>,
    pub permissions: Arc<PermissionEngine>,
    pub secrets: Arc<PluginSecretStore>,
    queue: Mutex<()>,
    initialized: OnceCell<Result<(), String>>,
    shutting_down: parking_lot::Mutex<bool>,
}

/// Install request.
pub struct InstallRequest {
    pub archive_path: PathBuf,
    pub enable: Option<bool>,
    pub source: Source,
    pub catalog: Option<CatalogExpectation>,
}

impl PluginManager {
    pub fn new(
        database: Arc<PluginDatabase>,
        store: Arc<PackageStore>,
        supervisor: Arc<RuntimeSupervisor>,
        contributions: Arc<ContributionService>,
        permissions: Arc<PermissionEngine>,
        secrets: Arc<PluginSecretStore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            database,
            store,
            supervisor,
            contributions,
            permissions,
            secrets,
            queue: Mutex::new(()),
            initialized: OnceCell::new(),
            shutting_down: parking_lot::Mutex::new(false),
        })
    }

    /// Recover the package store, then start eager plugins. Idempotent.
    pub async fn initialize(&self) -> PluginResult<()> {
        let result = self
            .initialized
            .get_or_init(|| async {
                let store = self.store.clone();
                let recovered = tokio::task::spawn_blocking(move || store.initialize())
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|r| r.map_err(|e| e.message().to_string()));
                if let Err(err) = recovered {
                    return Err(err);
                }
                self.contributions.initialize().await;
                Ok(())
            })
            .await;
        result.clone().map_err(PluginError::host)
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.get().is_some_and(Result::is_ok)
    }

    async fn ready(&self) -> PluginResult<()> {
        if *self.shutting_down.lock() {
            return Err(PluginError::host("Plugin manager is shutting down"));
        }
        self.initialize().await
    }

    pub async fn list(&self) -> PluginResult<Vec<PluginRecord>> {
        self.ready().await?;
        self.database.list_plugins()
    }

    /// Install (or switch to) a package version.
    pub async fn install(&self, request: InstallRequest) -> PluginResult<Option<PluginRecord>> {
        let _guard = self.queue.lock().await;
        self.ready().await?;
        let handle = tokio::runtime::Handle::current();
        let store = self.store.clone();
        let database = self.database.clone();
        let contributions = self.contributions.clone();
        let supervisor = self.supervisor.clone();
        let stopped: Arc<parking_lot::Mutex<Option<(String, String)>>> = Arc::new(parking_lot::Mutex::new(None));
        let stopped_inner = stopped.clone();
        let InstallRequest { archive_path, enable, source, catalog } = request;
        let installed = tokio::task::spawn_blocking(move || {
            let mut before = |event: &BeforeActivate| -> PluginResult<()> {
                let Some(previous) = event.previous.as_ref().filter(|p| p.enabled) else { return Ok(()) };
                database.set_enabled(&event.plugin_id, false)?;
                contributions.on_plugin_disabled(&event.plugin_id);
                *stopped_inner.lock() = Some((event.plugin_id.clone(), previous.active_version.clone().unwrap_or_default()));
                handle.block_on(supervisor.stop(&event.plugin_id))
            };
            store.install(&archive_path, InstallOptions { source, enable, catalog, before_activate: Some(&mut before) })
        })
        .await
        .map_err(|e| PluginError::host(e.to_string()))?;
        let stopped = stopped.lock().clone();
        let plugin = match installed {
            Ok(plugin) => plugin,
            Err(err) => {
                if let Some((plugin_id, version)) = stopped {
                    if self.database.get_active_plugin(&plugin_id)?.is_some_and(|p| p.active_version.as_deref() == Some(version.as_str())) {
                        self.database.set_enabled(&plugin_id, true)?;
                        if self.contributions.on_plugin_enabled(&plugin_id).await.is_err() {
                            self.database.set_enabled(&plugin_id, false)?;
                        }
                    }
                }
                return Err(err);
            }
        };
        if let Some(plugin) = plugin.as_ref().filter(|p| p.enabled) {
            if let Err(err) = self.contributions.on_plugin_enabled(&plugin.id).await {
                self.database.set_enabled(&plugin.id, false)?;
                self.contributions.on_plugin_disabled(&plugin.id);
                if let Some((plugin_id, version)) = stopped.filter(|(_, v)| Some(v.as_str()) != plugin.active_version.as_deref()) {
                    let restored = self
                        .database
                        .set_active_version(&plugin_id, &version, true, plugin.active_version.as_deref())
                        .map(|_| ());
                    let restarted = match restored {
                        Ok(()) => self.contributions.on_plugin_enabled(&plugin_id).await.map(|_| ()),
                        Err(e) => Err(e),
                    };
                    if restarted.is_err() {
                        if let Ok(Some(r)) = self.database.get_active_plugin(&plugin_id) {
                            if r.active_version.as_deref() == Some(version.as_str()) && r.enabled {
                                let _ = self.database.set_enabled(&plugin_id, false);
                            }
                        }
                    }
                }
                return Err(err);
            }
        }
        Ok(plugin)
    }

    pub async fn set_enabled(&self, plugin_id: &str, enabled: bool, expected_source_owner: Option<&str>) -> PluginResult<Option<PluginRecord>> {
        let _guard = self.queue.lock().await;
        self.ready().await?;
        if let Some(owner) = expected_source_owner {
            if self.database.private_owner(plugin_id)? != owner {
                return Err(PluginError::host("Plugin source changed before its lifecycle update"));
            }
        }
        if enabled {
            let plugin = self.database.get_active_plugin(plugin_id)?;
            if let Some(plugin) = &plugin {
                self.store.assert_compatible(plugin).map_err(|(_, e)| e)?;
                if plugin.runtime.quarantined_at.is_some() {
                    self.database.clear_quarantine(plugin_id, plugin.active_version.as_deref())?;
                }
            }
            self.database.set_enabled(plugin_id, true)?;
            if let Err(err) = self.contributions.on_plugin_enabled(plugin_id).await {
                self.database.set_enabled(plugin_id, false)?;
                self.contributions.on_plugin_disabled(plugin_id);
                return Err(err);
            }
        } else {
            self.database.set_enabled(plugin_id, false)?;
            self.contributions.on_plugin_disabled(plugin_id);
            self.supervisor.stop(plugin_id).await?;
        }
        self.database.get_active_plugin(plugin_id)
    }

    pub async fn revoke_permissions(&self, plugin_id: &str) -> PluginResult<Option<PluginRecord>> {
        let _guard = self.queue.lock().await;
        self.ready().await?;
        if self.database.get_active_plugin(plugin_id)?.is_none() {
            return Err(PluginError::host("Plugin is not installed"));
        }
        let mut errors = Vec::new();
        if let Err(e) = self.database.set_enabled(plugin_id, false) {
            errors.push(e);
        }
        if let Err(e) = self.permissions.revoke_all(plugin_id) {
            errors.push(e);
        }
        self.contributions.on_plugin_disabled(plugin_id);
        if let Err(e) = self.supervisor.stop(plugin_id).await {
            errors.push(e);
        }
        if let Some(first) = errors.into_iter().next() {
            return Err(first);
        }
        self.database.get_active_plugin(plugin_id)
    }

    pub async fn restart(&self, plugin_id: &str) -> PluginResult<Option<PluginRecord>> {
        let _guard = self.queue.lock().await;
        self.ready().await?;
        self.supervisor.restart(plugin_id).await?;
        self.database.get_active_plugin(plugin_id)
    }

    pub async fn reset_uninstalled_source(&self, plugin_id: &str, expected_source_id: &str) -> PluginResult<()> {
        let _guard = self.queue.lock().await;
        self.ready().await?;
        if self.database.get_active_plugin(plugin_id)?.is_some() {
            return Err(PluginError::host("Uninstall the plugin before changing source"));
        }
        if self.database.get_plugin_source(plugin_id)?.id != expected_source_id {
            return Err(PluginError::host("Plugin source changed; review the reset again"));
        }
        self.supervisor.stop(plugin_id).await?;
        self.permissions.revoke_all(plugin_id)?;
        self.secrets.clear_plugin_memory(plugin_id);
        self.store.clear_uninstalled_private_files(plugin_id)?;
        self.database.clear_uninstalled_source_data(plugin_id, expected_source_id)
    }

    /// Run `operation` in the queue, then optionally disable every plugin of
    /// a removed market source (`changeMarketSource`).
    pub async fn change_market_source<T>(&self, operation: impl FnOnce() -> PluginResult<T>, disable_source_id: Option<&str>) -> PluginResult<T> {
        let _guard = self.queue.lock().await;
        self.ready().await?;
        let result = operation()?;
        if let Some(source_id) = disable_source_id {
            for plugin in self.database.list_plugins()? {
                if plugin.source.id != source_id {
                    continue;
                }
                let _ = self.database.set_enabled(&plugin.id, false);
                self.contributions.on_plugin_disabled(&plugin.id);
                let _ = self.supervisor.stop(&plugin.id).await;
            }
        }
        Ok(result)
    }

    pub async fn uninstall(&self, plugin_id: &str) -> PluginResult<bool> {
        let _guard = self.queue.lock().await;
        self.ready().await?;
        if self.database.get_active_plugin(plugin_id)?.is_some() {
            self.database.set_enabled(plugin_id, false)?;
            self.contributions.on_plugin_disabled(plugin_id);
        }
        self.supervisor.stop(plugin_id).await?;
        let store = self.store.clone();
        let id = plugin_id.to_string();
        tokio::task::spawn_blocking(move || store.uninstall(&id)).await.map_err(|e| PluginError::host(e.to_string()))?
    }

    pub async fn shutdown(&self) {
        *self.shutting_down.lock() = true;
        self.supervisor.shutdown().await;
        let _guard = self.queue.lock().await;
    }
}
