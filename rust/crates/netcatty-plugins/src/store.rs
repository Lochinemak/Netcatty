//! Package store: install / uninstall transactions, startup recovery and
//! digest verification (port of `electron/plugins/packageStore.cjs`).
//!
//! Layout under `<userData>/plugins/`:
//! `packages/<id>/<version>/{install.json, package.ncpkg, package/}` and
//! `staging/{install-*, verify-*, remove-*}`. A package is never extracted
//! into the active tree directly: it is staged, validated, digested,
//! renamed into place and only then committed in one SQLite transaction.
//! Synchronous: callers run it on a blocking thread.

use crate::database::{InstallRecord, PluginDatabase, PluginRecord, VersionRecord};
use crate::error::{PluginError, PluginResult};
use crate::package::archive::{self, create_private_dir_all, PackageValidation};
use crate::package::compat::{self, assert_browser_only};
use crate::package::limits;
use crate::source::{assert_source, assert_storage_segment, installed_version_dir, is_path_inside, PluginPaths, Source};
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const INSTALL_METADATA_FILE: &str = "install.json";
pub const ARCHIVE_SNAPSHOT_FILE: &str = "package.ncpkg";
pub const PACKAGE_DIRECTORY: &str = "package";
pub const REMOVAL_METADATA_FILE: &str = "remove.json";
pub const REMOVED_PLUGIN_DIRECTORY: &str = "plugin";

/// Errors carrying the Electron `error.code` used by callers.
pub const CODE_INCOMPATIBLE: &str = "PLUGIN_INCOMPATIBLE";
pub const CODE_UNSUPPORTED_RUNTIME: &str = "PLUGIN_UNSUPPORTED_RUNTIME";

fn host(message: impl Into<String>) -> PluginError {
    PluginError::host(message)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Durably fsync a directory (best effort on Windows).
pub fn sync_directory(directory: &Path) -> PluginResult<()> {
    match File::open(directory).and_then(|f| f.sync_all()) {
        Ok(()) => Ok(()),
        Err(_) if cfg!(windows) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn sync_directory_tree(directory: &Path) -> PluginResult<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_directory_tree(&entry.path())?;
        }
    }
    sync_directory(directory)
}

fn write_durable_metadata(path: &Path, value: &Value) -> PluginResult<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(format!("{}\n", serde_json::to_string(value)?).as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// `copyImmutableArchive`: copy a regular, non-symbolic file while hashing
/// it, rejecting concurrent modification. Returns `(bytes, sha256)`.
pub fn copy_immutable_archive(source: &Path, destination: &Path, max_bytes: u64) -> PluginResult<(u64, String)> {
    let before = fs::symlink_metadata(source)?;
    if !before.is_file() {
        return Err(host("Plugin package source must be a regular non-symbolic file"));
    }
    if before.len() > max_bytes {
        return Err(host(format!("Plugin archive exceeds {max_bytes} bytes")));
    }
    let mut input = File::open(source)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(destination)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > before.len() {
            return Err(host("Plugin package source changed while it was staged"));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    let after = fs::metadata(source)?;
    if total != before.len() || after.len() != before.len() || after.modified().ok() != before.modified().ok() {
        return Err(host("Plugin package source changed while it was staged"));
    }
    output.sync_all()?;
    Ok((total, hex::encode(hasher.finalize())))
}

#[derive(Debug, Clone)]
struct InstallMetadata {
    plugin_id: String,
    version: String,
    archive_sha256: String,
    content_sha256: String,
    source: Source,
}

fn validate_install_metadata(value: &Value) -> PluginResult<InstallMetadata> {
    let s = |k: &str| value.get(k).and_then(Value::as_str).unwrap_or("");
    if !value.is_object() {
        return Err(host("Invalid plugin install metadata"));
    }
    let plugin_id = assert_storage_segment(s("pluginId"), "ID")?;
    let version = assert_storage_segment(s("version"), "version")?;
    if !is_sha256_hex(s("archiveSha256")) {
        return Err(host("Invalid plugin install archive hash"));
    }
    if !is_sha256_hex(s("contentSha256")) {
        return Err(host("Invalid plugin install content hash"));
    }
    let source = match value.get("source") {
        Some(v) if !v.is_null() => serde_json::from_value::<Source>(v.clone()).map_err(|_| host("Invalid host source identity"))?,
        _ => Source::local(),
    };
    Ok(InstallMetadata {
        plugin_id,
        version,
        archive_sha256: s("archiveSha256").into(),
        content_sha256: s("contentSha256").into(),
        source: assert_source(&source)?,
    })
}

fn read_json(path: &Path) -> PluginResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

#[derive(Debug, Clone)]
struct VerifiedArchive {
    archive_sha256: String,
    content_sha256: String,
    manifest: Value,
}

/// Catalog expectations for marketplace installs.
#[derive(Debug, Clone)]
pub struct CatalogExpectation {
    pub id: String,
    pub version: String,
    pub license: Option<String>,
    pub sha256: String,
    pub manifest: Value,
}

/// Why the store is about to change the active version.
#[derive(Debug, Clone)]
pub struct BeforeActivate {
    pub plugin_id: String,
    pub version: String,
    pub previous: Option<PluginRecord>,
    pub reason: &'static str,
}

pub struct InstallOptions<'a> {
    pub source: Source,
    /// `Some(true)` enable, `Some(false)` force disabled, `None` keep.
    pub enable: Option<bool>,
    pub catalog: Option<CatalogExpectation>,
    pub before_activate: Option<&'a mut dyn FnMut(&BeforeActivate) -> PluginResult<()>>,
}

impl Default for InstallOptions<'_> {
    fn default() -> Self {
        Self { source: Source::local(), enable: None, catalog: None, before_activate: None }
    }
}

pub struct PackageStore {
    pub allow_advanced_plugins: bool,
    pub paths: PluginPaths,
    pub database: Arc<PluginDatabase>,
    pub netcatty_version: String,
    pub api_version: String,
    pub supported_features: Vec<String>,
    verified: Mutex<HashMap<String, VerifiedArchive>>,
}

fn version_key(plugin_id: &str, version: &str) -> String {
    format!("{plugin_id}\0{version}")
}

impl PackageStore {
    pub fn new(
        paths: PluginPaths,
        database: Arc<PluginDatabase>,
        netcatty_version: String,
        api_version: String,
        supported_features: Vec<String>,
        allow_advanced_plugins: bool,
    ) -> Self {
        Self {
            allow_advanced_plugins,
            paths,
            database,
            netcatty_version,
            api_version,
            supported_features,
            verified: Mutex::new(HashMap::new()),
        }
    }

    /// Create directories, recover interrupted transactions and reconcile
    /// compatibility of every enabled plugin.
    pub fn initialize(&self) -> PluginResult<()> {
        for dir in self.paths.directories() {
            create_private_dir_all(dir)?;
        }
        self.recover()?;
        for plugin in self.database.list_plugins()? {
            if plugin.enabled {
                // Incompatible / unsupported plugins are disabled inside.
                let _ = self.assert_compatible(&plugin);
            }
        }
        Ok(())
    }

    pub fn compatibility(&self, manifest: &Value) -> compat::Compatibility {
        compat::check_compatibility(manifest, &self.netcatty_version, Some(&self.api_version), &self.supported_features)
    }

    /// `assertCompatible`: disables the active version when incompatible.
    pub fn assert_compatible(&self, plugin: &PluginRecord) -> Result<compat::Compatibility, (String, PluginError)> {
        let manifest = plugin.manifest.clone().unwrap_or(Value::Null);
        let result = self.compatibility(&manifest);
        let mut error = None;
        if !self.allow_advanced_plugins {
            if let Err(e) = assert_browser_only(&manifest) {
                error = Some((CODE_UNSUPPORTED_RUNTIME.to_string(), e));
            }
        }
        if error.is_none() && result.compatible {
            return Ok(result);
        }
        let (code, error) = error.unwrap_or_else(|| {
            (
                CODE_INCOMPATIBLE.to_string(),
                host(format!("Plugin is incompatible: {}", result.errors.join("; "))),
            )
        });
        if let Ok(Some(current)) = self.database.get_active_plugin(&plugin.id) {
            if current.active_version == plugin.active_version {
                let _ = self.database.set_enabled(&plugin.id, false);
                let _ = self.database.set_runtime_state(
                    &plugin.id,
                    "error",
                    plugin.active_version.as_deref(),
                    None,
                    Some(error.message()),
                    None,
                );
            }
        }
        Err((code, error))
    }

    /// `install(archivePath, options)`.
    pub fn install(&self, archive_path: &Path, mut options: InstallOptions<'_>) -> PluginResult<Option<PluginRecord>> {
        if !archive_path.is_absolute() {
            return Err(host("Plugin package path must be absolute"));
        }
        if archive_path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref() != Some("ncpkg") {
            return Err(host("Plugin packages must use the .ncpkg extension"));
        }
        let staging = self.paths.staging.join(format!("install-{}", uuid::Uuid::new_v4()));
        create_private_dir_all(&self.paths.staging)?;
        fs::create_dir(&staging)?;
        let result = self.install_staged(archive_path, &staging, &mut options);
        let _ = fs::remove_dir_all(&staging);
        result
    }

    fn install_staged(&self, archive_path: &Path, staging: &Path, options: &mut InstallOptions<'_>) -> PluginResult<Option<PluginRecord>> {
        let snapshot_path = staging.join(ARCHIVE_SNAPSHOT_FILE);
        let extracted = staging.join(PACKAGE_DIRECTORY);
        let (_, archive_sha) = copy_immutable_archive(archive_path, &snapshot_path, limits::ARCHIVE_BYTES as u64)?;
        let validation = archive::extract_package(&snapshot_path, &extracted)?;
        sync_directory_tree(&extracted)?;
        let manifest = validation.manifest.clone();
        if !self.allow_advanced_plugins {
            assert_browser_only(&manifest)?;
        }
        let compatibility = self.compatibility(&manifest);
        if !compatibility.compatible {
            return Err(host(format!("Plugin is incompatible: {}", compatibility.errors.join("; "))));
        }
        let plugin_id = assert_storage_segment(manifest["id"].as_str().unwrap_or(""), "ID")?;
        let version = assert_storage_segment(manifest["version"].as_str().unwrap_or(""), "version")?;
        let target = installed_version_dir(&self.paths, &plugin_id, &version)?;
        let source = self.database.assert_install_source(&plugin_id, &options.source)?;
        let previous = self.database.get_active_plugin(&plugin_id)?;
        if let Some(catalog) = &options.catalog {
            if archive_sha != catalog.sha256 {
                return Err(host("Catalog package SHA-256 mismatch"));
            }
            assert_catalog_manifest(&manifest, catalog)?;
            if manifest != catalog.manifest {
                return Err(host("Catalog manifest does not match package"));
            }
        }
        let enable_after = match options.enable {
            Some(false) => false,
            Some(true) => true,
            None => previous.as_ref().is_some_and(|p| p.enabled),
        };
        let force_disabled = options.enable == Some(false);
        let mut prepared = false;
        let mut prepare = |reason: &'static str, options: &mut InstallOptions<'_>| -> PluginResult<()> {
            if prepared {
                return Ok(());
            }
            if let Some(callback) = options.before_activate.as_mut() {
                callback(&BeforeActivate {
                    plugin_id: plugin_id.clone(),
                    version: version.clone(),
                    previous: previous.clone(),
                    reason,
                })?;
            }
            prepared = true;
            Ok(())
        };
        let switching = previous.as_ref().and_then(|p| p.active_version.as_deref()) != Some(version.as_str()) || force_disabled;
        if let Some(existing) = self.database.get_version(&plugin_id, &version)? {
            if existing.archive_sha256 != archive_sha {
                return Err(host(format!("Plugin {plugin_id}@{version} is already installed with different contents")));
            }
            match self.verify_installed_version(&VersionRef::from(&existing), true) {
                Ok(valid) => {
                    if switching {
                        prepare("switch-active-version", options)?;
                    }
                    let package = target.join(PACKAGE_DIRECTORY);
                    self.database.install_version(
                        &InstallRecord {
                            source,
                            plugin_id: plugin_id.clone(),
                            version: version.clone(),
                            manifest: valid.manifest,
                            archive_sha256: existing.archive_sha256.clone(),
                            package_relative_path: relative_to(&self.paths.packages, &package),
                        },
                        enable_after,
                        force_disabled,
                    )?;
                    return self.database.get_active_plugin(&plugin_id);
                }
                Err(_) => {
                    if previous.as_ref().and_then(|p| p.active_version.as_deref()) == Some(version.as_str()) {
                        prepare("replace-active-files", options)?;
                    }
                    let _ = fs::remove_dir_all(&target);
                }
            }
        }
        if target.exists() {
            return Err(host(format!("Plugin {plugin_id}@{version} has an uncommitted installed directory")));
        }
        let metadata = json!({
            "source": source,
            "pluginId": plugin_id,
            "version": version,
            "archiveSha256": archive_sha,
            "contentSha256": validation.content_sha256,
        });
        write_durable_metadata(&staging.join(INSTALL_METADATA_FILE), &metadata)?;
        sync_directory(staging)?;
        let parent = target.parent().expect("version dir has a parent");
        create_private_dir_all(parent)?;
        if switching {
            prepare("switch-active-version", options)?;
        }
        fs::rename(staging, &target)?;
        sync_directory(parent)?;
        let package_relative_path = relative_to(&self.paths.packages, &target.join(PACKAGE_DIRECTORY));
        if let Err(err) = self.database.install_version(
            &InstallRecord {
                source,
                plugin_id: plugin_id.clone(),
                version: version.clone(),
                manifest: manifest.clone(),
                archive_sha256: archive_sha.clone(),
                package_relative_path,
            },
            enable_after,
            force_disabled,
        ) {
            self.verified.lock().remove(&version_key(&plugin_id, &version));
            let _ = fs::remove_dir_all(&target);
            let _ = sync_directory(parent);
            return Err(err);
        }
        self.verified.lock().insert(
            version_key(&plugin_id, &version),
            VerifiedArchive { archive_sha256: archive_sha, content_sha256: validation.content_sha256, manifest },
        );
        self.database.get_active_plugin(&plugin_id)
    }

    /// Startup recovery of interrupted install / uninstall transactions.
    pub fn recover(&self) -> PluginResult<()> {
        self.verified.lock().clear();
        create_private_dir_all(&self.paths.staging)?;
        for entry in fs::read_dir(&self.paths.staging)? {
            let entry = entry?;
            let staged = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if !entry.file_type()?.is_dir() || !name.starts_with("remove-") {
                remove_any(&staged);
                continue;
            }
            let moved = staged.join(REMOVED_PLUGIN_DIRECTORY);
            if fs::symlink_metadata(&moved).is_err() {
                // Debris from before the package moved: nothing to restore.
                remove_any(&staged);
                continue;
            }
            let metadata = read_json(&staged.join(REMOVAL_METADATA_FILE))?;
            let plugin_id = assert_storage_segment(metadata.get("pluginId").and_then(Value::as_str).unwrap_or(""), "ID")?;
            let installed = self.paths.packages.join(&plugin_id);
            if self.database.get_active_plugin(&plugin_id)?.is_some() {
                let exists = fs::symlink_metadata(&installed).map(|m| m.is_dir()).unwrap_or(false);
                if !exists {
                    let meta = fs::symlink_metadata(&moved)?;
                    if !meta.is_dir() {
                        return Err(host(format!("Pending plugin removal is incomplete: {plugin_id}")));
                    }
                    fs::rename(&moved, &installed)?;
                    sync_directory(&self.paths.packages)?;
                }
            }
            remove_any(&staged);
        }
        create_private_dir_all(&self.paths.packages)?;
        for plugin_entry in fs::read_dir(&self.paths.packages)? {
            let plugin_entry = plugin_entry?;
            if !plugin_entry.file_type()?.is_dir() {
                continue;
            }
            let plugin_name = plugin_entry.file_name().to_string_lossy().into_owned();
            for version_entry in fs::read_dir(plugin_entry.path())? {
                let version_entry = version_entry?;
                if !version_entry.file_type()?.is_dir() {
                    continue;
                }
                let version_name = version_entry.file_name().to_string_lossy().into_owned();
                let version_dir = version_entry.path();
                let committed = self.database.get_version(&plugin_name, &version_name)?;
                let outcome = (|| -> PluginResult<()> {
                    let metadata = validate_install_metadata(&read_json(&version_dir.join(INSTALL_METADATA_FILE))?)?;
                    if metadata.plugin_id != plugin_name || metadata.version != version_name {
                        return Err(host("Plugin install metadata does not match its directory"));
                    }
                    self.database.assert_install_source(&metadata.plugin_id, &metadata.source)?;
                    if let Some(committed) = &committed {
                        if committed.archive_sha256 != metadata.archive_sha256 {
                            return Err(host("Plugin install archive hash does not match its database record"));
                        }
                    }
                    let package_relative_path = relative_to(&self.paths.packages, &version_dir.join(PACKAGE_DIRECTORY));
                    let reference = match &committed {
                        Some(c) => VersionRef::from(c),
                        None => VersionRef {
                            plugin_id: metadata.plugin_id.clone(),
                            version: metadata.version.clone(),
                            archive_sha256: metadata.archive_sha256.clone(),
                            package_relative_path: package_relative_path.clone(),
                            manifest: None,
                        },
                    };
                    let validation = self.verify_installed_version(&reference, false)?;
                    if committed.is_none() {
                        self.database.install_version(
                            &InstallRecord {
                                source: metadata.source,
                                plugin_id: metadata.plugin_id,
                                version: metadata.version,
                                manifest: validation.manifest,
                                archive_sha256: metadata.archive_sha256,
                                package_relative_path,
                            },
                            false,
                            true,
                        )?;
                    }
                    Ok(())
                })();
                if let Err(err) = outcome {
                    self.verified.lock().remove(&version_key(&plugin_name, &version_name));
                    match committed {
                        Some(committed) => {
                            tracing::warn!(plugin = %plugin_name, error = %err, "retaining invalid committed plugin package fail-closed");
                            if let Some(active) = self.database.get_active_plugin(&committed.plugin_id)? {
                                if active.active_version.as_deref() == Some(committed.version.as_str()) {
                                    self.database.set_enabled(&committed.plugin_id, false)?;
                                    self.database.set_runtime_state(
                                        &committed.plugin_id,
                                        "error",
                                        Some(&committed.version),
                                        None,
                                        Some(&format!("Installed package integrity check failed: {}", err.message())),
                                        None,
                                    )?;
                                }
                            }
                        }
                        None => {
                            tracing::warn!(plugin = %plugin_name, error = %err, "removing invalid uncommitted plugin package");
                            remove_any(&version_dir);
                        }
                    }
                }
            }
        }
        for plugin in self.database.list_plugins()? {
            if plugin.package_relative_path.is_none() {
                continue;
            }
            if let Err(err) = self.prepare_package_root(&plugin) {
                self.database.set_enabled(&plugin.id, false)?;
                self.database.set_runtime_state(
                    &plugin.id,
                    "error",
                    None,
                    None,
                    Some(&format!("Installed package integrity check failed: {}", err.message())),
                    None,
                )?;
            }
        }
        Ok(())
    }

    /// `resolvePackageRoot` (lexical containment).
    pub fn resolve_package_root(&self, package_relative_path: Option<&str>) -> PluginResult<PathBuf> {
        let relative = package_relative_path.ok_or_else(|| host("Plugin package path is invalid"))?;
        if Path::new(relative).is_absolute() {
            return Err(host("Plugin package path is invalid"));
        }
        let root = self.paths.packages.join(relative);
        if !is_path_inside(&self.paths.packages, &root) {
            return Err(host("Plugin package path escapes the package store"));
        }
        Ok(root)
    }

    fn load_verified_archive(&self, record: &VersionRef, refresh: bool) -> PluginResult<VerifiedArchive> {
        let plugin_id = assert_storage_segment(&record.plugin_id, "ID")?;
        let version = assert_storage_segment(&record.version, "version")?;
        if !is_sha256_hex(&record.archive_sha256) {
            return Err(host("Plugin database archive hash is invalid"));
        }
        let key = version_key(&plugin_id, &version);
        if !refresh {
            let cached = self.verified.lock().get(&key).cloned();
            if let Some(cached) = cached.filter(|c| c.archive_sha256 == record.archive_sha256) {
                return Ok(cached);
            }
        }
        let version_dir = installed_version_dir(&self.paths, &plugin_id, &version)?;
        let metadata = validate_install_metadata(&read_json(&version_dir.join(INSTALL_METADATA_FILE))?)?;
        if metadata.plugin_id != plugin_id || metadata.version != version || metadata.archive_sha256 != record.archive_sha256 {
            return Err(host("Plugin install metadata does not match its database record"));
        }
        let verify_dir = self.paths.staging.join(format!("verify-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&verify_dir)?;
        let result = (|| {
            let snapshot = verify_dir.join(ARCHIVE_SNAPSHOT_FILE);
            let (_, sha) = copy_immutable_archive(&version_dir.join(ARCHIVE_SNAPSHOT_FILE), &snapshot, limits::ARCHIVE_BYTES as u64)?;
            if sha != record.archive_sha256 {
                return Err(host("Retained plugin archive hash does not match its database record"));
            }
            let validation = archive::validate_package(&snapshot)?;
            if validation.content_sha256 != metadata.content_sha256 {
                return Err(host("Retained plugin archive content does not match install metadata"));
            }
            if validation.manifest["id"] != json!(plugin_id) || validation.manifest["version"] != json!(version) {
                return Err(host("Retained plugin archive identity does not match its database record"));
            }
            let verified = VerifiedArchive {
                archive_sha256: record.archive_sha256.clone(),
                content_sha256: validation.content_sha256,
                manifest: validation.manifest,
            };
            self.verified.lock().insert(key, verified.clone());
            Ok(verified)
        })();
        let _ = fs::remove_dir_all(&verify_dir);
        result
    }

    /// `verifyInstalledVersion`: rescan the installed tree and compare its
    /// logical-content digest with the retained, verified snapshot.
    pub fn verify_installed_version(&self, record: &VersionRef, refresh_archive: bool) -> PluginResult<PackageValidation> {
        let expected = self.load_verified_archive(record, refresh_archive)?;
        let root = self.resolve_package_root(Some(&record.package_relative_path))?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(host("Plugin package root is not a directory"));
        }
        let validation = archive::validate_directory(&root, false)?;
        if validation.manifest["id"] != json!(record.plugin_id) || validation.manifest["version"] != json!(record.version) {
            return Err(host("Installed plugin identity does not match its database record"));
        }
        if validation.content_sha256 != expected.content_sha256 {
            return Err(host("Installed plugin files do not match the retained package archive"));
        }
        if let Some(manifest) = &record.manifest {
            if manifest != &expected.manifest {
                return Err(host("Plugin database manifest does not match the retained package archive"));
            }
        }
        Ok(validation)
    }

    /// `preparePackageRoot`: the mandatory execution boundary. Drift
    /// disables the active version before any runtime can observe it.
    pub fn prepare_package_root(&self, plugin: &PluginRecord) -> PluginResult<PathBuf> {
        let reference = VersionRef::from_plugin(plugin)?;
        match self.verify_installed_version(&reference, false) {
            Ok(_) => self.resolve_package_root(Some(&reference.package_relative_path)),
            Err(err) => {
                if let Ok(Some(active)) = self.database.get_active_plugin(&reference.plugin_id) {
                    if active.active_version.as_deref() == Some(reference.version.as_str()) {
                        let _ = self.database.set_enabled(&reference.plugin_id, false);
                        let _ = self.database.set_runtime_state(
                            &reference.plugin_id,
                            "error",
                            Some(&reference.version),
                            None,
                            Some(&format!("Installed package integrity check failed: {}", err.message())),
                            None,
                        );
                    }
                }
                Err(err)
            }
        }
    }

    pub fn clear_uninstalled_private_files(&self, plugin_id: &str) -> PluginResult<()> {
        assert_storage_segment(plugin_id, "ID")?;
        if self.database.get_active_plugin(plugin_id)?.is_some() {
            return Err(host("Plugin is still installed"));
        }
        let _ = fs::remove_dir_all(self.paths.data.join(plugin_id));
        Ok(())
    }

    /// Two-phase uninstall: move under `staging/remove-*`, delete the row.
    pub fn uninstall(&self, plugin_id: &str) -> PluginResult<bool> {
        if self.database.get_active_plugin(plugin_id)?.is_none() {
            return Ok(false);
        }
        let plugin_dir = self.paths.packages.join(assert_storage_segment(plugin_id, "ID")?);
        let removal = self.paths.staging.join(format!("remove-{}", uuid::Uuid::new_v4()));
        let moved_path = removal.join(REMOVED_PLUGIN_DIRECTORY);
        fs::create_dir(&removal)?;
        write_durable_metadata(&removal.join(REMOVAL_METADATA_FILE), &json!({ "pluginId": plugin_id }))?;
        sync_directory(&removal)?;
        let mut moved = false;
        match fs::rename(&plugin_dir, &moved_path) {
            Ok(()) => {
                moved = true;
                sync_directory(&removal)?;
                sync_directory(&self.paths.packages)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        if let Err(err) = self.database.remove_plugin(plugin_id) {
            let mut restored = !moved;
            if moved && fs::rename(&moved_path, &plugin_dir).is_ok() {
                let _ = sync_directory(&self.paths.packages);
                restored = true;
            }
            if restored {
                let _ = fs::remove_dir_all(&removal);
            }
            return Err(err);
        }
        let _ = fs::remove_dir_all(&removal);
        let prefix = format!("{plugin_id}\0");
        self.verified.lock().retain(|k, _| !k.starts_with(&prefix));
        Ok(true)
    }
}

/// `assertCatalogManifest`.
pub fn assert_catalog_manifest(manifest: &Value, expected: &CatalogExpectation) -> PluginResult<()> {
    if manifest["id"] != json!(expected.id) || manifest["version"] != json!(expected.version) {
        return Err(host("Catalog package identity/version mismatch"));
    }
    assert_browser_only(manifest)?;
    let license = manifest.get("license").and_then(Value::as_str);
    if license.is_none() || license != expected.license.as_deref() {
        return Err(host("Catalog package license mismatch"));
    }
    Ok(())
}

/// The identity fields verification needs from a version or plugin row.
#[derive(Debug, Clone)]
pub struct VersionRef {
    pub plugin_id: String,
    pub version: String,
    pub archive_sha256: String,
    pub package_relative_path: String,
    pub manifest: Option<Value>,
}

impl From<&VersionRecord> for VersionRef {
    fn from(v: &VersionRecord) -> Self {
        Self {
            plugin_id: v.plugin_id.clone(),
            version: v.version.clone(),
            archive_sha256: v.archive_sha256.clone(),
            package_relative_path: v.package_relative_path.clone(),
            manifest: None,
        }
    }
}

impl VersionRef {
    pub fn from_plugin(plugin: &PluginRecord) -> PluginResult<Self> {
        Ok(Self {
            plugin_id: plugin.id.clone(),
            version: plugin.active_version.clone().ok_or_else(|| host("Invalid plugin version"))?,
            archive_sha256: plugin.archive_sha256.clone().ok_or_else(|| host("Plugin database archive hash is invalid"))?,
            package_relative_path: plugin.package_relative_path.clone().ok_or_else(|| host("Plugin package path is invalid"))?,
            manifest: plugin.manifest.clone(),
        })
    }
}

fn relative_to(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .map(|p| p.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join(std::path::MAIN_SEPARATOR_STR))
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

fn remove_any(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            let _ = fs::remove_dir_all(path);
        }
        Ok(_) => {
            let _ = fs::remove_file(path);
        }
        Err(_) => {}
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::package::archive::build_package;

    pub fn fixture_dir(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../electron/plugins/fixtures").join(name)
    }

    pub fn make_store(dir: &Path, advanced: bool) -> PackageStore {
        let paths = PluginPaths::new(dir);
        let db = Arc::new(PluginDatabase::open(&paths.database).unwrap());
        let store = PackageStore::new(paths, db, "1.2.1".into(), "0.1.0-internal.1".into(), vec![], advanced);
        store.initialize().unwrap();
        store
    }

    pub fn pack_fixture(dir: &Path, name: &str) -> PathBuf {
        let out = dir.join(format!("{name}.ncpkg"));
        build_package(&fixture_dir(name), &out).unwrap();
        out
    }

    #[test]
    fn install_verify_drift_and_uninstall() {
        let tmp = tempfile::tempdir().unwrap();
        let pkgs = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path(), false);
        let archive = pack_fixture(pkgs.path(), "browser-runtime-plugin");
        let plugin = store.install(&archive, InstallOptions { enable: Some(true), ..Default::default() }).unwrap().unwrap();
        assert!(plugin.enabled);
        let root = store.prepare_package_root(&plugin).unwrap();
        assert!(root.join("netcatty.plugin.json").exists());
        // Idempotent reinstall of the same archive.
        let again = store.install(&archive, InstallOptions::default()).unwrap().unwrap();
        assert_eq!(again.archive_sha256, plugin.archive_sha256);
        // Drift: modify the installed tree.
        let entry = root.join(plugin.manifest.as_ref().unwrap()["main"]["browser"].as_str().unwrap());
        fs::write(&entry, b"tampered").unwrap();
        assert!(store.prepare_package_root(&plugin).is_err());
        let after = store.database.get_active_plugin(&plugin.id).unwrap().unwrap();
        assert!(!after.enabled);
        assert_eq!(after.runtime.status, "error");
        assert!(store.uninstall(&plugin.id).unwrap());
        assert!(store.database.get_active_plugin(&plugin.id).unwrap().is_none());
        assert!(!store.paths.packages.join(&plugin.id).exists());
    }

    #[test]
    fn browser_only_gate_rejects_utility_plugins() {
        let tmp = tempfile::tempdir().unwrap();
        let pkgs = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path(), false);
        let archive = pack_fixture(pkgs.path(), "utility-runtime-plugin");
        assert!(store.install(&archive, InstallOptions::default()).is_err());
        let store = make_store(tmp.path(), true);
        assert!(store.install(&archive, InstallOptions::default()).is_ok());
    }

    #[test]
    fn recovery_imports_committed_rename_and_restores_removal() {
        let tmp = tempfile::tempdir().unwrap();
        let pkgs = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path(), false);
        let archive = pack_fixture(pkgs.path(), "browser-runtime-plugin");
        let plugin = store.install(&archive, InstallOptions { enable: Some(true), ..Default::default() }).unwrap().unwrap();
        // Simulate a crash after the durable rename but before the DB commit:
        // drop the database row while keeping the files.
        store.database.remove_plugin(&plugin.id).unwrap();
        store.recover().unwrap();
        let recovered = store.database.get_active_plugin(&plugin.id).unwrap().unwrap();
        assert!(!recovered.enabled, "recovered versions are imported disabled");
        // Simulate an interrupted uninstall: package moved, row still present.
        let removal = store.paths.staging.join("remove-test");
        fs::create_dir_all(&removal).unwrap();
        fs::write(removal.join(REMOVAL_METADATA_FILE), json!({ "pluginId": plugin.id }).to_string()).unwrap();
        fs::rename(store.paths.packages.join(&plugin.id), removal.join(REMOVED_PLUGIN_DIRECTORY)).unwrap();
        store.recover().unwrap();
        assert!(store.paths.packages.join(&plugin.id).exists());
        assert!(!removal.exists());
        // Staging debris is cleaned.
        fs::create_dir_all(store.paths.staging.join("install-x")).unwrap();
        store.recover().unwrap();
        assert!(!store.paths.staging.join("install-x").exists());
    }

    #[test]
    fn rejects_tampered_archives() {
        let tmp = tempfile::tempdir().unwrap();
        let pkgs = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path(), false);
        let archive = pack_fixture(pkgs.path(), "browser-runtime-plugin");
        let mut bytes = fs::read(&archive).unwrap();
        // Corrupt the first file's content byte (CRC mismatch).
        let name_len = u16::from_le_bytes([bytes[26], bytes[27]]) as usize;
        bytes[30 + name_len] ^= 0xff;
        let bad = pkgs.path().join("bad.ncpkg");
        fs::write(&bad, bytes).unwrap();
        assert!(store.install(&bad, InstallOptions::default()).is_err());
        assert!(store.install(&pkgs.path().join("x.zip"), InstallOptions::default()).is_err());
    }
}
