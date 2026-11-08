//! `plugins.sqlite` (port of `electron/plugins/database.cjs`).
//!
//! Same schema, pragmas (WAL, foreign keys, `synchronous=FULL`), schema
//! version chain and immediate transactions as the Electron host, so a
//! database written by either host is readable by the other.

use crate::constants::now_ms;
use crate::error::{PluginError, PluginResult};
use crate::source::{assert_source, is_plugin_id_like, is_private_owner, private_owner, Source};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: i64 = 7;
pub const MAX_SECURITY_AUDIT_DETAILS_BYTES: usize = 16 * 1024;
pub const MAX_SECURITY_AUDIT_RECORDS_PER_PLUGIN: i64 = 1_000;

const REQUIRED_SCHEMA_COLUMNS: &[(&str, &[&str])] = &[
    ("plugin_source_bindings", &["plugin_id", "source_json"]),
    ("plugin_host_preferences", &["key", "value_json", "updated_at"]),
    ("plugins", &["id", "enabled", "active_version", "installed_at", "updated_at"]),
    ("plugin_versions", &["plugin_id", "version", "manifest_json", "archive_sha256", "package_relative_path", "installed_at"]),
    ("plugin_runtime_state", &["plugin_id", "plugin_version", "status", "runtime_kind", "last_error", "quarantined_at", "updated_at"]),
    ("plugin_crashes", &["plugin_id", "plugin_version", "crashed_at"]),
    ("plugin_kv", &["plugin_id", "key", "value_json", "updated_at"]),
    ("plugin_settings", &["plugin_id", "setting_id", "scope", "scope_id", "value_json", "updated_at"]),
    ("plugin_view_state", &["plugin_id", "view_id", "scope_id", "state_json", "updated_at"]),
    ("plugin_permission_grants", &["plugin_id", "permission", "resource", "resource_kind", "declaration_hash", "granted_at"]),
    ("plugin_secrets", &["plugin_id", "key", "secret_ref", "ciphertext", "created_at", "updated_at"]),
    ("plugin_security_audit", &["id", "plugin_id", "event", "details_json", "created_at"]),
    ("plugin_sync_sidecars", &["plugin_id", "kind", "key", "value_json", "updated_at"]),
    ("plugin_sync_provider_bindings", &["provider_id", "plugin_id", "created_at", "updated_at"]),
];

const INITIAL_SCHEMA: &str = r#"
CREATE TABLE plugins (
  id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  active_version TEXT,
  installed_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE plugin_versions (
  plugin_id TEXT NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
  version TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  archive_sha256 TEXT NOT NULL,
  package_relative_path TEXT NOT NULL,
  installed_at INTEGER NOT NULL,
  PRIMARY KEY (plugin_id, version)
);
CREATE TABLE plugin_runtime_state (
  plugin_id TEXT NOT NULL,
  plugin_version TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'stopped',
  runtime_kind TEXT,
  last_error TEXT,
  quarantined_at INTEGER,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (plugin_id, plugin_version),
  FOREIGN KEY (plugin_id, plugin_version)
    REFERENCES plugin_versions(plugin_id, version) ON DELETE CASCADE
);
CREATE TABLE plugin_crashes (
  plugin_id TEXT NOT NULL,
  plugin_version TEXT NOT NULL,
  crashed_at INTEGER NOT NULL,
  FOREIGN KEY (plugin_id, plugin_version)
    REFERENCES plugin_versions(plugin_id, version) ON DELETE CASCADE
);
CREATE INDEX plugin_crashes_lookup
  ON plugin_crashes(plugin_id, plugin_version, crashed_at);
CREATE TABLE plugin_kv (
  plugin_id TEXT NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  value_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (plugin_id, key)
);
CREATE TABLE plugin_settings (
  plugin_id TEXT NOT NULL,
  setting_id TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('application', 'workspace', 'host', 'session', 'device')),
  scope_id TEXT NOT NULL,
  value_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (plugin_id, setting_id, scope, scope_id)
);
CREATE INDEX plugin_settings_lookup
  ON plugin_settings(plugin_id, scope, scope_id, setting_id);
CREATE TABLE plugin_view_state (
  plugin_id TEXT NOT NULL,
  view_id TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  state_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (plugin_id, view_id, scope_id)
);
CREATE INDEX plugin_view_state_lookup
  ON plugin_view_state(plugin_id, scope_id, view_id);
CREATE TABLE plugin_permission_grants (
  plugin_id TEXT NOT NULL,
  permission TEXT NOT NULL,
  resource TEXT NOT NULL,
  resource_kind TEXT NOT NULL CHECK (resource_kind IN ('exact', 'directory')),
  declaration_hash TEXT NOT NULL,
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (plugin_id, permission, resource)
);
CREATE TABLE plugin_secrets (
  plugin_id TEXT NOT NULL,
  key TEXT NOT NULL,
  secret_ref TEXT NOT NULL UNIQUE,
  ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (plugin_id, key)
);
CREATE INDEX plugin_secrets_ref_lookup
  ON plugin_secrets(plugin_id, secret_ref);
CREATE TABLE plugin_security_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plugin_id TEXT NOT NULL,
  event TEXT NOT NULL,
  details_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX plugin_security_audit_lookup
  ON plugin_security_audit(plugin_id, created_at DESC);
CREATE TABLE plugin_sync_sidecars (
  plugin_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('settings', 'account_baseline', 'crdt_baseline')),
  key TEXT NOT NULL,
  value_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (plugin_id, kind, key)
);
CREATE INDEX plugin_sync_sidecars_lookup
  ON plugin_sync_sidecars(plugin_id, kind, key);
CREATE TABLE plugin_sync_provider_bindings (
  provider_id TEXT PRIMARY KEY,
  plugin_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
PRAGMA user_version = 3;
"#;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeState {
    pub status: String,
    pub kind: Option<String>,
    pub last_error: Option<String>,
    pub quarantined_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PluginRecord {
    pub id: String,
    pub source: Source,
    pub enabled: bool,
    pub active_version: Option<String>,
    pub installed_at: i64,
    pub updated_at: i64,
    pub manifest: Option<Value>,
    pub archive_sha256: Option<String>,
    pub package_relative_path: Option<String>,
    pub runtime: RuntimeState,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VersionRecord {
    pub plugin_id: String,
    pub version: String,
    pub manifest: Value,
    pub archive_sha256: String,
    pub package_relative_path: String,
    pub installed_at: i64,
}

/// Install request for [`PluginDatabase::install_version`].
#[derive(Debug, Clone)]
pub struct InstallRecord {
    pub source: Source,
    pub plugin_id: String,
    pub version: String,
    pub manifest: Value,
    pub archive_sha256: String,
    pub package_relative_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingRow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<String>,
    pub setting_id: String,
    pub scope: String,
    pub scope_id: String,
    pub value: Value,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SidecarRow {
    pub plugin_id: String,
    pub kind: String,
    pub key: String,
    pub value: Value,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantRow {
    pub plugin_id: String,
    pub permission: String,
    pub resource: String,
    pub resource_kind: String,
    pub declaration_hash: String,
    pub granted_at: i64,
}

#[derive(Debug, Clone)]
pub struct SecretRow {
    pub plugin_id: Option<String>,
    pub key: String,
    pub secret_ref: String,
    pub ciphertext: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRow {
    pub event: String,
    pub details: Value,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct CrashResult {
    pub count: i64,
    pub quarantined: bool,
    pub quarantined_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct SyncBinding {
    pub provider_id: String,
    pub plugin_id: String,
}

fn parse_json(text: &str, label: &str) -> PluginResult<Value> {
    serde_json::from_str(text).map_err(|_| PluginError::host(format!("Corrupt plugin database {label}")))
}

/// `plugins.sqlite`. All methods are synchronous and serialized by one
/// connection mutex (the Electron host uses the synchronous `node:sqlite`).
pub struct PluginDatabase {
    pub path: PathBuf,
    conn: Mutex<Connection>,
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
}

impl PluginDatabase {
    pub fn open(path: &Path) -> PluginResult<Self> {
        Self::open_with_clock(path, Box::new(now_ms))
    }

    pub fn open_with_clock(path: &Path, clock: Box<dyn Fn() -> i64 + Send + Sync>) -> PluginResult<Self> {
        if !path.is_absolute() {
            return Err(PluginError::host("Plugin database path must be absolute"));
        }
        if let Some(parent) = path.parent() {
            crate::package::archive::create_private_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let db = Self {
            path: path.to_path_buf(),
            conn: Mutex::new(conn),
            clock,
        };
        db.initialize_schema()?;
        Ok(db)
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    fn initialize_schema(&self) -> PluginResult<()> {
        let conn = self.conn.lock();
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(PluginError::host(format!(
                "Plugin database schema {version} is newer than supported {SCHEMA_VERSION}"
            )));
        }
        let tx = |sql: &str| -> PluginResult<()> {
            conn.execute_batch(&format!("BEGIN IMMEDIATE;{sql}\nCOMMIT;")).inspect_err(|_| {
                let _ = conn.execute_batch("ROLLBACK");
            })?;
            Ok(())
        };
        match version {
            0 => tx(INITIAL_SCHEMA)?,
            1 => tx(
                "CREATE TABLE IF NOT EXISTS plugin_sync_sidecars (plugin_id TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('settings', 'account_baseline', 'crdt_baseline')), key TEXT NOT NULL, value_json TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (plugin_id, kind, key));
                 CREATE INDEX IF NOT EXISTS plugin_sync_sidecars_lookup ON plugin_sync_sidecars(plugin_id, kind, key);
                 CREATE TABLE IF NOT EXISTS plugin_sync_provider_bindings (provider_id TEXT PRIMARY KEY, plugin_id TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                 PRAGMA user_version = 3;",
            )?,
            2 => tx(
                "CREATE TABLE IF NOT EXISTS plugin_sync_provider_bindings (provider_id TEXT PRIMARY KEY, plugin_id TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                 PRAGMA user_version = 3;",
            )?,
            _ => {}
        }
        if version <= 3 {
            tx("CREATE TABLE plugin_host_preferences (key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at INTEGER NOT NULL);
                PRAGMA user_version = 4;")?;
        }
        if version <= 4 {
            tx("CREATE TABLE IF NOT EXISTS plugin_source_bindings (plugin_id TEXT PRIMARY KEY, source_json TEXT NOT NULL);")?;
        }
        for (table, columns) in REQUIRED_SCHEMA_COLUMNS {
            let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let actual: Vec<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<Result<_, _>>()?;
            if actual != *columns {
                return Err(PluginError::host(
                    "Pre-release plugin database schema is obsolete; reset userData/plugins/plugins.sqlite",
                ));
            }
        }
        if version <= 5 {
            conn.execute_batch("BEGIN IMMEDIATE")?;
            let result = (|| -> PluginResult<()> {
                let ids: Vec<String> = conn
                    .prepare(
                        "SELECT id AS plugin_id FROM plugins
                         UNION SELECT plugin_id FROM plugin_settings
                         UNION SELECT plugin_id FROM plugin_view_state
                         UNION SELECT plugin_id FROM plugin_permission_grants
                         UNION SELECT plugin_id FROM plugin_secrets
                         UNION SELECT plugin_id FROM plugin_sync_sidecars",
                    )?
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                let local = serde_json::to_string(&Source::local())?;
                for id in ids {
                    if is_plugin_id_like(&id) {
                        conn.execute(
                            "INSERT OR IGNORE INTO plugin_source_bindings(plugin_id,source_json) VALUES(?,?)",
                            params![id, local],
                        )?;
                    }
                }
                conn.execute_batch("PRAGMA user_version = 6")?;
                Ok(())
            })();
            finish_tx(&conn, result)?;
        }
        if version <= 6 {
            conn.execute_batch("BEGIN IMMEDIATE")?;
            let result = (|| -> PluginResult<()> {
                for table in ["plugin_settings", "plugin_view_state", "plugin_permission_grants", "plugin_secrets", "plugin_sync_sidecars"] {
                    let ids: Vec<String> = conn
                        .prepare(&format!("SELECT DISTINCT plugin_id FROM {table}"))?
                        .query_map([], |r| r.get(0))?
                        .collect::<Result<_, _>>()?;
                    for id in ids {
                        if is_plugin_id_like(&id) {
                            let owner = private_owner(&Source::local(), &id)?;
                            conn.execute(&format!("UPDATE {table} SET plugin_id = ? WHERE plugin_id = ?"), params![owner, id])?;
                        }
                    }
                }
                let rows: Vec<(String, String)> = conn
                    .prepare("SELECT plugin_id, key FROM plugin_kv")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                for (plugin_id, key) in rows {
                    if source_of(&conn, &plugin_id)?.id == "local" {
                        let prefix = format!("{}:", private_owner(&Source::local(), &plugin_id)?);
                        if !key.starts_with(&prefix) {
                            conn.execute(
                                "UPDATE plugin_kv SET key = ? WHERE plugin_id = ? AND key = ?",
                                params![format!("{prefix}{key}"), plugin_id, key],
                            )?;
                        }
                    }
                }
                conn.execute_batch("PRAGMA user_version = 7")?;
                Ok(())
            })();
            finish_tx(&conn, result)?;
        }
        Ok(())
    }

    /// Run `f` inside `BEGIN IMMEDIATE` / `COMMIT` (rollback on error).
    pub fn transaction<T>(&self, f: impl FnOnce(&Connection) -> PluginResult<T>) -> PluginResult<T> {
        let conn = self.conn.lock();
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = f(&conn);
        finish_tx(&conn, result)
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> PluginResult<T>) -> PluginResult<T> {
        let conn = self.conn.lock();
        f(&conn)
    }

    // ---- source identity -------------------------------------------------

    pub fn get_plugin_source(&self, plugin_id: &str) -> PluginResult<Source> {
        self.with(|c| source_of(c, plugin_id))
    }

    pub fn get_retained_plugin_source(&self, plugin_id: &str) -> PluginResult<Option<Source>> {
        self.with(|c| {
            if let Some(source) = bound_source(c, plugin_id)? {
                return Ok(Some(source));
            }
            let exists = c
                .query_row("SELECT id FROM plugins WHERE id = ?", [plugin_id], |_| Ok(()))
                .optional()?
                .is_some();
            Ok(exists.then(Source::local))
        })
    }

    pub fn assert_install_source(&self, plugin_id: &str, source: &Source) -> PluginResult<Source> {
        self.with(|c| assert_install_source(c, plugin_id, source))
    }

    pub fn private_owner(&self, plugin_id: &str) -> PluginResult<String> {
        self.with(|c| owner_of(c, plugin_id))
    }

    pub fn public_plugin_id(&self, owner: &str) -> Option<String> {
        self.with(|c| Ok(public_id(c, owner))).ok().flatten()
    }

    pub fn clear_uninstalled_source_data(&self, plugin_id: &str, expected_source_id: &str) -> PluginResult<()> {
        if self.get_active_plugin(plugin_id)?.is_some() {
            return Err(PluginError::host("Uninstall the plugin before changing its source"));
        }
        if self.get_plugin_source(plugin_id)?.id != expected_source_id {
            return Err(PluginError::host("Plugin source changed; review the reset again"));
        }
        let owner = self.private_owner(plugin_id)?;
        self.transaction(|c| {
            for table in ["plugin_settings", "plugin_view_state", "plugin_permission_grants", "plugin_secrets", "plugin_sync_sidecars", "plugin_sync_provider_bindings"] {
                c.execute(&format!("DELETE FROM {table} WHERE plugin_id = ? OR plugin_id = ?"), params![owner, plugin_id])?;
            }
            c.execute("DELETE FROM plugin_host_preferences WHERE key LIKE ?", [format!("permission:{owner}:%")])?;
            c.execute("DELETE FROM plugin_source_bindings WHERE plugin_id = ?", [plugin_id])?;
            Ok(())
        })
    }

    // ---- versions / plugins ----------------------------------------------

    /// `installVersion`. `enable` / `force_disabled` mirror the Electron options.
    pub fn install_version(&self, record: &InstallRecord, enable: bool, force_disabled: bool) -> PluginResult<()> {
        if enable && force_disabled {
            return Err(PluginError::host("Plugin version cannot be enabled and force-disabled together"));
        }
        let now = self.now();
        let manifest_json = serde_json::to_string(&record.manifest)?;
        self.transaction(|c| {
            let source = assert_install_source(c, &record.plugin_id, &record.source)?;
            c.execute(
                "INSERT INTO plugin_source_bindings(plugin_id,source_json) VALUES(?,?) ON CONFLICT(plugin_id) DO UPDATE SET source_json=excluded.source_json",
                params![record.plugin_id, serde_json::to_string(&source)?],
            )?;
            c.execute(
                "INSERT INTO plugins(id, enabled, active_version, installed_at, updated_at)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(id) DO UPDATE SET
                   active_version = excluded.active_version,
                   enabled = CASE WHEN ? THEN excluded.enabled ELSE plugins.enabled END,
                   updated_at = excluded.updated_at",
                params![record.plugin_id, i64::from(enable), record.version, now, now, i64::from(enable || force_disabled)],
            )?;
            c.execute(
                "INSERT INTO plugin_versions(plugin_id, version, manifest_json, archive_sha256, package_relative_path, installed_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(plugin_id, version) DO UPDATE SET
                   manifest_json = excluded.manifest_json,
                   archive_sha256 = excluded.archive_sha256,
                   package_relative_path = excluded.package_relative_path,
                   installed_at = excluded.installed_at",
                params![record.plugin_id, record.version, manifest_json, record.archive_sha256, record.package_relative_path, now],
            )?;
            c.execute(
                "INSERT INTO plugin_runtime_state(plugin_id, plugin_version, status, updated_at)
                 VALUES (?, ?, 'stopped', ?)
                 ON CONFLICT(plugin_id, plugin_version) DO NOTHING",
                params![record.plugin_id, record.version, now],
            )?;
            Ok(())
        })
    }

    pub fn get_version(&self, plugin_id: &str, version: &str) -> PluginResult<Option<VersionRecord>> {
        self.with(|c| get_version(c, plugin_id, version))
    }

    pub fn get_active_plugin(&self, plugin_id: &str) -> PluginResult<Option<PluginRecord>> {
        self.with(|c| {
            let row = c
                .query_row(&format!("{PLUGIN_SELECT} WHERE p.id = ?"), [plugin_id], map_plugin_row)
                .optional()?;
            row.map(|r| finish_plugin(c, r)).transpose()
        })
    }

    pub fn list_plugins(&self) -> PluginResult<Vec<PluginRecord>> {
        self.with(|c| {
            let rows: Vec<RawPlugin> = c
                .prepare(&format!("{PLUGIN_SELECT} ORDER BY p.id COLLATE BINARY"))?
                .query_map([], map_plugin_row)?
                .collect::<Result<_, _>>()?;
            rows.into_iter().map(|r| finish_plugin(c, r)).collect()
        })
    }

    pub fn list_installed_versions(&self) -> PluginResult<Vec<VersionRecord>> {
        self.with(|c| {
            let rows: Vec<(String, String, String, String, String, i64)> = c
                .prepare(
                    "SELECT plugin_id, version, manifest_json, archive_sha256, package_relative_path, installed_at
                     FROM plugin_versions ORDER BY plugin_id COLLATE BINARY, installed_at DESC, version COLLATE BINARY",
                )?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
                .collect::<Result<_, _>>()?;
            rows.into_iter().map(map_version).collect()
        })
    }

    pub fn set_enabled(&self, plugin_id: &str, enabled: bool) -> PluginResult<()> {
        let now = self.now();
        let changed = self.with(|c| {
            Ok(c.execute(
                "UPDATE plugins SET enabled = ?, updated_at = ? WHERE id = ?",
                params![i64::from(enabled), now, plugin_id],
            )?)
        })?;
        if changed != 1 {
            return Err(PluginError::host(format!("Plugin is not installed: {plugin_id}")));
        }
        Ok(())
    }

    /// `setActiveVersion` with optional compare-and-set on the previous version.
    pub fn set_active_version(
        &self,
        plugin_id: &str,
        version: &str,
        enabled: bool,
        expected_active_version: Option<&str>,
    ) -> PluginResult<Option<PluginRecord>> {
        let now = self.now();
        self.transaction(|c| {
            if get_version(c, plugin_id, version)?.is_none() {
                return Err(PluginError::host(format!("Plugin version is not installed: {plugin_id}@{version}")));
            }
            let changed = match expected_active_version {
                None => c.execute(
                    "UPDATE plugins SET active_version = ?, enabled = ?, updated_at = ? WHERE id = ?",
                    params![version, i64::from(enabled), now, plugin_id],
                )?,
                Some(expected) => c.execute(
                    "UPDATE plugins SET active_version = ?, enabled = ?, updated_at = ? WHERE id = ? AND active_version = ?",
                    params![version, i64::from(enabled), now, plugin_id, expected],
                )?,
            };
            if changed != 1 {
                return Err(PluginError::host(format!(
                    "Plugin active version changed before it could be restored: {plugin_id}"
                )));
            }
            Ok(())
        })?;
        self.get_active_plugin(plugin_id)
    }

    /// `setRuntimeState`.
    pub fn set_runtime_state(
        &self,
        plugin_id: &str,
        status: &str,
        plugin_version: Option<&str>,
        kind: Option<&str>,
        error: Option<&str>,
        quarantined_at: Option<i64>,
    ) -> PluginResult<()> {
        let now = self.now();
        self.with(|c| {
            let active: Option<String> = c
                .query_row("SELECT active_version FROM plugins WHERE id = ?", [plugin_id], |r| r.get(0))
                .optional()?
                .flatten();
            let version = plugin_version
                .map(str::to_string)
                .or(active)
                .ok_or_else(|| PluginError::host(format!("Plugin is not installed: {plugin_id}")))?;
            if get_version(c, plugin_id, &version)?.is_none() {
                return Err(PluginError::host(format!("Plugin version is not installed: {plugin_id}@{version}")));
            }
            let error: Option<String> = error.map(|e| e.chars().take(4_096).collect());
            c.execute(
                "INSERT INTO plugin_runtime_state(plugin_id, plugin_version, status, runtime_kind, last_error, quarantined_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(plugin_id, plugin_version) DO UPDATE SET
                   status = excluded.status,
                   runtime_kind = excluded.runtime_kind,
                   last_error = excluded.last_error,
                   quarantined_at = COALESCE(excluded.quarantined_at, plugin_runtime_state.quarantined_at),
                   updated_at = excluded.updated_at",
                params![plugin_id, version, status, kind, error, quarantined_at, now],
            )?;
            Ok(())
        })
    }

    /// `recordCrash`: version-scoped crash window and quarantine.
    pub fn record_crash(&self, plugin_id: &str, version: &str, window_ms: i64, threshold: i64) -> PluginResult<CrashResult> {
        let now = self.now();
        self.transaction(|c| {
            if get_version(c, plugin_id, version)?.is_none() {
                return Err(PluginError::host(format!("Plugin version is not installed: {plugin_id}@{version}")));
            }
            c.execute(
                "DELETE FROM plugin_crashes WHERE plugin_id = ? AND plugin_version = ? AND crashed_at < ?",
                params![plugin_id, version, now - window_ms],
            )?;
            c.execute(
                "INSERT INTO plugin_crashes(plugin_id, plugin_version, crashed_at) VALUES (?, ?, ?)",
                params![plugin_id, version, now],
            )?;
            let count: i64 = c.query_row(
                "SELECT COUNT(*) FROM plugin_crashes WHERE plugin_id = ? AND plugin_version = ?",
                params![plugin_id, version],
                |r| r.get(0),
            )?;
            let quarantined = count >= threshold;
            if quarantined {
                c.execute(
                    "UPDATE plugin_runtime_state SET status = 'quarantined', quarantined_at = ?, updated_at = ?
                     WHERE plugin_id = ? AND plugin_version = ?",
                    params![now, now, plugin_id, version],
                )?;
            }
            Ok(CrashResult {
                count,
                quarantined,
                quarantined_at: quarantined.then_some(now),
            })
        })
    }

    pub fn clear_quarantine(&self, plugin_id: &str, version: Option<&str>) -> PluginResult<()> {
        let now = self.now();
        self.transaction(|c| {
            let active: Option<String> = c
                .query_row("SELECT active_version FROM plugins WHERE id = ?", [plugin_id], |r| r.get(0))
                .optional()?
                .flatten();
            let target = version
                .map(str::to_string)
                .or(active)
                .ok_or_else(|| PluginError::host(format!("Plugin is not installed: {plugin_id}")))?;
            if get_version(c, plugin_id, &target)?.is_none() {
                return Err(PluginError::host(format!("Plugin version is not installed: {plugin_id}@{target}")));
            }
            c.execute("DELETE FROM plugin_crashes WHERE plugin_id = ? AND plugin_version = ?", params![plugin_id, target])?;
            c.execute(
                "UPDATE plugin_runtime_state SET status = 'stopped', last_error = NULL, quarantined_at = NULL, updated_at = ?
                 WHERE plugin_id = ? AND plugin_version = ?",
                params![now, plugin_id, target],
            )?;
            Ok(())
        })
    }

    pub fn remove_plugin(&self, plugin_id: &str) -> PluginResult<()> {
        self.with(|c| {
            c.execute("DELETE FROM plugins WHERE id = ?", [plugin_id])?;
            Ok(())
        })
    }

    // ---- key/value storage -------------------------------------------------

    fn kv_key(c: &Connection, plugin_id: &str, key: &str) -> PluginResult<String> {
        let owner = owner_of(c, plugin_id)?;
        Ok(if owner != plugin_id { format!("{owner}:{key}") } else { key.to_string() })
    }

    pub fn get_value(&self, plugin_id: &str, key: &str) -> PluginResult<Option<Value>> {
        self.with(|c| {
            let key = Self::kv_key(c, plugin_id, key)?;
            let row: Option<String> = c
                .query_row("SELECT value_json FROM plugin_kv WHERE plugin_id = ? AND key = ?", params![plugin_id, key], |r| r.get(0))
                .optional()?;
            row.map(|t| parse_json(&t, "key/value entry")).transpose()
        })
    }

    pub fn set_value(&self, plugin_id: &str, key: &str, value: &Value) -> PluginResult<()> {
        let now = self.now();
        self.with(|c| {
            let key = Self::kv_key(c, plugin_id, key)?;
            c.execute(
                "INSERT INTO plugin_kv(plugin_id, key, value_json, updated_at) VALUES (?, ?, ?, ?)
                 ON CONFLICT(plugin_id, key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
                params![plugin_id, key, serde_json::to_string(value)?, now],
            )?;
            Ok(())
        })
    }

    pub fn delete_value(&self, plugin_id: &str, key: &str) -> PluginResult<()> {
        self.with(|c| {
            let key = Self::kv_key(c, plugin_id, key)?;
            c.execute("DELETE FROM plugin_kv WHERE plugin_id = ? AND key = ?", params![plugin_id, key])?;
            Ok(())
        })
    }

    pub fn list_keys(&self, plugin_id: &str) -> PluginResult<Vec<String>> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            let keys: Vec<String> = c
                .prepare("SELECT key FROM plugin_kv WHERE plugin_id = ? ORDER BY key COLLATE BINARY")?
                .query_map([plugin_id], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            if owner == plugin_id {
                return Ok(keys);
            }
            let prefix = format!("{owner}:");
            Ok(keys.into_iter().filter_map(|k| k.strip_prefix(&prefix).map(str::to_string)).collect())
        })
    }

    // ---- settings ---------------------------------------------------------

    pub fn get_setting(&self, plugin_id: &str, setting_id: &str, scope: &str, scope_id: &str) -> PluginResult<Option<Value>> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            let row: Option<String> = c
                .query_row(
                    "SELECT value_json FROM plugin_settings WHERE plugin_id = ? AND setting_id = ? AND scope = ? AND scope_id = ?",
                    params![owner, setting_id, scope, scope_id],
                    |r| r.get(0),
                )
                .optional()?;
            row.map(|t| parse_json(&t, "setting value")).transpose()
        })
    }

    pub fn set_setting(&self, plugin_id: &str, setting_id: &str, scope: &str, scope_id: &str, value: &Value, updated_at: Option<i64>) -> PluginResult<()> {
        let stamp = updated_at.unwrap_or_else(|| self.now());
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            c.execute(
                "INSERT INTO plugin_settings(plugin_id, setting_id, scope, scope_id, value_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(plugin_id, setting_id, scope, scope_id) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
                params![owner, setting_id, scope, scope_id, serde_json::to_string(value)?, stamp],
            )?;
            Ok(())
        })
    }

    pub fn delete_setting(&self, plugin_id: &str, setting_id: &str, scope: &str, scope_id: &str) -> PluginResult<()> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            c.execute(
                "DELETE FROM plugin_settings WHERE plugin_id = ? AND setting_id = ? AND scope = ? AND scope_id = ?",
                params![owner, setting_id, scope, scope_id],
            )?;
            Ok(())
        })
    }

    pub fn list_settings(&self, plugin_id: &str) -> PluginResult<Vec<SettingRow>> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            let rows: Vec<(String, String, String, String, i64)> = c
                .prepare(
                    "SELECT setting_id, scope, scope_id, value_json, updated_at FROM plugin_settings WHERE plugin_id = ?
                     ORDER BY setting_id COLLATE BINARY, scope COLLATE BINARY, scope_id COLLATE BINARY",
                )?
                .query_map([owner], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
                .collect::<Result<_, _>>()?;
            rows.into_iter()
                .map(|(setting_id, scope, scope_id, value, updated_at)| {
                    Ok(SettingRow { plugin_id: None, setting_id, scope, scope_id, value: parse_json(&value, "setting value")?, updated_at })
                })
                .collect()
        })
    }

    pub fn list_all_settings(&self) -> PluginResult<Vec<SettingRow>> {
        self.with(|c| {
            let rows: Vec<(String, String, String, String, String, i64)> = c
                .prepare(
                    "SELECT plugin_id, setting_id, scope, scope_id, value_json, updated_at FROM plugin_settings
                     ORDER BY plugin_id COLLATE BINARY, setting_id COLLATE BINARY, scope COLLATE BINARY, scope_id COLLATE BINARY",
                )?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
                .collect::<Result<_, _>>()?;
            rows.into_iter()
                .map(|(plugin_id, setting_id, scope, scope_id, value, updated_at)| {
                    Ok(SettingRow { plugin_id: Some(plugin_id), setting_id, scope, scope_id, value: parse_json(&value, "setting value")?, updated_at })
                })
                .collect()
        })
    }

    // ---- sync sidecars ------------------------------------------------------

    pub fn get_sync_sidecar(&self, plugin_id: &str, kind: &str, key: &str) -> PluginResult<Option<SidecarRow>> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            let row: Option<(String, i64)> = c
                .query_row(
                    "SELECT value_json, updated_at FROM plugin_sync_sidecars WHERE plugin_id = ? AND kind = ? AND key = ?",
                    params![owner, kind, key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            row.map(|(value, updated_at)| {
                Ok(SidecarRow { plugin_id: owner.clone(), kind: kind.into(), key: key.into(), value: parse_json(&value, "sync sidecar value")?, updated_at })
            })
            .transpose()
        })
    }

    pub fn set_sync_sidecar(&self, plugin_id: &str, kind: &str, key: &str, value: &Value, updated_at: Option<i64>) -> PluginResult<()> {
        let stamp = updated_at.unwrap_or_else(|| self.now());
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            c.execute(
                "INSERT INTO plugin_sync_sidecars(plugin_id, kind, key, value_json, updated_at) VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(plugin_id, kind, key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
                params![owner, kind, key, serde_json::to_string(value)?, stamp],
            )?;
            Ok(())
        })
    }

    pub fn delete_sync_sidecar(&self, plugin_id: &str, kind: &str, key: &str) -> PluginResult<()> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            c.execute("DELETE FROM plugin_sync_sidecars WHERE plugin_id = ? AND kind = ? AND key = ?", params![owner, kind, key])?;
            Ok(())
        })
    }

    fn sidecar_rows(c: &Connection, sql: &str, args: &[&dyn rusqlite::ToSql]) -> PluginResult<Vec<SidecarRow>> {
        let rows: Vec<(String, String, Vec<u8>, String, i64)> = c
            .prepare(sql)?
            .query_map(args, |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(plugin_id, kind, key, value, updated_at)| {
                Ok(SidecarRow {
                    plugin_id,
                    kind,
                    key: String::from_utf8_lossy(&key).into_owned(),
                    value: parse_json(&value, "sync sidecar value")?,
                    updated_at,
                })
            })
            .collect()
    }

    pub fn list_sync_sidecars(&self, plugin_id: &str) -> PluginResult<Vec<SidecarRow>> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            Self::sidecar_rows(
                c,
                "SELECT plugin_id, kind, CAST(key AS BLOB), value_json, updated_at FROM plugin_sync_sidecars WHERE plugin_id = ?
                 ORDER BY kind COLLATE BINARY, key COLLATE BINARY",
                &[&owner],
            )
        })
    }

    pub fn list_all_sync_sidecars(&self) -> PluginResult<Vec<SidecarRow>> {
        self.with(|c| {
            Self::sidecar_rows(
                c,
                "SELECT plugin_id, kind, CAST(key AS BLOB), value_json, updated_at FROM plugin_sync_sidecars
                 ORDER BY plugin_id COLLATE BINARY, kind COLLATE BINARY, key COLLATE BINARY",
                &[],
            )
        })
    }

    pub fn replace_all_sync_sidecars(&self, entries: &[SidecarRow]) -> PluginResult<()> {
        let now = self.now();
        self.transaction(|c| {
            c.execute("DELETE FROM plugin_sync_sidecars", [])?;
            for entry in entries {
                c.execute(
                    "INSERT INTO plugin_sync_sidecars(plugin_id, kind, key, value_json, updated_at) VALUES (?, ?, ?, ?, ?)",
                    params![entry.plugin_id, entry.kind, entry.key, serde_json::to_string(&entry.value)?, if entry.updated_at != 0 { entry.updated_at } else { now }],
                )?;
            }
            Ok(())
        })
    }

    // ---- view state ---------------------------------------------------------

    pub fn get_view_state(&self, plugin_id: &str, view_id: &str, scope_id: &str) -> PluginResult<Option<Value>> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            let row: Option<String> = c
                .query_row(
                    "SELECT state_json FROM plugin_view_state WHERE plugin_id = ? AND view_id = ? AND scope_id = ?",
                    params![owner, view_id, scope_id],
                    |r| r.get(0),
                )
                .optional()?;
            row.map(|t| parse_json(&t, "view state")).transpose()
        })
    }

    pub fn set_view_state(&self, plugin_id: &str, view_id: &str, scope_id: &str, state: &Value) -> PluginResult<()> {
        let now = self.now();
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            c.execute(
                "INSERT INTO plugin_view_state(plugin_id, view_id, scope_id, state_json, updated_at) VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(plugin_id, view_id, scope_id) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at",
                params![owner, view_id, scope_id, serde_json::to_string(state)?, now],
            )?;
            Ok(())
        })
    }

    pub fn delete_view_state(&self, plugin_id: &str, view_id: &str, scope_id: &str) -> PluginResult<()> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            c.execute("DELETE FROM plugin_view_state WHERE plugin_id = ? AND view_id = ? AND scope_id = ?", params![owner, view_id, scope_id])?;
            Ok(())
        })
    }

    // ---- permission grants ------------------------------------------------

    pub fn list_permission_grants(&self, plugin_id: &str) -> PluginResult<Vec<GrantRow>> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            let rows: Vec<(String, String, String, String, i64)> = c
                .prepare(
                    "SELECT permission, resource, resource_kind, declaration_hash, granted_at FROM plugin_permission_grants
                     WHERE plugin_id = ? ORDER BY permission COLLATE BINARY, resource COLLATE BINARY",
                )?
                .query_map([owner], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
                .collect::<Result<_, _>>()?;
            Ok(rows
                .into_iter()
                .map(|(permission, resource, resource_kind, declaration_hash, granted_at)| GrantRow {
                    plugin_id: plugin_id.to_string(),
                    permission,
                    resource,
                    resource_kind,
                    declaration_hash,
                    granted_at,
                })
                .collect())
        })
    }

    pub fn upsert_permission_grant(&self, plugin_id: &str, permission: &str, resource: &str, resource_kind: &str, declaration_hash: &str) -> PluginResult<()> {
        let now = self.now();
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            c.execute(
                "INSERT INTO plugin_permission_grants(plugin_id, permission, resource, resource_kind, declaration_hash, granted_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(plugin_id, permission, resource) DO UPDATE SET
                   resource_kind = excluded.resource_kind, declaration_hash = excluded.declaration_hash, granted_at = excluded.granted_at",
                params![owner, permission, resource, resource_kind, declaration_hash, now],
            )?;
            Ok(())
        })
    }

    pub fn delete_permission_grant(&self, plugin_id: &str, permission: &str, resource: &str) -> PluginResult<()> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            c.execute(
                "DELETE FROM plugin_permission_grants WHERE plugin_id = ? AND permission = ? AND resource = ?",
                params![owner, permission, resource],
            )?;
            Ok(())
        })
    }

    pub fn delete_all_permission_grants(&self, plugin_id: &str) -> PluginResult<()> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            c.execute("DELETE FROM plugin_permission_grants WHERE plugin_id = ?", [owner])?;
            Ok(())
        })
    }

    // ---- secrets ---------------------------------------------------------------

    fn secret_rows(c: &Connection, sql: &str, args: &[&dyn rusqlite::ToSql]) -> PluginResult<Vec<SecretRow>> {
        let rows: Vec<(String, String, String, Vec<u8>, i64, i64)> = c
            .prepare(sql)?
            .query_map(args, |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
            .collect::<Result<_, _>>()?;
        Ok(rows
            .into_iter()
            .map(|(owner, key, secret_ref, ciphertext, created_at, updated_at)| SecretRow {
                plugin_id: public_id(c, &owner),
                key,
                secret_ref,
                ciphertext,
                created_at,
                updated_at,
            })
            .collect())
    }

    pub fn get_secret_by_key(&self, plugin_id: &str, key: &str) -> PluginResult<Option<SecretRow>> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            Ok(Self::secret_rows(
                c,
                "SELECT plugin_id, key, secret_ref, ciphertext, created_at, updated_at FROM plugin_secrets WHERE plugin_id = ? AND key = ?",
                &[&owner, &key],
            )?
            .into_iter()
            .next())
        })
    }

    pub fn get_secret_by_ref(&self, plugin_id: &str, secret_ref: &str) -> PluginResult<Option<SecretRow>> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            Ok(Self::secret_rows(
                c,
                "SELECT plugin_id, key, secret_ref, ciphertext, created_at, updated_at FROM plugin_secrets WHERE plugin_id = ? AND secret_ref = ?",
                &[&owner, &secret_ref],
            )?
            .into_iter()
            .next())
        })
    }

    pub fn upsert_secret(&self, plugin_id: &str, key: &str, secret_ref: &str, ciphertext: &[u8]) -> PluginResult<()> {
        let now = self.now();
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            c.execute(
                "INSERT INTO plugin_secrets(plugin_id, key, secret_ref, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(plugin_id, key) DO UPDATE SET secret_ref = excluded.secret_ref, ciphertext = excluded.ciphertext, updated_at = excluded.updated_at",
                params![owner, key, secret_ref, ciphertext, now, now],
            )?;
            Ok(())
        })
    }

    pub fn delete_secret(&self, plugin_id: &str, key: &str) -> PluginResult<()> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            c.execute("DELETE FROM plugin_secrets WHERE plugin_id = ? AND key = ?", params![owner, key])?;
            Ok(())
        })
    }

    pub fn delete_secrets_by_key_prefix(&self, plugin_id: &str, prefix: &str) -> PluginResult<usize> {
        self.with(|c| {
            let owner = owner_of(c, plugin_id)?;
            Ok(c.execute(
                "DELETE FROM plugin_secrets WHERE plugin_id = ? AND (key = ? OR key LIKE ? ESCAPE '\\')",
                params![owner, prefix, format!("{}:%", escape_like(prefix))],
            )?)
        })
    }

    pub fn find_secrets_by_key(&self, key: &str) -> PluginResult<Vec<SecretRow>> {
        self.with(|c| {
            Self::secret_rows(
                c,
                "SELECT plugin_id, key, secret_ref, ciphertext, created_at, updated_at FROM plugin_secrets WHERE key = ?",
                &[&key],
            )
        })
    }

    pub fn list_plugin_ids_with_secret_key_prefix(&self, prefix: &str) -> PluginResult<Vec<String>> {
        self.with(|c| {
            let owners: Vec<String> = c
                .prepare("SELECT DISTINCT plugin_id FROM plugin_secrets WHERE key = ? OR key LIKE ? ESCAPE '\\'")?
                .query_map(params![prefix, format!("{}:%", escape_like(prefix))], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            Ok(owners.iter().filter_map(|o| public_id(c, o)).collect())
        })
    }

    // ---- sync provider bindings ------------------------------------------

    pub fn upsert_sync_provider_binding(&self, provider_id: &str, plugin_id: &str) -> PluginResult<()> {
        let now = self.now();
        self.with(|c| {
            c.execute(
                "INSERT INTO plugin_sync_provider_bindings(provider_id, plugin_id, created_at, updated_at) VALUES (?, ?, ?, ?)
                 ON CONFLICT(provider_id) DO UPDATE SET plugin_id = excluded.plugin_id, updated_at = excluded.updated_at",
                params![provider_id, plugin_id, now, now],
            )?;
            Ok(())
        })
    }

    pub fn get_sync_provider_binding(&self, provider_id: &str) -> PluginResult<Option<SyncBinding>> {
        self.with(|c| {
            Ok(c.query_row(
                "SELECT provider_id, plugin_id FROM plugin_sync_provider_bindings WHERE provider_id = ?",
                [provider_id],
                |r| Ok(SyncBinding { provider_id: r.get(0)?, plugin_id: r.get(1)? }),
            )
            .optional()?)
        })
    }

    pub fn delete_sync_provider_binding(&self, provider_id: &str) -> PluginResult<usize> {
        self.with(|c| Ok(c.execute("DELETE FROM plugin_sync_provider_bindings WHERE provider_id = ?", [provider_id])?))
    }

    /// `backfillSyncProviderBindingsFromLegacySecrets` (see the Electron
    /// comment: credential presence is the only ownership signal; ambiguous
    /// candidates stay unbound).
    pub fn backfill_sync_provider_bindings_from_legacy_secrets(&self) -> PluginResult<usize> {
        let legacy_prefix = "sync-provider-map:";
        let legacy: Vec<(String, String)> = self.with(|c| {
            let rows: Vec<(String, String)> = c
                .prepare("SELECT plugin_id, key FROM plugin_secrets WHERE key LIKE ? ESCAPE '\\'")?
                .query_map([format!("{}%", escape_like(legacy_prefix))], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            Ok(rows.into_iter().filter_map(|(owner, key)| public_id(c, &owner).map(|id| (id, key))).collect())
        })?;
        let mut by_provider: std::collections::BTreeMap<String, Vec<(String, String)>> = Default::default();
        for (plugin_id, key) in legacy {
            let Some(provider_id) = key.strip_prefix(legacy_prefix) else { continue };
            if provider_id.is_empty() || provider_id.contains('\0') || !provider_id.starts_with(&format!("{plugin_id}.")) {
                continue;
            }
            by_provider.entry(provider_id.to_string()).or_default().push((plugin_id, key.clone()));
        }
        let credential_owners: std::collections::HashSet<String> =
            self.list_plugin_ids_with_secret_key_prefix("sync-credential")?.into_iter().collect();
        let mut providers_by_owner: std::collections::HashMap<String, std::collections::HashSet<String>> = Default::default();
        for (provider_id, candidates) in &by_provider {
            for (plugin_id, _) in candidates {
                if credential_owners.contains(plugin_id) {
                    providers_by_owner.entry(plugin_id.clone()).or_default().insert(provider_id.clone());
                }
            }
        }
        let versions = self.list_installed_versions().unwrap_or_default();
        for version in &versions {
            if !credential_owners.contains(&version.plugin_id) {
                continue;
            }
            for provider in sync_provider_ids(&version.manifest) {
                providers_by_owner.entry(version.plugin_id.clone()).or_default().insert(provider);
            }
        }
        let mut promoted = 0;
        for (provider_id, candidates) in by_provider {
            if self.get_sync_provider_binding(&provider_id)?.is_some() {
                continue;
            }
            let owners: std::collections::BTreeSet<&String> =
                candidates.iter().filter(|(p, _)| credential_owners.contains(p)).map(|(p, _)| p).collect();
            if owners.len() != 1 {
                continue;
            }
            let chosen = (*owners.iter().next().expect("one owner")).clone();
            if providers_by_owner.get(&chosen).map_or(0, |s| s.len()) != 1 {
                continue;
            }
            let conflict = versions
                .iter()
                .any(|v| v.plugin_id != chosen && sync_provider_ids(&v.manifest).iter().any(|p| p == &provider_id));
            if conflict {
                continue;
            }
            self.upsert_sync_provider_binding(&provider_id, &chosen)?;
            for (plugin_id, key) in &candidates {
                self.delete_secret(plugin_id, key)?;
            }
            promoted += 1;
        }
        Ok(promoted)
    }

    // ---- audit / host preferences ------------------------------------------

    pub fn record_security_audit(&self, plugin_id: &str, event: &str, details: &Value) -> PluginResult<()> {
        let mut details_json = serde_json::to_string(details)?;
        if details_json.len() > MAX_SECURITY_AUDIT_DETAILS_BYTES {
            details_json = serde_json::to_string(&json!({
                "truncated": true,
                "originalBytes": details_json.len(),
                "sha256": hex::encode(Sha256::digest(details_json.as_bytes())),
            }))?;
        }
        let now = self.now();
        self.transaction(|c| append_audit(c, plugin_id, event, &details_json, now))
    }

    pub fn get_permission_mode(&self, plugin_id: &str, permission: &str) -> PluginResult<String> {
        self.with(|c| {
            let key = format!("permission:{}:{permission}", owner_of(c, plugin_id)?);
            let row: Option<String> = c
                .query_row("SELECT value_json FROM plugin_host_preferences WHERE key = ?", [key], |r| r.get(0))
                .optional()?;
            let mode = match row {
                Some(text) => parse_json(&text, "permission mode")?.as_str().unwrap_or("").to_string(),
                None => "allow".into(),
            };
            if !matches!(mode.as_str(), "allow" | "ask" | "deny") {
                return Err(PluginError::host("Corrupt plugin permission mode"));
            }
            Ok(mode)
        })
    }

    pub fn set_permission_mode(&self, plugin_id: &str, permission: &str, mode: &str) -> PluginResult<()> {
        let now = self.now();
        self.transaction(|c| {
            let owner = owner_of(c, plugin_id)?;
            c.execute(
                "INSERT INTO plugin_host_preferences(key,value_json,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",
                params![format!("permission:{owner}:{permission}"), serde_json::to_string(mode)?, now],
            )?;
            let details = serde_json::to_string(&json!({ "permission": permission, "mode": mode, "sourceOwner": owner }))?;
            append_audit(c, plugin_id, "permission.policy-edited", &details, now)
        })
    }

    pub fn get_host_theme_selection(&self) -> PluginResult<Value> {
        self.with(|c| theme_selection(c))
    }

    pub fn commit_host_theme_selection(&self, expected_revision: i64, selection: &Value, plugin_id: Option<&str>) -> PluginResult<()> {
        let now = self.now();
        self.transaction(|c| {
            if theme_selection(c)?.get("revision").and_then(Value::as_i64) != Some(expected_revision) {
                return Err(PluginError::host("Theme selection changed; refresh before applying"));
            }
            c.execute(
                "INSERT INTO plugin_host_preferences(key,value_json,updated_at) VALUES('theme',?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",
                params![serde_json::to_string(selection)?, now],
            )?;
            let details = serde_json::to_string(&json!({
                "revision": selection.get("revision"),
                "action": if plugin_id.is_some() { "apply" } else { "restore" },
            }))?;
            append_audit(c, plugin_id.unwrap_or("$host.appearance"), "theme-selection", &details, now)
        })
    }

    pub fn list_security_audit(&self, plugin_id: &str, limit: i64) -> PluginResult<Vec<AuditRow>> {
        let limit = limit.clamp(1, 1_000);
        self.with(|c| {
            let rows: Vec<(String, String, i64)> = c
                .prepare("SELECT event, details_json, created_at FROM plugin_security_audit WHERE plugin_id = ? ORDER BY id DESC LIMIT ?")?
                .query_map(params![plugin_id, limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?;
            rows.into_iter()
                .map(|(event, details, created_at)| Ok(AuditRow { event, details: parse_json(&details, "security audit entry")?, created_at }))
                .collect()
        })
    }
}

fn finish_tx<T>(conn: &Connection, result: PluginResult<T>) -> PluginResult<T> {
    match result {
        Ok(value) => {
            conn.execute_batch("COMMIT")?;
            Ok(value)
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(err)
        }
    }
}

fn escape_like(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

fn sync_provider_ids(manifest: &Value) -> Vec<String> {
    manifest
        .get("contributes")
        .and_then(|c| c.get("providers"))
        .and_then(Value::as_array)
        .map(|providers| {
            providers
                .iter()
                .filter(|p| p.get("kind").and_then(Value::as_str) == Some("sync"))
                .filter_map(|p| p.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn append_audit(c: &Connection, plugin_id: &str, event: &str, details_json: &str, now: i64) -> PluginResult<()> {
    c.execute(
        "INSERT INTO plugin_security_audit(plugin_id, event, details_json, created_at) VALUES (?, ?, ?, ?)",
        params![plugin_id, event, details_json, now],
    )?;
    c.execute(
        &format!(
            "DELETE FROM plugin_security_audit WHERE plugin_id = ? AND id NOT IN (
               SELECT id FROM plugin_security_audit WHERE plugin_id = ? ORDER BY id DESC LIMIT {MAX_SECURITY_AUDIT_RECORDS_PER_PLUGIN})"
        ),
        params![plugin_id, plugin_id],
    )?;
    Ok(())
}

fn theme_selection(c: &Connection) -> PluginResult<Value> {
    let row: Option<String> = c
        .query_row("SELECT value_json FROM plugin_host_preferences WHERE key = 'theme'", [], |r| r.get(0))
        .optional()?;
    match row {
        Some(text) => parse_json(&text, "host theme selection"),
        None => Ok(json!({ "formatVersion": 1, "revision": 0, "light": null, "dark": null })),
    }
}

fn bound_source(c: &Connection, plugin_id: &str) -> PluginResult<Option<Source>> {
    let row: Option<String> = c
        .query_row("SELECT source_json FROM plugin_source_bindings WHERE plugin_id = ?", [plugin_id], |r| r.get(0))
        .optional()?;
    match row {
        Some(text) => {
            let value = parse_json(&text, "source identity")?;
            let source: Source = serde_json::from_value(value).map_err(|_| PluginError::host("Invalid host source identity"))?;
            Ok(Some(assert_source(&source)?))
        }
        None => Ok(None),
    }
}

fn source_of(c: &Connection, plugin_id: &str) -> PluginResult<Source> {
    Ok(bound_source(c, plugin_id)?.unwrap_or_else(Source::local))
}

fn owner_of(c: &Connection, plugin_id: &str) -> PluginResult<String> {
    if is_private_owner(plugin_id) {
        return Ok(plugin_id.to_string());
    }
    private_owner(&source_of(c, plugin_id)?, plugin_id)
}

fn public_id(c: &Connection, owner: &str) -> Option<String> {
    if !is_private_owner(owner) {
        return None;
    }
    let plugin_id = &owner[owner.rfind(':')? + 1..];
    (owner_of(c, plugin_id).ok()?.as_str() == owner).then(|| plugin_id.to_string())
}

fn assert_install_source(c: &Connection, plugin_id: &str, source: &Source) -> PluginResult<Source> {
    let trusted = assert_source(source)?;
    let existing = match bound_source(c, plugin_id)? {
        Some(source) => Some(source),
        None => {
            let installed = c.query_row("SELECT id FROM plugins WHERE id = ?", [plugin_id], |_| Ok(())).optional()?.is_some();
            installed.then(Source::local)
        }
    };
    if let Some(existing) = existing {
        if existing.id != trusted.id {
            return Err(PluginError::host(
                "Plugin source differs. Uninstall and explicitly clear the old source's private data before reinstalling.",
            ));
        }
    }
    Ok(trusted)
}

fn get_version(c: &Connection, plugin_id: &str, version: &str) -> PluginResult<Option<VersionRecord>> {
    let row: Option<(String, String, String, String, String, i64)> = c
        .query_row(
            "SELECT plugin_id, version, manifest_json, archive_sha256, package_relative_path, installed_at
             FROM plugin_versions WHERE plugin_id = ? AND version = ?",
            params![plugin_id, version],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()?;
    row.map(map_version).transpose()
}

fn map_version(row: (String, String, String, String, String, i64)) -> PluginResult<VersionRecord> {
    Ok(VersionRecord {
        plugin_id: row.0,
        version: row.1,
        manifest: parse_json(&row.2, "manifest")?,
        archive_sha256: row.3,
        package_relative_path: row.4,
        installed_at: row.5,
    })
}

const PLUGIN_SELECT: &str = "SELECT p.id, p.enabled, p.active_version, p.installed_at, p.updated_at,
       v.manifest_json, v.archive_sha256, v.package_relative_path,
       r.status, r.runtime_kind, r.last_error, r.quarantined_at
FROM plugins p
LEFT JOIN plugin_versions v ON v.plugin_id = p.id AND v.version = p.active_version
LEFT JOIN plugin_runtime_state r ON r.plugin_id = p.id AND r.plugin_version = p.active_version";

struct RawPlugin {
    id: String,
    enabled: i64,
    active_version: Option<String>,
    installed_at: i64,
    updated_at: i64,
    manifest_json: Option<String>,
    archive_sha256: Option<String>,
    package_relative_path: Option<String>,
    status: Option<String>,
    runtime_kind: Option<String>,
    last_error: Option<String>,
    quarantined_at: Option<i64>,
}

fn map_plugin_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawPlugin> {
    Ok(RawPlugin {
        id: r.get(0)?,
        enabled: r.get(1)?,
        active_version: r.get(2)?,
        installed_at: r.get(3)?,
        updated_at: r.get(4)?,
        manifest_json: r.get(5)?,
        archive_sha256: r.get(6)?,
        package_relative_path: r.get(7)?,
        status: r.get(8)?,
        runtime_kind: r.get(9)?,
        last_error: r.get(10)?,
        quarantined_at: r.get(11)?,
    })
}

fn finish_plugin(c: &Connection, row: RawPlugin) -> PluginResult<PluginRecord> {
    Ok(PluginRecord {
        source: source_of(c, &row.id)?,
        id: row.id,
        enabled: row.enabled == 1,
        active_version: row.active_version,
        installed_at: row.installed_at,
        updated_at: row.updated_at,
        manifest: row.manifest_json.map(|m| parse_json(&m, "manifest")).transpose()?,
        archive_sha256: row.archive_sha256,
        package_relative_path: row.package_relative_path,
        runtime: RuntimeState {
            status: row.status.unwrap_or_else(|| "stopped".into()),
            kind: row.runtime_kind,
            last_error: row.last_error,
            quarantined_at: row.quarantined_at,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;

    fn record(version: &str) -> InstallRecord {
        InstallRecord {
            source: Source::local(),
            plugin_id: "com.example.plugin".into(),
            version: version.into(),
            manifest: json!({ "id": "com.example.plugin", "version": version }),
            archive_sha256: "a".repeat(64),
            package_relative_path: format!("com.example.plugin/{version}/package"),
        }
    }

    fn open(dir: &Path) -> (PluginDatabase, Arc<AtomicI64>) {
        let clock = Arc::new(AtomicI64::new(1_000));
        let c = clock.clone();
        let db = PluginDatabase::open_with_clock(&dir.join("plugins.sqlite"), Box::new(move || c.load(Ordering::SeqCst))).unwrap();
        (db, clock)
    }

    #[test]
    fn schema_layout_and_version() {
        let dir = tempfile::tempdir().unwrap();
        let (db, _) = open(dir.path());
        let version: i64 = db.with(|c| Ok(c.query_row("PRAGMA user_version", [], |r| r.get(0))?)).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        drop(db);
        // Reopen is idempotent.
        let (db, _) = open(dir.path());
        assert!(db.list_plugins().unwrap().is_empty());
    }

    #[test]
    fn rejects_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plugins.sqlite");
        Connection::open(&path).unwrap().execute_batch("PRAGMA user_version = 99").unwrap();
        assert!(PluginDatabase::open(&path).is_err());
    }

    #[test]
    fn install_enable_and_version_scoped_quarantine() {
        let dir = tempfile::tempdir().unwrap();
        let (db, clock) = open(dir.path());
        db.install_version(&record("1.0.0"), true, false).unwrap();
        let plugin = db.get_active_plugin("com.example.plugin").unwrap().unwrap();
        assert!(plugin.enabled);
        assert_eq!(plugin.runtime.status, "stopped");
        for i in 0..2 {
            clock.store(2_000 + i, Ordering::SeqCst);
            assert!(!db.record_crash("com.example.plugin", "1.0.0", 300_000, 3).unwrap().quarantined);
        }
        let crash = db.record_crash("com.example.plugin", "1.0.0", 300_000, 3).unwrap();
        assert!(crash.quarantined);
        assert_eq!(db.get_active_plugin("com.example.plugin").unwrap().unwrap().runtime.status, "quarantined");
        // A new version starts clean.
        db.install_version(&record("1.1.0"), false, false).unwrap();
        let plugin = db.get_active_plugin("com.example.plugin").unwrap().unwrap();
        assert_eq!(plugin.active_version.as_deref(), Some("1.1.0"));
        assert_eq!(plugin.runtime.status, "stopped");
        // Restoring the old version restores its quarantine.
        db.set_active_version("com.example.plugin", "1.0.0", false, Some("1.1.0")).unwrap();
        assert_eq!(db.get_active_plugin("com.example.plugin").unwrap().unwrap().runtime.status, "quarantined");
        db.clear_quarantine("com.example.plugin", None).unwrap();
        assert_eq!(db.get_active_plugin("com.example.plugin").unwrap().unwrap().runtime.status, "stopped");
        assert!(db.set_active_version("com.example.plugin", "1.1.0", false, Some("9.9.9")).is_err());
    }

    #[test]
    fn private_storage_is_source_namespaced() {
        let dir = tempfile::tempdir().unwrap();
        let (db, _) = open(dir.path());
        db.install_version(&record("1.0.0"), false, false).unwrap();
        db.set_value("com.example.plugin", "k", &json!({"a": 1})).unwrap();
        assert_eq!(db.get_value("com.example.plugin", "k").unwrap(), Some(json!({"a": 1})));
        assert_eq!(db.list_keys("com.example.plugin").unwrap(), vec!["k".to_string()]);
        db.set_setting("com.example.plugin", "com.example.plugin.s", "application", "", &json!(true), None).unwrap();
        let owner = db.private_owner("com.example.plugin").unwrap();
        assert_eq!(db.public_plugin_id(&owner).as_deref(), Some("com.example.plugin"));
        assert_eq!(db.list_all_settings().unwrap()[0].plugin_id.as_deref(), Some(owner.as_str()));
        // Source switch is rejected until data is cleared.
        let third = crate::source::third_party_source("X", "https://plugins.example.com").unwrap();
        assert!(db.assert_install_source("com.example.plugin", &third).is_err());
        db.remove_plugin("com.example.plugin").unwrap();
        db.clear_uninstalled_source_data("com.example.plugin", "local").unwrap();
        assert!(db.assert_install_source("com.example.plugin", &third).is_ok());
    }

    #[test]
    fn permission_modes_and_audit_cap() {
        let dir = tempfile::tempdir().unwrap();
        let (db, _) = open(dir.path());
        assert_eq!(db.get_permission_mode("com.example.plugin", "commands").unwrap(), "allow");
        db.set_permission_mode("com.example.plugin", "commands", "ask").unwrap();
        assert_eq!(db.get_permission_mode("com.example.plugin", "commands").unwrap(), "ask");
        let big = json!({ "x": "y".repeat(20_000) });
        db.record_security_audit("com.example.plugin", "e", &big).unwrap();
        let audit = db.list_security_audit("com.example.plugin", 10).unwrap();
        assert_eq!(audit[0].details["truncated"], json!(true));
        assert_eq!(audit.len(), 2);
    }
}
