//! Encrypted cloud-sync sidecars of plugin settings (ports of
//! `pluginSyncSidecarService.cjs` and `pluginSyncSidecarHelpers.cjs`).
//!
//! Only settings declared `sync: true` and not `secret` leave the device.
//! Rows are keyed by the opaque source owner; sidecars of plugins that are
//! not installed here are preserved for other devices.

use crate::contributions::ContributionService;
use crate::database::{PluginDatabase, SidecarRow};
use crate::error::PluginResult;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

#[derive(Clone)]
struct Field {
    id: String,
    secret: bool,
    sync: bool,
    scope: String,
}

fn syncable(field: &Field) -> bool {
    !field.secret && field.sync
}

pub fn settings_key(setting_id: &str, scope: &str, scope_id: &str) -> String {
    format!("{setting_id}\0{scope}\0{scope_id}")
}

fn parse_key(key: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = key.split('\0').collect();
    (parts.len() == 3 && parts.iter().all(|p| !p.is_empty())).then(|| (parts[0].into(), parts[1].into(), parts[2].into()))
}

fn target(field: &Field, scope: &str, scope_id: &str) -> Option<(String, String)> {
    let target_scope = if field.scope.is_empty() { scope.to_string() } else { field.scope.clone() };
    let target_id = match target_scope.as_str() {
        "application" => "application".to_string(),
        "device" => if scope == "device" { scope_id.to_string() } else { "device".to_string() },
        s if s != scope => return None,
        _ => scope_id.to_string(),
    };
    Some((target_scope, target_id))
}

fn kind_ok(kind: &str) -> bool {
    matches!(kind, "settings" | "account_baseline" | "crdt_baseline")
}

fn row_from(value: &Value) -> Option<SidecarRow> {
    let kind = value["kind"].as_str().filter(|k| kind_ok(k))?;
    Some(SidecarRow {
        plugin_id: value["pluginId"].as_str()?.to_string(),
        kind: kind.into(),
        key: value["key"].as_str().map(str::to_string).unwrap_or_else(|| value["key"].to_string()),
        value: value["value"].clone(),
        updated_at: value["updatedAt"].as_i64().unwrap_or(0),
    })
}

fn sort(rows: &mut [SidecarRow]) {
    rows.sort_by(|a, b| (a.plugin_id.as_str(), a.kind.as_str(), a.key.as_str()).cmp(&(b.plugin_id.as_str(), b.kind.as_str(), b.key.as_str())));
}

pub struct SidecarService {
    database: Arc<PluginDatabase>,
    contributions: Arc<ContributionService>,
}

impl SidecarService {
    pub fn new(database: Arc<PluginDatabase>, contributions: Arc<ContributionService>) -> Self {
        Self { database, contributions }
    }

    /// Owner → declared settings of enabled plugins.
    fn declared(&self) -> HashMap<String, Vec<Field>> {
        let snapshot = self.contributions.snapshot(&json!({})).unwrap_or(Value::Null);
        let mut map = HashMap::new();
        for plugin in snapshot["plugins"].as_array().cloned().unwrap_or_default() {
            let Ok(owner) = self.database.private_owner(plugin["id"].as_str().unwrap_or("")) else { continue };
            let fields = plugin["settings"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|s| Field { id: s["id"].as_str().unwrap_or("").into(), secret: s["secret"] == true, sync: s["sync"] == true, scope: s["scope"].as_str().unwrap_or("").into() })
                .collect();
            map.insert(owner, fields);
        }
        map
    }

    fn exclude_secret(rows: Vec<SidecarRow>, declared: &HashMap<String, Vec<Field>>) -> Vec<SidecarRow> {
        rows.into_iter()
            .filter(|row| {
                if row.kind != "settings" {
                    return true;
                }
                let Some(fields) = declared.get(&row.plugin_id) else { return true };
                let Some((setting, _, _)) = parse_key(&row.key) else { return false };
                fields.iter().find(|f| f.id == setting).is_none_or(syncable)
            })
            .collect()
    }

    fn to_bundle(rows: &[SidecarRow]) -> Value {
        json!({ "version": 1, "entries": rows.iter().map(|r| json!({ "pluginId": r.plugin_id, "kind": r.kind, "key": r.key, "value": r.value, "updatedAt": r.updated_at })).collect::<Vec<_>>() })
    }

    /// `collectForSync()`.
    pub fn collect(&self) -> PluginResult<Value> {
        let declared = self.declared();
        let now = crate::constants::now_ms();
        let mut entries = Vec::new();
        let mut settings: BTreeMap<String, SidecarRow> = BTreeMap::new();
        for row in self.database.list_all_sync_sidecars()? {
            if row.kind != "settings" {
                entries.push(row);
                continue;
            }
            if let Some(fields) = declared.get(&row.plugin_id) {
                let Some((setting, _, _)) = parse_key(&row.key) else { continue };
                if fields.iter().find(|f| f.id == setting).is_some_and(|f| !syncable(f)) {
                    continue;
                }
            }
            settings.insert(format!("{}\0{}", row.plugin_id, row.key), row);
        }
        for stored in self.database.list_all_settings()? {
            let owner = stored.plugin_id.clone().unwrap_or_default();
            let Some(field) = declared.get(&owner).and_then(|f| f.iter().find(|f| f.id == stored.setting_id)) else { continue };
            if !syncable(field) {
                continue;
            }
            let key = settings_key(&stored.setting_id, &stored.scope, &stored.scope_id);
            let entry = SidecarRow { plugin_id: owner.clone(), kind: "settings".into(), key: key.clone(), value: stored.value.clone(), updated_at: if stored.updated_at != 0 { stored.updated_at } else { now } };
            let map_key = format!("{owner}\0{key}");
            if settings.get(&map_key).is_none_or(|p| entry.updated_at >= p.updated_at) {
                settings.insert(map_key, entry);
            }
        }
        entries.extend(settings.into_values());
        let mut entries = Self::exclude_secret(entries, &declared);
        sort(&mut entries);
        self.database.replace_all_sync_sidecars(&entries)?;
        Ok(Self::to_bundle(&entries))
    }

    async fn apply_setting(&self, owner: &str, row: &SidecarRow, fields: &[Field]) {
        let Some(public) = self.database.public_plugin_id(owner) else { return };
        let Some((setting, scope, scope_id)) = parse_key(&row.key) else { return };
        let Some(field) = fields.iter().find(|f| f.id == setting).filter(|f| syncable(f)) else { return };
        let Some((target_scope, target_id)) = target(field, &scope, &scope_id) else { return };
        if self.contributions.update_setting(&public, &setting, &row.value, Some(&target_id), "host").await.is_err() {
            return;
        }
        let _ = self.database.set_setting(owner, &setting, &target_scope, &target_id, &row.value, Some(row.updated_at));
        if target_scope != scope || target_id != scope_id {
            let _ = self.database.delete_setting(owner, &setting, &scope, &scope_id);
            let next = settings_key(&setting, &target_scope, &target_id);
            let _ = self.database.set_sync_sidecar(owner, "settings", &next, &row.value, Some(row.updated_at));
            if next != row.key {
                let _ = self.database.delete_sync_sidecar(owner, "settings", &row.key);
            }
        }
    }

    /// `applyFromSync(bundle)` → merged entries.
    pub async fn apply(&self, bundle: &Value) -> PluginResult<Value> {
        let declared = self.declared();
        let local = self.database.list_all_sync_sidecars()?;
        let remote: Vec<SidecarRow> = bundle["entries"].as_array().map(|a| a.iter().filter_map(row_from).collect()).unwrap_or_default();
        let authoritative_empty = bundle["entries"].as_array().is_some_and(|a| a.is_empty());
        let remote_plugins: HashSet<&str> = remote.iter().map(|r| r.plugin_id.as_str()).collect();
        let remote_keys: HashSet<String> = remote.iter().map(|r| format!("{}\0{}\0{}", r.plugin_id, r.kind, r.key)).collect();
        let mut merged: BTreeMap<String, SidecarRow> = BTreeMap::new();
        for row in local.iter().filter(|r| r.kind != "settings" || (!authoritative_empty && !declared.contains_key(&r.plugin_id) && !remote_plugins.contains(r.plugin_id.as_str()))) {
            merged.insert(format!("{}\0{}\0{}", row.plugin_id, row.kind, row.key), row.clone());
        }
        for row in remote {
            if row.kind == "settings" {
                if let Some(fields) = declared.get(&row.plugin_id) {
                    let setting = row.key.split('\0').next().unwrap_or("");
                    if fields.iter().find(|f| f.id == setting).is_some_and(|f| !syncable(f)) {
                        continue;
                    }
                }
            }
            let key = format!("{}\0{}\0{}", row.plugin_id, row.kind, row.key);
            if merged.get(&key).is_none_or(|p| row.updated_at >= p.updated_at) {
                merged.insert(key, row);
            }
        }
        let mut safe = Self::exclude_secret(merged.into_values().collect(), &declared);
        sort(&mut safe);
        self.database.replace_all_sync_sidecars(&safe)?;
        // Reset locally stored syncable settings the remote no longer has.
        let mut resets: Vec<(String, String)> = local
            .iter()
            .filter(|r| r.kind == "settings" && declared.contains_key(&r.plugin_id) && !remote_keys.contains(&format!("{}\0{}\0{}", r.plugin_id, r.kind, r.key)))
            .map(|r| (r.plugin_id.clone(), r.key.clone()))
            .collect();
        for row in self.database.list_all_settings()? {
            let owner = row.plugin_id.clone().unwrap_or_default();
            if declared.get(&owner).and_then(|f| f.iter().find(|f| f.id == row.setting_id)).is_some_and(syncable) {
                let key = settings_key(&row.setting_id, &row.scope, &row.scope_id);
                if !remote_keys.contains(&format!("{owner}\0settings\0{key}")) {
                    resets.push((owner, key));
                }
            }
        }
        resets.sort();
        resets.dedup();
        for (owner, key) in resets {
            let (Some(public), Some((setting, scope, scope_id))) = (self.database.public_plugin_id(&owner), parse_key(&key)) else { continue };
            let _ = self.contributions.reset_setting(&public, &setting, Some(&scope_id)).await;
            let _ = self.database.delete_setting(&owner, &setting, &scope, &scope_id);
        }
        for row in safe.iter().filter(|r| r.kind == "settings") {
            if let Some(fields) = declared.get(&row.plugin_id) {
                self.apply_setting(&row.plugin_id.clone(), row, fields).await;
            }
        }
        Ok(Self::to_bundle(&safe)["entries"].clone())
    }

    /// Replay retained sidecars into settings before activation.
    pub async fn hydrate(&self, plugin_id: &str) {
        let Ok(owner) = self.database.private_owner(plugin_id) else { return };
        let Some(fields) = self.declared().get(&owner).cloned() else { return };
        let local = self.database.list_settings(plugin_id).unwrap_or_default();
        for row in self.database.list_sync_sidecars(plugin_id).unwrap_or_default() {
            if row.kind != "settings" {
                continue;
            }
            let Some((setting, scope, scope_id)) = parse_key(&row.key) else { continue };
            let Some(field) = fields.iter().find(|f| f.id == setting) else { continue };
            let Some((ts, tid)) = target(field, &scope, &scope_id) else { continue };
            if local.iter().any(|l| l.setting_id == setting && l.scope == ts && l.scope_id == tid && l.updated_at > row.updated_at) {
                continue;
            }
            self.apply_setting(&owner, &row, &fields).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_targets() {
        assert_eq!(parse_key(&settings_key("a.b.c", "host", "h1")), Some(("a.b.c".into(), "host".into(), "h1".into())));
        assert!(parse_key("x\0y").is_none());
        let field = Field { id: "a".into(), secret: false, sync: true, scope: "application".into() };
        assert_eq!(target(&field, "host", "h"), Some(("application".into(), "application".into())));
        let host = Field { scope: "host".into(), ..field };
        assert_eq!(target(&host, "workspace", "w"), None);
    }
}
