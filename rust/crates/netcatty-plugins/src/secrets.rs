//! OS-encrypted plugin secrets (port of `electron/plugins/secretStore.cjs`).
//!
//! The database keeps only ciphertext and opaque random references; the
//! cipher is the application's credential cipher (AES-256-GCM keyed from the
//! OS keychain, `netcatty-store`). When no OS-backed key is available the
//! store fails closed instead of writing plaintext.

use crate::database::PluginDatabase;
use crate::error::{codes, PluginError, PluginResult};
use base64::Engine;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Encryption backend (the credential cipher in the app).
pub trait SecretCipher: Send + Sync {
    fn available(&self) -> bool;
    fn encrypt(&self, plaintext: &str) -> PluginResult<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8]) -> PluginResult<String>;
}

/// [`SecretCipher`] over `netcatty_store::CredentialCipher`.
pub struct CredentialSecretCipher<F>(pub F);

impl<F> SecretCipher for CredentialSecretCipher<F>
where
    F: Fn() -> Option<Arc<netcatty_store::CredentialCipher>> + Send + Sync,
{
    fn available(&self) -> bool {
        (self.0)().is_some_and(|c| c.available())
    }
    fn encrypt(&self, plaintext: &str) -> PluginResult<Vec<u8>> {
        let cipher = (self.0)().filter(|c| c.available()).ok_or_else(unavailable)?;
        let value = cipher
            .encrypt(plaintext)
            .map_err(|_| PluginError::unavailable("OS-backed plugin secret encryption failed"))?;
        if !netcatty_store::CredentialCipher::is_encrypted(&value) {
            return Err(unavailable());
        }
        Ok(value.into_bytes())
    }
    fn decrypt(&self, ciphertext: &[u8]) -> PluginResult<String> {
        let cipher = (self.0)().filter(|c| c.available()).ok_or_else(unavailable)?;
        let text = std::str::from_utf8(ciphertext).map_err(|_| data_loss())?;
        if !netcatty_store::CredentialCipher::is_encrypted(text) {
            return Err(data_loss());
        }
        cipher.decrypt(text).map_err(|_| data_loss())
    }
}

fn unavailable() -> PluginError {
    PluginError::unavailable("Secure OS-backed encryption is unavailable for plugin secrets")
}
fn data_loss() -> PluginError {
    PluginError::rpc(codes::DATA_LOSS, "Plugin secret could not be decrypted")
}

pub fn assert_secret_key(key: &str) -> PluginResult<()> {
    let n = key.encode_utf16().count();
    if !(1..=256).contains(&n) || key.contains('\0') {
        return Err(PluginError::invalid("Plugin secret key is invalid"));
    }
    Ok(())
}

/// `assertSecretRef`: `{ kind: "secret", id, key }`.
pub fn assert_secret_ref(secret: &Value) -> PluginResult<(String, String)> {
    let id = secret.get("id").and_then(Value::as_str).unwrap_or("");
    let key = secret.get("key").and_then(Value::as_str).unwrap_or("");
    let id_len = id.encode_utf16().count();
    let key_len = key.encode_utf16().count();
    if secret.get("kind").and_then(Value::as_str) != Some("secret")
        || !(16..=256).contains(&id_len)
        || !(1..=256).contains(&key_len)
        || key.contains('\0')
    {
        return Err(PluginError::invalid("Plugin secret reference is invalid"));
    }
    Ok((id.to_string(), key.to_string()))
}

pub fn secret_ref_value(id: &str, key: &str) -> Value {
    json!({ "kind": "secret", "id": id, "key": key })
}

struct Stashed {
    value: String,
    secret_ref: String,
}

pub struct PluginSecretStore {
    database: Arc<PluginDatabase>,
    cipher: Arc<dyn SecretCipher>,
    overwrite_stash: Mutex<HashMap<String, Stashed>>,
}

impl PluginSecretStore {
    pub fn new(database: Arc<PluginDatabase>, cipher: Arc<dyn SecretCipher>) -> Self {
        Self { database, cipher, overwrite_stash: Mutex::new(HashMap::new()) }
    }

    fn stash_key(&self, plugin_id: &str, key: &str) -> String {
        format!("{}\0{key}", self.database.private_owner(plugin_id).unwrap_or_else(|_| plugin_id.to_string()))
    }

    pub fn clear_plugin_memory(&self, plugin_id: &str) {
        let prefix = format!("{}\0", self.database.private_owner(plugin_id).unwrap_or_else(|_| plugin_id.to_string()));
        self.overwrite_stash.lock().retain(|k, _| !k.starts_with(&prefix));
    }

    fn assert_available(&self) -> PluginResult<()> {
        if self.cipher.available() {
            Ok(())
        } else {
            Err(unavailable())
        }
    }

    pub fn get_reference(&self, plugin_id: &str, key: &str) -> PluginResult<Option<Value>> {
        assert_secret_key(key)?;
        Ok(self
            .database
            .get_secret_by_key(plugin_id, key)?
            .map(|r| secret_ref_value(&r.secret_ref, &r.key)))
    }

    pub fn get_record_by_reference(&self, plugin_id: &str, secret: &Value) -> PluginResult<crate::database::SecretRow> {
        let (id, key) = assert_secret_ref(secret)?;
        match self.database.get_secret_by_ref(plugin_id, &id)? {
            Some(record) if record.key == key => Ok(record),
            _ => Err(PluginError::not_found("Plugin secret reference was not found")),
        }
    }

    /// `set`; `stash_previous` keeps the previous plaintext and reference in
    /// memory so a failed provider connect can restore it.
    pub fn set(&self, plugin_id: &str, key: &str, value: &str, stash_previous: bool) -> PluginResult<Value> {
        self.assert_available()?;
        assert_secret_key(key)?;
        if value.len() > MAX_SECRET_BYTES {
            return Err(PluginError::invalid("Plugin secret value is invalid or too large"));
        }
        let stash_key = self.stash_key(plugin_id, key);
        let mut stashed = false;
        if stash_previous && !self.overwrite_stash.lock().contains_key(&stash_key) {
            if let Some(existing) = self.get_reference(plugin_id, key)? {
                if let Ok(previous) = self.resolve(plugin_id, &existing) {
                    let secret_ref = existing["id"].as_str().unwrap_or_default().to_string();
                    self.overwrite_stash.lock().insert(stash_key.clone(), Stashed { value: previous, secret_ref });
                    stashed = true;
                }
            }
        }
        let result = (|| {
            let bytes: [u8; 24] = rand::random();
            let secret_ref = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            let ciphertext = self.cipher.encrypt(value)?;
            if ciphertext.is_empty() {
                return Err(PluginError::unavailable("OS-backed plugin secret encryption failed"));
            }
            self.database.upsert_secret(plugin_id, key, &secret_ref, &ciphertext)?;
            Ok(secret_ref_value(&secret_ref, key))
        })();
        if result.is_err() && stashed {
            self.overwrite_stash.lock().remove(&stash_key);
        }
        result
    }

    pub fn restore_overwrite(&self, plugin_id: &str, key: &str) -> PluginResult<bool> {
        self.assert_available()?;
        assert_secret_key(key)?;
        let stash_key = self.stash_key(plugin_id, key);
        let (value, secret_ref) = match self.overwrite_stash.lock().get(&stash_key) {
            Some(s) => (s.value.clone(), s.secret_ref.clone()),
            None => return Ok(false),
        };
        let ciphertext = self.cipher.encrypt(&value)?;
        self.database.upsert_secret(plugin_id, key, &secret_ref, &ciphertext)?;
        self.overwrite_stash.lock().remove(&stash_key);
        Ok(true)
    }

    pub fn clear_overwrite_stash(&self, plugin_id: &str, key: &str) -> PluginResult<()> {
        assert_secret_key(key)?;
        self.overwrite_stash.lock().remove(&self.stash_key(plugin_id, key));
        Ok(())
    }

    pub fn delete(&self, plugin_id: &str, key: &str) -> PluginResult<()> {
        assert_secret_key(key)?;
        self.overwrite_stash.lock().remove(&self.stash_key(plugin_id, key));
        self.database.delete_secret(plugin_id, key)
    }

    pub fn delete_by_key_prefix(&self, plugin_id: &str, prefix: &str) -> PluginResult<usize> {
        assert_secret_key(prefix)?;
        let deleted = self.database.delete_secrets_by_key_prefix(plugin_id, prefix)?;
        let plugin_prefix = format!("{}\0", self.database.private_owner(plugin_id).unwrap_or_else(|_| plugin_id.to_string()));
        self.overwrite_stash.lock().retain(|stash_key, _| {
            let Some(secret_key) = stash_key.strip_prefix(&plugin_prefix) else { return true };
            !(secret_key == prefix || secret_key.starts_with(&format!("{prefix}:")))
        });
        Ok(deleted)
    }

    pub fn bind_sync_provider_plugin(&self, plugin_id: &str, provider_id: &str) -> PluginResult<()> {
        if plugin_id.is_empty() {
            return Err(PluginError::invalid("Plugin id is invalid"));
        }
        assert_secret_key(provider_id)?;
        if !provider_id.starts_with(&format!("{plugin_id}.")) {
            return Err(PluginError::invalid("Sync provider id is outside the plugin namespace"));
        }
        self.database.upsert_sync_provider_binding(provider_id, plugin_id)
    }

    pub fn resolve_sync_provider_plugin(&self, provider_id: &str) -> PluginResult<Option<String>> {
        assert_secret_key(provider_id)?;
        Ok(self
            .database
            .get_sync_provider_binding(provider_id)?
            .map(|b| b.plugin_id)
            .filter(|p| !p.is_empty() && provider_id.starts_with(&format!("{p}."))))
    }

    /// `backfillSyncProviderBindingsFromLiveProviders`: `(pluginId, providerId)` claims.
    pub fn backfill_sync_provider_bindings_from_live_providers(&self, providers: &[(String, String)]) -> PluginResult<usize> {
        let owners: HashSet<String> = self
            .database
            .list_plugin_ids_with_secret_key_prefix("sync-credential")?
            .into_iter()
            .filter(|p| !p.is_empty())
            .collect();
        if owners.is_empty() {
            return Ok(0);
        }
        let mut by_plugin: HashMap<&str, HashSet<&str>> = HashMap::new();
        let mut by_provider: HashMap<&str, HashSet<&str>> = HashMap::new();
        for (plugin_id, provider_id) in providers {
            if plugin_id.is_empty() || provider_id.is_empty() || !provider_id.starts_with(&format!("{plugin_id}.")) {
                continue;
            }
            by_provider.entry(provider_id).or_default().insert(plugin_id);
            if owners.contains(plugin_id) {
                by_plugin.entry(plugin_id).or_default().insert(provider_id);
            }
        }
        let mut promoted = 0;
        for (plugin_id, provider_ids) in by_plugin {
            if provider_ids.len() != 1 {
                continue;
            }
            let provider_id = *provider_ids.iter().next().expect("one provider");
            if by_provider.get(provider_id).map_or(0, HashSet::len) != 1 {
                continue;
            }
            if self.database.get_sync_provider_binding(provider_id)?.is_some() {
                continue;
            }
            if self.bind_sync_provider_plugin(plugin_id, provider_id).is_ok() {
                promoted += 1;
            }
        }
        Ok(promoted)
    }

    pub fn unbind_sync_provider_plugin(&self, plugin_id: &str, provider_id: &str) -> PluginResult<()> {
        assert_secret_key(provider_id)?;
        if let Some(existing) = self.database.get_sync_provider_binding(provider_id)? {
            if !existing.plugin_id.is_empty() && existing.plugin_id != plugin_id {
                return Ok(());
            }
        }
        let map_key = format!("sync-provider-map:{provider_id}");
        let _ = self.database.delete_secret(plugin_id, &map_key);
        for row in self.database.find_secrets_by_key(&map_key).unwrap_or_default() {
            if let Some(owner) = row.plugin_id {
                let _ = self.database.delete_secret(&owner, &row.key);
            }
        }
        self.database.upsert_sync_provider_binding(provider_id, "")
    }

    pub fn resolve(&self, plugin_id: &str, secret: &Value) -> PluginResult<String> {
        self.assert_available()?;
        let record = self.get_record_by_reference(plugin_id, secret)?;
        self.cipher.decrypt(&record.ciphertext)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::database::InstallRecord;
    use crate::source::Source;

    /// Reversible test cipher.
    pub struct TestCipher(pub bool);
    impl SecretCipher for TestCipher {
        fn available(&self) -> bool {
            self.0
        }
        fn encrypt(&self, plaintext: &str) -> PluginResult<Vec<u8>> {
            Ok(plaintext.bytes().rev().collect())
        }
        fn decrypt(&self, ciphertext: &[u8]) -> PluginResult<String> {
            Ok(String::from_utf8(ciphertext.iter().rev().copied().collect()).unwrap())
        }
    }

    fn setup(available: bool) -> (tempfile::TempDir, PluginSecretStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(PluginDatabase::open(&dir.path().join("p.sqlite")).unwrap());
        db.install_version(
            &InstallRecord {
                source: Source::local(),
                plugin_id: "com.example.sync".into(),
                version: "1.0.0".into(),
                manifest: json!({}),
                archive_sha256: "b".repeat(64),
                package_relative_path: "x".into(),
            },
            false,
            false,
        )
        .unwrap();
        (dir, PluginSecretStore::new(db, Arc::new(TestCipher(available))))
    }

    #[test]
    fn set_resolve_and_restore() {
        let (_dir, store) = setup(true);
        let first = store.set("com.example.sync", "token", "one", false).unwrap();
        assert_eq!(store.resolve("com.example.sync", &first).unwrap(), "one");
        let second = store.set("com.example.sync", "token", "two", true).unwrap();
        assert_ne!(first["id"], second["id"]);
        assert!(store.restore_overwrite("com.example.sync", "token").unwrap());
        // The original reference resolves again.
        assert_eq!(store.resolve("com.example.sync", &first).unwrap(), "one");
        assert!(store.resolve("com.example.sync", &json!({ "kind": "secret", "id": "x", "key": "token" })).is_err());
    }

    #[test]
    fn fails_closed_without_os_encryption() {
        let (_dir, store) = setup(false);
        let err = store.set("com.example.sync", "token", "v", false).unwrap_err();
        assert_eq!(err.code(), Some(codes::UNAVAILABLE));
    }

    #[test]
    fn sync_provider_bindings() {
        let (_dir, store) = setup(true);
        assert!(store.bind_sync_provider_plugin("com.example.sync", "com.other.p").is_err());
        store.set("com.example.sync", "sync-credential:a", "c", false).unwrap();
        let claims = vec![("com.example.sync".to_string(), "com.example.sync.drive".to_string())];
        assert_eq!(store.backfill_sync_provider_bindings_from_live_providers(&claims).unwrap(), 1);
        assert_eq!(store.resolve_sync_provider_plugin("com.example.sync.drive").unwrap().as_deref(), Some("com.example.sync"));
        store.unbind_sync_provider_plugin("com.example.sync", "com.example.sync.drive").unwrap();
        assert_eq!(store.resolve_sync_provider_plugin("com.example.sync.drive").unwrap(), None);
        // Tombstone blocks re-promotion.
        assert_eq!(store.backfill_sync_provider_bindings_from_live_providers(&claims).unwrap(), 0);
        assert_eq!(store.delete_by_key_prefix("com.example.sync", "sync-credential").unwrap(), 1);
    }
}
