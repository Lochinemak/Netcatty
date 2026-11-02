//! JSON document store keyed by storage key.

use netcatty_core::CoreResult;
use std::path::PathBuf;

/// File-backed key/value store. Keys are sanitized to safe file names
/// (`netcatty.vault.hosts` → `netcatty.vault.hosts.json`). Writes are atomic
/// (write to `.tmp`, fsync, rename).
pub struct KvStore {
    pub root: PathBuf,
}

impl KvStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub async fn get(&self, key: &str) -> CoreResult<Option<String>> {
        let _ = key;
        todo!("read <root>/<sanitized>.json (store agent task)")
    }

    pub async fn set(&self, key: &str, value: &str) -> CoreResult<()> {
        let _ = (key, value);
        todo!()
    }

    pub async fn remove(&self, key: &str) -> CoreResult<()> {
        let _ = key;
        todo!()
    }

    pub async fn keys(&self) -> CoreResult<Vec<String>> {
        todo!()
    }

    /// Map a storage key to a safe file name.
    pub fn file_name_for(key: &str) -> String {
        let _ = key;
        todo!("percent-encode anything outside [A-Za-z0-9._-] (store agent task)")
    }
}
