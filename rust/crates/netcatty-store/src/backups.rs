//! Vault backups (mirrors `vaultBackupBridge.cjs`).

use netcatty_core::CoreResult;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInfo {
    pub file_name: String,
    pub path: String,
    pub created_at: i64,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub struct BackupStore {
    pub dir: PathBuf,
    /// Maximum backups kept by [`BackupStore::trim`] (default 20).
    pub keep: usize,
}

impl BackupStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, keep: 20 }
    }

    /// Write `payload` (already serialized vault JSON) as
    /// `vault-<timestamp>[-<reason>].json` and trim old backups.
    pub async fn create(&self, payload: &str, reason: Option<&str>) -> CoreResult<BackupInfo> {
        let _ = (payload, reason);
        todo!("write + trim (store agent task)")
    }

    pub async fn list(&self) -> CoreResult<Vec<BackupInfo>> {
        todo!()
    }

    pub async fn read(&self, file_name: &str) -> CoreResult<String> {
        let _ = file_name;
        todo!("reject path traversal; read file (store agent task)")
    }

    pub async fn trim(&self) -> CoreResult<usize> {
        todo!()
    }

    pub async fn clear(&self) -> CoreResult<usize> {
        todo!()
    }
}
