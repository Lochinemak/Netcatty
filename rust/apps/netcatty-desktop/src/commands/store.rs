//! Persistence, credential encryption and vault backups.

use super::CmdResult;
use crate::state::AppState;
use netcatty_store::backups::BackupInfo;
use tauri::State;

#[tauri::command]
pub async fn store_get(state: State<'_, AppState>, key: String) -> CmdResult<Option<String>> {
    state.store.get(&key).await
}

#[tauri::command]
pub async fn store_set(state: State<'_, AppState>, key: String, value: String) -> CmdResult<()> {
    state.store.set(&key, &value).await
}

#[tauri::command]
pub async fn store_remove(state: State<'_, AppState>, key: String) -> CmdResult<()> {
    state.store.remove(&key).await
}

#[tauri::command]
pub async fn store_keys(state: State<'_, AppState>) -> CmdResult<Vec<String>> {
    state.store.keys().await
}

#[tauri::command]
pub fn credentials_available(state: State<'_, AppState>) -> bool {
    state.cipher.available()
}

#[tauri::command]
pub fn credentials_encrypt(state: State<'_, AppState>, plaintext: String) -> CmdResult<String> {
    state.cipher.encrypt(&plaintext)
}

#[tauri::command]
pub fn credentials_decrypt(state: State<'_, AppState>, value: String) -> CmdResult<String> {
    state.cipher.decrypt(&value)
}

#[tauri::command]
pub async fn vault_backup_create(state: State<'_, AppState>, payload: String, reason: Option<String>) -> CmdResult<BackupInfo> {
    netcatty_store::backups::BackupStore::new(state.paths.backups_dir()).create(&payload, reason.as_deref()).await
}

#[tauri::command]
pub async fn vault_backup_list(state: State<'_, AppState>) -> CmdResult<Vec<BackupInfo>> {
    netcatty_store::backups::BackupStore::new(state.paths.backups_dir()).list().await
}

#[tauri::command]
pub async fn vault_backup_read(state: State<'_, AppState>, file_name: String) -> CmdResult<String> {
    netcatty_store::backups::BackupStore::new(state.paths.backups_dir()).read(&file_name).await
}

#[tauri::command]
pub async fn vault_backup_trim(state: State<'_, AppState>) -> CmdResult<usize> {
    netcatty_store::backups::BackupStore::new(state.paths.backups_dir()).trim().await
}

#[tauri::command]
pub async fn vault_backup_clear(state: State<'_, AppState>) -> CmdResult<usize> {
    netcatty_store::backups::BackupStore::new(state.paths.backups_dir()).clear().await
}
