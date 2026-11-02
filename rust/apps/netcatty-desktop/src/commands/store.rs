//! Persistence, credential encryption and vault backups.

use super::CmdResult;
use crate::state::Ctx;
use netcatty_store::backups::BackupInfo;

#[tauri::command]
pub async fn store_get<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    key: String,
) -> CmdResult<Option<String>> {
    state.store.get(&key).await
}

#[tauri::command]
pub async fn store_set<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    key: String,
    value: String,
) -> CmdResult<()> {
    state.store.set(&key, &value).await
}

#[tauri::command]
pub async fn store_remove<R: tauri::Runtime>(state: Ctx<'_, R>, key: String) -> CmdResult<()> {
    state.store.remove(&key).await
}

#[tauri::command]
pub async fn store_keys<R: tauri::Runtime>(state: Ctx<'_, R>) -> CmdResult<Vec<String>> {
    state.store.keys().await
}

#[tauri::command]
pub fn credentials_available<R: tauri::Runtime>(state: Ctx<'_, R>) -> bool {
    state.cipher().available()
}

#[tauri::command]
pub fn credentials_encrypt<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    plaintext: String,
) -> CmdResult<String> {
    state.cipher().encrypt(&plaintext)
}

#[tauri::command]
pub fn credentials_decrypt<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    value: String,
) -> CmdResult<String> {
    state.cipher().decrypt(&value)
}

#[tauri::command]
pub async fn vault_backup_create<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: String,
    reason: Option<String>,
) -> CmdResult<BackupInfo> {
    netcatty_store::backups::BackupStore::new(state.paths.backups_dir())
        .create(&payload, reason.as_deref())
        .await
}

#[tauri::command]
pub async fn vault_backup_list<R: tauri::Runtime>(state: Ctx<'_, R>) -> CmdResult<Vec<BackupInfo>> {
    netcatty_store::backups::BackupStore::new(state.paths.backups_dir())
        .list()
        .await
}

#[tauri::command]
pub async fn vault_backup_read<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    file_name: String,
) -> CmdResult<String> {
    netcatty_store::backups::BackupStore::new(state.paths.backups_dir())
        .read(&file_name)
        .await
}

#[tauri::command]
pub async fn vault_backup_trim<R: tauri::Runtime>(state: Ctx<'_, R>) -> CmdResult<usize> {
    netcatty_store::backups::BackupStore::new(state.paths.backups_dir())
        .trim()
        .await
}

#[tauri::command]
pub async fn vault_backup_clear<R: tauri::Runtime>(state: Ctx<'_, R>) -> CmdResult<usize> {
    netcatty_store::backups::BackupStore::new(state.paths.backups_dir())
        .clear()
        .await
}
