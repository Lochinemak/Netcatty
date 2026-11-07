//! Persistence, credential encryption and vault backups.

use super::CmdResult;
use crate::state::Ctx;
use netcatty_store::backups::{
    BackupStore, BackupSummary, ClearResult, CreateOptions, CreateResult, ReadResult, TrimResult,
};

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

// ---------------------------------------------------------------------------
// Vault backups (Electron: `vaultBackupBridge.cjs`). Successful creates,
// trims and clears emit `netcatty:vault-backups:changed` so other windows
// (the settings window's list) refresh.
// ---------------------------------------------------------------------------

fn backups<'a, R: tauri::Runtime>(state: &'a Ctx<'_, R>) -> BackupStore<'a> {
    BackupStore::new(state.paths.backups_dir(), state.cipher())
}

fn backups_changed<R: tauri::Runtime>(state: &Ctx<'_, R>) {
    crate::events::emit(
        &state.app,
        netcatty_core::ipc::events::VAULT_BACKUPS_CHANGED,
        (),
    );
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupCapabilities {
    encryption_available: bool,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupIdPayload {
    id: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupTrimPayload {
    max_count: Option<serde_json::Value>,
}

#[derive(serde::Serialize)]
pub struct OpenDirResult {
    success: bool,
    path: String,
}

#[tauri::command]
pub fn vault_backup_capabilities<R: tauri::Runtime>(state: Ctx<'_, R>) -> BackupCapabilities {
    BackupCapabilities {
        encryption_available: state.cipher().available(),
    }
}

#[tauri::command]
pub async fn vault_backup_create<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: Option<CreateOptions>,
) -> CmdResult<CreateResult> {
    let result = backups(&state).create(payload.unwrap_or_default()).await?;
    if result.created {
        backups_changed(&state);
    }
    Ok(result)
}

#[tauri::command]
pub async fn vault_backup_list<R: tauri::Runtime>(
    state: Ctx<'_, R>,
) -> CmdResult<Vec<BackupSummary>> {
    backups(&state).list()
}

#[tauri::command]
pub async fn vault_backup_read<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: Option<BackupIdPayload>,
) -> CmdResult<ReadResult> {
    let id = payload.and_then(|p| p.id).unwrap_or_default();
    backups(&state).read(&id)
}

#[tauri::command]
pub async fn vault_backup_trim<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: Option<BackupTrimPayload>,
) -> CmdResult<TrimResult> {
    let max_count = payload.and_then(|p| p.max_count);
    let result = backups(&state).trim(max_count.as_ref()).await?;
    if result.deleted_count > 0 {
        backups_changed(&state);
    }
    Ok(result)
}

#[tauri::command]
pub async fn vault_backup_clear<R: tauri::Runtime>(state: Ctx<'_, R>) -> CmdResult<ClearResult> {
    let result = backups(&state).clear().await;
    // Refresh other windows after partial deletion as well as success.
    backups_changed(&state);
    result
}

#[tauri::command]
pub async fn vault_backup_open_dir<R: tauri::Runtime>(
    state: Ctx<'_, R>,
) -> CmdResult<OpenDirResult> {
    use tauri_plugin_opener::OpenerExt;
    let dir = state.paths.backups_dir();
    std::fs::create_dir_all(&dir).map_err(|e| netcatty_core::CoreError::io(e.to_string()))?;
    let path = dir.to_string_lossy().into_owned();
    state
        .app
        .opener()
        .open_path(path.clone(), None::<&str>)
        .map_err(|e| netcatty_core::CoreError::io(e.to_string()))?;
    Ok(OpenDirResult {
        success: true,
        path,
    })
}
