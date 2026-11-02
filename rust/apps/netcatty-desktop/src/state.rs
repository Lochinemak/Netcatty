//! Managed application state.

use crate::prompts::PromptBroker;
use crate::sessions::SessionRegistry;
use netcatty_forward::TunnelRegistry;
use netcatty_sftp::SftpClient;
use netcatty_store::{AppPaths, CredentialCipher, KvStore};
use std::sync::Arc;
use tauri::AppHandle;

/// Everything the commands need. Cheap to clone via the `tauri::State`
/// wrapper; internal collections are concurrent.
pub struct AppState {
    pub app: AppHandle,
    pub paths: AppPaths,
    pub store: KvStore,
    pub cipher: CredentialCipher,
    pub sessions: SessionRegistry,
    pub sftp: dashmap::DashMap<String, Arc<SftpClient>>,
    pub tunnels: Arc<TunnelRegistry>,
    pub prompts: Arc<PromptBroker>,
}

impl AppState {
    pub fn new(app: AppHandle) -> Self {
        let paths = AppPaths::resolve();
        let store = KvStore::new(paths.store_dir());
        let cipher = CredentialCipher::load_or_create();
        let prompts = Arc::new(PromptBroker::new(app.clone()));
        let tunnels = Arc::new(TunnelRegistry::new());
        let sessions = SessionRegistry::new(app.clone());
        Self { app, paths, store, cipher, sessions, sftp: dashmap::DashMap::new(), tunnels, prompts }
    }
}
