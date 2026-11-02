//! Managed application state.

use crate::prompts::PromptBroker;
use crate::sessions::{SessionRegistry, SftpMap};
use netcatty_forward::TunnelRegistry;
use netcatty_sftp::{SftpClient, TransferHandle};
use netcatty_ssh::SshConnection;
use netcatty_store::{AppPaths, CredentialCipher, KvStore};
use std::sync::Arc;
use tauri::AppHandle;
use tokio_util::sync::CancellationToken;

/// Everything the commands need. Cheap to clone via the `tauri::State`
/// wrapper; internal collections are concurrent.
pub struct AppState {
    pub app: AppHandle,
    pub paths: AppPaths,
    pub store: KvStore,
    pub cipher: CredentialCipher,
    pub sessions: SessionRegistry,
    /// Open SFTP browsers keyed by `sftpId`. Shared with the session
    /// registry so connection release can see SFTP leases.
    pub sftp: SftpMap,
    pub tunnels: Arc<TunnelRegistry>,
    pub prompts: Arc<PromptBroker>,
    /// Running streaming transfers keyed by `transferId`.
    pub transfers: dashmap::DashMap<String, TransferHandle>,
    /// Cancellation tokens of running `local_list_tree` scans keyed by `scanId`.
    pub tree_scans: dashmap::DashMap<String, CancellationToken>,
    /// Abort handles of in-flight `session_test_connection` tasks.
    pub test_connections: dashmap::DashMap<String, tokio::task::AbortHandle>,
    /// Connections dialed privately for a tunnel (not shared with a session),
    /// keyed by `tunnelId`; disconnected when the tunnel stops.
    pub tunnel_connections: dashmap::DashMap<String, Arc<SshConnection>>,
}

impl AppState {
    pub fn new(app: AppHandle) -> Self {
        let paths = AppPaths::resolve();
        for dir in [
            paths.store_dir(),
            paths.backups_dir(),
            paths.temp_dir(),
            paths.logs_dir.clone(),
        ] {
            if let Err(err) = std::fs::create_dir_all(&dir) {
                tracing::warn!(path = %dir.display(), %err, "could not create application directory");
            }
        }
        let store = KvStore::new(paths.store_dir());
        let cipher = CredentialCipher::load_or_create();
        if !cipher.available() {
            tracing::warn!("credential cipher unavailable; secrets will be stored unencrypted");
        }
        let prompts = Arc::new(PromptBroker::new(app.clone()));
        let tunnels = Arc::new(TunnelRegistry::new());
        crate::commands::forward::spawn_tunnel_event_forwarder(app.clone(), tunnels.subscribe());
        let sftp: SftpMap = Arc::new(dashmap::DashMap::new());
        let sessions = SessionRegistry::new(app.clone(), sftp.clone());
        Self {
            app,
            paths,
            store,
            cipher,
            sessions,
            sftp,
            tunnels,
            prompts,
            transfers: dashmap::DashMap::new(),
            tree_scans: dashmap::DashMap::new(),
            test_connections: dashmap::DashMap::new(),
            tunnel_connections: dashmap::DashMap::new(),
        }
    }

    /// Disconnect `conn` unless a session, SFTP client or other holder still
    /// references it.
    pub async fn release_connection(&self, conn: Arc<SshConnection>) {
        self.sessions.release_connection(conn).await;
    }

    /// Look up an open SFTP client.
    pub fn sftp_client(&self, sftp_id: &str) -> netcatty_core::CoreResult<Arc<SftpClient>> {
        self.sftp.get(sftp_id).map(|c| c.clone()).ok_or_else(|| {
            netcatty_core::CoreError::not_found(format!("sftp session {sftp_id} not found"))
        })
    }
}
