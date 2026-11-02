//! Managed application state.

use crate::prompts::PromptBroker;
use crate::sessions::{SessionRegistry, SftpMap};
use netcatty_forward::TunnelRegistry;
use netcatty_sftp::{SftpClient, TransferHandle};
use netcatty_ssh::SshConnection;
use netcatty_store::{AppPaths, CredentialCipher, KvStore};
use std::sync::Arc;
use tauri::ipc::{CommandArg, CommandItem, InvokeError};
use tauri::{AppHandle, Runtime, State};
use tokio_util::sync::CancellationToken;

/// Everything the commands need. Cheap to clone via the `tauri::State`
/// wrapper; internal collections are concurrent.
pub struct AppState<R: Runtime> {
    pub app: AppHandle<R>,
    pub paths: AppPaths,
    pub store: KvStore,
    /// Credential cipher, loaded on first use (see [`AppState::cipher`]) so
    /// keychain access never sits on the startup path.
    cipher: std::sync::OnceLock<CredentialCipher>,
    pub sessions: SessionRegistry<R>,
    /// Open SFTP browsers keyed by `sftpId`. Shared with the session
    /// registry so connection release can see SFTP leases.
    pub sftp: SftpMap,
    pub tunnels: Arc<TunnelRegistry>,
    pub prompts: Arc<PromptBroker<R>>,
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

/// Command argument giving access to the managed [`AppState`].
///
/// Commands are generic over the runtime `R` so they can be exercised with
/// `tauri::test::MockRuntime`. `tauri::State<'_, AppState<R>>` cannot be
/// used for that directly: Tauri's `CommandArg<'de, R> for State<'r, T>`
/// impl does not relate `T` to the invoke's `R`, so `R` would never be
/// inferred. This newtype's impl ties both together.
pub struct Ctx<'r, R: Runtime>(pub State<'r, AppState<R>>);

impl<'de, 'r, R: Runtime> CommandArg<'de, R> for Ctx<'r, R>
where
    'de: 'r,
{
    fn from_command(command: CommandItem<'de, R>) -> Result<Self, InvokeError> {
        State::<'r, AppState<R>>::from_command(command).map(Ctx)
    }
}

impl<R: Runtime> std::ops::Deref for Ctx<'_, R> {
    type Target = AppState<R>;
    fn deref(&self) -> &AppState<R> {
        self.0.inner()
    }
}

impl<R: Runtime> AppState<R> {
    /// Build the state with the credential master key from the OS keychain
    /// (see [`CredentialCipher::load_or_create`]).
    pub fn new(app: AppHandle<R>) -> Self {
        Self::build(app, None)
    }

    /// The credential cipher, loading the master key on first use
    /// ([`CredentialCipher::load_or_create_for`]: keychain in release
    /// builds, a file in the data directory in debug builds).
    pub fn cipher(&self) -> &CredentialCipher {
        self.cipher.get_or_init(|| {
            let cipher = CredentialCipher::load_or_create_for(&self.paths.data_dir);
            if !cipher.available() {
                tracing::warn!("credential cipher unavailable; secrets will be stored unencrypted");
            }
            cipher
        })
    }

    /// Build the state with an explicit credential cipher. Used by the
    /// headless IPC tests, which must not touch the user's keychain.
    pub fn with_cipher(app: AppHandle<R>, cipher: CredentialCipher) -> Self {
        Self::build(app, Some(cipher))
    }

    fn build(app: AppHandle<R>, cipher: Option<CredentialCipher>) -> Self {
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
        let cipher_slot = std::sync::OnceLock::new();
        if let Some(cipher) = cipher {
            let _ = cipher_slot.set(cipher);
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
            cipher: cipher_slot,
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
