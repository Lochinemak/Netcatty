//! Tauri commands. Each submodule registers its commands in [`handler`].
//!
//! Conventions:
//! * Command names are `snake_case` and listed in `rust/docs/ipc-contract.md`.
//! * Complex inputs arrive as a single `payload` argument deserialized from
//!   the renderer's camelCase JSON; simple inputs are positional named args.
//! * Errors are `netcatty_core::CoreError` (serialized `{ code, message }`).
//! * Binary responses use `tauri::ipc::Response` so the renderer receives an
//!   `ArrayBuffer`; binary requests use `tauri::ipc::Request` raw bodies.

pub mod app;
pub mod forward;
pub mod localfs;
pub mod session;
pub mod sftp;
pub mod ssh;
pub mod store;

use netcatty_core::CoreError;

/// Alias used by every command.
pub type CmdResult<T> = Result<T, CoreError>;

pub fn handler() -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        app::app_get_version,
        app::app_get_temp_dir_path,
        app::app_reveal_in_folder,
        app::system_info,
        session::session_start_ssh,
        session::session_test_connection,
        session::session_cancel_test_connection,
        session::session_start_local,
        session::session_write,
        session::session_resize,
        session::session_interrupt,
        session::session_set_flow_paused,
        session::session_ack_flow,
        session::session_close,
        session::session_exec,
        session::session_pwd,
        session::session_remote_info,
        session::local_get_default_shell,
        session::local_discover_shells,
        session::local_validate_path,
        ssh::ssh_generate_key_pair,
        ssh::ssh_check_agent,
        ssh::ssh_get_default_keys,
        ssh::ssh_read_known_hosts,
        ssh::ssh_respond_host_key,
        ssh::ssh_respond_keyboard_interactive,
        ssh::ssh_respond_passphrase,
        sftp::sftp_open,
        sftp::sftp_open_for_session,
        sftp::sftp_list,
        sftp::sftp_realpath,
        sftp::sftp_read,
        sftp::sftp_read_binary,
        sftp::sftp_write,
        sftp::sftp_write_binary,
        sftp::sftp_mkdir,
        sftp::sftp_delete,
        sftp::sftp_rename,
        sftp::sftp_stat,
        sftp::sftp_lstat,
        sftp::sftp_chmod,
        sftp::sftp_extract,
        sftp::sftp_home_dir,
        sftp::sftp_close,
        sftp::transfer_start,
        sftp::transfer_cancel,
        sftp::transfer_pause,
        forward::portforward_start,
        forward::portforward_stop,
        forward::portforward_stop_by_rule,
        forward::portforward_stop_all,
        forward::portforward_status,
        forward::portforward_list,
        forward::portforward_snapshot,
        localfs::local_list_dir,
        localfs::local_read_file,
        localfs::local_write_file,
        localfs::local_delete,
        localfs::local_rename,
        localfs::local_mkdir,
        localfs::local_stat,
        localfs::local_lstat,
        localfs::local_realpath,
        localfs::local_extract,
        localfs::local_list_tree,
        localfs::local_cancel_tree_scan,
        localfs::local_home_dir,
        localfs::local_list_drives,
        store::store_get,
        store::store_set,
        store::store_remove,
        store::store_keys,
        store::credentials_available,
        store::credentials_encrypt,
        store::credentials_decrypt,
        store::vault_backup_create,
        store::vault_backup_list,
        store::vault_backup_read,
        store::vault_backup_trim,
        store::vault_backup_clear,
    ]
}
