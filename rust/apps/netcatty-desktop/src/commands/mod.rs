//! Tauri commands. Each submodule registers its commands in [`handler`].
//!
//! Conventions:
//! * Command names are `snake_case` and listed in `rust/docs/ipc-contract.md`.
//! * Complex inputs arrive as a single `payload` argument deserialized from
//!   the renderer's camelCase JSON; simple inputs are positional named args.
//! * Errors are `netcatty_core::CoreError` (serialized `{ code, message }`).
//! * Binary responses use `tauri::ipc::Response` so the renderer receives an
//!   `ArrayBuffer`; binary requests use `tauri::ipc::Request` raw bodies.

pub mod ai;
pub mod agents;
pub mod app;
pub mod autostart;
pub mod catty;
pub mod clipboard;
pub mod diagnostics;
pub mod filewatch;
pub mod forward;
pub mod hostbrowser;
pub mod hotkey;
pub mod localfs;
pub mod mcp;
pub mod monitor;
pub mod mosh;
pub mod notification;
pub mod openwith;
pub mod rdesktop;
pub mod scripts;
pub mod serial;
pub mod session;
pub mod sessionlog;
pub mod sftp;
pub mod ssh;
pub mod store;
pub mod sync;
pub mod system;
pub mod telnet;
pub mod temp;
pub mod tempdir;
pub mod totp;
pub mod tray;
pub mod update;
pub mod window;
pub mod windows;

use netcatty_core::CoreError;

/// Alias used by every command.
pub type CmdResult<T> = Result<T, CoreError>;

/// Read a string header of a raw-body invoke. Header values are strings the
/// renderer percent-encodes with `encodeURIComponent` (see the contract), so
/// they are percent-decoded here. Header names are matched case-insensitively.
pub(crate) fn header_str(headers: &tauri::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(percent_decode)
}

/// Required header variant of [`header_str`].
pub(crate) fn require_header(headers: &tauri::http::HeaderMap, name: &str) -> CmdResult<String> {
    header_str(headers, name).ok_or_else(|| CoreError::invalid(format!("missing `{name}` header")))
}

/// Percent-decode a header value (`encodeURIComponent` on the JS side).
pub(crate) fn percent_decode(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

/// Raw body of a `tauri::ipc::Request`, or `INVALID_ARGUMENT` when the
/// renderer sent JSON instead of an `ArrayBuffer`.
pub(crate) fn raw_body<'a>(request: &'a tauri::ipc::Request<'_>) -> CmdResult<&'a [u8]> {
    match request.body() {
        tauri::ipc::InvokeBody::Raw(bytes) => Ok(bytes.as_slice()),
        tauri::ipc::InvokeBody::Json(_) => {
            Err(CoreError::invalid("expected a raw binary request body"))
        }
    }
}

pub fn handler<R: tauri::Runtime>() -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static
{
    tauri::generate_handler![
        // AI control plane: Catty exec, capabilities, MCP host, External MCP.
        catty::ai_exec,
        catty::ai_catty_cancel_exec,
        mcp::ai_capability,
        mcp::ai_vault_agent_respond,
        mcp::ai_mcp_update_sessions,
        mcp::ai_mcp_update_live_sessions,
        mcp::ai_mcp_merge_sessions,
        mcp::ai_mcp_update_attachments,
        mcp::ai_mcp_set_command_blocklist,
        mcp::ai_mcp_set_command_timeout,
        mcp::ai_mcp_set_max_iterations,
        mcp::ai_mcp_set_permission_mode,
        mcp::ai_mcp_set_tool_integration_mode,
        mcp::ai_mcp_sync_permission_grants,
        mcp::ai_mcp_approval_respond,
        mcp::ai_mcp_approval_cancel_timeout,
        mcp::mcp_set_approval_alert_mode,
        mcp::tool_output_persistence_status,
        mcp::tool_output_write,
        mcp::tool_output_restore,
        mcp::tool_output_read,
        mcp::tool_output_delete,
        mcp::tool_output_delete_chat,
        mcp::tool_output_delete_terminal_session,
        mcp::tool_output_delete_terminal,
        mcp::external_mcp_get_status,
        mcp::external_mcp_set_enabled,
        mcp::external_mcp_set_config,
        mcp::external_mcp_get_universal_setup_prompt,
        mcp::external_mcp_client_status,
        mcp::external_mcp_client_add,
        app::app_get_version,
        app::app_renderer_log,
        temp::temp_upload_begin,
        temp::temp_upload_chunk,
        temp::temp_delete_file,
        app::app_get_temp_dir_path,
        app::app_reveal_in_folder,
        app::system_info,
        app::app_set_http_proxy,
        app::app_get_http_proxy,
        // Window management / settings window.
        window::window_open_settings,
        window::window_close_settings,
        window::window_renderer_ready,
        window::window_minimize,
        window::window_maximize,
        window::window_close,
        window::window_is_maximized,
        window::window_is_fullscreen,
        window::window_focus,
        window::window_set_title,
        window::window_open_main,
        window::app_quit,
        window::app_set_theme,
        window::app_set_background_color,
        window::app_set_language,
        window::app_broadcast_settings_changed,
        // Editor / terminal popup / session windows, attach hand-over,
        // opacity / blur (commands/windows, rust/docs/ipc-windows.md).
        windows::windows_open_editor,
        windows::windows_editor_ready,
        windows::windows_focus_editor,
        windows::windows_close_editor_tabs,
        windows::windows_save_editor_tab,
        windows::windows_dock_editor_tab,
        windows::windows_report_editor_dirty,
        windows::windows_report_editor_tabs_closed,
        windows::windows_remap_editor_session,
        windows::windows_report,
        windows::windows_open_terminal_popup,
        windows::windows_terminal_popup_config,
        windows::windows_mark_attach_close_prepared,
        windows::windows_open_session,
        windows::windows_take_open_session,
        windows::windows_track_session,
        windows::windows_output_routes,
        windows::windows_rebind_output,
        windows::windows_restore_output,
        windows::windows_request_snapshot,
        windows::windows_apply_snapshot,
        windows::windows_set_opacity,
        windows::windows_set_background_blur,
        windows::windows_set_terminal_keyboard_focus,
        // Crash logs / diagnostics.
        diagnostics::crash_logs_list,
        diagnostics::crash_logs_read,
        diagnostics::crash_logs_clear,
        diagnostics::crash_logs_open_dir,
        diagnostics::app_log_diagnostic,
        // Clipboard files / images.
        clipboard::clipboard_read_files,
        clipboard::clipboard_read_image,
        clipboard::clipboard_has_image,
        // Temp directory management.
        tempdir::tempdir_info,
        tempdir::tempdir_clear,
        tempdir::tempdir_open,
        tempdir::tempdir_set_custom,
        tempdir::tempdir_reset_custom,
        // Edit-and-sync file watches.
        filewatch::filewatch_start,
        filewatch::filewatch_stop,
        filewatch::filewatch_list,
        filewatch::filewatch_register_temp_file,
        filewatch::filewatch_unregister_temp_file,
        // Open with external applications / native confirmations.
        openwith::app_select_application,
        openwith::app_open_with_application,
        openwith::sftp_download_to_temp,
        openwith::dialog_confirm_close_busy,
        openwith::sftp_same_host_copy_dir,
        totp::totp_preview,
        // Tray, tray panel, global hotkey, autostart, notifications.
        tray::tray_set_show_icon,
        tray::tray_is_show_icon,
        tray::tray_set_close_to_tray,
        tray::tray_is_close_to_tray,
        tray::tray_update_menu_data,
        tray::tray_get_menu_data,
        tray::tray_panel_hide,
        tray::tray_panel_jump_to_session,
        tray::tray_panel_connect_to_host,
        tray::tray_panel_start_port_forward,
        tray::tray_panel_close_session,
        hotkey::hotkey_register,
        hotkey::hotkey_unregister,
        hotkey::hotkey_status,
        autostart::autostart_get,
        autostart::autostart_set,
        notification::notification_show,
        // Session logs (export, auto-save, manual / automatic recording).
        sessionlog::session_log_export,
        sessionlog::session_log_select_dir,
        sessionlog::session_log_auto_save,
        sessionlog::session_log_open_dir,
        sessionlog::session_log_clear_dir,
        sessionlog::session_log_manual_choose_path,
        sessionlog::session_log_manual_start,
        sessionlog::session_log_manual_stop,
        sessionlog::session_log_manual_status,
        sessionlog::session_log_prepare,
        sessionlog::session_log_reveal,
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
        rdesktop::rdesktop_connect,
        rdesktop::rdesktop_input,
        rdesktop::rdesktop_close,
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
        store::vault_backup_capabilities,
        store::vault_backup_create,
        store::vault_backup_list,
        store::vault_backup_read,
        store::vault_backup_trim,
        store::vault_backup_clear,
        store::vault_backup_open_dir,
        sync::cloudsync_password_set,
        sync::cloudsync_password_get,
        sync::cloudsync_password_clear,
        sync::oauth_prepare_callback,
        sync::oauth_await_callback,
        sync::oauth_cancel_callback,
        sync::github_device_flow_start,
        sync::github_device_flow_poll,
        sync::github_device_flow_cancel,
        sync::github_gist_raw_content,
        sync::google_oauth_exchange,
        sync::google_oauth_refresh,
        sync::google_oauth_userinfo,
        sync::google_drive_find_sync_file,
        sync::google_drive_create_sync_file,
        sync::google_drive_update_sync_file,
        sync::google_drive_download_sync_file,
        sync::google_drive_delete_sync_file,
        sync::onedrive_oauth_exchange,
        sync::onedrive_oauth_refresh,
        sync::onedrive_oauth_userinfo,
        sync::onedrive_find_sync_file,
        sync::onedrive_upload_sync_file,
        sync::onedrive_download_sync_file,
        sync::onedrive_delete_sync_file,
        sync::webdav_initialize,
        sync::webdav_upload,
        sync::webdav_download,
        sync::webdav_delete,
        sync::s3_initialize,
        sync::s3_upload,
        sync::s3_download,
        sync::s3_delete,
        // Telnet / serial / Mosh / EternalTerminal sessions.
        telnet::telnet_start,
        telnet::telnet_get_echo_mode,
        telnet::session_notify_user_input,
        telnet::session_set_encoding,
        serial::serial_start,
        serial::serial_list_ports,
        mosh::mosh_start,
        mosh::et_start,
        // System manager, server stats / monitor, PTY child processes
        // (commands/system.rs, commands/monitor.rs).
        system::system_probe_capabilities,
        system::system_list_processes,
        system::system_signal_process,
        system::system_setup_osc7_tracking,
        system::system_list_tmux_sessions,
        system::system_create_tmux_session,
        system::system_list_tmux_windows,
        system::system_list_tmux_panes,
        system::system_list_tmux_clients,
        system::system_tmux_action,
        system::system_list_docker_containers,
        system::system_list_docker_images,
        system::system_docker_stats,
        system::system_docker_inspect,
        system::system_docker_image_inspect,
        system::system_docker_action,
        system::system_docker_image_action,
        system::system_kubectl,
        system::system_list_accelerators,
        system::system_list_listening_ports,
        system::system_list_services,
        system::system_service_action,
        system::session_server_stats,
        system::session_distro_info,
        system::session_read_remote_history,
        system::pty_child_processes,
        monitor::monitor_update,
        monitor::monitor_snapshot,
        monitor::monitor_stop_all,
        monitor::monitor_retry,
        // Auto-update (commands/update.rs).
        update::update_check,
        update::update_download,
        update::update_install,
        update::update_get_status,
        update::update_get_auto_update,
        update::update_set_auto_update,
        update::app_report_dirty_editors,
        // AI core: provider proxy, chat streaming, privacy, user skills,
        // sessions backup (commands/ai.rs, logic in netcatty-ai).
        ai::ai_sync_providers,
        ai::ai_sync_web_search,
        ai::ai_allowlist_add_host,
        ai::ai_fetch,
        ai::ai_chat_stream,
        ai::ai_chat_cancel,
        ai::ai_set_chat_session_cancelled,
        ai::ai_privacy_status,
        ai::ai_privacy_transform,
        ai::ai_privacy_clear,
        ai::ai_privacy_initialize,
        ai::ai_user_skills_status,
        ai::ai_user_skills_open,
        ai::ai_user_skills_build_context,
        ai::ai_skills_cli_invocation,
        ai::ai_sessions_backup_write,
        ai::ai_sessions_backup_read_latest,
        ai::ai_sessions_backup_export,
        ai::ai_sessions_backup_import,
        // Script automation (commands/scripts.rs, rust/docs/ipc-scripts.md).
        scripts::script_run,
        scripts::script_stop,
        scripts::script_pause,
        scripts::script_resume,
        scripts::script_get_runs,
        scripts::script_dialog_response,
        scripts::script_screen_snapshot_response,
        scripts::script_recording_start,
        scripts::script_recording_stop,
        scripts::script_recording_append_step,
        // In-app host browser (commands/hostbrowser.rs).
        hostbrowser::hostbrowser_open,
        hostbrowser::hostbrowser_focus,
        hostbrowser::hostbrowser_request_panel,
        hostbrowser::hostbrowser_panel_layout,
        hostbrowser::hostbrowser_panel_url,
        hostbrowser::hostbrowser_panel_close,
        hostbrowser::hostbrowser_snapshot,
        hostbrowser::hostbrowser_command,
        hostbrowser::hostbrowser_bookmarks_list,
        hostbrowser::hostbrowser_bookmarks_upsert,
        hostbrowser::hostbrowser_bookmarks_remove,
        hostbrowser::hostbrowser_bookmarks_get_all,
        hostbrowser::hostbrowser_bookmarks_apply,
        hostbrowser::hostbrowser_downloads_list,
        hostbrowser::hostbrowser_downloads_theme,
        hostbrowser::hostbrowser_downloads_command,
        // Managed SDK agents, discovery, Codex login / App Server (commands/agents.rs).
        agents::ai_agents_discover,
        agents::ai_resolve_cli,
        agents::ai_shell_env_prewarm,
        agents::ai_codex_get_integration,
        agents::ai_codex_start_login,
        agents::ai_codex_get_login_session,
        agents::ai_codex_cancel_login,
        agents::ai_codex_logout,
        agents::ai_sdk_agent_stream,
        agents::ai_sdk_agent_steer,
        agents::ai_sdk_agent_list_models,
        agents::ai_sdk_agent_cancel,
        agents::ai_sdk_agent_cleanup,
        agents::ai_sdk_agent_elicitation_response,
        agents::ai_sdk_agent_mcp_status,
        agents::ai_sdk_agent_account_info,
        agents::ai_sdk_agent_plugin_install,
        agents::ai_sdk_agent_plugin_enable,
        agents::ai_sdk_agent_plugin_disable,
        agents::ai_sdk_agent_marketplace_install,
        agents::ai_sdk_agent_marketplace_remove,
        agents::codex_app_server_status,
        agents::codex_app_server_respond,
        agents::codex_app_server_cancel_timeout,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding_matches_encode_uri_component() {
        assert_eq!(
            percent_decode("%2Ftmp%2F%E4%B8%AD%E6%96%87.txt"),
            "/tmp/中文.txt"
        );
        assert_eq!(percent_decode("plain-path_1.txt"), "plain-path_1.txt");
        // `+` is not a space for encodeURIComponent.
        assert_eq!(percent_decode("a+b%20c"), "a+b c");
        // Invalid sequences are passed through lossily rather than failing.
        assert_eq!(percent_decode("%ZZ"), "%ZZ");
    }

    #[test]
    fn header_lookup_is_case_insensitive_and_decoded() {
        let mut headers = tauri::http::HeaderMap::new();
        headers.insert("sftpid", tauri::http::HeaderValue::from_static("abc"));
        headers.insert(
            "path",
            tauri::http::HeaderValue::from_static("%2Fsrv%2Fdata"),
        );
        assert_eq!(header_str(&headers, "sftpId").as_deref(), Some("abc"));
        assert_eq!(header_str(&headers, "path").as_deref(), Some("/srv/data"));
        assert!(header_str(&headers, "encoding").is_none());
        assert!(require_header(&headers, "encoding").is_err());
    }
}
