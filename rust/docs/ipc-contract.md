# Netcatty Rust backend — IPC contract

This document is the single source of truth for how the React renderer talks
to the Rust (Tauri 2) backend. The Rust side implements the commands and
events listed here; the renderer-side adapter (`infrastructure/tauri/`)
implements the existing `NetcattyBridge` interface
(`types/global/netcatty-bridge-*.d.ts`) on top of them so the rest of the
renderer does not change.

## Transport

* Commands: `window.__TAURI__.core.invoke(name, args)` (`withGlobalTauri`).
  Argument names are camelCase on the JS side and snake_case in Rust
  (Tauri converts automatically: `sftpId` ↔ `sftp_id`).
* Complex inputs are passed as one `payload` object whose shape is the
  corresponding `netcatty_core::ipc` struct (camelCase JSON).
* Events: `window.__TAURI__.event.listen(name, ({ payload }) => ...)`.
  Event names keep the Electron channel names (see
  `netcatty_core::ipc::events`).
* Errors: every failing command rejects with
  `{ code: ErrorCode, message: string }` (`netcatty_core::CoreError`).
  `ErrorCode` ∈ `INVALID_ARGUMENT | NOT_FOUND | AUTH_FAILED | HOST_KEY_REJECTED |
  NETWORK | TIMEOUT | CANCELLED | IO | UNSUPPORTED | INTERNAL`.
* Binary data:
  * **Responses**: commands marked *(binary)* return `tauri::ipc::Response`
    → the renderer receives an `ArrayBuffer`.
  * **Requests**: commands marked *(raw body)* are invoked with an
    `ArrayBuffer`/`Uint8Array` as the args value and metadata in the
    `headers` option, e.g.
    `invoke("local_write_file", bytes, { headers: { path } })`.
    Header values are strings; non-ASCII paths are percent-encoded with
    `encodeURIComponent` and decoded in Rust.

## Sessions and terminal

| Command | Args | Returns | Notes |
| --- | --- | --- | --- |
| `session_start_ssh` | `payload: SshSessionOptions` | `{ sessionId }` | Resolves once the shell channel is open. `sessionId` from payload is honored, else generated. Reuses the connection of `payload.sourceSessionId` when alive and `reuseTransport !== false`. |
| `session_test_connection` | `payload: SshSessionOptions` | `{ sessionId }` | Connect + auth + disconnect. Prompts fire like a real start. |
| `session_cancel_test_connection` | `sessionId` | `{ success, error? }` | |
| `session_start_local` | `payload: LocalSessionOptions` | `{ sessionId }` | |
| `session_write` | `payload: WriteToSessionPayload` | `void` | `data` is UTF-8 text (encoded to the session charset before it is sent), or base64 when `binary`. `lineDelayMs` (clamped to 2000 ms) paces multi-line writes line by line; the command resolves immediately and the remaining lines are written in the background. |
| `session_resize` | `payload: { sessionId, cols, rows }` | `void` | |
| `session_interrupt` | `sessionId` | `void` | Sends `0x03`. |
| `session_set_flow_paused` | `sessionId, paused` | `void` | Pauses the output pump. Output is buffered (up to 4 MiB; beyond that it is dropped with a warning) and flushed as one `netcatty:data` on resume. |
| `session_ack_flow` | `sessionId, bytes` | `void` | Accepted for compatibility; no-op. |
| `session_close` | `sessionId` | `void` | Emits `netcatty:exit` with `reason: "closed"` (exactly one `netcatty:exit` is ever emitted per session). Cancels pending prompts of the session. Idempotent. The shared SSH connection is disconnected only when no other session or SFTP browser uses it. |
| `session_exec` | `payload: ExecCommandOptions` | `ExecResult { stdout, stderr, code }` | Uses the connection of `payload.sessionId` when alive, else dials a private connection (closed afterwards) with prompts only when `enableKeyboardInteractive` is true (otherwise unattended: no prompts, unknown host keys accepted for that one-shot connection). `timeout` ms. |
| `session_pwd` | `sessionId` | `{ success, cwd?, error? }` | Local sessions: PTY cwd discovery. SSH sessions: **known gap** — the interactive shell's cwd cannot be read from a sibling exec channel, so the login `$HOME` is returned (the Electron bridge's `allowHomeFallback` behaviour); `success: false` when even that fails. |
| `session_remote_info` | `sessionId` | `{ success, serverBanner?, software?, error? }` | `software` = text after `SSH-2.0-` (first token). |
| `local_get_default_shell` | — | `string` | |
| `local_discover_shells` | — | `DiscoveredShell[]` | |
| `local_validate_path` | `path, kind?` | `{ exists, isFile, isDirectory }` | |

Events:

| Event | Payload |
| --- | --- |
| `netcatty:data` | `{ sessionId, data: string }` — output decoded with the session charset (`utf-8` default, `gb18030` (+ `gbk`/`gb2312`/`cp936`), `big5`, `shift_jis`, `euc-kr`, `latin1`/`iso-8859-1`; unknown labels → `utf-8`). Streaming decoder: multi-byte sequences split across chunks are handled. Bursts are coalesced (up to 256 KiB per event). |
| `netcatty:exit` | `SessionExitEvent { sessionId, exitCode?, signal?, exitSignal?, error?, reason, remoteClosedWithoutExitStatus? }` — `reason: "exited"` when the backend ended (`"signaled"` with `exitSignal` when killed by a signal), `"closed"` after `session_close`. |
| `netcatty:auth:failed` | `{ sessionId, error, hostname }` emitted before the start command rejects with `AUTH_FAILED`. |
| `netcatty:chain:progress` | `ChainProgressEvent` per jump hop. |

## Remote desktop (VNC / RDP)

Graphical sessions for hosts whose protocol is `vnc` or `rdp`. They are not
terminal sessions: none of the `session_*` commands apply to them.

| Command | Args | Returns | Notes |
| --- | --- | --- | --- |
| `rdesktop_connect` | `payload: RemoteDesktopOptions`, `onEvent: Channel` | `{ sessionId }` | Resolves as soon as the session task is running, **before** the connection is established. `INVALID_ARGUMENT` for an unknown protocol, an empty hostname or a `sessionId` that is still running. `port` defaults to 5900 / 3389, the requested desktop size to 1280×800 (clamped to 200–8192). `username` / `domain` are RDP only. |
| `rdesktop_input` | `payload: { sessionId, events: RemoteDesktopInputEvent[] }` | `void` | Events are applied in order. Unknown or finished sessions are ignored (input races with the session ending). |
| `rdesktop_close` | `sessionId` | `void` | Idempotent. `closed` is still delivered on the channel. |

`RemoteDesktopInputEvent` (tagged by `type`, coordinates in remote pixels):

| `type` | Fields |
| --- | --- |
| `pointer` | `x, y, buttons` — mask: bit 0 left, bit 1 middle, bit 2 right |
| `wheel` | `x, y, deltaX, deltaY` — whole notches; positive `deltaY` scrolls up, positive `deltaX` right |
| `key` | `down, keysym, scancode` — `keysym` is the X11 keysym (used by VNC); `scancode` the PC set-1 scancode with `0xE000` or-ed in for extended keys (used by RDP, which falls back to the Unicode character of `keysym` when it is 0) |
| `clipboard` | `text` — offered to the remote side (VNC only) |
| `refresh` | — full repaint |

Output does not use the global event bus. Everything a session emits arrives,
in order, on the `tauri::ipc::Channel` passed as `onEvent`:

* **JSON messages** — `RemoteDesktopControlEvent`, tagged by `type`:
  `connected { width, height }`, `resize { width, height }` (reallocate the
  canvas; a repaint follows), `clipboard { text }`, `bell`, and
  `closed { error? }`. `closed` is sent exactly once and is always the last
  message; `error` is absent for a deliberate close and carries the reason for
  a failed connect or a dropped session.
* **Binary messages** (`ArrayBuffer`), first byte is the tag, integers are
  `u16` little endian:
  * `1` frame: `[1][x][y][width][height]` followed by `width * height * 4`
    bytes of RGBA (rows top to bottom, alpha always 255);
  * `2` copy rectangle: `[2][srcX][srcY][dstX][dstY][width][height]` — copy
    that region of the current framebuffer.

## SSH prompts (host key, keyboard-interactive, passphrase)

Rust emits a request event and waits (5 min) for the matching response
command. An unanswered host-key request rejects the key; an unanswered
keyboard-interactive request cancels authentication and emits
`netcatty:keyboard-interactive-cancelled` with `reason: "timeout"`; an
unanswered passphrase request skips the key and emits
`netcatty:passphrase-timeout`. Closing the owning session (or cancelling a
test connection / stopping a tunnel) drops its pending requests and emits
`netcatty:keyboard-interactive-cancelled` / `netcatty:passphrase-cancelled`
with `reason: "session-closed"` (`"cancelled"` / `"tunnel-stopped"`).
`requestId`s are UUIDs generated by Rust; `sessionId` is the terminal
session id, the test-connection id, the SFTP `sessionId` or the `tunnelId`
depending on who is connecting.

| Event → Response command | Request payload | Response payload |
| --- | --- | --- |
| `netcatty:host-key:verify` → `ssh_respond_host_key` | `HostKeyVerifyRequest { requestId, sessionId, hostname, port, status: "unknown"\|"changed", keyType, fingerprint, publicKey, knownHostId?, knownFingerprint? }` | `payload: { requestId, accept, addToKnownHosts }` |
| `netcatty:keyboard-interactive` → `ssh_respond_keyboard_interactive` | `KeyboardInteractiveRequest { requestId, sessionId, hostId?, name, instructions, prompts: [{prompt, echo}], hostname, savedPassword?, allowSavePassword?, totpUri? }` | `payload: { requestId, responses: string[], cancelled }` |
| `netcatty:keyboard-interactive-cancelled` | `{ requestId, sessionId?, reason? }` (`PromptCancelledEvent`, defined in `apps/netcatty-desktop/src/prompts.rs`) | — |
| `netcatty:passphrase-request` → `ssh_respond_passphrase` | `PassphraseRequest { requestId, keyPath, keyName, hostname?, passphraseInvalid?, sessionId? }` | `payload: { requestId, passphrase?, cancelled, skip }` |
| `netcatty:passphrase-timeout` / `-cancelled` | `{ requestId, sessionId?, reason? }` (same `PromptCancelledEvent`) | — |

Response commands return `{ success, error? }`.

When the user accepts with `addToKnownHosts`, the renderer persists the key
in its vault (same as Electron); Rust only reports the decision.

Other SSH utilities:

| Command | Args | Returns |
| --- | --- | --- |
| `ssh_generate_key_pair` | `payload: { type, bits?, comment?, passphrase? }` | `GenerateKeyPairResult` |
| `ssh_check_agent` | `payload?: { identityAgent? }` | `{ running, startupType: "running" \| "stopped", error }` — connects to `identityAgent` (`~` expanded) or `$SSH_AUTH_SOCK` (Windows: the OpenSSH named pipe) and lists identities; 3 s timeout. |
| `ssh_get_default_keys` | — | `[{ name, path }]` |
| `ssh_read_known_hosts` | — | `KnownHost[]` parsed from `~/.ssh/known_hosts` |

## SFTP

All `sftp_*` commands take `sftpId` first. `encoding?` is
`"auto" | "utf-8" | "gb18030"`.

| Command | Args | Returns |
| --- | --- | --- |
| `sftp_open` | `payload: SshSessionOptions` | `{ sftpId, homeDir?, reusedConnection? }` — reuses the connection of `sourceSessionId`, or of any live session to the same `user@host:port`, when `reuseTransport !== false` and `singleChannelSsh !== true`. An optional `encoding` (or `filenameEncoding`) field in the payload sets the browser's default filename encoding (`auto` when absent). Prompts are emitted with `sessionId = payload.sessionId` (else a new id). |
| `sftp_open_for_session` | `sessionId, payload?` | same; opens on the live connection of `sessionId`, falling back to `sftp_open(payload)` with `sourceSessionId = sessionId` when that session is gone (`NOT_FOUND` without a payload) |
| `sftp_list` | `sftpId, path, encoding?` | `RemoteFile[]` |
| `sftp_realpath` | `sftpId, path, encoding?` | `string` |
| `sftp_read` | `sftpId, path, encoding?` | `string` (UTF-8 lossy) |
| `sftp_read_binary` *(binary)* | `sftpId, path, encoding?` | `ArrayBuffer` |
| `sftp_write` | `sftpId, path, content: string, encoding?` | `void` |
| `sftp_write_binary` *(raw body)* | headers `sftpId, path, encoding?` | `void` |
| `sftp_mkdir` | `sftpId, path, encoding?` | `void` |
| `sftp_delete` | `sftpId, path, encoding?, expectedType?` | `void` |
| `sftp_rename` | `sftpId, oldPath, newPath, encoding?` | `void` |
| `sftp_stat` | `sftpId, path, encoding?` | `StatResult` |
| `sftp_lstat` | `sftpId, path, encoding?` | `StatResult \| null` |
| `sftp_chmod` | `sftpId, path, mode, encoding?` | `void` |
| `sftp_extract` | `sftpId, path, encoding?` | `{ success }` |
| `sftp_home_dir` | `sftpId, encoding?` | `{ success, homeDir?, error? }` |
| `sftp_close` | `sftpId` | `{ success }` — idempotent; the SSH connection is disconnected only when no terminal session or other browser uses it |

Events: `netcatty:sftp:connection-progress` → `{ sessionId, label, status, detail? }`
with `status` ∈ `connecting | connected | error` (`sessionId` is the value
described under `sftp_open`; `label` is `hostLabel` or `user@host`).

### Transfers

| Command | Args | Returns |
| --- | --- | --- |
| `transfer_start` | `payload: StreamTransferOptions` | `StreamTransferResult` (resolves at completion / failure / cancel / pause): completed → `{ transferId, totalBytes }`; cancelled → `{ transferId, cancelled: true }`; paused → `{ transferId, cancelled: true, warning: "paused" }` (the `paused` event carries `checkpointBytes` for the resume); failed → `{ transferId, error }`. `sourceSftpId` / `targetSftpId` are required for `sftp` endpoints. |
| `transfer_cancel` | `transferId` | `void` (no-op for unknown ids) |
| `transfer_pause` | `transferId` | `{ success, error? }` |

Event `netcatty:sftp:global-transfer` → `TransferEvent` (`type` ∈ `queued,
started, progress, pausing, paused, resumed, cancelled, completed, failed`).
Rust emits `started` once (with `direction`, `fileName`, `startedAt`,
`totalBytes`), `progress` throttled to ~10/s per transfer (`transferred`,
`totalBytes`, `speed` bytes/s), then exactly one of `completed | failed |
cancelled | paused` (with `endedAt`, and `checkpointBytes` for resumable
outcomes).

## Port forwarding

| Command | Args | Returns |
| --- | --- | --- |
| `portforward_start` | `payload: PortForwardOptions` | `PortForwardStartResult { tunnelId, success, reused?, status?, error? }` — when a live tunnel for the same `ruleId` exists, returns its `tunnelId` with `reused: true` and its `status`; otherwise dials (reusing a live session connection to the same endpoint when `reuseTransport !== false` and `singleChannelSsh !== true`; prompts use `sessionId = tunnelId`) and resolves `{ success: true, status: "active" }` or `{ success: false, status: "error", error }` (never rejects for connection failures). |
| `portforward_stop` | `tunnelId` | `{ success, error? }` (unknown ids succeed) |
| `portforward_stop_by_rule` | `ruleId` | `{ success }` |
| `portforward_stop_all` | — | `{ success }` |
| `portforward_status` | `tunnelId` | `{ status, error? }` — `status: "unknown"` for an unknown tunnel |
| `portforward_list` | — | `PortForwardTunnelInfo[]` |
| `portforward_snapshot` | — | `PortForwardSnapshot { epoch, revision, tunnels }` |

Events: `netcatty:portforward:status` → `PortForwardStatusEvent`;
`netcatty:portforward:runtime` → `PortForwardRuntimeEvent` (`kind` ∈
`upsert | remove | reset`).

## Local filesystem

| Command | Args | Returns |
| --- | --- | --- |
| `local_list_dir` | `path` | `RemoteFile[]` |
| `local_read_file` *(binary)* | `path, maxBytes?` | `ArrayBuffer` (last `maxBytes` bytes when given) |
| `local_write_file` *(raw body)* | header `path` | `void` (`INVALID_ARGUMENT` when the body is JSON instead of raw bytes) |
| `local_delete` | `path, expectedType?` | `void` |
| `local_rename` | `oldPath, newPath` | `void` |
| `local_mkdir` | `path` | `void` |
| `local_stat` / `local_lstat` | `path` | `StatResult` |
| `local_realpath` | `path` | `string` |
| `local_extract` | `path` | `void` |
| `local_list_tree` | `scanId, path, limits?: { maxDirectories?, maxEntries? }` | `LocalTreeEntry[]`; progress on `netcatty:local:tree-progress` → `LocalTreeProgressEvent`. A second scan with a running `scanId` is rejected. |
| `local_cancel_tree_scan` | `scanId` | `void` (no-op for unknown ids) |
| `local_home_dir` | — | `string` |
| `local_list_drives` | — | `string[]` |
| `system_info` | — | `{ username, hostname }` |

## Store, credentials, backups

| Command | Args | Returns |
| --- | --- | --- |
| `store_get` | `key` | `string \| null` |
| `store_set` | `key, value` | `void` |
| `store_remove` | `key` | `void` |
| `store_keys` | — | `string[]` |
| `credentials_available` | — | `boolean` |
| `credentials_encrypt` | `plaintext` | `string` (`enc:v2:...`) |
| `credentials_decrypt` | `value` | `string` |
| `vault_backup_capabilities` | — | `{ encryptionAvailable }` |
| `vault_backup_create` | `payload: { payload, reason?, sourceAppVersion?, targetAppVersion?, syncDataVersion?, maxCount? }` | `{ created, backup }` (`created: false` when the newest backup has the same fingerprint) |
| `vault_backup_list` | — | backup summaries, newest first |
| `vault_backup_read` | `payload: { id }` | `{ backup, payload }` |
| `vault_backup_trim` | `payload: { maxCount }` | `{ deletedCount, keptCount }` |
| `vault_backup_clear` | — | `{ deletedCount }` |
| `vault_backup_open_dir` | — | `{ success, path }` |

Vault backups follow `vaultBackupBridge.cjs`: one
`vault-backup-<createdAt>-<id>.json` record per backup (0600, atomic write),
fingerprint dedupe (top-level `syncedAt` ignored), retention 1–100 (default
20), payload encrypted with the credential cipher (`payloadEncoding:
"cipher-v2"`; Electron's `safeStorage-v1` records cannot be read, legacy
`plain-json-v1` can). Creates / trims / clears emit
`netcatty:vault-backups:changed`.

## Cloud sync

Implemented by the `netcatty-sync` crate. The renderer keeps the sync engine
(encryption, merge, conflicts); these commands move the encrypted
`SyncedFile` and run the HTTP calls a WebView cannot make because of CORS.
Error messages match the Electron bridges (`githubAuthBridge`,
`googleAuthBridge`, `onedriveAuthBridge`, `cloudSyncBridge`, `oauthBridge`),
including the `ONEDRIVE_REAUTH_REQUIRED:` prefix on dead OneDrive refresh
tokens.

| Command | Args | Returns |
| --- | --- | --- |
| `cloudsync_password_set` | `password?` (empty clears) | `true`; emits `netcatty:cloudsync:password-available` |
| `cloudsync_password_get` | — | `string \| null` (memory, else `cloud-sync-session.enc` decrypted) |
| `cloudsync_password_clear` | — | `true` |
| `oauth_prepare_callback` | — | `{ sessionId, port, redirectUri }` (`127.0.0.1:45678`, OS port if busy) |
| `oauth_await_callback` | `expectedState?, sessionId?` | `{ code, state? }`; rejects on cancel, CSRF, provider error, 5 min timeout |
| `oauth_cancel_callback` | `sessionId?` | `void` |
| `github_device_flow_start` | `payload: { clientId?, scope? }` | `{ deviceCode, userCode, verificationUri, expiresAt, interval }` |
| `github_device_flow_poll` | `payload: { clientId?, deviceCode, pollId? }` | raw token JSON (`access_token` or `error`) |
| `github_device_flow_cancel` | `pollId` | `void` (the poll rejects with "…aborted") |
| `github_gist_raw_content` | `payload: { accessToken, rawUrl }` | `string` (only `gist.githubusercontent.com`) |
| `google_oauth_exchange` / `google_oauth_refresh` | `payload` (PKCE code / refresh token) | `{ accessToken, refreshToken?, expiresAt, tokenType?, scope? }` |
| `google_oauth_userinfo` | `payload: { accessToken }` | userinfo JSON |
| `google_drive_{find,create,update,download,delete}_sync_file` | `payload: { accessToken, fileId?, fileName?, syncedFile? }` | `{ fileId }` / `{ ok: true }` / `{ syncedFile }` |
| `onedrive_oauth_exchange` / `onedrive_oauth_refresh` | `payload` | token set as above |
| `onedrive_oauth_userinfo` | `payload: { accessToken }` | `{ id, email, name, avatarDataUrl? }` |
| `onedrive_{find,upload,download,delete}_sync_file` | `payload: { accessToken, fileId?, fileName?, syncedFile? }` | `{ fileId }` / `{ syncedFile }` / `{ ok: true }` |
| `webdav_{initialize,upload,download,delete}` | `config: WebDAVConfig, syncedFile?` | `{ resourceId }` / `{ syncedFile }` / `{ ok: true }` |
| `s3_{initialize,upload,download,delete}` | `config: S3Config, syncedFile?` | `{ resourceId }` / `{ syncedFile }` / `{ ok: true }` |

WebDAV supports Basic (UTF-8 credentials), Bearer token and Digest auth and
replaces the file with temp-`PUT` + `MOVE`, falling back to a padded in-place
`PUT` for servers that do not truncate on overwrite. S3 requests are signed
with SigV4 (path-style by default). `allowInsecure` skips TLS verification
for that endpoint only. Requests honour the system proxy.

## Windows

Implemented in `commands/window.rs` (Electron: `windowManager.cjs`,
`settingsWindow.cjs`). Window commands act on the calling window.

* Main window chrome matches Electron: inset traffic lights on macOS
  (`tauri.macos.conf.json`: overlay title bar), frameless on Windows / Linux
  (`tauri.{windows,linux}.conf.json`) with the renderer's own buttons. The
  renderer's `.app-drag` / `.app-no-drag` regions are made draggable by
  `infrastructure/tauri/dragRegion.ts` (`start_dragging`,
  `internal_toggle_maximize` on double click).
* The settings window (label `settings`, `index.html#/settings`, 980×720) is
  created hidden, shown on `window_renderer_ready` (3 s fallback), hidden on
  close and reused. Closing the main window destroys it so the app quits.

| Command | Args | Returns |
| --- | --- | --- |
| `window_open_settings` | — | `true` (creates or re-shows, centred on the caller's monitor) |
| `window_close_settings` | — | `bool` (hides the settings window) |
| `window_renderer_ready` | — | `void` (shows the caller if hidden) |
| `window_minimize` / `window_close` | — | `void` |
| `window_maximize` | — | `bool` new maximized state (toggles) |
| `window_is_maximized` / `window_is_fullscreen` | — | `bool` |
| `window_focus` | — | `true` |
| `window_set_title` | `title?` | `bool` (empty → "Netcatty") |
| `window_open_main` | — | `bool` |
| `app_quit` | — | `void` |
| `app_set_theme` | `theme: "light" \| "dark" \| "system"` | `true` (native theme of every window) |
| `app_set_background_color` | `color?` (`#rgb[a]`, `#rrggbb[aa]`, `"H S% L%"`) | `bool` (`false` if unparseable) |
| `app_set_language` | `language?` | `true`; emits `netcatty:language-changed` |
| `app_broadcast_settings_changed` | `payload: { key, value }` | `void`; emits `netcatty:settings:changed` `{ source, payload }` |

Events: `netcatty:settings:changed` (`{ source, payload }`, the adapter
drops events whose `source` is its own window), `netcatty:language-changed`
(language string), `netcatty:window:fullscreen-changed` (`{ label,
fullscreen }`, filtered by label).

## Temp directory

`commands/tempdir.rs` (Electron: `tempDirBridge.cjs` without the AI
tool-output store). The effective temp dir is the custom root when set, else
`<cache>/netcatty/tmp`; upload staging, clipboard images and
`app_get_temp_dir_path` all use it. A custom root must be absolute, gets
`Netcatty` appended, may not traverse symlinks, and must be empty or carry
`.netcatty-managed-temp`; it persists in `<data>/temp-dir-pref.json`.

| Command | Args | Returns |
| --- | --- | --- |
| `tempdir_info` | — | `{ path, fileCount, totalSize, isCustom, defaultPath }` |
| `tempdir_clear` | — | `{ deletedCount, failedCount, error? }` (marker kept) |
| `tempdir_open` | — | `{ success }` |
| `tempdir_set_custom` | `dir` | `{ ok, path? , error? }` |
| `tempdir_reset_custom` | — | `{ ok, path?, error? }` |

`chooseTempDir` is the dialog plugin's directory picker.

## File watch (edit and sync)

`commands/filewatch.rs` (Electron: `fileWatcherBridge.cjs`). A watch polls the
local temp file every second; a newer mtime or a size change is debounced
500 ms and uploaded with the transfer engine (`run_transfer`, no
global-transfer events). Syncs of one watch are serialized; deleting the
local file stops the watch; `sftp_close` stops the session's watches and
deletes its registered temp files. Max 256 watches. No OS notification is
shown on sync (Electron shows one).

| Command | Args | Returns |
| --- | --- | --- |
| `filewatch_start` | `localPath, remotePath, sftpId, encoding?` | `{ watchId, reused? }` |
| `filewatch_stop` | `watchId, cleanupTempFile?` | `{ success }` |
| `filewatch_list` | — | `[{ watchId, localPath, remotePath, sftpId }]` |
| `filewatch_register_temp_file` | `sftpId, localPath` | `{ success }` |
| `filewatch_unregister_temp_file` | `sftpId, localPath` | `{ success, retained, wasTracked }` (deletes unless watched) |

Events: `netcatty:filewatch:synced` `{ watchId, localPath, remotePath,
bytesWritten, warning? }`, `netcatty:filewatch:error` `{ …, error }`,
`netcatty:filewatch:stopped` `{ watchId, localPath, remotePath, sftpId }`.

## App HTTP proxy

`netcatty_sync::proxy` (Electron: `httpNetworkProxyBridge.cjs`): the proxy
for the backend's own HTTP calls (cloud sync, OAuth), not SSH proxies.
`system` uses reqwest's system proxy, `direct` none, `custom` routes through
`url` except the bypass list (`<local>` = localhost / loopback); userinfo is
stripped from the URL; an empty custom URL acts like `system`. Not persisted
(the renderer re-applies its setting at startup); local terminals are not
affected.

| Command | Args | Returns |
| --- | --- | --- |
| `app_set_http_proxy` | `settings: { mode, url, bypass }` | `{ success: true, settings }` (normalized) |
| `app_get_http_proxy` | — | `{ settings }` |

## Crash logs, diagnostics, clipboard extras

Crash log: `netcatty_store::crashlog` (Electron: `crashLogBridge.cjs`), JSONL
files `<data>/crash-logs/crash-YYYY-MM-DD.log`, 30-day retention, 16 MB per
file. Rust panics are recorded by the hook installed in `run()`.
Clipboard files / images use `arboard` (`commands/clipboard.rs`, Electron:
`clipboardFiles.cjs`).

| Command | Args | Returns |
| --- | --- | --- |
| `crash_logs_list` | — | `[{ fileName, date, size, entryCount }]` newest first |
| `crash_logs_read` | `fileName` (`crash-YYYY-MM-DD.log` only) | last ≤ 500 entries of the last 256 KB |
| `crash_logs_clear` | — | `{ deletedCount }` |
| `crash_logs_open_dir` | — | `{ success }` |
| `app_log_diagnostic` | `payload: { source?, message?, extra? }` | `{ success: true }` (`terminal-perf` goes to the tracing log only) |
| `clipboard_read_files` | — | `[{ path, name, isDirectory, size }]` (file list, else `file://` text lines) |
| `clipboard_read_image` | — | `{ path, name, mediaType: "image/png", size } \| null` (PNG written to the temp dir) |
| `clipboard_has_image` | — | `bool` |

## Session logs

`commands/sessionlog.rs` + the `netcatty-sessionlog` crate (Electron:
`sessionLogsBridge.cjs`, `sessionLogStreamManager.cjs`,
`terminalLogSanitizer.cjs`, `programmaticCommandLog.cjs`). Formats: `raw`
(`.log`, output as received), `txt` (terminal replay: cursor moves, erases,
`\r` overwrites, cleared screens kept as history, alternate-screen paint
omitted) and `html` (the same replay with SGR styles, wrapped in Electron's
light / dark page). The sanitizer is a byte-for-byte port, checked against
the JavaScript one with randomized differential runs.

File names: automatic logs and auto-save write
`<directory>/<safe host label>/<YYYY-MM-DDTHH-MM-SS>.<ext>` (local time);
export and manual logs default to `<safe label>_<YYYY-MM-DDTHH-MM-SS>.<ext>`.
"Safe" replaces `<>:"/\|?*` and control characters with `_`, trims, turns
trailing dots into `_` and suffixes Windows device names.

Streams: every decoded chunk passes `sessions.rs` `deliver` →
`sessionlog::tap_output` (before flow-control buffering), is buffered and
written by a per-stream flush thread every 500 ms (immediately at 64 KiB).
`raw` appends; `txt` / `html` rewrite the rendered file. Two managers mirror
Electron's main / worker split: **automatic** logs (`sessionLog: { enabled,
directory, format, timestampsEnabled }` on `session_start_ssh` /
`session_start_local`; label `hostLabel || hostname`, local `Local`) end with
the session; **manual** recordings (token-guarded) survive reconnects and end
only on `session_log_manual_stop`. `session_write` registers sudo-autofill
markers and `logRewrite: { sentCommand, displayCommand }` so injected
commands do not appear in logs. A new session kind needs the three hooks:
`session_starting` before inserting into the registry, output through
`deliver`, and `remove_and_release` (calls `session_ended`).

| Command | Args | Returns |
| --- | --- | --- |
| `session_log_export` | `payload: { terminalData, hostLabel, hostname, startTime, format, plainText? }` | `{ success: true, filePath }` \| `{ success: false, canceled: true }`; rejects `INVALID_ARGUMENT` "No terminal data to export". Save dialog (txt / log / html / all filters); the chosen extension picks the format. |
| `session_log_select_dir` | — | `{ success: true, directory }` \| `{ success: false, canceled: true }` |
| `session_log_auto_save` | `payload: { terminalData, hostLabel, hostname, hostId, startTime, format, directory }` | `{ success, filePath?, error? }` ("Missing terminal data or directory") |
| `session_log_open_dir` | `directory` | `{ success, error? }` ("No directory specified", `ENOENT: …` when missing) |
| `session_log_clear_dir` | `directory` | `{ success, deletedCount, failedCount, error? }` — only session-log artifacts; live stream files / host folders and symlinks are kept; a missing directory is success |
| `session_log_manual_choose_path` | `payload: { sessionId, sessionName?, preferredDirectory?, format? }` | `{ success, canceled, selectionToken?, filePath?, format?, error? }` — save dialog (default `~`, format default `raw`); `.ext` appended when missing, then an overwrite confirmation if that file exists |
| `session_log_manual_start` | `payload: { sessionId, sessionName?, preferredDirectory?, selectionToken?, format?, timestampsEnabled?, initialLine?, alternateScreenActive? }` | `{ success, started, canceled?, filePath?, error? }` — redeems the token (single use, same session and window); `filePath` in the payload is refused; no token → dialog first |
| `session_log_manual_stop` | `payload: { sessionId }` | `{ success, stopped, filePath?, error? }` |
| `session_log_manual_status` | `payload: { sessionId }` | `{ success, isLogging, hasSessionLog, error? }` — `isLogging` = manual recording; `hasSessionLog` = a manual or automatic log exists |
| `session_log_prepare` | `payload: { sessionId }` | `{ success, filePath?, error? }` — flushes the live log (or returns the finalized one; manual before automatic) |
| `session_log_reveal` | `payload: { sessionId }` | as prepare, then reveals the file (opener plugin) |

## App

| Command | Args | Returns |
| --- | --- | --- |
| `app_get_version` | — | `string` |
| `app_get_temp_dir_path` | — | `string` |
| `app_reveal_in_folder` | `path` | `void` (opener plugin `reveal_item_in_dir`) |

Dialogs, clipboard and opening URLs use the Tauri plugins directly from the
adapter (`window.__TAURI__.dialog`, `.clipboardManager`, `.opener`).

## Mapping `NetcattyBridge` → commands (adapter cheat-sheet)

| Bridge method | Command / plugin |
| --- | --- |
| `startSSHSession(o)` | `session_start_ssh` → `.sessionId` |
| `testConnection(o)` / `cancelTestConnection(id)` | `session_test_connection` / `session_cancel_test_connection` |
| `startLocalSession(o)` | `session_start_local` → `.sessionId` |
| `writeToSession(id, data, opts)` | `session_write` (fire-and-forget; `opts.logRewrite` forwarded) |
| `resizeSession`, `interruptSession`, `setSessionFlowPaused`, `ackSessionFlow`, `closeSession` | `session_resize`, `session_interrupt`, `session_set_flow_paused`, `session_ack_flow`, `session_close` |
| `onSessionData(id, cb)` / `onSessionExit(id, cb)` | listen `netcatty:data` / `netcatty:exit`, filter by `sessionId`; return unlisten |
| `startRemoteDesktopSession(o, onEvent)` | `rdesktop_connect` with a `Channel`; binary messages are decoded into `frame` / `copyRect` events |
| `sendRemoteDesktopInput(id, events)` / `closeRemoteDesktopSession(id)` | `rdesktop_input` (fire-and-forget) / `rdesktop_close` |
| `execCommand(o)` | `session_exec` |
| `openSettingsWindow()` / `closeSettingsWindow()` / `rendererReady()` | `window_open_settings` / `window_close_settings` / `window_renderer_ready` |
| `windowMinimize/Maximize/Close/IsMaximized/IsFullscreen/Focus()`, `setWindowTitle(t)` | `window_*` on the calling window |
| `setTheme`, `setBackgroundColor`, `setLanguage` / `onLanguageChanged` | `app_set_theme`, `app_set_background_color`, `app_set_language` / `netcatty:language-changed` |
| `notifySettingsChanged(p)` / `onSettingsChanged(cb)` | `app_broadcast_settings_changed` / `netcatty:settings:changed` minus own window |
| `getSessionPwd`, `getSessionRemoteInfo` | `session_pwd`, `session_remote_info` |
| `generateKeyPair`, `checkSshAgent`, `getDefaultKeys`, `readKnownHosts` | `ssh_*` |
| `onHostKeyVerification` / `respondHostKeyVerification` | listen `netcatty:host-key:verify` / `ssh_respond_host_key` |
| `onKeyboardInteractive` / `respondKeyboardInteractive` | listen / `ssh_respond_keyboard_interactive` |
| `onPassphraseRequest` / `respondPassphrase` / `respondPassphraseSkip` | listen / `ssh_respond_passphrase` (`skip: true`) |
| `openSftp(o)` → `string` | `sftp_open` → `.sftpId` |
| `openSftpForSession(id, o)` | `sftp_open_for_session` → `.sftpId` |
| `listSftp` … `getSftpHomeDir` | `sftp_*` |
| `startStreamTransfer`, `cancelTransfer`, `pauseTransfer` | `transfer_*` |
| `onGlobalSftpTransferEvent` | listen `netcatty:sftp:global-transfer` |
| `startPortForward(o)` etc. | `portforward_*` |
| `onPortForwardStatus(cb)` | listen `netcatty:portforward:status` |
| `listLocalDir` … `listDrives`, `getSystemInfo` | `local_*`, `system_info` |
| `credentialsAvailable/Encrypt/Decrypt` | `credentials_*` |
| `cloudSync{Set,Get,Clear}SessionPassword` / `onCloudSyncSessionPasswordAvailable` | `cloudsync_password_*` / listen `netcatty:cloudsync:password-available` |
| `prepareOAuthCallback`, `awaitOAuthCallback`, `cancelOAuthCallback` | `oauth_*_callback` |
| `github*`, `google*`, `googleDrive*`, `onedrive*` | `github_*`, `google_*`, `onedrive_*` (options object as `payload`) |
| `cloudSyncWebdav*` / `cloudSyncS3*` | `webdav_*` / `s3_*` (`config`, `syncedFile`) |
| `readClipboardText/writeClipboardText` | clipboard-manager plugin |
| `selectDirectory/selectFile/showSaveDialog` | dialog plugin |
| `openExternal` | opener plugin |
| `exportSessionLog`, `selectSessionLogsDir`, `autoSaveSessionLog` | `session_log_export`, `session_log_select_dir`, `session_log_auto_save` (`payload`) |
| `openSessionLogsDir(dir)`, `clearSessionLogsDir(dir)` | `session_log_open_dir`, `session_log_clear_dir` (`directory`) |
| `chooseManualSessionLogPath`, `startManualSessionLog`, `stopManualSessionLog`, `getManualSessionLogStatus` | `session_log_manual_choose_path`, `session_log_manual_start`, `session_log_manual_stop`, `session_log_manual_status` (`payload`) |
| `prepareSessionLog`, `revealSessionLog` | `session_log_prepare`, `session_log_reveal` (`payload: { sessionId }` only) |

Bridge methods that have no Rust counterpart in this version (AI, plugins,
MCP, Mosh/ET, FIDO, plugin sync providers, tray, auto-update,
file watch, system manager) are left `undefined` on the adapter; the renderer already
treats them as optional.
