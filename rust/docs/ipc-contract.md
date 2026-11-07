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
| `vault_backup_create` | `payload: string, reason?` | `BackupInfo` |
| `vault_backup_list` | — | `BackupInfo[]` |
| `vault_backup_read` | `fileName` | `string` |
| `vault_backup_trim` / `vault_backup_clear` | — | `number` |

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

## System manager, server stats and monitor

Implemented in `commands/system.rs` and `commands/monitor.rs`; command
builders, parsers and stats bookkeeping live in the `netcatty-sysmgr` crate.
Every reply is the Electron bridge object verbatim (same keys, same
user-visible error strings such as `"Session not found"`, `"Missing
sessionId"`, `"Remote SSH server does not support extra exec channels"`),
because the renderer parses them; failures are replies with
`success: false`, never rejected invokes. `payload` is exactly the object the
Electron preload sends over IPC (including `sessionId`).

Where commands run (Electron `execOnSession`):

* SSH sessions: a new exec channel on the session's existing connection
  (`bounded_exec`: separate channel-open / run bounds, output cap, optional
  stdin, `SIGKILL` + close on timeout; the connection is never torn down).
  Commands of one session are serialized.
* Local terminal sessions: `sh -c` on this machine (`powershell.exe
  -NoProfile -NonInteractive -Command` on Windows).
* Sessions started with `singleChannelSsh`, or whose server banner is a
  known single-channel implementation, refuse extra exec channels.
* `sudo` fallbacks (docker, systemctl) use the session's
  `sudoAutofillPassword` start option on stdin (`sudo -S -p ''`).

| Command | Args | Returns |
| --- | --- | --- |
| `system_probe_capabilities` | `payload: { sessionId }` | `{ success, pending?, error?, capabilities? }` |
| `system_list_processes` | `payload: { sessionId }` | `{ success, pending?, error?, processes? }` |
| `system_signal_process` | `payload: { sessionId, pid, signal?, nice? }` | `{ success, pending?, error?, code? }` |
| `system_setup_osc7_tracking` | `payload: { sessionId, command }` | `{ success, pending?, stdout?, stderr?, code?, error? }` |
| `system_list_tmux_sessions` / `system_create_tmux_session` / `system_list_tmux_windows` / `system_list_tmux_panes` / `system_list_tmux_clients` / `system_tmux_action` | `payload` | as `listTmuxSessions` … `tmuxAction` (60 s per-session tmux environment cache) |
| `system_list_docker_containers` / `system_list_docker_images` | `payload: { sessionId, runtime? }` | `{ success, error?, errorCode?, containers? \| images? }` |
| `system_docker_stats` / `system_docker_inspect` / `system_docker_image_inspect` / `system_docker_action` / `system_docker_image_action` | `payload` | as the bridge methods (`runtime` = `docker` \| `podman` \| `nerdctl`) |
| `system_kubectl` | `payload: { sessionId, op, context?, namespace?, pod? }` | `{ success, error?, errorCode?, contexts?, current?, namespaces?, pods? }` |
| `system_list_accelerators` | `payload: { sessionId }` | `{ success, pending?, error?, devices?, processes?, nvidiaDriverVersion?, probedAt? }` |
| `system_list_listening_ports` | `payload: { sessionId }` | `{ success, pending?, error?, ports? }` |
| `system_list_services` / `system_service_action` | `payload` | `{ success, pending?, error?, units? }` / `{ success, pending?, error? }` |
| `session_server_stats` | `sessionId` | `{ success, pending?, error?, stats? }` (`getServerStats` shape) |
| `session_distro_info` | `sessionId` | `{ success, stdout?, stderr?, error? }` |
| `session_read_remote_history` | `sessionId, limit?` | `{ success, error?, shell?, bash?, zsh?, fish? }` |
| `pty_child_processes` | `sessionId` | `{ pid, command }[]` — direct children of a local terminal's shell; `[]` otherwise |
| `monitor_update` | `panels: MonitorPanelDemand[]` | `MonitorSnapshot` (rejects `INVALID_ARGUMENT` for a non-array) |
| `monitor_snapshot` | `cursor?: MonitorHistoryCursor` | `MonitorSnapshot` (`historyMode: "append"` when the cursor matches `runtimeId` + `epoch`) |
| `monitor_stop_all` | — | `void` |
| `monitor_retry` | `hostId` | `void` (the next `monitor_update` re-dials that host if it failed) |

Server stats: one primary probe (plus a second Linux disk probe, kept apart
for Dropbear's 9000-byte command limit) wrapped in a remote watchdog that
kills the probe shell when the client gives up; the scripts are
byte-identical to Electron's. CPU / per-core / network / block-device rates
are deltas against the previous sample of the same connection.
`latencyMs` is an SSH transport ping on that connection (skipped when the
host's keepalive interval is disabled), `responseLatencyMs` the time until
the exec request was confirmed. Terminal samples are reused for 4 s.

Monitor: demand is owned by the calling window (its label). Each distinct
endpoint (profile, route, identity, keepalive policy) gets one entry
(max 256) that reuses a live session connection to the same
`user@host:port`, else dials (prompts bound to `monitor-<uuid>`; logins are
serialized), then samples on the smallest panel interval with
`interval × min(6, 2^failures)` back-off. Network devices and single-channel
servers (by banner) are `unsupported`. Terminal stats and the monitor share
one sampler per connection (baselines, 30-minute / 1800-point history and
the monitor's separate, cached `nvidia-smi` probe).

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
| `writeToSession(id, data, opts)` | `session_write` (fire-and-forget) |
| `resizeSession`, `interruptSession`, `setSessionFlowPaused`, `ackSessionFlow`, `closeSession` | `session_resize`, `session_interrupt`, `session_set_flow_paused`, `session_ack_flow`, `session_close` |
| `onSessionData(id, cb)` / `onSessionExit(id, cb)` | listen `netcatty:data` / `netcatty:exit`, filter by `sessionId`; return unlisten |
| `startRemoteDesktopSession(o, onEvent)` | `rdesktop_connect` with a `Channel`; binary messages are decoded into `frame` / `copyRect` events |
| `sendRemoteDesktopInput(id, events)` / `closeRemoteDesktopSession(id)` | `rdesktop_input` (fire-and-forget) / `rdesktop_close` |
| `execCommand(o)` | `session_exec` |
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
| `getServerStats`, `getSessionDistroInfo`, `readRemoteHistory` | `session_server_stats`, `session_distro_info`, `session_read_remote_history` |
| `probeSystemCapabilities` … `systemServiceAction` (system manager) | `system_*` (`payload` = the Electron IPC payload) |
| `monitorUpdate`, `monitorSnapshot`, `monitorStopAll`, `monitorRetry` | `monitor_update`, `monitor_snapshot`, `monitor_stop_all`, `monitor_retry` |
| `ptyGetChildProcesses` | `pty_child_processes` |

Bridge methods that have no Rust counterpart in this version (AI, plugins,
MCP, Mosh/ET, FIDO, plugin sync providers, tray, auto-update, session logs,
file watch) are left `undefined` on the adapter; the renderer already
treats them as optional.
