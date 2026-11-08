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
| `session_write` | `payload: WriteToSessionPayload` | `void` | `data` is UTF-8 text (encoded to the session charset before it is sent), or base64 when `binary`. `lineDelayMs` (clamped to 2000 ms) paces multi-line writes line by line; the command resolves immediately and the remaining lines are written in the background. `automated: false` input cancels telnet / serial auto-login; `serialEraseChar` (serial only) expands a single Backspace into one per encoded byte of that character. |
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
| `netcatty:data` | `{ sessionId, data: string, meta? }` — `meta` is `{ moshHandshake?, moshHandshakeRequiresUserInput? }` on Mosh bootstrap output (absent otherwise). Output decoded with the session charset (`utf-8` default, `gb18030` (+ `gbk`/`gb2312`/`cp936`), `big5`, `shift_jis`, `euc-kr`, `latin1`/`iso-8859-1`; unknown labels → `utf-8`). Streaming decoder: multi-byte sequences split across chunks are handled. Bursts are coalesced (up to 256 KiB per event). |
| `netcatty:exit` | `SessionExitEvent { sessionId, exitCode?, signal?, exitSignal?, error?, reason, remoteClosedWithoutExitStatus? }` — `reason: "exited"` when the backend ended (`"signaled"` with `exitSignal` when killed by a signal), `"closed"` after `session_close`. |
| `netcatty:auth:failed` | `{ sessionId, error, hostname }` emitted before the start command rejects with `AUTH_FAILED`. |
| `netcatty:chain:progress` | `ChainProgressEvent` per jump hop. |

## Telnet, serial, Mosh and EternalTerminal

These sessions live in the same registry as SSH / local sessions, so
`session_write`, `session_resize`, `session_interrupt`,
`session_set_flow_paused`, `session_close`, `netcatty:data` and the single
`netcatty:exit` behave exactly as above. Start options are the renderer's
objects (camelCase; unknown fields ignored); `sessionId` is honoured.
Errors keep the Electron messages.

| Command | Args | Returns | Notes |
| --- | --- | --- | --- |
| `telnet_start` | `payload: { sessionId?, hostname, port? = 23, username?, password?, cols?, rows?, charset?, label?, bootEpoch? }` | `{ sessionId }` | Resolves once TCP is connected. `TIMEOUT` `Connection timeout to <host>:<port>` after 10 s, `NETWORK` `Failed to connect: <reason>`. Telnet negotiation starts on the first IAC from the peer (raw TCP services pass through untouched): DO SGA, WILL TERMINAL-TYPE (`XTERM-256COLOR`), WILL NAWS; ECHO / SGA accepted, everything else refused. Input follows NVT newline rules (CR → CR LF) and doubles 0xFF once negotiation is active; `session_resize` sends NAWS when the peer enabled it. Peer close → exit `{ exitCode: 0, reason: "closed" }`, socket error → `{ exitCode: 1, error, reason: "error" }`. |
| `telnet_get_echo_mode` | `sessionId` | `{ success: true, sessionId, remoteEcho, localEcho }` or `{ success: false, error: "Telnet echo mode unavailable" }` | Initial mode `remoteEcho: true, localEcho: false`. |
| `serial_start` | `payload: { sessionId?, path, baudRate? = 115200, dataBits? = 8, stopBits? = 1, parity? = "none", flowControl? = "none", username?, password?, charset?, label?, bootEpoch? }` | `{ sessionId }` | Hardware ports and PTY devices; on Windows also local `\\.\pipe\name` consoles (elsewhere: `Windows named pipes are only supported on Windows`). Open failure → `IO` `Failed to open serial port: <reason>`. `stopBits: 1.5` opens with 2; `mark` / `space` parity are rejected. Exit: `{ exitCode: 0, reason: "closed" }` on hang-up, `{ exitCode: 1, error, reason: "error" }` on a read error. |
| `serial_list_ports` | — | `[{ path, manufacturer, serialNumber, vendorId, productId, pnpId, type: "hardware" }]` | `vendorId` / `productId` are 4-digit lower-case hex, `pnpId` is always empty. Errors yield `[]`. |
| `mosh_start` | `payload: { sessionId?, hostname, port? = 22, username?, password?, passphrase?, privateKey?, certificate?, authMethod?, requiresMfa?, identityFilePaths?, useSshAgent?, agentPublicKeys?, identityAgent?, identitiesOnly?, agentForwarding?, moshServerPath?, knownHosts?, verifyHostKeys?, env?, cols?, rows?, charset?, label?, bootEpoch? }` | `{ sessionId }` | Resolves once the bootstrap `ssh` runs in a PTY (`ssh -n -tt ... -- sh -c '...exec mosh-server new -s -c 256 -l LANG=...'`). Its output carries `meta.moshHandshake` (and `moshHandshakeRequiresUserInput` at prompts Netcatty does not answer); a saved passphrase / password is typed once; the `MOSH IP` / `MOSH CONNECT` lines are hidden. When ssh exits with a parsed key, `mosh-client <ip> <port>` (`MOSH_KEY`, `MOSH_NO_TERM_INIT=1`) replaces it in the same session and `netcatty:mosh:ready` fires; mosh-client exit → `reason: "exited"` (status 0) or `"error"`. No `MOSH CONNECT` → a hint line and exit `{ reason: "error", error: "Mosh SSH startup failed: no MOSH CONNECT from mosh-server (UDP client not started)" }`. Missing binaries: `Bundled mosh-client not found. ...` / `OpenSSH client not found. ...`. |
| `et_start` | `payload`: as `mosh_start` plus `etPort? = 2022`, `jumpHosts?` (at most one), `legacyAlgorithms?` | `{ sessionId }` | Runs `et [-p port] [-f --ssh-socket <agent>] --ssh-option ... [--jumphost u@h --jport 2022] user@host` in a PTY with `ET_NO_TELEMETRY=1`. A private `et-ssh-home-<id>` directory under the app temp dir holds key / certificate files, an ssh `config` (comma-valued options, jump `Host` block, `Include` of the user and system config) and a PATH-fronted `ssh -F` wrapper; it is removed when the session ends. Saved passwords / passphrases are answered through `SSH_ASKPASS` pointing at the Netcatty executable itself (helper mode, see `src/askpass.rs`). Exit: `reason: "exited"` for status 0, else `"error"`. |
| `session_notify_user_input` | `sessionId` | `void` | Line-mode "first keystroke" notification: cancels telnet / serial auto-login. Ignored for other sessions. |
| `session_set_encoding` | `sessionId, encoding` | `{ ok, encoding }` | Any session: the pump switches its decoder before the next chunk and input is encoded with the new charset. `encoding` is the normalised label (`utf-8`, `gb18030`, `big5`, `shift_jis`, `euc-kr`, `latin1`, ...). `{ ok: false }` for unknown sessions. |

Events:

| Event | Payload |
| --- | --- |
| `netcatty:telnet:echo-mode` | `{ sessionId, remoteEcho, localEcho }` on every ECHO negotiation. |
| `netcatty:telnet:auto-login-complete` | `{ sessionId, bootEpoch? }` — a command prompt appeared after the saved credentials were sent (telnet and serial). |
| `netcatty:telnet:auto-login-cancelled` | `{ sessionId, bootEpoch? }` — the user typed first; serial sessions also report a stalled exchange (a password prompt with no saved password, or the 60 s window expiring at a login prompt). |
| `netcatty:mosh:ready` | `{ sessionId, bootEpoch? }` — `mosh-client` replaced the bootstrap PTY. |

Auto-login (telnet and serial, only with a saved username or password):
answers one "Press RETURN" banner, sends the username at a login prompt
(also `用户名` / `账号` / Kylin-style prompts without a colon) and the
password at a password prompt, each once; a bare CR / LF from the user before
any prompt is a console wake and does not cancel it. The detector gives up
after 60 s.

Client binaries: `mosh-client` and `et` are looked up in the bundled
resources (`<resource_dir>/mosh/`, `<resource_dir>/et/`; in debug builds also
`resources/<tool>/<platform-arch>/` of the repository, the Electron
development layout), then on the session's `PATH`. `ssh` comes from `PATH`
(Windows: also `%SystemRoot%\System32\OpenSSH\ssh.exe`).

Not ported: ZMODEM / YMODEM (`onZmodemEvent`, `cancelZmodem`,
`startZmodemDragDropUpload`, `onZmodemOverwriteRequest`,
`respondZmodemOverwrite`, `sendSerialYmodem`, `receiveSerialYmodem` stay
undefined), the Mosh / ET host-stats companion SSH connection, session
logging for these sessions, and FIDO2 agent preparation for the external ssh.

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

## Open with external applications

`commands/openwith.rs` (Electron: handlers in `main/registerBridges.cjs`).

| Command | Args | Returns |
| --- | --- | --- |
| `app_select_application` | — | `{ path, name } \| null` (native picker: `.app` on macOS, executables on Windows) |
| `app_open_with_application` | `filePath, appPath` | `true` once launched (`open -a` on macOS); rejects when the app cannot start |
| `sftp_download_to_temp` | `sftpId, remotePath, fileName, encoding?, transferId` | `{ localPath, cancelled }`; progress on `netcatty:sftp:global-transfer` under `transferId`, partial file removed on error / cancel |
| `dialog_confirm_close_busy` | `payload: { command, title?, message?, cancelLabel?, closeLabel? }` | `bool` (`true` only for Close) |
| `totp_preview` | `payload: { text?, uri? }` | `{ ok, uri, code, secondsRemaining, period, algorithm, digits, issuer, label }` or `{ ok: false, error }` (codes of `domain/totp.shared.cjs`) |
| `sftp_same_host_copy_dir` | `sftpId, sourcePath, targetPath` | `{ success }` — `mkdir -p` + `cp -ra src/. dst/` over exec; `false` (any failure) makes the renderer copy file by file |

## File watch (edit and sync)

`commands/filewatch.rs` (Electron: `fileWatcherBridge.cjs`). A watch polls the
local temp file every second; a newer mtime or a size change is debounced
500 ms and uploaded with the transfer engine (`run_transfer`, no
global-transfer events). Syncs of one watch are serialized; deleting the
local file stops the watch; `sftp_close` stops the session's watches and
deletes its registered temp files. Max 256 watches. Sync results also show
a native notification, as in Electron.

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

## Tray, global hotkey, auto launch, notifications

Implemented in `commands/tray.rs`, `hotkey.rs`, `autostart.rs` and
`notification.rs` (Electron: `globalShortcutBridge.cjs`,
`trayPanelBounds.cjs`, `autoLaunch.cjs`, `systemNotification.cjs`).

* **Tray icon** (`tray-icon` feature, artwork from `public/tray-icon*`): exists
  while `showTrayIcon` is on, is created by `tray_set_close_to_tray(true)`
  unless hidden by preference, and is pinned during a hidden auto-launch
  until the main window is shown once. macOS: left click toggles the tray
  panel. Windows: left click opens the main window, right click toggles the
  panel. Linux trays report no clicks, so they get Electron's native menu
  (Open Main Window, sessions, port-forward rules, Quit).
* **Tray panel**: window `tray-panel` on `index.html#/tray`, 360×520,
  frameless, always on top, no taskbar entry, transparent except on macOS
  (that needs the private-API feature). Placed next to the icon on the
  icon's monitor (below a menu-bar icon, above a bottom taskbar, clamped to
  the work area; port of `trayPanelBounds.cjs`). Created on first use and
  shown on `window_renderer_ready` (3 s fallback); hidden on blur / close
  and reused. While visible it gets `netcatty:trayPanel:refresh` every
  second.
* **Close to tray**: with it on (and the icon present or hidden by
  preference) closing the main window hides it; on macOS a fullscreen window
  leaves fullscreen first. Clicking the Dock icon re-shows it
  (`RunEvent::Reopen`). A real close also destroys the hidden panel so the
  app quits.
* **Hidden launch**: `--hidden` (the autostart argument) keeps the main
  window hidden (`window_renderer_ready` does not show it) and pins the tray.
* **Global hotkey** (`tauri-plugin-global-shortcut`): the renderer string
  (`"⌘ + Space"`, `"Ctrl + `"`) becomes an Electron accelerator
  (`CommandOrControl+Space`, returned as `accelerator`) and then a plugin
  shortcut (`Return` → `Enter`, shifted US symbols → their key). Pressing it
  hides a focused main window, otherwise shows and focuses it.
* **Auto launch** (`tauri-plugin-autostart`, argument `--hidden`): macOS
  LaunchAgent, Windows `Run` key, Linux XDG autostart (AppImage path when
  run from one). Debug builds report `supported: false`.
* **Notifications** (`tauri-plugin-notification`): title / body sanitized
  like Electron (controls stripped, whitespace collapsed, 120 / 500 chars
  with `…`). A click shows and focuses the window that raised it and emits
  `netcatty:tray:focusSession` `{ sessionId, label }` for it.

| Command | Args | Returns |
| --- | --- | --- |
| `tray_set_show_icon` | `enabled` | `{ success: true, enabled }` |
| `tray_is_show_icon` | — | `{ enabled }` (default `true`) |
| `tray_set_close_to_tray` | `enabled` | `{ success: true, enabled }` |
| `tray_is_close_to_tray` | — | `{ enabled }` (default `false`) |
| `tray_update_menu_data` | `payload: { sessions?, portForwardRules?, hosts? }` | `{ success: true }`; absent lists are kept; rebuilds the Linux menu and pushes `netcatty:trayPanel:setMenuData` to an open panel |
| `tray_get_menu_data` | — | `TrayMenuData { sessions, portForwardRules, hosts }` |
| `tray_panel_hide` | — | `{ success: true }` |
| `tray_panel_jump_to_session` | `sessionId` | `{ success: true }`; emits `netcatty:trayPanel:jumpToSession` (main window not focused) |
| `tray_panel_connect_to_host` | `hostId` | `{ success: true }`; focuses the main window, emits `netcatty:trayPanel:connectToHost` |
| `tray_panel_start_port_forward` | `ruleId` | `{ success, error? }`; emits `netcatty:trayPanel:startPortForward` (`"Main window is not ready"` without a main window) |
| `tray_panel_close_session` | `sessionId` | `{ success, error? }`; emits `netcatty:trayPanel:closeSession` |
| `hotkey_register` | `hotkey?` | `{ success, enabled?, accelerator?, error? }` — empty / `"Disabled"` → `{ success: true, enabled: false }`; `"Invalid hotkey format"`; `"Hotkey may be in use by another application"` |
| `hotkey_unregister` | — | `{ success: true }` |
| `hotkey_status` | — | `{ enabled, hotkey: string \| null }` |
| `autostart_get` | — | `{ success, enabled, supported }` (`success: false` = state unknown) |
| `autostart_set` | `enabled` | `{ success, enabled, supported }` — the state read back after the write |
| `notification_show` | `payload: { title, body, sessionId?, dedupeKey?, whenUnfocused? }` | `{ shown, reason? }` — `reason`: `"focused"` (`whenUnfocused` and a Netcatty window is focused), `"duplicate"` (`dedupeKey` already shown), `"unavailable"`, or the plugin error |

Events (broadcast; the adapter delivers the `trayPanel:*` actions and
`tray:togglePortForward` to the main window only):

| Event | Payload |
| --- | --- |
| `netcatty:tray:focusSession` | `{ sessionId, label }` — for the window `label` |
| `netcatty:tray:togglePortForward` | `{ ruleId, start }` (tray menu) |
| `netcatty:trayPanel:jumpToSession` / `connectToHost` / `closeSession` / `startPortForward` | the id string |
| `netcatty:trayPanel:setMenuData` | `TrayMenuData` |
| `netcatty:trayPanel:refresh` | — |

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

AI control plane (Catty exec, capabilities, MCP host, approvals, tool-output store, External MCP): see [`ipc-mcp.md`](ipc-mcp.md).

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
| `startTelnetSession`, `startSerialSession`, `startMoshSession`, `startEtSession` | `telnet_start`, `serial_start`, `mosh_start`, `et_start` → `.sessionId` (protocol events subscribed first) |
| `listSerialPorts()` / `getTelnetEchoMode(id)` | `serial_list_ports` / `telnet_get_echo_mode` |
| `onTelnetEchoMode`, `onTelnetAutoLoginComplete`, `onTelnetAutoLoginCancelled`, `onMoshSessionReady` | listen `netcatty:telnet:echo-mode`, `netcatty:telnet:auto-login-complete`, `netcatty:telnet:auto-login-cancelled`, `netcatty:mosh:ready`, filtered by `sessionId` |
| `notifySessionUserInput(id)` / `setSessionEncoding(id, enc)` | `session_notify_user_input` (fire-and-forget) / `session_set_encoding` |
| `execCommand(o)` | `session_exec` |
| `openSettingsWindow()` / `closeSettingsWindow()` / `rendererReady()` | `window_open_settings` / `window_close_settings` / `window_renderer_ready` |
| `windowMinimize/Maximize/Close/IsMaximized/IsFullscreen/Focus()`, `setWindowTitle(t)` | `window_*` on the calling window |
| `setTheme`, `setBackgroundColor`, `setLanguage` / `onLanguageChanged` | `app_set_theme`, `app_set_background_color`, `app_set_language` / `netcatty:language-changed` |
| `notifySettingsChanged(p)` / `onSettingsChanged(cb)` | `app_broadcast_settings_changed` / `netcatty:settings:changed` minus own window |
| `registerGlobalHotkey(h)` / `unregisterGlobalHotkey()` / `getGlobalHotkeyStatus()` | `hotkey_register` / `hotkey_unregister` / `hotkey_status` |
| `setShowTrayIcon`, `isShowTrayIcon`, `setCloseToTray`, `isCloseToTray` | `tray_set_show_icon`, `tray_is_show_icon`, `tray_set_close_to_tray`, `tray_is_close_to_tray` |
| `updateTrayMenuData(d)` | `tray_update_menu_data` (`payload`) |
| `onTrayFocusSession(cb)` / `onTrayTogglePortForward(cb)` | `netcatty:tray:focusSession` for this window's label / `netcatty:tray:togglePortForward` + `netcatty:trayPanel:startPortForward` (`start: true`), main window only |
| `onTrayPanelJumpToSession` / `ConnectToHost` / `CloseSession` | `netcatty:trayPanel:*`, main window only |
| `hideTrayPanel`, `jumpToSessionFromTrayPanel`, `connectToHostFromTrayPanel`, `startPortForwardFromTrayPanel`, `closeSessionFromTrayPanel` | `tray_panel_*` |
| `onTrayPanelMenuData(cb)` / `onTrayPanelRefresh(cb)` | `tray_get_menu_data` once (unless a push came first) + `netcatty:trayPanel:setMenuData` / `netcatty:trayPanel:refresh` |
| `getAutoLaunch()` / `setAutoLaunch(e)` | `autostart_get` / `autostart_set` |
| `showSystemNotification(p)` | `notification_show` (`payload`) |
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
| `exportSessionLog`, `selectSessionLogsDir`, `autoSaveSessionLog` | `session_log_export`, `session_log_select_dir`, `session_log_auto_save` (`payload`) |
| `openSessionLogsDir(dir)`, `clearSessionLogsDir(dir)` | `session_log_open_dir`, `session_log_clear_dir` (`directory`) |
| `chooseManualSessionLogPath`, `startManualSessionLog`, `stopManualSessionLog`, `getManualSessionLogStatus` | `session_log_manual_choose_path`, `session_log_manual_start`, `session_log_manual_stop`, `session_log_manual_status` (`payload`) |
| `prepareSessionLog`, `revealSessionLog` | `session_log_prepare`, `session_log_reveal` (`payload: { sessionId }` only) |

Bridge methods that have no Rust counterpart in this version (AI, plugins,
MCP, ZMODEM/YMODEM, FIDO, plugin sync providers, auto-update) are left
`undefined` on the adapter; the renderer already treats them as optional.
`onTrayPanelCloseRequest` stays undefined too: the Electron main process
never sends that event.
