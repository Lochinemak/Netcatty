# Transfers, native drag, X11, Mosh / ET stats and SSH cwd

`commands/transfers2.rs` (managed state `Transfers2State`, registered by
`transfers2::setup` in `lib.rs`), the `netcatty-transfers` crate
(admission queue, compressed-upload helpers, cleanup and drag rules),
`netcatty-ssh::x11` (X11 proxy) and `netcatty-sysmgr::cwd` (cwd probe).
Renderer adapter: `infrastructure/tauri/bridge/transfers.ts`
(`createTransfersBridge`). Electron sources: `transferBridge.cjs`,
`transferLimits.cjs`, `compressUploadBridge.cjs`, `localFileDragBridge.cjs`,
`x11Forwarding.cjs`, `sshBridge/moshStatsConnection.cjs`,
`sshBridge/sessionOps.cjs` (`getSessionPwd`).

## Global transfer queue

Every renderer `transfer_start` is admitted through one queue before it
runs (`sftp::run_transfer` → `transfers2::admit`). Resource keys are
`host:<sourceHostId>` / `host:<targetHostId>`, else
`session:<sourceSftpId>` / `session:<targetSftpId>`, else `local`; a job
runs when each of its keys has fewer running transfers than the limit
(default 2). Jobs are scanned in queue order, so a busy host never blocks
another host. Payload extras honoured: `skipAdmission: true` (run at once),
`globalConcurrency` (sets the limit first), `lifecycleEpoch` (copied to the
`queued` event). Internal transfers (file watch syncs) are not queued.

Events on `netcatty:sftp:global-transfer`:

* `queued` before admission: the `started` fields plus
  `controlKind: "stream"`, `lifecycleState: "queued"` (and `lifecycleEpoch`
  when the payload has one); `started` follows when the slot is granted.
* `transfer_pause` on a queued transfer: `{ type: "paused", transferId,
  checkpointBytes, resumeStage, lifecycleEpoch? }` (checkpoint = the largest
  of `checkpointBytes` / `downloadCheckpointBytes` / `uploadCheckpointBytes`
  of the payload, never 0 when one was given); `transfer_start` resolves
  `{ transferId, cancelled: true, warning: "paused" }`.
* `transfer_cancel` on a queued transfer: `{ type: "cancelled", transferId,
  endedAt }`; `transfer_start` resolves `{ transferId, error: "Transfer
  cancelled", cancelled: true }`.

| Command | Args | Returns |
| --- | --- | --- |
| `transfer_prioritize` | `transferId` | `{ success }` — `true` when the transfer was queued and moved to the front |
| `transfer_set_concurrency` | `limit` | `{ success: true, limit }` — integers 1..=16 apply (and admit waiting jobs at once); anything else leaves the limit unchanged |
| `transfer_cleanup` | `payload: { transferId, sourcePath, targetPath, targetSftpId?, targetEncoding?, stagedTargetPath? }` | `{ success }` (`false` + `error` only without `transferId`) |

`transfer_cleanup` (dismiss / clear / fresh-id retry) removes only
Netcatty's own artifacts and does nothing while that `transferId` is still
running: the temp stages `<temp>/.transfer_<id>_<name>.part` of the target
and source basenames, the engine stage `.<name>.netcatty-part` next to the
target (through SFTP when `targetSftpId` names an open browser, on disk when
`targetSftpId` is absent; files only), and `stagedTargetPath` recursively —
but only when it is exactly `${targetPath}.netcatty-<id with [^A-Za-z0-9_-]
→ _>.part` (the renderer's directory-replace stage); any other path is
refused with a warning in the log.

Not ported: `resumeTransfer` / `clearPendingTransferCancel` stay as before
(a paused transfer is restarted by the renderer with its checkpoint).

## Compressed folder upload

| Command | Args | Returns |
| --- | --- | --- |
| `compress_check_support` | `sftpId` | `{ supported, localTar, remoteTar, error? }` — local `tar --version` (10 s), remote `tar --version` on an exec channel (15 s; `code 0` with output). Cached per `sftpId` for 10 s (64 entries). Single-channel servers (by banner) report `remoteTar: false`. |
| `compress_start` | `payload: { compressionId, folderPath, targetPath, sftpId, folderName, totalBytes, lifecycleEpoch? }` | resolves at the end: `{ compressionId, success: true }` \| `{ compressionId, cancelled: true }` \| `{ compressionId, error }`; rejects `INVALID_ARGUMENT` "Compressed upload is already active: <id>" |
| `compress_cancel` | `compressionId` | `{ success: true }`; `{ success: true, inactive: true }` when it already settled |
| `compress_pause` | `compressionId` | `{ success: true, deferred, lifecycleEpoch }` \| `{ success: false, reason: "Compression is not active" }` |
| `compress_resume` | `compressionId` | `{ success: true, lifecycleEpoch }` \| `{ success: false, reason }` |

Phases (progress percent → `transferred = percent/100 × totalBytes`):

1. **compressing** 0–30 %: `tar -czf - --exclude=._* --exclude=.DS_Store
   --exclude=.Spotlight-V100 --exclude=.Trashes <folder>` with the parent as
   cwd and the temp archive (`<temp>/<ts>_<n>_<folder>.tar.gz`) as stdout,
   so no local path reaches argv (Windows `%SystemRoot%\System32\tar.exe`);
   an archive inside the source is excluded from itself. Progress from the
   archive size every 500 ms. Cancel: SIGTERM, SIGKILL after 750 ms.
2. **uploading** 30–90 %: the archive goes to
   `<target>/.<folder sanitized>.netcatty-<sha256(id)[..16]>.tar.gz` through
   the transfer engine (staged, admitted through the global queue under
   `session:<sftpId>`, silent: no `compress-<id>` events).
3. **extracting** 90–100 %: one `sh` script on an exec channel (timeout 60 s
   + 30 s per started 10 MiB, max 10 min) extracts into
   `.netcatty-compress-<hash>.stage` next to the target, copies an existing
   folder into the stage first (merge semantics), swaps it into place through
   a stable `.backup`, restores the backup on any failure / signal, refuses a
   symlink target and removes the archive. Commits to the same
   `user@host:port` + folder are serialized. Then a best-effort `rm -f` of
   the archive and the local temp archive.

Every value spliced into remote commands is single-quoted; the folder name
is reduced to its basename and `.` / `..` are refused. The SFTP client is
held for the whole operation, so closing the browser tab does not tear the
connection down mid-upload.

Events (`netcatty:sftp:global-transfer`, `transferId = compressionId`, every
event carries `lifecycleEpoch` and `lifecycleState`): `started` (`direction:
"upload"`, `fileName: "<folder> (compressed)"`, `sourcePath`, `targetPath:
"<target>/<folder>"`, `totalBytes`, `isDirectory: true`, `controlKind:
"compressed-upload"`, `phase: "compressing"`, `startedAt`), `progress`
(`transferred`, `totalBytes`, `speed: 0`, `phase`), `pausing` / `paused` /
`resumed` (`phase`), and exactly one of `completed` (`transferred`,
`totalBytes`) / `failed` (`error`) / `cancelled` (`endedAt`).

Pause: compressing → SIGSTOP / SIGCONT of the local tar on Unix (Windows:
`deferred`, takes effect at the next phase boundary); uploading → the
transfer stops at its checkpoint and restarts from it on resume;
extracting → `deferred`, applied after the atomic extraction. The terminal
event is published once; a late cancel never overrides `completed`.

Electron's `netcatty:compress:progress|complete|error|cancelled` sender
events are not emitted: the renderer only consumes the global transfer
events.

## Native drag of local files

| Command | Args | Returns |
| --- | --- | --- |
| `local_drag_start` | `payload: { requestId, paths }` | `{ started, error? }` |
| `local_drag_cancel` | `requestId` | `void` (adapter: fire-and-forget) |

Validation (`netcatty-transfers::drag`): `requestId` 1–128 chars, 1–4096
paths, absolute, no NUL; on Windows a drive (`C:\`) or UNC share
(`\\server\share`) and never a device path (`\\.\`, `\\?\`). Spelling is
kept (no `..` collapsing), only identical strings are de-duplicated. Each
path is `stat`ed (symlinks followed; broken links and special files are
refused); no content is read. A `local_drag_cancel` of the same window
before validation finished turns the reply into `{ started: false }`. The
drag runs on the main thread through the `drag` crate (macOS AppKit, Windows
OLE, Linux GTK via `gtk_window()`), copy operation, with a 16×16 orange
image. `started: true` never means the drop was accepted. Only local files
are dragged (remote panes keep their HTML drag, as in Electron).

Platform notes: Electron tracks the native mouse gesture in the main process
to refuse a drag whose button was already released; Tauri exposes no such
hook, so that check is not ported (the OS drag simply ends immediately).
The Linux path compiles against `tauri::WebviewWindow::gtk_window` and was
not built in this change (developed on macOS).

## X11 forwarding

`session_start_ssh` with `x11Forwarding: true` always dials a fresh
connection (no transport reuse), generates a random fake
MIT-MAGIC-COOKIE-1 for the `x11-req`, and takes the connection's `x11`
channel receiver. Each forwarded channel connects to the local display:
`x11Display`, else `$DISPLAY`, else `:0` (`localhost:0` on Windows); `:N` →
`/tmp/.X11-unix/XN` (TCP `localhost:6000+N` on Windows), `unix:N` → the
socket, `host:N[.S]` → TCP `6000+N` (`N ≥ 100` is a port), absolute paths
(XQuartz `.../org.xquartz:0`) are unix sockets. The real cookie comes from
`xauth list` (XQuartz's `/opt/X11/bin/xauth` on macOS; 2 s bound, read once
per connection) and replaces the fake one in the client's setup packet;
without a local cookie bytes pass through unchanged. A failed local connect
closes the channel and writes Electron's hint lines into the terminal
(`[X11] Could not connect to the local X11 server: …`, the display target,
and the VcXsrv / XQuartz / Xorg hint). Difference: russh accepts the channel
before the local connect, so a refused display closes the channel instead
of rejecting its open.

## Mosh / ET host-stats companion

Mosh and ET sessions have no SSH transport of their own. `mosh_start`
records the start options (`remember_companion`, protocol `mosh`; usable
once `netcatty:mosh:ready` fired — the handshake vetted the host) and
`et_start` records them right away (protocol `et`; ET through a jump host is
skipped, as Electron uses ET's own ssh environment there). On the first
stats / distro / history / system-manager call (`system.rs` `session_kind`)
a companion SSH connection is dialed to the same `user@host:port` (no jump
hosts, 10 s connect / auth bounds, no keepalive): stored password,
key, identity files, and the local agent unless disabled or an explicit key
is given. It never prompts: keyboard-interactive and passphrase requests
are declined, and a host key that the vault does not trust is accepted only
when `~/.ssh/known_hosts` holds that exact key (fingerprint) for
`host:port`. Authentication or host-key rejections disable the companion for
the session; network errors are retried on the next call. Concurrent calls
share one attempt. Companions of ended sessions are disconnected by a 30 s
sweep.

## SSH terminal cwd (`session_pwd`)

`session_pwd(sessionId, allowHomeFallback?, allowLoginShellFallback?,
timeoutMs?)` — Electron's options (the adapter now forwards them). Local
sessions are unchanged. SSH sessions run Electron's probe (byte-identical,
comments stripped to stay under Dropbear's 9000-byte exec limit) on a
sibling exec channel: `exec sh -c` (so `$PPID` is sshd under fish / zsh),
`NC_SSHD_PPID`, remote watchdog; find the login shell (sibling with a tty,
else a process sharing `SSH_CONNECTION`), follow the deepest foreground
shell (`su` / `sudo`), read `/proc/<pid>/cwd` or `lsof -Fnt` (directories
only; annotation-shaped names verified, `\xNN` / octal escapes decoded
strictly as UTF-8, caret forms refused), then the login shell's cwd
(`allowLoginShellFallback`, default = `allowHomeFallback`), then the home
directory (`allowHomeFallback`, default on). Timeout `timeoutMs` clamped to
100–5000 ms (open bound 5 s). The login shell pid reported on stderr is
remembered per session and targets later probes; a connection shared by
several terminals without a known pid fails with "Current directory is
ambiguous across shared terminal channels". Errors: "Timeout getting pwd",
"Could not determine cwd", "Session changed during cwd probe", and the
single-channel error for `singleChannelSsh` sessions / single-channel
banners. Electron's parked-reconnect cwd recovery is not ported (the Rust
backend has no parked reconnects).

## Session logs for telnet / serial / Mosh / ET

These sessions use the session-log hooks documented in the contract's
"Session logs" section (`session_starting` with `label || hostname`,
`deliver`, `remove_and_release`); `sessionLog` in their start options
enables the automatic log exactly like SSH / local sessions.
