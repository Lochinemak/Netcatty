# ZMODEM (`rz` / `sz`) and serial YMODEM

Protocol code: `crates/netcatty-zmodem` (sans-IO ZMODEM sessions, the
terminal-output sentry, async YMODEM). Driver and commands:
`apps/netcatty-desktop/src/commands/zmodem.rs`. Renderer adapter:
`infrastructure/tauri/bridge/zmodem.ts` (`createZmodemBridge`). Electron
spec: `electron/bridges/zmodemHelper.cjs` (on `zmodem.js` +
`zmodemFastPath.cjs`), `ymodemTransfer.cjs`, the ZMODEM wiring of
`terminalBridge.cjs`, `sshBridge/startSession.cjs`, `main/registerBridges.cjs`.
Renderer consumers (`useZmodemTransfer`, `useTerminalDragDrop`, the serial
YMODEM actions) are unchanged.

## How it hooks into sessions

Every terminal session kind (SSH, local, telnet, serial, Mosh, ET) goes
through the session pump in `sessions.rs`, which calls three hooks:

* `zmodem::filter_output(app, sessionId, &mut raw)` before a raw chunk is
  decoded. Without any ZMODEM state for the session, a chunk with no ZDLE
  (0x18) and no trailing `*` returns immediately. Otherwise the session's
  `Sentry`:
  * detects the start header (`ZRQINIT` from `sz` → download, `ZRINIT` from
    `rz` → upload) at the end of a chunk, also when it is split across
    chunks;
  * during a transfer feeds every byte to the protocol session; nothing
    reaches `netcatty:data` (pre-header garbage excepted, as in zmodem.js);
  * outside a transfer strips visible hex headers, hides the echo of a
    drag-drop upload command (5 s TTL), withholds a trailing partial hex
    header (1 s; 16 ms for a bare `*`/`**`, so typed stars are not delayed)
    and swallows output for 2 s after an abort while re-sending CAN.
  * While a YMODEM transfer runs, the raw stream goes to it instead and
    nothing is displayed (Electron drops serial output then too).
* `zmodem::poll_flush` in the pump's wake branch: releases a withheld
  fragment once its deadline passed (a timer wakes the pump through the
  flow-control `Notify`).
* `zmodem::session_ended` from `remove_and_release`: cancels a running
  transfer silently (the renderer already got `netcatty:exit`).

`session_write` and `session_interrupt` call `zmodem::intercept_input`:
during a ZMODEM or YMODEM transfer input is swallowed and Ctrl+C cancels the
transfer.

Protocol replies and upload data are written through one ordered writer task
per session (`SessionRegistry::write_input`, raw bytes, `automated`), which
counts outstanding bytes: uploads pause above 1 MiB queued and report
delivered (written) bytes as progress, so the bar tracks the transport
(Electron #3663). A transport that accepts nothing for 60 s fails the upload.

## Transfers

**Download** (remote `sz`): Netcatty answers ZRINIT at once (so `sz` does not
time out), then asks for a folder (native dialog "Select download directory
(ZMODEM)"). Offers wait until a folder is chosen. Each file is saved under
its basename (path components stripped); an existing name becomes
`name (1).ext`, … Partial files are deleted on failure / cancel. Dialog
cancel aborts with `Transfer cancelled`.

**Upload** (remote `rz`): files come from a pending drag-drop (below) or the
file picker "Select files to upload (ZMODEM)". A ZSINIT keepalive goes out
every 5 s while the user picks, and the duplicate-ZSINIT race of zmodem.js
is avoided (`zmodemFastPath` fixes). For SSH sessions (not drag-drop, not
single-channel servers) the cwd of the running `rz` is probed over an exec
channel; for every existing name the renderer gets an overwrite request
(120 s timeout → skip; "apply to rest" reuses the answer; cancel aborts),
overwritten files are removed first and their permission bits restored
afterwards (#1079). Timeouts: offer and file confirmation 45 s (120 s once
backpressure was seen), session close 15 s; on expiry the remote `rz` is
aborted (CAN ×8, Ctrl+C) and the error says so. A receiver ZSKIP fails the
upload with the Electron messages ("Remote protected existing files …" /
"Remote skipped some files …"). A mid-file ZRPOS resends from that offset.

**Cancel** (`cancelZmodem`, Ctrl+C): abort sequence + CAN ×8, 2 s cooldown;
for uploads stray `rz` restarts are ignored for 300 ms and Ctrl+C follows
after 120 ms. Reports `netcatty:zmodem:error` `Transfer cancelled`.

Protocol details (from zmodem.js): Netcatty's ZRINIT advertises CANFDX |
CANOVIO | CANFC32; the sender always escapes control characters; data goes
out as CRC16 ZCRCG subpackets of ≤ 8 KiB (ZCRCE at EOF); receivers with a
buffer size, half duplex, no overlapped I/O or ESC8 are refused. ZCRCQ /
ZCRCW subpackets are acknowledged, repeated ZRQINIT / ZFILE are tolerated,
and the "OO" after ZFIN may arrive in a later chunk.

## Commands

| Command | Args | Returns | Bridge method |
| --- | --- | --- | --- |
| `zmodem_cancel` | `sessionId`, `options?: { interrupt?: boolean }` | — | `cancelZmodem` |
| `zmodem_overwrite_response` | `payload: { requestId, action: "overwrite" \| "skip" \| "cancel", applyToRest }` | — | `respondZmodemOverwrite` |
| `zmodem_drag_drop_upload` | `payload: { sessionId, files: [{ path, remoteName?, temp? }], uploadCommand? }` | `{ success, error? }` | `startZmodemDragDropUpload` |
| `serial_ymodem_send` | `payload: { sessionId, filePath, timeoutMs? }` | `{ success, fileName?, totalBytes?, writtenBytes?, packetsSent?, error?, code? }` | `sendSerialYmodem` |
| `serial_ymodem_receive` | `payload: { sessionId, destinationDir, timeoutMs? }` | `{ success, files?, fileCount?, fileName?, filePath?, totalBytes?, writtenBytes?, error?, code? }` | `receiveSerialYmodem` |

`zmodem_drag_drop_upload` validates the files, types `uploadCommand`
(default `rz -y\r`) into the session and keeps the files for the upload that
starts when `rz` answers; if it does not within 15 s the command is
interrupted and `netcatty:zmodem:error` reports "ZMODEM drag-drop upload did
not start". Errors (as `{ success: false, error }`): "ZMODEM upload is not
available for this session", "ZMODEM transfer already in progress", "No
readable files to upload", "ZMODEM drag-drop upload already pending". Files
marked `temp` (the adapter stages in-memory drops with `stageUploadFile`)
are deleted after the upload or on failure.

YMODEM requires a serial session. Error codes are Electron's
(`YMODEM_TIMEOUT`, `YMODEM_CANCELLED`, `YMODEM_REMOTE_CANCELLED`,
`YMODEM_RETRY_LIMIT`, `YMODEM_INVALID_SIZE`, `YMODEM_EOT_EXPECTED`,
`YMODEM_INCOMPLETE_FILE`, `YMODEM_DESTINATION_NOT_DIRECTORY`,
`YMODEM_DESTINATION_EXISTS`, `YMODEM_NOT_FILE`, `YMODEM_SERIAL_CLOSED`,
`YMODEM_TRANSFER_ERROR`). Received files never overwrite (`name (1).ext`);
a failed receive sends the CAN/BS cancel sequence to the sender. Default
timeout 60 s per byte wait, 10 retries.

## Events

| Event | Payload |
| --- | --- |
| `netcatty:zmodem:detect` | `{ sessionId, transferType: "upload" \| "download" }` |
| `netcatty:zmodem:progress` | `{ sessionId, filename, transferred, total, fileIndex, fileCount, transferType, finalizing? }` (`fileCount: -1` for downloads; throttled to 10/s; `finalizing: true` while waiting for the receiver to confirm an upload) |
| `netcatty:zmodem:complete` | `{ sessionId }` |
| `netcatty:zmodem:error` | `{ sessionId, error }` |
| `netcatty:zmodem:overwrite-request` | `{ sessionId, requestId, filename }` |

The adapter delivers the first four to `onZmodemEvent(sessionId, cb)` with
`type: "detect" | "progress" | "complete" | "error"` added, exactly like the
Electron preload.

## Differences from Electron

* Error recovery is somewhat more tolerant than zmodem.js: repeated
  ZRQINIT / ZFILE headers are answered instead of failing, ZCRCW is
  acknowledged, mid-upload ZRPOS resends from the requested offset, the
  abort sequence is recognised across chunk boundaries. ZDATA offset
  mismatches on download still fail ("Error correction is unimplemented."),
  as in zmodem.js.
* `interruptRemote` (SSH channel `signal("INT")`) is not available on the
  russh shell channel; the Ctrl+C byte that Electron also sends is used.
