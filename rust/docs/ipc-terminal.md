# Terminal plumbing and autocomplete

Implemented in `apps/netcatty-desktop/src/commands/terminal.rs` (plus small
hooks in `commands/session.rs`). Renderer adapter:
`infrastructure/tauri/bridge/terminal.ts` (`createTerminalBridge`). Electron
spec: `electron/preload/api.cjs`, the `figSpecApi` of `electron/preload.cjs`,
`terminalBridge.cjs` (paste receipts, PTY clear, drain / display-ready),
`sshBridge/startSession.cjs` (reuse fallback), `sshBridge/sessionOps.cjs`
(`listSessionDir`) and `main/registerBridges.cjs` (fig specs, local listdir).

## Paste write receipts

`session_write` takes the Electron `pasteRequestId` and `lineDelayMs`
options. A write with a `pasteRequestId` gets receipts on
`netcatty:paste-write` once each transport write returned (not when the
remote ran it):

| Event | Payload |
| --- | --- |
| `netcatty:paste-write` | `{ sessionId, requestId, index?, done? }` |

* one event per written chunk with its `index` (a single write is index 0);
  the last one also has `done: true`;
* a batch that is cancelled or blocked (ZMODEM transfer running) ends with
  `{ done: true }` and no `index`; a failed write is reported like a
  cancelled one.

Paced writes (`lineDelayMs`, one line per delay) are cancellable, as in
Electron's `clearPendingAutomatedWrites`: a new paste, a new paced write or a
real keystroke (not an xterm report like `ESC[12;3R`, not `automated`)
cancels the remaining lines of the session's pending batches, and so does
`interruptSession(id, trace, { cancelPendingWritesOnly: true })`:

| Command | Args | Returns |
| --- | --- | --- |
| `terminal_cancel_pending_writes` | `sessionId` | — |

## Connection reuse fallback

`session_start_ssh` with a `sourceSessionId` (reuse allowed, not
single-channel) that had to dial a fresh connection, because the source is
gone or points elsewhere, emits:

| Event | Payload |
| --- | --- |
| `netcatty:connection-reuse:fallback` | `{ sessionId, sourceSessionId }` |

The adapter calls `onConnectionReuseFallback(cb)` listeners as
`cb(sessionId, sourceSessionId)`.

## Windows PTY info

| Command | Args | Returns |
| --- | --- | --- |
| `terminal_windows_pty_info` | — | `null` off Windows, else `{ backend: "conpty", buildNumber? }` |

`getWindowsPtyInfo()` is synchronous in the renderer, so the adapter fetches
the answer once at startup (Windows only) and returns it from then on (`null`
before, which makes the renderer default to `conpty`). portable-pty always
uses ConPTY (no winpty fallback), hence `conpty` regardless of the build;
the build number comes from `ver`.

## Fig autocomplete specs

| Command | Args | Returns | Bridge method |
| --- | --- | --- | --- |
| `figspec_list` | — | `string[]` | `listFigSpecs` |
| `figspec_load` | `commandName` | `string \| null` (the spec module source) | `loadFigSpec` |

Specs are the files Electron uses: `@withfig/autocomplete/build` (names from
its `index.js`) plus Netcatty's `electron/specs`, local ones first, without
the `aws` / `gcloud` / `az` specs. Names must match `[@a-zA-Z0-9._/+-]`, not
start with `/` or `\` and not contain `..`.

Location: `<resource_dir>/figspecs/withfig` and `<resource_dir>/figspecs/local`,
staged by `node rust/scripts/stage-figspecs.cjs` (the Tauri build workflow
runs it and maps `resources/figspecs/` to `figspecs/` in `bundle.resources`);
debug builds fall back to the checkout (`node_modules/@withfig/autocomplete/build`,
`electron/specs`). A release built without staging lists no specs.

The spec files are ES modules whose default export is the spec. Electron's
main process `import()`ed them and JSON round-tripped the result over IPC;
the backend has no JavaScript engine, so `figspec_load` returns the source
and the adapter imports it through a blob URL and applies the same JSON
round trip (functions such as generators are dropped). A missing or broken
spec resolves to `null`.

## Directory listings

| Command | Args | Returns | Bridge method |
| --- | --- | --- | --- |
| `autocomplete_local_listdir` | `payload: { path, foldersOnly?, filterPrefix?, limit? }` | `{ success, entries: [{ name, type }], error? }` | `listAutocompleteLocalDir` |
| `autocomplete_remote_listdir` | `payload: { sessionId, path, foldersOnly?, filterPrefix?, limit? }` | same | `listAutocompleteRemoteDir` |

`type` is `file`, `directory` or `symlink`; `filterPrefix` matches
case-insensitively; `limit` is clamped to 1..=200 (default 100); `~` is the
home directory. `foldersOnly` keeps directories and symlinks to directories.

The remote listing runs Electron's POSIX `find` + `sh` script on one exec
channel of the session's SSH connection (NUL-delimited output, no Python /
Perl needed; relative paths resolve against the interactive shell's cwd via
`/proc/<pid>/cwd`). Errors: `Session not found` (unknown or non-SSH
session), `Remote SSH server does not support extra exec channels`
(single-channel servers), `Invalid directory path`, `Invalid directory
listing response`, or the exec error.

## Electron-only plumbing

These bridge methods exist for Electron's terminal worker / MessagePort
architecture; the adapter keeps their shape with the behaviour the renderer
needs under Tauri:

| Method | Tauri behaviour | Why |
| --- | --- | --- |
| `onTerminalOutputDrainRequest(sessionId, cb)` | returns a disposer; never fires | Electron's main asks the renderer to drain its output port before confirming a flow pause. Tauri delivers output as events and `session_set_flow_paused` resolves once the pump is paused, so no drain is requested. |
| `respondTerminalOutputDrain(requestId)` | no-op | answer to the above |
| `notifyTerminalSessionDisplayReady(sessionId)` | no-op | retries output routed to a not yet mounted window; Tauri emits to every window and the bridge keeps a replay backlog |
| `clearSessionPtyBuffer(sessionId)` | no-op | node-pty's ConPTY `clear()`; portable-pty exposes no ConPTY handle to clear (SSH and non-ConPTY sessions were a no-op in Electron as well) |
| `clearTerminalOutputSessionState` | — (not a bridge method) | Electron's preload clears its MCP marker filter on close; the Tauri bridge clears it on `netcatty:exit` (`McpMarkerFilter.clear`), which `session_close` always emits |
