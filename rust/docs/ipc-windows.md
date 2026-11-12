# Multi-window IPC (`commands/windows`)

Ports Electron's `windowManager/editorWindow.cjs`, `terminalPopupWindow.cjs`,
`terminalPopupPlacement.cjs`, the `netcatty:window:openSession` handler,
`terminalAttachRestore.cjs`, the attach / snapshot handlers of
`terminalBridge.cjs`, `rendererSessionLifetime.cjs`, `dirtyEditorGuard.cjs` +
the `before-quit` guard, window opacity / background blur and the macOS
application menu. Renderer adapter: `infrastructure/tauri/bridge/windows.ts`.

## Windows

Every extra window loads the same renderer with the Electron hash route, so
the renderer code paths are unchanged. Windows are created hidden and shown
by `window_renderer_ready` (3 s fallback), with the Electron chrome (inset
traffic lights at 12,12 on macOS, frameless elsewhere), the current theme,
background colour and opacity, centred on the invoking window.

| Label | Route | Electron |
| --- | --- | --- |
| `editor` | `index.html#/editor-window` | single detached SFTP editor window (1100×760, min 640×420) |
| `terminal-popup-<n>` | `index.html#/terminal-popup` | system-manager / AI observe popups (920×580, min 480×320) |
| `session-<n>` | `index.html#/session-window` | "open session in new window" (1400×900, min 900×600) |

Capabilities: `capabilities/windows.json` grants these labels the same
permissions as the main window.

### Event targeting

Tauri's default JS `listen()` uses `target: Any`, which also hears events Rust
sends with `emit_to(otherLabel, …)`. The adapter therefore listens through a
hub bound to the current window (`listenToCurrentWindow`, target
`WebviewWindow { label }`): it receives broadcasts and events addressed to
this window only. The update bridge uses the same hub, so
`app:query-dirty-editors` reaches only the queried window.

### Request / response round trips

Rust emits a request event (with a generated `requestId`) to one window and
awaits the reply the renderer sends through `windows_report(channel,
payload)`. Only the queried window, on the expected channel, with the same
`requestId`, settles the request; a destroyed window fails its pending
requests at once (`Target window is gone`).

| Command | Args | Returns |
| --- | --- | --- |
| `windows_report` | `channel, payload` | `bool` (matched a pending request) |

Reply channels: `netcatty:window:editorOpenTabResult`,
`netcatty:window:editorCloseTabsResult`, `netcatty:window:editorSaveResult`,
`netcatty:window:editorDockResult`, `netcatty:terminal:snapshot-response`,
`netcatty:terminal:apply-snapshot-response`.

## Detached editor window

| Command | Args | Returns | Notes |
| --- | --- | --- | --- |
| `windows_open_editor` | `payload: EditorWindowTabSnapshot` | `{ success, reused?, error? }` | Sanitised like Electron (required ids, 10 MiB content cap → `Invalid editor payload`). Opens / reuses `editor`, waits for `windows_editor_ready` (30 s, else the window is destroyed), sends `editorOpenTab` and waits for `editorOpenTabResult { ok: true }` (30 s). The calling window becomes the tab's *source*; only accepted tabs are owned. `Editor window is closing` during a native close. |
| `windows_editor_ready` | — | `void` | The editor page subscribed to `editorOpenTab` (Electron `netcatty:window:editorReady`). |
| `windows_focus_editor` | `editorId?` | `{ success, error? }` | Emits `editorActivateTab`, shows the window. `Editor window is not open`. |
| `windows_close_editor_tabs` | `payload: { editorIds, force? }` | `{ success, cancelled, closedIds, error? }` | Waits for pending opens of those tabs, then the editor's Save / Discard / Cancel flow (`editorCloseTabs`, 120 s; forced: 8 s, then closes anyway). Sources get `editorTabsClosed`. |
| `windows_save_editor_tab` | `payload: { editorId, sessionId, sftpTabId, hostId, remotePath, content }` | `{ ok, liveConnectionId?, error? }` | Routed to the source window (`editorSaveRequest` → `editorSaveResult`, 30 s). A `liveConnectionId` emits `editorRemapSession` to the editor. |
| `windows_dock_editor_tab` | `payload: EditorWindowTabSnapshot` | `{ success, error? }` | Source window (`editorDockRequest` → `editorDockResult`, 8 s). |
| `windows_report_editor_dirty` | `payload: { editorId, dirty }` | `void` | → `editorDirtyChanged` to the source. |
| `windows_report_editor_tabs_closed` | `payload: { editorIds? , editorId? }` | `void` | → `editorTabsClosed` to each source (accepted tabs). |
| `windows_remap_editor_session` | `payload: { fromSessionId, toSessionId }` | `void` | → `editorRemapSession` to the editor. |

Events (to one window): `netcatty:window:editorOpenTab`, `…editorActivateTab`,
`…editorCloseTabs`, `…editorSaveRequest`, `…editorDockRequest`,
`…editorDirtyChanged`, `…editorTabsClosed`, `…editorRemapSession` (Electron
payloads; requests carry `requestId`).

Lifecycle: a native close of `editor` (title bar, `windowClose`) runs the
close flow for every tab and is coalesced; Cancel keeps the window. When the
window is destroyed every remaining tab is reported closed to its source.

## Terminal popups and session windows

| Command | Args | Returns | Notes |
| --- | --- | --- | --- |
| `windows_open_terminal_popup` | `payload: TerminalPopupPayload` | `{ success, popupId?, reused?, error? }` | `popupId` from the payload or a UUID (`Terminal popup ID is already active: …`). With `attachSessionId`: one popup per session (reused) and a random `attachAuthorization` grant bound to session + popup window. Placed beside `avoidClientRect` (CSS px of the invoking window) with Electron's placement rules, else centred. |
| `windows_terminal_popup_config` | — | payload \| `null` | The popup page pulls its config (payload + `popupId` + `attachAuthorization`); Electron pushes it after load and buffers it in the preload. Kept for remounts. |
| `windows_mark_attach_close_prepared` | `sessionId, authorization` | `{ success, error? }` | Only from the grant's popup (`Unauthorized attach request`). |
| `windows_open_session` | `payload: { title, sourceSession, localShellType? }` | `{ success, error? }` | Opens `session-<n>` and resolves once its page took the payload (8 s: `New window did not become ready in time`). `Invalid session payload` without `sourceSession`. |
| `windows_take_open_session` | — | payload \| `null` | The session window takes its `onOpenSessionInNewWindow` payload once. |

Attach popup close: a close of an attached popup that has not called
`windows_mark_attach_close_prepared` is prevented and
`netcatty:terminal-popup:prepare-close { sessionId, authorization }` is sent;
the page pushes its state home and closes again. After 2 s the popup is
destroyed regardless. When a popup is destroyed its grant is released and an
attached session's display returns to the main window.

## Session output routing and attach hand-over

Rust tracks each session's owner and display window. A routed session's
output is emitted as `netcatty:data/<display label>`, which only that window
listens for: Tauri evaluates an event in every webview that has a listener for
its name (the target only filters the handlers), so a per-window name is what
keeps hidden windows (tray panel, settings) from receiving terminal output.
Untracked sessions, and the rare out-of-pump writes (X11 notices, MCP), use the
broadcast `netcatty:data`.

* the window that started a session reports it with `windows_track_session`
  (the adapter does this after every `startSession`); its sessions are closed
  when the window is destroyed (Electron `rendererSessionLifetime`);
* the display window follows the owner, except while an attach popup holds
  it (rebind) — the popup never becomes the owner;
* every change is broadcast as `netcatty:window:session-output-route
  { sessionId, label | null, revision }` (Tauri-only); the adapter drops
  output (and its replay backlog) of sessions displayed by another window.
  Unknown / unrouted sessions are accepted everywhere. New windows load the
  current table with `windows_output_routes` (`{ routes: [...] }`); stale
  changes are ignored by revision.

Numeric `webContentsId`s are stable per-window ids (the main window is the
only restore target, like Electron's `findRegisteredMainWebContents`).

| Command | Args | Returns | Notes |
| --- | --- | --- | --- |
| `windows_track_session` | `sessionId` | `void` | Prunes routes of ended sessions. |
| `windows_output_routes` | — | `{ routes: RouteChange[] }` | |
| `windows_rebind_output` | `sessionId, authorization` | `{ success, previousWebContentsId?, webContentsId?, error? }` | Grant required (`Unauthorized attach request`); `Session not found`. |
| `windows_restore_output` | `sessionId, webContentsId?, authorization` | `{ success, restored?, webContentsId?, error? }` | Back to the main window; `{ success: true, restored: false }` for an ended session. |
| `windows_request_snapshot` | `sessionId, authorization` | `{ success, snapshot, perCharacterInput?, kittyKeyboardModeState?, kittyKeyboardProtocolEnabled?, passwordPromptActive?, cwd?, title?, error? }` | `netcatty:terminal:snapshot-request { sessionId, requestId }` to the display window, 2 s (`timeout`). Kitty state normalised like Electron. |
| `windows_apply_snapshot` | `payload` (Electron `applySnapshot` shape + `authorization`) | `{ success, error? }` | `netcatty:terminal:apply-snapshot` to the main window (without the token); answered only when the page returns `true` (2 s `timeout`). `Missing sessionId or snapshot`, `Home renderer not found`. |

## Window state, chrome and the quit guard

| Command | Args | Returns | Notes |
| --- | --- | --- | --- |
| `windows_set_opacity` | `opacity` (number \| null) | `true` | Clamped 0.5 … 1 on every app window (main, settings, editor, popups, session windows). macOS: `NSWindow.alphaValue`. Linux: no-op (as in Electron). Windows: **not applied** (WebView2 is not composited into `WS_EX_LAYERED` windows). |
| `windows_set_background_blur` | `enabled` | `bool` (supported) | macOS only, like Electron: while enabled *and* opacity < 1, windows keep alpha 1, get the `hud` vibrancy material and a transparent backing (the tray panel gets the material only). Background colour pushes keep the transparent backing; disabling restores the last colour or the theme default. |
| `windows_set_terminal_keyboard_focus` | `focused` | `void` | Recorded per window (`windows::has_terminal_keyboard_focus`). |

Events (to one window): `netcatty:window:shown` (main / session window shown:
renderer-ready show, tray / hotkey / Dock foreground, `window_open_main`),
`netcatty:window:will-hide` (right before the tray hides the main window),
`netcatty:window:focus-requested` (explicit foreground requests),
`netcatty:window:command-close` (macOS Cmd+W).

macOS application menu (Electron `buildAppMenu`, labels in en / ru / zh-CN /
zh-TW, rebuilt on `app_set_language`): app menu (About, Hide, Hide Others,
Show All, Quit), Edit, View (Reload, Toggle Developer Tools in debug builds,
Full Screen), Window (Minimize, Zoom, **Close Window** Cmd+W, Bring All to
Front). Close Window sends `command-close` to the main / settings window (the
renderer closes the active tab first) and closes other windows directly. Quit
calls `app.exit(0)`. Windows / Linux get no native menu (frameless windows;
the renderer handles Ctrl+W).

Unsaved-editor checks (`app:query-dirty-editors` / `app_report_dirty_editors`
from `ipc-update.md`, 5 s, fail open):

* **Quit** (`RunEvent::ExitRequested` with an exit code: menu Quit, tray Quit,
  `quitApp`): the exit is held while the main, session and editor windows
  are asked; a clean answer re-issues `app.exit(code)`, a dirty one brings
  those windows forward (and shows a native "Unsaved changes" box for
  editors). The update restart (`RESTART_EXIT_CODE`) skips it — the install
  already asked the same windows (`windows::dirty_editor_windows`).
* **Main / session window close** (unless hidden to the tray): the editor
  tabs the window is the source of go through the editor's close flow, then
  the window is asked; it closes only when both pass.

## Not ported / limitations

* `displayRecovery.cjs` (moving a window back to a reconnected display),
  persisted window bounds of the main window (`window-state.json`) and the
  Windows-specific frameless chrome options (`windowsWindowChrome.cjs`).
* The View menu has no zoom items (the renderer handles them) and no plugin
  menu.
* Electron's flow pause around an attach restore: the route change and later
  output travel the same ordered event stream, so no pause is needed.
