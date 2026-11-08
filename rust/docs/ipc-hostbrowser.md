# Host browser — IPC contract (Tauri)

The in-app "Host Browser" (Electron: `electron/hostBrowser/hostBrowserManager.cjs`,
the stores next to it and the `netcatty:host-browser:*` preload methods). Rust:
`crates/netcatty-hostbrowser` (stores, URL / PDF / theme policy, download file
reservation; pure) and `apps/netcatty-desktop/src/commands/hostbrowser.rs`
(commands, page windows, SOCKS route). Renderer adapter:
`infrastructure/tauri/bridge/hostBrowser.ts`. Conventions are those of
[ipc-contract.md](ipc-contract.md).

## Shape

* A browser record holds up to 32 tabs for one host. Each tab that shows a
  page is its own borderless `WebviewWindow` (label `hb-tab-…`), parented to an
  owner window and positioned over a rectangle of it. Only the active tab's
  window is shown; the others are hidden (not destroyed).
* **Embedded panel** (`openHostBrowser({ embedded: true, browserId })`, the
  renderer's side panel next to a terminal): the owner is the calling renderer
  window, the rectangle comes from `setHostBrowserPanelLayout`, the renderer
  draws the tab strip and address bar (`HostBrowserSidePanel`).
* **Standalone window** (`embedded` absent, id = `hostId`): the owner is a
  browser window (label `host-browser-<n>`) showing Electron's chrome
  (`hostbrowser/browser.html|css|js`, unchanged), its downloads panel is a
  second parented window (`host-browser-dl-<n>`, `downloads.html`). Both are
  served by the `netcatty-hostbrowser:` protocol (Windows:
  `http://netcatty-hostbrowser.localhost/`) and use `tauri-adapter.js` in
  place of the Electron preloads. Capability `capabilities/hostbrowser.json`
  grants them `core:event:default`; page windows get no capability (remote
  origins cannot invoke anything).

### Why not one window with several webviews

Tauri's multi-webview windows (`unstable` feature, `Window::add_child`) were
tried first (spike on macOS 15, Tauri 2.12.5). The child webview renders and
all page callbacks work, but as soon as a second webview is added to the main
window, `get_webview_window("main")` returns `None`: the main window is no
longer a `WebviewWindow`, which breaks every window / tray / settings command
and the `WebviewWindow` command argument. Parented windows keep the main
window intact. Trade-offs: page windows are native windows above the app (the
renderer's popovers cannot overlap a live page, as in Electron; covered pages
are hidden instead of pictured, see below) and on Linux/Wayland the compositor
may refuse to position them.

## Network route

* SSH hosts: `openHostBrowser` starts a dedicated dynamic (SOCKS5) forward
  through `netcatty-forward` (`portforward_start` with the renderer's
  `connectionOptions`, `type: "dynamic"`, `localPort: 0`, `bindAddress:
  127.0.0.1`, `reuseTransport: false`, tunnel id `host-browser-<uuid>`) and
  reads the bound port (`TunnelRegistry::local_addr`). Pages are created with
  `proxy_url(socks5://127.0.0.1:<port>)`; names resolve on the SSH server
  (verified: a page served inside an sshd container under the container's
  own hostname loads, the host cannot resolve that name itself).
* A webview's proxy is fixed when it is created, so page windows exist only
  while the route is `connected`. When the tunnel goes `inactive` / `error`
  the browser is demoted (`route: "disconnected"`, page windows destroyed,
  running downloads flagged as cancelled, tunnel stopped); `retry` / reopening
  dials again and pages are recreated lazily with the new port (back/forward
  history of a recreated page starts over).
* Local hosts (`local: true`) browse directly.
* Navigations are refused unless the route is connected and the scheme is in
  the page allowlist (`http https ws wss blob data`). This is checked for
  frame navigations; sub-resources cannot be filtered (no request hook for
  external pages in wry).

### Per platform

| | SOCKS proxy for pages | Loopback (`localhost`, `127/8`, `::1`) | Notes |
| --- | --- | --- | --- |
| macOS | WebKit `WKWebsiteDataStore.proxyConfigurations` (wry `mac-proxy`, cargo feature `hostbrowser-proxy`, default on). **macOS 14+**; `build.rs` weak-links `Network.framework` so older systems still launch and SSH routes report "requires macOS 14". Verified end to end against sshd. | **Not proxied by WebKit** (verified): such pages would open the *local* machine's services, so SSH-routed browsers refuse them ("Pages on the host's own loopback address … cannot be opened through SSH on macOS"). Electron proxied loopback. | Each tab is an ephemeral (`incognito`) store: tabs do not share cookies. |
| Windows | WebView2 `--proxy-server=socks5://…` (wry), each browser in its own user-data folder (`<cache>/host-browser/<uuid>`, removed on close) because browser arguments are per environment. | Proxied (`--proxy-bypass-list=<-loopback>`), as in Electron. | Extra switches: `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, `--ignore-certificate-errors` (Electron accepted invalid certificates in page tabs). Not run on Windows yet. |
| Linux | WebKitGTK custom network proxy settings on an ephemeral context per page (wry). | Not verified. | Tabs do not share cookies. Wayland may ignore window positions. Not run on Linux yet. |

## Commands

All commands are `async`; the caller window is the `WebviewWindow` argument
(Electron: `event.sender`). Embedded browsers are controlled only by the
window that opened them (`browserId` given); without `browserId` the caller
must be the standalone chrome (or its downloads panel for `downloads_*`).

| Command | Args | Returns | Bridge method |
| --- | --- | --- | --- |
| `hostbrowser_open` | `payload: { browserId?, embedded?, local?, hostId, label, theme, themeTokens?, connectionOptions? }` | `{ reused }` | `openHostBrowser` |
| `hostbrowser_panel_layout` | `payload: { browserId, visible, occluded?, theme?, themeTokens?, bounds? }` | `true`, or `{ layers: [] }` while covered | `setHostBrowserPanelLayout` |
| `hostbrowser_panel_url` | `payload: { browserId, url }` | `true` (queued until connected) | `openHostBrowserUrl` |
| `hostbrowser_panel_close` | `browserId` | `true` | `closeHostBrowserPanel` |
| `hostbrowser_focus` | `hostId` | connected (`bool`) | `focusHostBrowser` |
| `hostbrowser_request_panel` | `payload: { host, sessionId?, url? }` | `true`; emits `request-panel` to the main window, shows it | `requestHostBrowserPanel` |
| `hostbrowser_snapshot` | `browserId?` | `HostBrowserState` (+ `theme`, `themeTokens`, `platform`, `isMaximized`, `embedded`, `downloadsPanelOpen`) | `getHostBrowserPanelState` / chrome `snapshot` |
| `hostbrowser_command` | `command, browserId?` | state (`null` after `window-close`) | `commandHostBrowserPanel` / chrome `command` |
| `hostbrowser_bookmarks_list` | `browserId?` | bookmarks of this host + all-hosts, with `siteIcon*` | `listHostBrowserPanelBookmarks` |
| `hostbrowser_bookmarks_upsert` | `bookmark, browserId?` | bookmark | `saveHostBrowserPanelBookmark` |
| `hostbrowser_bookmarks_remove` | `id, browserId?` | `bool` | `removeHostBrowserPanelBookmark` |
| `hostbrowser_bookmarks_get_all` | — | all bookmarks (app windows only) | `getHostBrowserBookmarks` |
| `hostbrowser_bookmarks_apply` | `items` | `true` (app windows only; replaces the list) | `applyHostBrowserBookmarks` |
| `hostbrowser_downloads_list` | `browserId?` | downloads of this host (`missing` flag) | `listHostBrowserPanelDownloads` |
| `hostbrowser_downloads_command` | `command: { type, id? }, browserId?` | `bool` | `commandHostBrowserPanelDownload` |
| `hostbrowser_downloads_theme` | — | `{ theme, themeTokens }` (downloads panel) | — |

`command.type`: `new-tab {url?}`, `navigate {url, tabId?}`, `activate`,
`close-tab`, `back`, `forward`, `reload`, `stop`, `reorder {tabId,
beforeTabId}`, `set-icon {tabId, dataUrl?, glyph, color}`, `reset-icon`,
`retry`, `set-overlay {open}`, `set-panel {open}`, `set-download-panel
{open}`, and for the standalone chrome `window-minimize`, `window-maximize`,
`window-close`, `window-drag` (replaces `-webkit-app-region: drag`).
Download `type`: `open-folder`, `clear`, `cancel`, `remove`, `open`,
`reveal`, `save-as`, `close` (panel). Error messages are Electron's
(`Too many open tabs`, `Enter a valid web address`, `Browser belongs to
another terminal window`, `Untrusted browser control`, …) with code
`INVALID_ARGUMENT`; a failed route rejects `retry` with `NETWORK`.

## Events

| Event | Payload | Consumer |
| --- | --- | --- |
| `netcatty:host-browser:panel-event` | Electron's `HostBrowserPanelEvent` (`state` / `downloads {startedId?}` / `bookmarks` / `shortcut`) plus `ownerLabel` | adapter keeps events of its window, strips `ownerLabel` |
| `netcatty:host-browser:request-panel` | `{ targetLabel: "main", request }` | adapter (main window), **retained until `onHostBrowserPanelRequest` subscribes**, like the preload |
| `netcatty:host-browser:bookmarks-changed` | `null` | every window |
| `netcatty:host-browser:state`, `:downloads-changed`, `:site-icons-changed`, `:shortcut`, `:theme` | `{ labels, payload }` | standalone chrome / downloads panel (`tauri-adapter.js` filters by label) |

Tauri delivers every event to every `listen()` subscriber (also with
`emit_to`), hence the label fields.

## Pages

* Keyboard shortcuts in a page (⌘/Ctrl + T, W, R, L): an initialisation
  script navigates to `netcatty-hb://shortcut/<type>`; the navigation handler
  cancels it and emits the `shortcut` event (Electron: `before-input-event`).
* `window.open` / `target=_blank` open a new tab (`on_new_window`, denied as
  a window).
* Title: `on_document_title_changed`. Loading: `on_page_load`
  started / finished. Back / forward availability is tracked from committed
  navigations (wry exposes no history API); in-page `pushState` navigations
  are not seen.
* Website icons: after each load the page's `<link rel=icon>` URLs (or
  `/favicon.ico` when nothing is stored) are fetched through the same SOCKS
  route (reqwest `socks5h`, 5 s, 64 KiB, raster types only) into the site
  icon store; custom icons win, as in Electron.
* Embedded focus: showing a page window makes it key on macOS, so the owner
  window is refocused afterwards (Electron attached views without focusing).

## Downloads

`on_download`: `Requested` reserves a non-colliding name in the user's
Downloads directory (`reserve_download_file`, O_EXCL, `name (n).ext`), then
removes the empty placeholder just before the engine writes (WebKit refuses
an existing destination), records `progressing` and opens the standalone
downloads panel; `Finished` records `completed` (size from disk) or
`interrupted`. The store logic is Electron's (per-host history, 500 entries,
active → interrupted after restart, deferred progress writes).

Gaps: the engines report no byte progress (`received`/`total` are 0 until the
end) and cannot cancel a transfer; `cancel` marks the download, which is
removed and recorded as `cancelled` when the engine finishes. Downloads are
accepted only while the route is connected.

## Policy differences from Electron

* **PDF**: Electron rewrote `Content-Disposition` of PDF navigations to
  `attachment` because Chromium's PDF viewer was blocked. wry cannot touch
  response headers of external pages; WebKit / WebView2 render PDFs inline
  with their built-in viewer, so PDFs are shown, not downloaded. The policy is
  kept as `netcatty_hostbrowser::pdf_download_headers` (with Electron's tests)
  for a runtime that can apply it.
* **Invalid TLS certificates**: accepted on Windows (WebView2 switch); WebKit
  (macOS / Linux) shows its error page, wry offers no certificate hook.
* **Covered pages**: Electron returned pictures of the page while a menu
  covered it; Tauri cannot capture a webview, so the page is hidden and the
  renderer shows an empty area (`{ layers: [] }`).
* **Cookies**: per tab on macOS / Linux (ephemeral stores), per browser on
  Windows. Electron used one in-memory session per browser.
* **Zoom**: the renderer's bounds are taken as logical pixels (no page zoom
  in the Tauri renderer).

## Tests

* `cargo test -p netcatty-hostbrowser`: stores (Electron's store / download /
  icon tests), address normalisation, page scheme allowlist, loopback
  detection, PDF policy, theme tokens.
* `cargo test -p netcatty-desktop --test ipc_hostbrowser`: command dispatch on
  `MockRuntime` (bookmark sync, panel requests, embedded lifecycle on a local
  route, tab commands, ownership checks, download commands).
* `node --test --import tsx infrastructure/tauri/bridge/hostBrowser.test.ts`:
  adapter argument shapes, owner filtering, panel request backlog.
* Manual / real runtime (macOS, 2026-11-08): an example binary drove the
  commands in the real app against `rust/scripts/e2e-sshd`: route connects,
  pages load by the container's hostname through the SOCKS forward, loopback
  is refused, a download is stored and completed, back / forward, two tabs,
  page window geometry, standalone chrome + downloads panel rendering through
  the adapter.
