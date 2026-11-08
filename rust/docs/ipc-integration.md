# OS shell integration

Deep links, launch arguments, single instance, "open terminal here", the
Windows Explorer verbs, portable data, app icon variants and the macOS Dock
menu.

* Logic: `crates/netcatty-integration` (pure, unit tested on every OS):
  `putty.rs`, `securecrt.rs`, `deeplink.rs`, `open_terminal.rs`,
  `launch.rs`, `explorer.rs`, `app_icon.rs`, `dock.rs`; `macos.rs` holds the
  AppKit / Launch Services calls.
* Tauri side: `apps/netcatty-desktop/src/commands/integration.rs`.
* Renderer adapter: `infrastructure/tauri/bridge/integration.ts`
  (`createIntegrationBridge`).
* Electron spec: `electron/deepLink.cjs`, `openTerminalPath.cjs`,
  `explorerContextMenu.cjs`, `puttyCommandLine.cjs`,
  `secureCrtCommandLine.cjs`, `portableData.cjs`, `mainWindowReuse.cjs`,
  `bridges/appIconManager.cjs`, the Dock menu in
  `bridges/globalShortcutBridge.cjs` and the `second-instance` / `open-url` /
  `open-file` / `activate` handlers in `main.cjs`.

## Launch intents

| Source | Platform | Arrives through |
| --- | --- | --- |
| `ssh://` / `telnet://` / `jms://` URL | Windows, Linux | argv (cold start) or `tauri-plugin-single-instance` (running app) |
| `ssh://` / `telnet://` / `jms://` URL | macOS | Apple Event → `tauri-plugin-deep-link` `on_open_url` |
| PuTTY argv (`-ssh user@host -P 22 -pw x`, `-telnet`, `-l`, `-newtab`) | all | argv / single instance |
| SecureCRT argv (`/SSH2 /L user /P 22 /PASSWORD x host`, `/TELNET`, `/N`) | all | argv / single instance |
| `--open-terminal-path <dir>` / `--open-terminal-shell <id>` | all | argv / single instance (Explorer verbs, scripts) |
| folder dropped on the Dock icon / "Open With" | macOS | Apple Event (`file://` URL; `Info.plist` declares `public.folder`) |

Parsing, gating and second-instance routing are Electron's, case for case
(the Electron tests are ported): SecureCRT switches are tried before PuTTY;
option operands are never standalone URLs; a launch with any scheme URL is
not parsed as a command line; PuTTY / SecureCRT launches
(`viaCommandLine`) bypass the `ssh://` switch, scheme links follow it;
`jms://` follows its own switch (default off). Second instance routing, first
match wins: jms URLs → telnet → ssh → open-terminal requests (relative paths
resolve against the second instance's working directory; nothing valid →
focus) → focus. The forwarded argv keeps its original order (no Chromium
regrouping) and is zeroized after parsing; queued URLs (which may carry a
password) are zeroized on drop and never logged.

### Delivery

Intents are queued in Rust until the **main** window's bridge attaches, then
emitted live (main window brought forward first; recreated from the config
when it no longer exists — Electron `getReusableMainWindow` /
`createAndShowMainWindow`).

| Command | Args | Returns |
| --- | --- | --- |
| `integration_renderer_attach` | — | `{ intents: [{ channel, payload }], coldStartSettled: true }` — queued intents handed over once; marks cold start settled. Windows other than `main` get `{ intents: [], coldStartSettled: true }`. |

Events (main window, Electron channel names and payloads):

| Event | Payload |
| --- | --- |
| `netcatty:deepLink:ssh` | `{ url, tabName? }` |
| `netcatty:deepLink:telnet` | `{ url, tabName? }` |
| `netcatty:deepLink:jms` | `{ url }` |
| `netcatty:openTerminalPath` | `{ path?, shell? }` |

The adapter listens to the four channels before calling
`integration_renderer_attach` (on the first `on*` subscription), feeds the
returned intents through the same path and then fires
`onColdStartIntentsSettled` (also when the attach call fails, so the startup
terminal is never blocked). Intents without a subscriber yet are buffered
until one subscribes. Outside the main window `onColdStartIntentsSettled`
fires immediately and the intent subscriptions are no-ops.

## Deep-link switches

| Command | Args | Returns |
| --- | --- | --- |
| `integration_get_ssh_deep_link_enabled` | — | `bool` (default `true`) |
| `integration_set_ssh_deep_link_enabled` | `{ enabled }` | `{ enabled, success }` |
| `integration_get_jms_deep_link_enabled` | — | `bool` (default `false`) |
| `integration_set_jms_deep_link_enabled` | `{ enabled }` | `{ enabled, success }` |

The ssh switch drives both the `ssh` and `telnet` handlers (ssh decides
success; a telnet change is undone when ssh failed). A toggle applies the OS
change, persists `{ "enabled": bool }` to `ssh-deep-link-preferences.json` /
`jms-deep-link-preferences.json` in the data directory, rolls the OS change
back when persisting fails, and drops queued scheme links (not command-line
launches) when the result is disabled. At startup (release builds) the saved
preference is re-applied; a failed ssh registration disables handling and
drops queued scheme links. Debug builds skip the startup registration so a
development binary never becomes the system ssh handler.

OS registration:

* macOS: Launch Services (`LSSetDefaultHandlerForURLScheme`). Removing hands
  the scheme to the first other registered handler (else `None`); not being
  the default counts as removed. An unbundled binary has no bundle id: the
  call succeeds without touching Launch Services.
* Windows: `HKCU\Software\Classes\<scheme>` (`URL:<scheme>`, `URL Protocol`,
  `shell\open\command = "exe" "%1"`). Removal deletes the key only when it
  launches this executable.
* Linux: `tauri-plugin-deep-link` (`.desktop` handler + `xdg-mime`).
* Bundles: `plugins.deep-link.desktop.schemes = [ssh, telnet, jms]` in
  `tauri.conf.json` (Info.plist URL types, Linux `MimeType`, installer
  registry entries).

## Explorer context menu (Windows)

| Command | Args | Returns |
| --- | --- | --- |
| `integration_get_explorer_context_menu_enabled` | — | `{ enabled, supported }` |
| `integration_set_explorer_context_menu_enabled` | `{ enabled }` | `{ success, enabled, supported }` |

Same keys, label (`Open in Netcatty`), icon (`exe,0`), command
(`"exe" -- --open-terminal-path="%1."` / `"%V."`), suppression
(`ProgrammaticAccessOnly` in HKCU over HKLM verbs), preference / probe files
(`explorer-context-menu-preferences.json`, `explorer-context-menu-probe.json`)
and schema version (3) as Electron, through the registry API instead of
`reg.exe`. HKLM verbs are never deleted by the toggle. Startup reconciliation
(`apply_initial`) runs in release builds. The NSIS installer writes the same
verbs (`windows/installer-hooks.nsh`, `bundle.windows.nsis.installerHooks`).
Elsewhere: `{ enabled: false, supported: false }` and the toggle is a no-op.

## App icon variants

| Command | Args | Returns |
| --- | --- | --- |
| `integration_set_app_icon_variant` | `{ variant }` | `bool` — `false` when the variant artwork is missing |

Artwork comes from the renderer assets (`icons/variants/<v>.png`, macOS
`icons/variants/macos/<v>.png`; the non-mac original falls back to
`icon-win.png` / `icon.png`), read through the asset resolver (debug builds:
the repo `public/`). macOS sets the Dock icon (`applicationIconImage`);
Windows / Linux set every window icon; Windows also swaps the tray icon to
the variant cropped to its artwork and scaled to the small-icon size
(`16px × scale`), the packaged tray artwork for `original`.

## macOS Dock menu and reopen

`applicationDockMenu:` is added to the app delegate class at runtime and
builds the menu each time it opens from the tray menu data the renderer
syncs (`updateTrayMenuData` hosts): "Open Main Window", a separator,
"New Connection" with the saved hosts (pinned, then most recently connected,
then label; disabled "No Saved Hosts" when empty). A host click is
`tray_panel_connect_to_host` (`netcatty:trayPanel:connectToHost`). A Dock
click (`RunEvent::Reopen`) with the main window gone recreates it.

## Portable data

`AppPaths::resolve` (netcatty-store): `NETCATTY_PORTABLE_DATA_DIR`, else on
Windows release builds a `data` directory beside the executable (or beside
`PORTABLE_EXECUTABLE_DIR`) — Electron `portableData.cjs`.

## Not ported

* App Lock gating (out of scope): the Dock host list is never hidden and
  intents are delivered without waiting for an unlock.
* macOS keeping the process alive after the last window closed (Electron
  `window-all-closed`): the Tauri build still quits, as before.
* `launch.cjs` / `launchEnv.cjs` sanitize `NODE_OPTIONS` for the Electron
  dev launcher; there is no equivalent in the Tauri build.
