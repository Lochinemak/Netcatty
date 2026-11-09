# Auto-update

Implemented in `apps/netcatty-desktop/src/commands/update.rs` on
`tauri-plugin-updater` (Electron: `electron/bridges/autoUpdateBridge.cjs`,
`dirtyEditorGuard.cjs`, `windowManager.quittingForUpdate`). The renderer side
is `infrastructure/tauri/bridge/update.ts` (`createUpdateBridge`); the
consumer, `application/state/useUpdateCheck.ts`, is unchanged.

## Model

The renderer drives a **prompt** flow; nothing is installed without an
explicit request:

1. `update_check` contacts the manifest. An update that is strictly newer
   (semver) than the running version is announced with
   `netcatty:update:update-available`; otherwise
   `netcatty:update:update-not-available`.
2. When the `autoUpdate` preference is on, the announced update is downloaded
   immediately (status `downloading`); otherwise the status stays `available`
   until `update_download` is called.
3. The download streams `netcatty:update:download-progress`, verifies the
   minisign signature against `plugins.updater.pubkey` and ends with
   `netcatty:update:downloaded` (status `ready`) or `netcatty:update:error`.
4. `update_install` first asks every main window about unsaved editors (see
   below). With unsaved work it broadcasts `netcatty:update:needs-save` and
   stops. Otherwise it commits the app to a quit (close-to-tray is switched
   off — Electron's `quittingForUpdate`), installs the verified bundle and
   relaunches (`AppHandle::request_restart`; on Windows the installer exits
   the process itself). A failed install rolls the flags back, sets status
   `error` and broadcasts `netcatty:update:error`; a 60 s watchdog does the
   same rollback if the process is somehow still alive.

Automatic checks (Electron's `startAutoCheck`): one check 5 s after startup
and one 2 s after the preference is re-enabled, both only while the
preference is on and the updater is supported. A manual `update_check`
cancels a queued automatic check so two never overlap. The hourly cadence is
the renderer's, as under Electron.

The preference is persisted in the KV store under `auto-update.enabled`
(`"true"` / `"false"`, default enabled — Electron: `auto-update-pref.json`).

## Commands

| Command | Args | Returns |
| --- | --- | --- |
| `update_check` | — | `CheckResult` (below) |
| `update_download` | — | `{ success, error? }` — resolves when the download finished (or failed) |
| `update_install` | — | `void`; outcome arrives as events (quit, `needs-save` or `error`) |
| `update_get_status` | — | `{ status: "idle" \| "available" \| "downloading" \| "ready" \| "error", percent, error, version, isChecking }` |
| `update_get_auto_update` | — | `{ enabled }` |
| `update_set_auto_update` | `enabled` | `{ success }` |
| `app_report_dirty_editors` | `payload: { requestId, hasDirty, reason?, pending? }` | `void` (reply to `app:query-dirty-editors`, see below) |

`CheckResult` (Electron's `netcatty:update:check` shapes):

| Situation | Result |
| --- | --- |
| update found | `{ available: true, supported: true, version, releaseNotes, releaseDate }` |
| up to date | `{ available: false, supported: true }` |
| check failed (network, manifest) | `{ available: false, supported: true, error }` — not broadcast |
| a check is already running | `{ available: false, supported: true, checking: true }` |
| a download is running | `{ available: true, supported: true, downloading: true, version }` |
| an update is ready to install | `{ available: true, supported: true, ready: true, version }` |
| updater unavailable | `{ available: false, supported: false, error, releasesUrl }` |

## Events

| Event | Payload |
| --- | --- |
| `netcatty:update:update-available` | `{ version, releaseNotes, releaseDate }` |
| `netcatty:update:update-not-available` | `{}` |
| `netcatty:update:download-progress` | `{ percent, bytesPerSecond, transferred, total }` (at most every 150 ms, and on every whole-percent change) |
| `netcatty:update:downloaded` | — |
| `netcatty:update:error` | `{ error }` — download and install failures |
| `netcatty:update:needs-save` | — an install was blocked by unsaved work |
| `app:query-dirty-editors` | `{ requestId, deadline }` — sent to one window (see below) |

All `netcatty:update:*` events are broadcast to every window so the settings
window sees the same state as the main window.

## "Manual download" fallback

`supported: false` makes the renderer show its "open GitHub releases" link
instead of the download button (`useUpdateCheck.startDownload`). The updater
is reported unsupported when:

* this is a debug build (`cargo run`, `tauri dev`): nothing to replace;
* the updater plugin could not initialise (no `plugins.updater` config —
  the headless tests);
* `plugins.updater.pubkey` is not a minisign public key (the placeholder in
  `tauri.conf.json`), i.e. an unsigned build;
* on Linux, the package format is unknown: not an AppImage (`APPIMAGE` env
  or bundle type) and not a deb / rpm bundle — snaps, tarballs, distro
  packages. AppImages are replaced in place; deb / rpm bundles are installed
  through `dpkg -i` / `rpm -U` with `pkexec` / a graphical sudo, the
  package-manager path Electron used for its marked deb / rpm / pacman builds.

macOS and Windows release bundles are always supported (`.app.tar.gz`
replacing the bundle, NSIS / MSI installer in passive mode).

## Dirty-editor guard

Before committing to the quit, `update_install` runs Electron's
`dirtyEditorGuard` round trip against every main window (settings and tray
panel windows do not own editor tabs):

1. Rust emits `app:query-dirty-editors` `{ requestId, deadline }` to the
   window (`deadline` is Unix milliseconds, 5 s ahead).
2. The renderer (`useAppStartupEffects.ts`, unchanged) answers through the
   bridge's `reportDirtyEditorsResult(hasDirty, reason, { requestId, pending })`
   → `app_report_dirty_editors`. Only the queried window's reply is
   accepted (the command checks the caller's label, Electron checked
   `event.sender`).
3. `{ hasDirty: true, reason: "transfers", pending: true }` acknowledges
   unfinished transfers being paused and keeps the query open; the final
   reply settles it. On timeout the guard fails open, unless transfers were
   acknowledged as pending — then it blocks, like Electron.

`DirtyEditorGuard` is reusable for a before-quit guard (Electron
`main.cjs` `before-quit`), which is not ported yet.

## Build, signing and publishing

* `tauri.conf.json`: `plugins.updater.endpoints` points at
  `https://github.com/<owner>/Netcatty/releases/latest/download/latest.json`
  — a static manifest, so no `{{target}}` / `{{arch}}` placeholders are
  needed: the plugin looks up `{os}-{arch}-{bundle}` then `{os}-{arch}` in its
  `platforms` object. `bundle.createUpdaterArtifacts: true` makes the bundler
  write `Netcatty.app.tar.gz` (macOS) and a minisign `.sig` next to every
  installer when `TAURI_SIGNING_PRIVATE_KEY` is set.
* `.github/workflows/build-tauri.yml`: the build jobs read
  `TAURI_SIGNING_PRIVATE_KEY` / `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` from the
  repository secrets (optional `TAURI_UPDATER_PUBKEY` variable for forks),
  point the endpoint at the building repository, request updater artifacts
  only when the key is present, and upload the `.sig` files and the
  per-architecture `Netcatty_<arch>.app.tar.gz`. The release job writes
  `latest.json` from the signed artifacts (`darwin-aarch64`, `darwin-x86_64`,
  `windows-x86_64[-nsis|-msi]`, `linux-x86_64[-appimage|-deb|-rpm]`,
  `linux-aarch64-deb|-rpm`) and publishes it with the bundles.
* Key generation and where the public key goes: `rust/README.md`,
  "Auto-update signing".
