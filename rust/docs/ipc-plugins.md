# Plugin host IPC (`commands/plugins.rs`, crate `netcatty-plugins`)

Rust port of `electron/plugins/` (plugin platform contract `0.1.0-internal.1`).
Plugins built with `@netcatty/plugin-sdk` run unchanged: the host speaks the
same JSON-RPC contract (`packages/plugin-contract/schema`), validated with the
same committed JSON Schema.

Renderer adapter: `infrastructure/tauri/bridge/plugins.ts`
(`createPluginsBridge`), iframe relay: `bridge/pluginRuntimeHost.ts`.

## Commands

| Command | Args | Result |
| --- | --- | --- |
| `plugin_call` | `{ method, payload }` | method result |
| `plugin_runtime_attach` | `{ runtimeId, channel }` | `bool` |
| `plugin_runtime_messages` | `{ runtimeId, messages: Value[] }` | `bool` |
| `plugin_runtime_exited` | `{ runtimeId, reason? }` | — |
| `plugin_runtime_reset` | — | — |

`method` is the suffix of the Electron IPC channel
`netcatty:plugins:<method>` and `payload` is the Electron payload unchanged
(see `electron/preload/api.cjs`). The calling window's label is the owner of
permission prompts, interactions, views and the selected terminal target.
Binary fields travel as base64 under `<name>Base64` keys
(`connection-write.dataBase64`, `importer-detect.sampleBase64`,
`sync-write-object.dataBase64`, `sync-write-chunk.chunkBase64`; results
`importer-select-file.sampleBase64`, `sync-read-object.dataBase64`,
`sync-read-chunk.chunkBase64`); the adapter converts to/from `Uint8Array`.

While the host is unavailable, `terminal-providers`, `terminal-session-event`,
`extension-providers` (→ `[]`), `sync-sidecars-collect` (→ `null`),
`sync-sidecars-apply` (→ `{ applied: false }`), `credential-catalog-update`
(→ `0`), `get-/set-scope-catalog` degrade instead of failing
(`handlePassive`).

### Methods

* Status / lifecycle: `status` (`{ available, experimental, credentialStorageAvailable }`),
  `host-available-sync` (cached by `pluginHostReady()`), `list`, `install`
  (`{ archivePath, enable }`), `set-enabled`, `restart`, `uninstall`,
  `source-binding`, `reset-source`.
* Logs: `log-status`, `log-configure`, `log-open` (opens the folder),
  `log-export` (save dialog), `log-clear` (confirmation dialog).
* Permissions: `permissions`, `set-permission-mode` (optimistic
  `policyRevision`), `revoke-permissions`, `permission-ready`,
  `permission-response` (`{ requestId, actionToken, decision }`).
* Interactions: `interaction-ready`, `interaction-response`, `terminal-target`.
* Contributions: `contributions`, `execute-command`, `update-setting`,
  `reset-setting`, `set-environment`, `get-scope-catalog`, `set-scope-catalog`,
  `credential-catalog-update` (`{ entries: [{ id, ciphertext }] }`; ciphertext
  in the app credential-cipher format `enc:v2:`).
* Themes / icons: `theme-catalog`, `theme-apply`, `brand-icon`, `contribution-icon`.
* Host-drawn views: `host-ui-open`, `host-ui-close`, `host-ui-resource`, `host-ui-event`.
* Terminal Providers: `terminal-providers`, `terminal-provide` (`requestId`),
  `terminal-cancel`, `terminal-session-event`.
* Extension Providers: `extension-providers`, `extension-invoke`,
  `extension-cancel`, `connection-start`, `connection-write`,
  `connection-control`, `authentication-respond`, `importer-detect`,
  `importer-select-file`, `importer-release-file`, `importer-parse-file`.
* Sync Providers: `sync-connect`, `sync-disconnect`, `sync-get-account`,
  `sync-get-capabilities`, `sync-read-object`, `sync-read-chunk`,
  `sync-write-object`, `sync-write-begin`, `sync-write-chunk`,
  `sync-write-commit`, `sync-delete-object`, `sync-put-secret`,
  `sync-delete-secrets`, `sync-restore-secrets`, `sync-sidecars-collect`,
  `sync-sidecars-apply`.
* Not available in this build (return `UNSUPPORTED` / an empty catalog):
  `catalog`, `sources` (built-in official source only), `add-source`,
  `update-source`, `remove-source`, `author`, `catalog-readme`,
  `catalog-readme-images`, `catalog-install`; `ai-host-ready`,
  `agent-host-ready` return `false`.

## Events (Electron channel names)

`netcatty:plugins:contributions-changed`, `themes-changed`,
`catalog-changed`, `permission-prompt` (to the owner window),
`host-interaction` (to the owner window), `host-ui-update`, `view-closed`,
`scope-catalog-changed`, `importer-progress`, `authentication-challenge`,
`runtime-state` (Rust-only diagnostics), plus the relay events
`netcatty:plugins:runtime-launch` `{ runtimeId, url }` and
`netcatty:plugins:runtime-stop` `{ runtimeId }` (main window only).

Plugin connections are terminal sessions (`protocol: "plugin"`): output and
exit use `netcatty:data` / `netcatty:exit`; the first zero-byte delivery
carries `meta.pluginConnectionReady`. `connection-data` / `connection-closed`
are not emitted.

## Runtimes

* **Browser** (default): hidden `<iframe sandbox="allow-scripts">` in the main
  webview, opaque origin (no Tauri IPC, storage or DOM access to the app),
  documents served by the `netcatty-plugin` scheme
  (`netcatty-plugin://localhost/<token>/…`, Windows
  `http://netcatty-plugin.localhost/<token>/…`) with a restrictive CSP and an
  inline preload shim that hands the MessagePort to `browserRuntime.mjs`. The
  relay batches port messages in order into `plugin_runtime_messages`; Rust
  replies on the attached `Channel`. Stream `ArrayBuffer` transfers travel as
  `transferBase64`. The app CSP allows `frame-src` for the scheme
  (`vite.config.ts`).
* **Utility** (Node entry, companions, interceptors): only with
  `NETCATTY_PLUGIN_DEV=1` (same gate as Electron). Runs
  `rust/crates/netcatty-plugins/runtime/nodeStdioRuntime.mjs` under Node
  (newline JSON over stdio, virtual ports for interceptors) with
  `electron/plugins/runtime/runtimePeer.mjs`. Node is found through
  `NETCATTY_PLUGIN_NODE` or `PATH`; without it activation fails with
  "Advanced (Node) plugins need a Node.js runtime: install Node 20+ on PATH or
  set NETCATTY_PLUGIN_NODE …". Install still validates such packages.
* Resources are resolved from `NETCATTY_PLUGIN_APP_ROOT`, the bundle resource
  dir `plugin-runtime/` (`electron/plugins/runtime`, `node_modules/@netcatty/plugin-{sdk,contract}/dist`,
  the Node bootstrap), or the source checkout in development.

## Storage

`<data>/plugins/` exactly as Electron: `plugins.sqlite` (schema 7, WAL,
`synchronous=FULL`), `packages/<id>/<version>/{install.json,package.ncpkg,package/}`,
`staging/`, `logs/host-v1/runtime*.jsonl`, `local-logging.json`. Plugin
secrets are ciphertext of the app credential cipher (fails closed when no
OS-backed key is available).

## Differences from Electron

* Icons are validated and returned as data URLs of the original bytes instead
  of being rasterized to 64 px PNG; unsafe SVGs are rejected.
* Host-drawn view CSS gets a preflight check in Rust; the renderer's css-tree
  validation (`domain/pluginViewStylePolicy.cjs`) stays authoritative.
* CPU / memory sampling of runtime processes is not implemented (browser
  runtimes share the webview process).
* Not ported: market sources / catalog, byte streams (`network.stream`), AI
  model invocation / selected context, plugin agents, vault host actions,
  companion executables, terminal input/output interceptors (the Node
  runtime transports interceptor ports, but the terminal data pipeline is not
  wired), directory enumeration. Their features are not advertised in
  `plugin.initialize`.

## Tests

* `cargo test -p netcatty-plugins` — unit tests plus
  `tests/example_plugins.rs`: builds `examples/plugins/hello-netcatty` and
  `starter-netcatty` into `.ncpkg` (byte-identical to `netcatty-plugin pack`),
  installs them and drives commands, settings, terminal Providers, lifecycle
  events, views messages, restart / disable / uninstall over the real
  JSON-RPC contract (runtimePeer under Node). Skips without Node or built
  examples (`npm run build:plugin-packages`).
* `cargo test -p netcatty-desktop --test ipc_plugins` — headless IPC.
* `node --test --import tsx infrastructure/tauri/bridge/plugins.test.ts`.
