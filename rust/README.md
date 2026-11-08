# Netcatty — Rust / Tauri 2 backend

This directory holds the Rust rewrite of Netcatty's backend. The Electron main
process (`electron/`) is replaced by a Tauri 2 application whose Rust side
provides SSH, SFTP, port forwarding, local terminals, embedded VNC / RDP
desktops, local filesystem access, persistence and credential encryption. The React renderer (`components/`,
`application/`, `domain/`, `infrastructure/`) is reused unchanged: a small
adapter (`infrastructure/tauri/`) implements the existing `window.netcatty`
bridge contract on top of Tauri commands and events.

```
rust/
├── Cargo.toml                 workspace
├── rust-toolchain.toml        stable toolchain (rustup picks it up automatically)
├── docs/ipc-contract.md       renderer <-> Rust command / event contract
├── crates/
│   ├── netcatty-core          domain models + IPC payload types (pure, no I/O)
│   ├── netcatty-ssh           russh: connect, auth, host keys, shell, exec, proxies, jump hosts, keygen
│   ├── netcatty-sftp          SFTP browsing + streaming transfers
│   ├── netcatty-forward       local / remote / dynamic (SOCKS5) port forwarding
│   ├── netcatty-pty           local shells (portable-pty) + shell discovery
│   ├── netcatty-localfs       local file browser operations, tree scans
│   ├── netcatty-rdesktop      embedded remote desktops: VNC (vnc-rs) and RDP (IronRDP)
│   ├── netcatty-sessionlog    session logs: terminal replay to txt / html, live log streams
│   ├── netcatty-store         JSON key/value store, OS-keychain credential cipher, vault backups
│   ├── netcatty-sync          cloud sync transports: GitHub, Google Drive, OneDrive, WebDAV, S3, OAuth callback
│   ├── netcatty-sysmgr        system manager + server stats: remote command builders and parsers (processes, tmux, docker/podman/nerdctl, kubectl, GPUs, ports, systemd, stats)
│   ├── netcatty-telnet        telnet framing / option negotiation, login-prompt auto-login (pure)
│   ├── netcatty-serial        serial ports (serialport, no libudev), port listing, Windows named pipes
│   └── netcatty-mosh          Mosh handshake sniffer + ssh/mosh-client command lines, ET invocation, askpass (pure)
└── apps/
    └── netcatty-desktop       Tauri 2 app: commands, session registry, prompt broker, events
```

## Why this shape

* The renderer only ever talks to the backend through one contract
  (`types/global/netcatty-bridge-*.d.ts`). Replacing what sits behind it is
  the lowest-risk way to move the heavy lifting (crypto, networking, PTYs,
  file I/O) to Rust while keeping the 390k-line UI.
* Each capability is its own crate with a small public API and unit tests, so
  it can be reused by a future CLI or a different shell.
* Everything that crosses the IPC boundary is a `serde` type in
  `netcatty-core::ipc` with camelCase field names identical to the Electron
  payloads. Unknown fields on `Host` and session options are preserved via
  `#[serde(flatten)]`, so existing vaults round-trip.

## Running

Prerequisites: Rust stable (rustup), Node 22, and the platform prerequisites
for Tauri 2 (<https://v2.tauri.app/start/prerequisites/>; on macOS: Xcode
command line tools).

```bash
npm install                     # once; renderer dependencies
npm run build:plugin-runtime-deps   # once; builds the @netcatty/plugin-* workspace packages Vite imports
npm run tauri:dev               # starts Vite on :5173 and the Tauri app
```

Status (2026-11-03): `npm run tauri:dev` compiles, Vite starts, the native
window opens and the renderer connects to Vite HMR (it needs the plugin
workspace packages built first, second command above). Backend behaviour is
covered by the headless IPC tests and the sshd end-to-end suite below;
clicking through the UI inside the Tauri window is the remaining manual
check.

Other commands:

```bash
npm run tauri:check             # cargo check --workspace
npm run tauri:test              # cargo test --workspace
npm run tauri:build             # production bundle (dmg/app, msi/nsis, deb/appimage)
cd rust && cargo test -p netcatty-ssh     # one crate
```

Logs: set `NETCATTY_LOG=debug` (tracing `EnvFilter` syntax). Portable mode:
set `NETCATTY_PORTABLE_DATA_DIR=/path` to keep all data next to the binary.

## How a terminal session flows

1. Renderer calls `window.netcatty.startSSHSession(options)`; the adapter
   invokes the `session_start_ssh` command with the same options object.
2. `netcatty-ssh::connect` dials (direct, HTTP CONNECT, SOCKS5 or
   ProxyCommand), chains jump hosts over `direct-tcpip` channels, verifies the
   host key against the vault's known hosts, and authenticates
   (publickey → keyboard-interactive → password, TOTP auto-answer).
   Anything needing the user (unknown host key, 2FA prompt, key passphrase)
   is emitted as an event and awaited through the `PromptBroker` until the
   renderer answers with the matching `ssh_respond_*` command.
3. A PTY shell channel is opened; the `SessionRegistry` pump decodes output
   with the session charset and emits `netcatty:data`; input arrives via
   `session_write`; `netcatty:exit` is emitted exactly once.
4. SFTP browsers and port forwards can reuse the authenticated connection of a
   live session (`sourceSessionId`), so a 2FA login is not repeated.

## Scope of this first version

Implemented in Rust:

* SSH sessions (password, key, certificate, agent, keyboard-interactive,
  TOTP), host-key verification, jump hosts, HTTP/SOCKS5/command proxies,
  keepalive, legacy algorithm toggles, exec, key generation, known_hosts import
* SFTP browse (list/stat/read/write/mkdir/rename/delete/chmod/extract) with
  GB18030 filename handling, streaming transfers with progress, cancel,
  pause/resume checkpoints, connection reuse
* Port forwarding: local, remote, dynamic SOCKS5, with the authoritative
  runtime snapshot and status events the UI expects
* Local terminals with shell discovery and cwd detection
* Telnet sessions (lazy option negotiation, NAWS, echo-mode events, NVT
  newlines, IAC escaping), serial sessions (hardware ports, PTY devices,
  Windows named pipes, byte-oriented Backspace, port listing) and the shared
  Username / Password auto-login with its renderer events
* Mosh (system `ssh` bootstrap in a PTY, saved password typed, swap to
  `mosh-client`, `netcatty:mosh:ready`) and EternalTerminal (`et` with a
  private ssh config, `-F` wrapper and an askpass helper served by the
  Netcatty executable). `mosh-client` / `et` come from the bundled resources
  (`build-tauri.yml` fetches the same MoshCatty / et releases the Electron
  build bundles) or, when absent, from `PATH`
* Runtime charset switching for any terminal session (`setSessionEncoding`)
* Local file browser operations and tree scans with progress
* Embedded remote desktops (hosts with protocol `vnc` / `rdp`): the backend
  decodes the remote framebuffer and streams RGBA rectangles over a per-session
  Tauri channel; the renderer paints them on a canvas inside a regular pane, so
  desktops split and move between tabs like terminals.
  * VNC: no-auth and VNC password authentication; Raw / CopyRect / ZRLE
    encodings; pointer, wheel and keyboard input; remote → local clipboard text.
  * RDP: TLS + NLA (CredSSP with NTLM) logon with user name, password and
    optional domain; keyboard (scancodes, Unicode fallback), mouse and wheel.
    The server certificate is not validated (RDP hosts are normally
    self-signed), matching mstsc's "connect anyway".
  * A connect attempt is bounded (15 s TCP, 45 s handshake) and every outcome,
    including a crash of the protocol engine, ends in one `closed` channel
    message, so a pane never stays on "connecting". The RDP TLS upgrade
    installs the `aws-lc-rs` rustls provider itself: the application links
    `reqwest` as well, and rustls panics when feature unification leaves it
    with two providers and no process-level default.
* JSON document store, AES-256-GCM credential encryption keyed from the OS
  keychain, vault backups
* Cloud sync transports (`netcatty-sync`): GitHub Gist device flow, Google
  Drive and OneDrive (OAuth loopback callback + PKCE), WebDAV (Basic / Digest
  / token) and S3 (SigV4); the sync master password is kept encrypted with
  the credential cipher
* Windows: reusable settings window, Electron-style chrome (inset traffic
  lights on macOS, frameless with the renderer's own buttons elsewhere, drag
  regions), title-bar controls, native theme / background colour, language
  and cross-window settings sync
* Crash log (Rust panics + renderer diagnostics, Electron's JSONL format),
  clipboard file lists and images, temp directory management (info, clear,
  custom root), Electron-compatible local vault backups, app-level HTTP proxy
  for cloud sync / OAuth (system / direct / custom), edit-and-sync file
  watches for files opened with external apps (temp download, application
  picker, open-with), busy-terminal close confirmation
* Tray icon (native menu on Linux), tray panel window, close-to-tray,
  global "Quake mode" hotkey, launch at login hidden to the tray
  (`--hidden`), native notifications with click-to-focus
* Auto-update (`tauri-plugin-updater`, `docs/ipc-update.md`): signed bundles
  from GitHub Releases with Electron's prompt flow (check → download with
  progress → install on request), persisted auto-download preference,
  startup check, dirty-editor guard before install, and a "download
  manually" fallback for unsigned / dev builds and unknown Linux packages
* System manager (`netcatty-sysmgr`): capability probe, processes and
  signals, tmux (sessions / windows / panes / clients / actions), Docker /
  Podman / nerdctl containers and images, kubectl contexts / namespaces /
  pods, NVIDIA / Ascend accelerators, listening ports, systemd services with
  sudo fallback, OSC 7 setup — on the session's SSH connection, or locally
  for local terminals
* Server stats (`getServerStats`, distro probe, remote shell history) and the
  server monitor panels (`monitor*`), sharing one sampler per connection;
  child processes of local terminals (busy check on close)
* Session logs: export (txt / raw / html), auto-save, logs directory open /
  clear, manual "record session log" and automatic per-session logs streamed
  live from the session pump, with Electron's file naming and a byte-for-byte
  port of its terminal-to-text / HTML sanitizer (`netcatty-sessionlog`)
* Tauri shell: dialogs, clipboard, opener, event fan-out

Not yet ported (the renderer treats these bridge methods as optional and
hides the features when they are absent):

* AI bridge (chat streaming, SDK agents, MCP server), plugin runtime, external
  MCP controller
* ZMODEM/YMODEM file transfer (terminal sessions and serial), the Mosh / ET
  host-stats companion SSH connection
* FIDO2 security keys and Windows Hello / app lock
* Plugin-provided sync providers (they need the plugin runtime)
* Deep links, Explorer context menu, the macOS Dock menu (saved hosts),
  per-variant tray icons (`appIconManager`), the before-quit dirty-editor
  guard (the install-time one is ported)
* Compressed folder upload
* X11 forwarding is requested on the channel but no local X11 proxy is
  started yet
* Remote desktop gaps: Kerberos-only RDP accounts, RDP clipboard / audio /
  drive redirection, dynamic RDP resize (the desktop keeps the size requested
  at connect time and is scaled to the pane), VNC Tight/JPEG encoding and
  Apple Remote Desktop authentication, local → remote clipboard, connecting
  through an SSH jump host or proxy

The `electron/` directory is untouched; `npm run dev` still runs the Electron
build so both backends can be compared while the port matures.

## Auto-update signing

Release bundles are signed with a minisign key pair so the in-app updater
(`tauri-plugin-updater`, see `docs/ipc-update.md`) can verify what it
downloads. Generate the pair once, on a machine you trust:

```bash
cd rust/apps/netcatty-desktop
npx --yes @tauri-apps/cli@^2 signer generate -w ~/.tauri/netcatty.key
# or, with the Rust CLI installed: cargo tauri signer generate -w ~/.tauri/netcatty.key
```

* `~/.tauri/netcatty.key` is the **private key**. Never commit it. Store its
  contents in the `TAURI_SIGNING_PRIVATE_KEY` repository secret and the
  password you chose in `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`;
  `.github/workflows/build-tauri.yml` exports both to the bundler. Keep a
  backup: a lost key means existing installs can never verify a new release.
* `~/.tauri/netcatty.key.pub` is the **public key**. Paste its contents into
  `plugins.updater.pubkey` in `rust/apps/netcatty-desktop/tauri.conf.json`
  (replacing `REPLACE_WITH_TAURI_UPDATER_PUBLIC_KEY`) and commit that. A
  fork that signs with its own key can instead set the
  `TAURI_UPDATER_PUBKEY` repository variable, which the workflow writes into
  the CI config.

With the key present the bundler writes `Netcatty.app.tar.gz` plus `.sig`
on macOS and a `.sig` next to every installer; the release job turns them
into `latest.json`, which the configured endpoint
(`.../releases/latest/download/latest.json`) serves. Without the key the
workflow still builds installers, but switches `createUpdaterArtifacts` off
(the bundler refuses to sign without a key) and the app reports updates as
"download manually". The same applies to `npm run tauri:build` on a
developer machine: either export `TAURI_SIGNING_PRIVATE_KEY` or pass
`--config '{"bundle":{"createUpdaterArtifacts":false}}'`. Debug builds never
auto-update.

## Headless IPC tests

`apps/netcatty-desktop/tests/ipc_smoke.rs` drives the real command dispatch,
managed state and event emission through `tauri::test`'s mock runtime (no
window): local shell start → write → `netcatty:data` → resize → close →
exactly one `netcatty:exit`, the store and credential commands, local file
commands including the raw-body / raw-response binary path, shell
discovery, the system-manager commands on a local session (capabilities,
processes, PTY child processes) and the monitor panel bookkeeping. Telnet
runs against an in-process fake server (negotiation, NAWS, echo mode,
auto-login, exit), serial over a pseudo-terminal pair, and Mosh / ET with
fake `ssh` / `mosh-client` / `et` scripts on the session `PATH`. The crate is generic over `tauri::Runtime` for this reason;
commands take `Ctx<'_, R>` (a thin `State<AppState<R>>` extractor).

Note for packaging: `CredentialCipher::load_or_create` runs synchronously in
the Tauri `setup` hook and talks to the OS keychain; unsigned development
binaries trigger a keychain prompt on macOS, which delays window creation
until the user answers.

## End-to-end tests

`crates/netcatty-e2e` holds tests that run the SSH, SFTP and port-forwarding
crates against a real OpenSSH server (password and publickey auth, exec,
interactive shell with resize and exit codes, host-key prompt / trusted /
changed flows, SFTP browse and edit with non-ASCII names, a 3 MB upload and
download with progress and `.part` staging, local / dynamic SOCKS5 / remote
forwards). They are skipped unless `NETCATTY_E2E_SSH_HOST` is set. With
Docker installed:

```bash
rust/scripts/e2e-sshd/run.sh
```

builds a throwaway Alpine sshd container, runs the suite and removes the
container again. On 2026-11-03 all 10 tests passed against it.

## Conventions

* Commands are `snake_case`; renderer-facing JSON is camelCase.
* Errors cross the boundary as `{ code, message }` (`netcatty_core::CoreError`).
* Event names are the Electron channel names (`netcatty:data`, …) so the
  adapter is a thin mapping — see `docs/ipc-contract.md`.
* Never log credentials, key material or terminal output.
* Binary payloads use `tauri::ipc::Response` (responses) and raw request
  bodies with metadata headers (requests) instead of JSON byte arrays.
