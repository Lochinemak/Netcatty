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
│   ├── netcatty-store         JSON key/value store, OS-keychain credential cipher, vault backups
│   ├── netcatty-sync          cloud sync transports: GitHub, Google Drive, OneDrive, WebDAV, S3, OAuth callback
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
* JSON document store, AES-256-GCM credential encryption keyed from the OS
  keychain, vault backups
* Cloud sync transports (`netcatty-sync`): GitHub Gist device flow, Google
  Drive and OneDrive (OAuth loopback callback + PKCE), WebDAV (Basic / Digest
  / token) and S3 (SigV4); the sync master password is kept encrypted with
  the credential cipher
* Tauri shell: window, dialogs, clipboard, opener, event fan-out

Not yet ported (the renderer treats these bridge methods as optional and
hides the features when they are absent):

* AI bridge (chat streaming, SDK agents, MCP server), plugin runtime, external
  MCP controller
* ZMODEM/YMODEM file transfer (terminal sessions and serial), the Mosh / ET
  host-stats companion SSH connection
* FIDO2 security keys and Windows Hello / app lock
* Plugin-provided sync providers (they need the plugin runtime)
* Tray, tray panel, global shortcuts, auto-launch, auto-update, deep links,
  Explorer context menu
* Session logging, file watch (edit-and-sync), compressed folder upload,
  system manager (processes/tmux/docker/kubectl), monitor bridge
* X11 forwarding is requested on the channel but no local X11 proxy is
  started yet
* Remote desktop gaps: Kerberos-only RDP accounts, RDP clipboard / audio /
  drive redirection, dynamic RDP resize (the desktop keeps the size requested
  at connect time and is scaled to the pane), VNC Tight/JPEG encoding and
  Apple Remote Desktop authentication, local → remote clipboard, connecting
  through an SSH jump host or proxy

The `electron/` directory is untouched; `npm run dev` still runs the Electron
build so both backends can be compared while the port matures.

## Headless IPC tests

`apps/netcatty-desktop/tests/ipc_smoke.rs` drives the real command dispatch,
managed state and event emission through `tauri::test`'s mock runtime (no
window): local shell start → write → `netcatty:data` → resize → close →
exactly one `netcatty:exit`, the store and credential commands, local file
commands including the raw-body / raw-response binary path, and shell
discovery. Telnet runs against an in-process fake server (negotiation, NAWS,
echo mode, auto-login, exit), serial over a pseudo-terminal pair, and Mosh /
ET with fake `ssh` / `mosh-client` / `et` scripts on the session `PATH`. The crate is generic over `tauri::Runtime` for this reason;
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
