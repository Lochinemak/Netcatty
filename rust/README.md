# Netcatty — Rust / Tauri 2 backend

This directory holds the Rust rewrite of Netcatty's backend. The Electron main
process (`electron/`) is replaced by a Tauri 2 application whose Rust side
provides SSH, SFTP, port forwarding, local terminals, local filesystem access,
persistence and credential encryption. The React renderer (`components/`,
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
│   └── netcatty-store         JSON key/value store, OS-keychain credential cipher, vault backups
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
npm run tauri:dev               # starts Vite on :5173 and the Tauri app
```

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
* Local file browser operations and tree scans with progress
* JSON document store, AES-256-GCM credential encryption keyed from the OS
  keychain, vault backups
* Tauri shell: window, dialogs, clipboard, opener, event fan-out

Not yet ported (the renderer treats these bridge methods as optional and
hides the features when they are absent):

* AI bridge (chat streaming, SDK agents, MCP server), plugin runtime, external
  MCP controller
* Mosh / EternalTerminal, telnet and serial sessions, ZMODEM/YMODEM
* FIDO2 security keys and Windows Hello / app lock
* Cloud sync (S3/WebDAV/OneDrive/Google), GitHub/Google OAuth
* Tray, tray panel, global shortcuts, auto-launch, auto-update, deep links,
  Explorer context menu
* Session logging, file watch (edit-and-sync), compressed folder upload,
  system manager (processes/tmux/docker/kubectl), monitor bridge
* X11 forwarding is requested on the channel but no local X11 proxy is
  started yet

The `electron/` directory is untouched; `npm run dev` still runs the Electron
build so both backends can be compared while the port matures.

## Conventions

* Commands are `snake_case`; renderer-facing JSON is camelCase.
* Errors cross the boundary as `{ code, message }` (`netcatty_core::CoreError`).
* Event names are the Electron channel names (`netcatty:data`, …) so the
  adapter is a thin mapping — see `docs/ipc-contract.md`.
* Never log credentials, key material or terminal output.
* Binary payloads use `tauri::ipc::Response` (responses) and raw request
  bodies with metadata headers (requests) instead of JSON byte arrays.
