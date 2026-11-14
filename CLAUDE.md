# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this branch builds

**`main` builds the Tauri 2 + Rust app.** New backend work goes in `rust/` and
`infrastructure/tauri/`. `build-tauri.yml` is what publishes releases.

The Electron backend in `electron/` is still here, fully working, as the
*behavioural reference* for the port — it is the spec when you need to know what
a bridge method is supposed to do. It is not the product. Do not add features to
it; change it only to fix the reference itself.

Both backends implement the same renderer-facing contract, so the React app
under `components/`, `application/`, `domain/` and `infrastructure/` is shared
and runs on either one.

## Commands

```bash
# Install dependencies
npm install

# Once, before the first tauri:dev — Vite imports these workspace packages
npm run build:plugin-runtime-deps

# Tauri app in dev (Vite on :5173 + the native window)
npm run tauri:dev

# Rust: check, test, lint
npm run tauri:check                      # cargo check --workspace
npm run tauri:test                       # cargo test --workspace
cd rust && cargo test -p netcatty-ssh    # one crate
cd rust && cargo clippy --workspace --all-targets -- -D warnings   # CI adds --locked

# Production bundle for the current platform
npm run tauri:build

# Lint + test the renderer (and the Electron reference)
npm run lint
npm run lint:fix
npm test

# Run a single JS/TS test file
node --test --import tsx path/to/file.test.ts

# Build the renderer only
npm run build

# Legacy Electron build — the reference backend, not the product
npm run dev
npm run pack
```

CI (`test.yml`) runs `npm run lint`, `npm test`, `npm run build`, then
`cargo clippy -D warnings` and `cargo test --workspace` in `rust/`. There is no
`cargo fmt` gate, but keep the tree `rustfmt`-clean. Electron's own runtime
tests live in `test-electron.yml` and only run when `electron/**` changes.

## Architecture

Netcatty is an SSH manager, terminal and SFTP browser. One React renderer, one
IPC contract, and (currently) two backends behind it.

### Rust backend (`rust/`)

A Cargo workspace: one crate per capability (`netcatty-ssh`, `netcatty-sftp`,
`netcatty-pty`, `netcatty-store`, `netcatty-ai`, `netcatty-plugins`, …) plus the
Tauri app at `rust/apps/netcatty-desktop`, which owns the commands, the session
registry, the prompt broker and event emission.

**[`rust/README.md`](./rust/README.md) is the authoritative document** for the
crate layout, how a session flows end to end, what is ported, what is not, the
headless IPC tests, the sshd end-to-end suite, and updater signing. Read it
before touching the backend. Per-domain contracts live in `rust/docs/ipc-*.md`.

### Renderer (React + Vite)

Three layers, unchanged by the port:

- **`domain/`** — pure TypeScript logic, no side effects. Models (`models.ts`), host helpers, workspace tree operations.
- **`application/state/`** — React hooks that own state and persistence boundaries. Key hooks: `useVaultState` (hosts/keys/snippets), `useSessionState` (terminal sessions/workspace), `useSettingsState` (theme/config).
- **`infrastructure/`** — external edges: `persistence/localStorageAdapter.ts` for storage, `services/` for network calls, `config/` for defaults, storage keys and terminal themes, `tauri/` for the backend adapter.
- **`components/`** — presentation only. `App.tsx` wires hooks to components; no business logic in components.

See [`AGENTS.md`](./AGENTS.md) for the full layer rules and the subsystem notes
(AI harness, capability catalog, plugin host, side-panel splits, aside panels).

### The IPC contract

The renderer only ever talks to a backend through **`window.netcatty`**, typed
in `types/global/netcatty-bridge-*.d.ts`. Never reach past it — no
`ipcRenderer`, no `invoke()` from a component.

- **Tauri path:** `index.tsx` imports `infrastructure/tauri/bootstrap` first,
  which installs the bridge onto `window.netcatty` before any other module
  evaluates. Each bridge method calls one `snake_case` Tauri command through
  `tauriApi.ts`; events keep the Electron channel names (`netcatty:data`, …).
  Tauri is reached through the global `window.__TAURI__` (`withGlobalTauri`), not
  the `@tauri-apps/api` npm packages, so the Electron build stays dependency-free.
- **Electron path:** `electron/preload.cjs` exposes the same surface via
  `contextBridge`; handlers live in `electron/bridges/*.cjs`, one file per
  capability domain, tests alongside (`*.test.cjs`).

Errors cross the boundary as `{ code, message }`. Binary payloads use raw
request bodies and `tauri::ipc::Response`, not JSON byte arrays.

**`scripts/tauri-ipc-contract.test.cjs` is the guard** (part of `npm test`). It
cross-checks every command in `generate_handler![]` against every command the
adapter invokes, and every declared bridge method against its implementation.
Three allowlists carry the intent, each entry with a written reason, so read
them before adding one:

- `COMMANDS_WITHOUT_A_CALLER` — a registered command no adapter method invokes.
- `NOTHING_TO_CALL` — the method legitimately answers without a backend call.
- `NOT_IMPLEMENTED` — a real gap, documented in `rust/README.md`. Adding to this
  list is admitting a feature does not work; don't use it to silence the guard.

### Where new code goes

| Change | Where |
|--------|-------|
| New backend capability | a crate in `rust/crates/`, pure where possible, with unit tests |
| Exposing it to the UI | a command in `rust/apps/netcatty-desktop/src/commands/`, registered in `generate_handler![]`, plus a method in `infrastructure/tauri/` and its type in `types/global/` |
| New pure logic | `domain/` |
| New stateful behaviour | a hook in `application/state/` |
| New external edge | `infrastructure/services/` or `infrastructure/persistence/` |
| UI | `components/`, consuming hooks only |

## Key conventions

- Rust commands are `snake_case`; renderer-facing JSON is camelCase. IPC types
  are `serde` types in `netcatty-core::ipc`; unknown fields on `Host` and
  session options are preserved with `#[serde(flatten)]` so existing vaults
  round-trip.
- Never log credentials, key material or terminal output.
- All storage reads/writes go through `localStorageAdapter`; storage keys are in `infrastructure/config/storageKeys.ts`.
- User-visible temporary files (SFTP downloads opened in an external editor, staged uploads, exported archives) go in Netcatty's own temp directory so Settings → System can show and clear them: `commands::tempdir::temp_file_path(app, name)` in Rust, `tempDirBridge.getTempFilePath(fileName)` in the Electron main process. Don't reach for `std::env::temp_dir()` / `os.tmpdir()` for those; a handful of internal, short-lived scratch dirs in Rust do use it directly and are not a precedent.
- Aside panels (VaultView subpages) use the shared design system in `components/ui/aside-panel.tsx` — see `AGENTS.md` for usage patterns.
- Renderer code is TypeScript/ESM; Electron main/bridges are CommonJS (`.cjs`).
- Path alias `@/` resolves to the repo root (configured in `vite.config.ts` and `tsconfig.json`).

## Branches and releases

- `main` is the Tauri app. Branch from it.
- `upstream-main` mirrors the upstream Electron project. Fast-forward only;
  never commit to it.
- Releases: push a strict `v<MAJOR>.<MINOR>.<PATCH>` tag (no `-rc` suffixes).
  `build-tauri.yml` builds all four platform targets, then publishes the GitHub
  Release with `latest.json` for the in-app updater. The version comes from the
  tag, not from `tauri.conf.json`.
- Updater bundles can only be signed in CI: the private key and its passphrase
  live in repository secrets, which cannot be read back out. A local
  `npm run tauri:build` either needs `TAURI_SIGNING_PRIVATE_KEY` exported or
  `--config '{"bundle":{"createUpdaterArtifacts":false}}'`.

## Reporting Issues & PRs

Issues that skip the format gate are auto-closed. When opening issues (including via `gh` / API):

- Title must start with `[Bug]`, `[Feature]`, or `[Other]` plus a short summary.
- Body must use `.github/ISSUE_TEMPLATE/` (Bug Report or Feature Request) and fill required fields.
- PRs should follow `.github/PULL_REQUEST_TEMPLATE.md`.

See [CONTRIBUTING.md](./CONTRIBUTING.md) and the "Reporting Issues & PRs" section in [AGENTS.md](./AGENTS.md).
