<p align="center">
  <img src="public/icon.png" alt="Netcatty" width="128" height="128">
</p>

<h1 align="center">Netcatty</h1>

<p align="center">
  <strong>🔥 AI-Powered SSH Client, SFTP Browser & Terminal Manager 🚀</strong><br/>
  <a href="https://netcatty.app"><strong>netcatty.app</strong></a>
</p>

<p align="center">
  <a href="https://trendshift.io/repositories/18391?utm_source=trendshift-badge&amp;utm_medium=badge&amp;utm_campaign=badge-trendshift-18391" target="_blank" rel="noopener noreferrer">
    <img src="https://trendshift.io/api/badge/trendshift/repositories/18391/daily?language=TypeScript" alt="binaricat/Netcatty | Trendshift" width="250" height="55"/>
  </a>
</p>

<p align="center">
  A beautiful, feature-rich SSH workspace built with Tauri 2, Rust, React, and xterm.js.<br/>
  🔥 Built-in AI Agent · Split terminals · Vault views · SFTP workflows · Custom themes — all in one.
</p>

<p align="center">
  <a href="https://github.com/binaricat/Netcatty/releases/latest"><img alt="GitHub Release" src="https://img.shields.io/github/v/release/binaricat/Netcatty?style=for-the-badge&logo=github&label=Release"></a>
  &nbsp;
  <a href="#"><img alt="Platform" src="https://img.shields.io/badge/Platform-macOS%20%7C%20Windows%20%7C%20Linux-blue?style=for-the-badge&logo=tauri"></a>
  &nbsp;
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-GPL--3.0-green?style=for-the-badge"></a>
</p>

<p align="center">
  <a href="https://github.com/binaricat/Netcatty/releases/latest">
    <img src="https://img.shields.io/github/v/release/binaricat/Netcatty?style=for-the-badge&logo=github&label=Download%20Latest&color=success" alt="Download Latest Release">
  </a>
</p>

<p align="center">
  <a href="https://github.com/sponsors/binaricat"><img src="https://img.shields.io/badge/GitHub-Sponsors-ea4aaa?style=for-the-badge&logo=githubsponsors&logoColor=white" height="28" alt="Sponsor on GitHub"></a>
  &nbsp;
  <a href="https://ko-fi.com/binaricat"><img src="https://img.shields.io/badge/Ko--fi-Support-29abe0?style=for-the-badge&logo=kofi&logoColor=white" height="28" alt="Support on Ko-fi"></a>
</p>

<p align="center">
  <a href="./README.md">English</a> · <a href="./README.zh-CN.md">简体中文</a> · <a href="./README.zh-TW.md">繁體中文</a> · <a href="./README.ja-JP.md">日本語</a>
</p>

---

> **This repository builds the Rust / Tauri 2 version of Netcatty.** The backend
> lives in [`rust/`](./rust); the React renderer is reused unchanged and reaches
> it through a thin adapter in [`infrastructure/tauri/`](./infrastructure/tauri).
> The original Electron backend remains in [`electron/`](./electron) as the
> behavioural reference for the port, not as what releases ship.
> [`rust/README.md`](./rust/README.md) documents the crate layout, what is
> ported, and what is not.

---

<img width="3358" height="1984" alt="image" src="docs/assets/readme/overview.webp" />


---

<a name="catty-agent"></a>
# 🔥 Catty Agent — Your IT Ops AI Partner

> 🚀 **Boost your IT ops daily work with AI power.** Catty Agent is the built-in AI assistant that understands your servers, executes commands, and handles complex multi-host operations — all through natural conversation.
### 🔥 What can Catty Agent do?

- 🚀 **Natural language server management** — just tell it what you need, no more memorizing commands
- 🔥 **Real-time server diagnostics** — check status, inspect logs, monitor resources through conversation
- 🚀 **Multi-host orchestration** — coordinate tasks across multiple servers simultaneously
- 🔥 **Intelligent context awareness** — understands your server environment and provides tailored responses
- 🚀 **One-click complex operations** — set up clusters, deploy services, and more with simple instructions

### 🎬 AI in Action

#### 🔥 Single Host — Intelligent Server Diagnostics

Ask Catty Agent to check a server's health, and it runs the right commands, analyzes the output, and gives you a clear summary — all in seconds.

<img width="3302" height="1978" alt="image" src="docs/assets/readme/catty-single-host.webp" />


#### 🚀 Multi-Host — Docker Swarm Cluster Setup

Watch Catty Agent orchestrate a Docker Swarm cluster across two servers in one conversation. It handles the init, token exchange, and node joining — you just tell it what you want.

<img width="3294" height="1974" alt="image" src="docs/assets/readme/catty-multi-host.webp" />


---

# Contents <!-- omit in toc -->

- [🔥 Catty Agent — AI Partner](#catty-agent)
- [What is Netcatty](#what-is-netcatty)
- [Why Netcatty](#why-netcatty)
- [Features](#features)
- [Screenshots](#screenshots)
  - [Main Window](#main-window)
  - [Vault Views](#vault-views)
  - [Split Terminals](#split-terminals)
- [Supported Distros](#supported-distros)
- [Getting Started](#getting-started)
  - [Open a local terminal from the command line](#open-a-local-terminal-from-the-command-line)
- [Build & Package](#build--package)
- [Tech Stack](#tech-stack)
- [Contributing](#contributing)
- [Contributors](#contributors)
- [Star History](#star-history)
- [License](#license)

---

<a name="what-is-netcatty"></a>
# What is Netcatty

**Netcatty** is a modern SSH client and terminal manager for macOS, Windows, and Linux, designed for developers, sysadmins, and DevOps engineers who need to manage multiple remote servers efficiently.

- **Netcatty is** an alternative to PuTTY, Termius, SecureCRT, and macOS Terminal.app for SSH connections
- **Netcatty is** a powerful SFTP client with dual-pane file browser
- **Netcatty is** a terminal workspace with split panes, tabs, and session management
- **Netcatty supports** SSH, local terminal, Telnet, Mosh, and Serial connections (when available)
- **Netcatty is not** a shell replacement — it connects to shells via SSH/Telnet/Mosh or local/serial sessions

---

<a name="why-netcatty"></a>
# Why Netcatty

If you regularly work with a fleet of servers, Netcatty is built for speed and flow:

- **Workspace-first** — split panes + tabs + session restore for “always-on” workflows
- **Vault organization** — grid/list/tree views with fast search and drag-friendly workflows
- **Serious SFTP** — built-in editor + drag & drop + smooth file operations

---

<a name="features"></a>
# Features

### 🗂️ Vault
- **Multiple views** — grid / list / tree
- **Fast search** — locate hosts and groups quickly

### 🖥️ Terminal Workspaces
- **Split panes** — horizontal and vertical splits for multi-tasking
- **Session management** — run multiple connections side-by-side
- **Save current screen** — right-click a terminal to save the visible final text, without replaying keystrokes or overwritten output; scroll first to save an earlier screen.
- **Inline images** — render Kitty graphics, SIXEL and iTerm inline images from remote programs
- **Archive shortcuts** — on Linux sessions, Ctrl/Cmd+click a printed `.tar`, `.tar.gz`/`.tgz`, `.tar.bz2`/`.tbz2`, `.tar.xz` or `.zip` name to fill an extraction command with the archive's absolute path into the prompt (kept next to any typed text); press Enter to run it. Names relative to the current directory need directory tracking (OSC 7, see the toolbar's Configure directory tracking); absolute paths always work. Windows, WSL, and macOS sessions are excluded.

### 📁 SFTP + Built-in Editor
- **File workflows** — drag & drop uploads/downloads
- **Edit in place** — built-in editor for quick changes

### 🎨 Personalization
- **Custom themes** — tune the app appearance to your taste
- **Keyword highlighting** — customize highlight rules for terminal output

---

<a name="screenshots"></a>
# Screenshots

<a name="main-window"></a>
## Main Window

The main window is designed for long-running SSH workflows: quick access to sessions, navigation, and core tools in one place.

<img width="3290" height="1988" alt="image" src="docs/assets/readme/main-window.webp" />


<img width="3324" height="1992" alt="image" src="docs/assets/readme/main-window-terminal.webp" />



<a name="vault-views"></a>
## Vault Views

Organize and navigate your hosts using the view that best fits the moment: grid for overview, list for scanning, tree for structure.

<img width="3292" height="1984" alt="image" src="docs/assets/readme/vault-grid.webp" />


<img width="3322" height="1998" alt="image" src="docs/assets/readme/vault-list.webp" />




## Monitoring View

Inspect CPU, memory, disk, network, and latency readings, with GPU details where available. Choose visible columns, resize them, select refresh intervals down to 1 second, and open a terminal directly from a monitored host.

Disk I/O shows aggregate read/write throughput for Linux hardware-backed block devices, without counting partitions or stacked virtual devices twice. Rates use two consecutive samples; `--` means unavailable or warming up, not zero activity. Disk I/O is currently unavailable on macOS; existing macOS monitoring is unchanged. The terminal system overview uses the same shared measurements.

<img width="3364" height="1982" alt="image" src="docs/assets/readme/monitoring.webp" />

<img width="3362" height="1980" alt="image" src="docs/assets/readme/monitoring-columns.webp" />




<a name="split-terminals"></a>
## Split Terminals

Split panes help you monitor multiple servers/services at the same time (deploy + logs + metrics) without juggling windows.

<img width="1560" height="871" alt="split" src="docs/assets/readme/split-terminals.webp" />

---

<a name="supported-distros"></a>
# Supported Distros

Netcatty automatically detects and displays OS icons for connected hosts:

<p align="center">
  <img src="public/distro/ubuntu.svg" width="48" alt="Ubuntu" title="Ubuntu">
  <img src="public/distro/debian.svg" width="48" alt="Debian" title="Debian">
  <img src="public/distro/centos.svg" width="48" alt="CentOS" title="CentOS">
  <img src="public/distro/fedora.svg" width="48" alt="Fedora" title="Fedora">
  <img src="public/distro/arch.svg" width="48" alt="Arch Linux" title="Arch Linux">
  <img src="public/distro/alpine.svg" width="48" alt="Alpine" title="Alpine">
  <img src="public/distro/amazon.svg" width="48" alt="Amazon Linux" title="Amazon Linux">
  <img src="public/distro/redhat.svg" width="48" alt="Red Hat" title="Red Hat">
  <img src="public/distro/rocky.svg" width="48" alt="Rocky Linux" title="Rocky Linux">
  <img src="public/distro/opensuse.svg" width="48" alt="openSUSE" title="openSUSE">
  <img src="public/distro/oracle.svg" width="48" alt="Oracle Linux" title="Oracle Linux">
  <img src="public/distro/kali.svg" width="48" alt="Kali Linux" title="Kali Linux">
  <img src="public/distro/almalinux.svg" width="48" alt="AlmaLinux" title="AlmaLinux">
</p>

<a name="getting-started"></a>
# Getting Started

### Download

Download the latest release for your platform from [GitHub Releases](https://github.com/binaricat/Netcatty/releases/latest).

| OS | Downloads |
| :--- | :--- |
| **macOS** | `.dmg` for arm64 and x64 — two builds, not a universal binary |
| **Windows** | x64 — `.msi` and an NSIS `.exe` installer |
| **Linux** | x64 — `.deb`, `.rpm`, AppImage · arm64 — `.deb`, `.rpm` |

Or browse all releases at [GitHub Releases](https://github.com/binaricat/Netcatty/releases).

### Code signing and privacy

Netcatty is applying to the SignPath Foundation open-source program. Once
approved, covered Windows release artifacts will use **Free code signing provided by SignPath.io, certificate by SignPath Foundation**.
See the [code signing policy](CODE_SIGNING_POLICY.md) and
[privacy policy](PRIVACY.md). Windows releases may remain unsigned until the
application and integration are complete.

> **Windows portable data:** Exit Netcatty, then create a folder named `data` beside `Netcatty.exe` (zip build) or beside the portable launcher. Netcatty will store its profile there on the next launch. Saved passwords and private keys remain protected by the Windows user account that created them, so they must be re-entered after moving the folder to another computer or Windows account.

> **Open folders in Netcatty on Windows:** The installed version adds **Open in Netcatty** to Explorer's folder context menu and folder-background context menu. It opens a local terminal in that folder. On Windows 11, choose **Show more options** first. Turn the menu off or on in **Settings → System → Windows Explorer**. ZIP and portable versions do not add this menu by default.

> **macOS Users:** macOS bundles are code-signed with this project's own certificate and are **not** notarized by Apple, so Gatekeeper warns on first launch — right-click the app in Finder and choose **Open** once to accept it. Builds produced without a signing certificate configured are only ad-hoc signed, and macOS then asks for Keychain access again after every update.

<a name="open-a-local-terminal-from-the-command-line"></a>
### Open a local terminal from the command line

`--open-terminal-path <dir>` opens a local terminal in that folder. `--open-terminal-shell <id-or-path>` selects the shell: a discovered id such as `pwsh`, `cmd`, or `wsl-ubuntu`, or a path to a shell executable. Either flag is enough. A shell alone opens a local tab in the default directory. A path alone uses the configured local shell. If Netcatty is already running, the tab opens in that window.

The Tauri build reads these flags from its own argv, so the extra `--` that the
Electron build needed on Windows is no longer required — it is still accepted,
so existing shortcuts keep working:

```bat
Netcatty.exe --open-terminal-shell=pwsh --open-terminal-path="D:\\proj"
```

On macOS, start a new instance with `open`, or run the binary directly:

```bash
open -n -a Netcatty --args --open-terminal-shell=zsh --open-terminal-path="$HOME/proj"
/Applications/Netcatty.app/Contents/MacOS/Netcatty --open-terminal-shell=zsh --open-terminal-path="$HOME/proj"
```

### Scoop (Windows x64, community-maintained)

With [Scoop](https://scoop.sh/) installed, you can install Netcatty from the community-maintained [lemon bucket](https://github.com/hoilc/scoop-lemon/blob/master/bucket/netcatty.json), which downloads the installer from Netcatty's official GitHub Releases:

```powershell
scoop bucket add lemon https://github.com/hoilc/scoop-lemon
scoop install lemon/netcatty
```

Exit Netcatty before updating or uninstalling:

```powershell
scoop update
scoop update netcatty
```

To uninstall:

```powershell
scoop uninstall netcatty
```

This is a third-party package, not an official Netcatty bucket, and updates may lag behind GitHub Releases. It currently supports x64 only. Settings remain in `%APPDATA%\netcatty` across updates and normal uninstalls; `scoop uninstall netcatty --purge` also deletes those settings. Use Scoop to manage updates for this installation.

### Nix / NixOS

Netcatty provides a flake that wraps the official Linux AppImage release for Nix and NixOS users:

```bash
nix run github:binaricat/Netcatty
```

For declarative installs, add the Netcatty flake as an input and use `inputs.netcatty.packages.${pkgs.system}.default` in your NixOS or Home Manager package list.

### Prerequisites
- Rust stable via [rustup](https://rustup.rs/) — the toolchain is pinned in [`rust/rust-toolchain.toml`](./rust/rust-toolchain.toml)
- Node.js 22+ and npm
- The [Tauri 2 platform prerequisites](https://v2.tauri.app/start/prerequisites/) — Xcode command line tools on macOS, WebKitGTK and friends on Linux
- macOS, Windows 10+, or Linux

### Development

```bash
# Clone the repository
git clone https://github.com/binaricat/Netcatty.git
cd Netcatty

# Install dependencies
npm install

# Build the plugin workspace packages the renderer imports (once)
npm run build:plugin-runtime-deps

# Start development mode (Vite on :5173 + the Tauri app)
npm run tauri:dev
```

`npm run dev` starts the legacy Electron build instead. It is kept so the two
backends can be compared while the port matures.

---

<a name="build--package"></a>
# Build & Package

```bash
# Build the renderer only
npm run build

# Check and test the Rust workspace
npm run tauri:check
npm run tauri:test

# Production bundle for the current platform
# macOS: .app + .dmg · Windows: .msi + NSIS .exe · Linux: .deb + .rpm + AppImage
npm run tauri:build
```

Release bundles are signed so the in-app updater can verify them — see
[Auto-update signing](./rust/README.md#auto-update-signing). Without a signing
key present, the bundler refuses to sign; pass
`--config '{"bundle":{"createUpdaterArtifacts":false}}'` to build installers
without updater artifacts.

<details>
<summary>Legacy Electron packaging</summary>

```bash
npm run pack         # current platform
npm run pack:mac     # macOS (DMG + ZIP)
npm run pack:win     # Windows (NSIS installer)
npm run pack:linux   # Linux (AppImage + DEB + RPM)
```

</details>

---

<a name="tech-stack"></a>
# Tech Stack

| Category | Technology |
|----------|------------|
| Shell | Tauri 2 |
| Backend | Rust (edition 2021), Tokio |
| Frontend | React 19, TypeScript |
| Build Tool | Vite 7 |
| Terminal | xterm.js |
| Styling | Tailwind CSS 4 |
| SSH/SFTP | russh, russh-sftp |
| PTY | portable-pty |
| Icons | Lucide React |

---

<a name="contributing"></a>
# Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See [AGENTS.md](AGENTS.md) for architecture overview and coding conventions.

---

<a name="contributors"></a>
# Contributors

Thanks to all the people who contribute!

<a href="https://github.com/binaricat/Netcatty/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=binaricat/Netcatty" />
</a>

---

<a name="license"></a>
# License

This project is licensed under the **GPL-3.0 License** - see the [LICENSE](LICENSE) file for details.

---

<a name="star-history"></a>
# Star History

<a href="https://www.star-history.com/#binaricat/Netcatty&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="docs/assets/star-history/star-history-dark.svg" />
   <source media="(prefers-color-scheme: light)" srcset="docs/assets/star-history/star-history-light.svg" />
   <img alt="Star History Chart" src="docs/assets/star-history/star-history-light.svg" />
 </picture>
</a>

---

<p align="center">
  Made with ❤️ by <a href="https://ko-fi.com/binaricat">binaricat</a>
</p>
