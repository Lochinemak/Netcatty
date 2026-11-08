# Security: app lock, FIDO2 security keys, TOTP QR scan, SSH debug log

Commands live in `apps/netcatty-desktop/src/commands/security/`
(`applock.rs`, `fido.rs`, `totp_scan.rs`, `ssh_debug.rs`); reusable logic in
`crates/netcatty-applock` and `crates/netcatty-fido`. The renderer adapter is
`infrastructure/tauri/bridge/security.ts` (`createSecurityBridge`), spread
last into `createTauriBridge.ts`; consumers (`AppLockGate`,
`useAppLockBridge`, `useAppLockState`, the FIDO modal in `AppSideEffects`,
`HostTotpFields`, Settings → System) are unchanged.

## App lock

Electron: `appLockSettingsStore.cjs`, `appLockRuntimeBridge.cjs`,
`appLockSystemAuthBridge.cjs`, `windowsHelloHelper/`,
`main/appLockLifecycle.cjs`.

### Storage and KDF

`<data dir>/app-lock-settings.json` (the Electron file name), pretty JSON
with a trailing newline, replaced atomically (temp file + rename, mode 0600):

```json
{
  "enabled": true,
  "timeoutMinutes": 15,
  "systemUnlockEnabled": false,
  "systemUnlockAutoPromptEnabled": false,
  "passwordVerifier": {
    "version": 1,
    "algorithm": "PBKDF2-SHA256",
    "iterations": 210000,
    "salt": "<16 bytes base64>",
    "hash": "<32 bytes base64>"
  }
}
```

The normalisation rules are Electron's (timeout ∈ `0|1|5|15|30|60`, else 15;
`enabled` needs a valid verifier with ≥ 100 000 iterations and canonical
base64; the system-unlock flags depend on `enabled`). A file written by the
Electron build verifies here and vice versa. The data directory is the
Electron `userData` directory on macOS and Windows (`…/Netcatty`, case
insensitive); on Linux the Tauri build uses `~/.local/share/netcatty`, so an
Electron file in `~/.config/Netcatty` is not picked up there.

Renderer-facing settings (`app_lock_get_settings`, mutation results,
`netcatty:appLock:settingsChanged`) carry zeroed salt / hash placeholders of
the right size; verification only happens in Rust (off the async runtime).

### Commands

| Bridge method | Command | Args | Returns |
| --- | --- | --- | --- |
| `getAppLockRuntimeState` | `app_lock_get_runtime_state` | — | `{ initialized, locked, reason, version, lastLockedAt, lastUnlockedAt, lastActivityAt }` |
| `getAppLockSettings` | `app_lock_get_settings` | — | public settings |
| `setAppLockTimeoutMinutes(t)` | `app_lock_set_timeout_minutes` | `timeoutMinutes` (number or numeric string) | public settings |
| `requestAppLockEnable()` | `app_lock_request_enable` | — | public settings (unchanged without a verifier) |
| `requestAppLockDisable(pw)` | `app_lock_request_disable` | `currentPassword` | settings (verifier removed, runtime unlocked) or `{ ok: false, error: "empty-current" \| "incorrect" }` |
| `requestAppLockReset(pw)` | `app_lock_request_reset` | `currentPassword` | as disable |
| `requestAppLockPasswordChange(input)` | `app_lock_request_password_change` | `input: { currentPassword?, nextPassword }` | settings (first password also enables) or `{ ok: false, error: "empty-next" \| "empty-current" \| "incorrect" }` |
| `setAppLockRuntimeLocked(reason)` | `app_lock_set_locked` | `reason` (`startup\|idle\|manual\|background`) | runtime state; no-op while disabled; `background` honours "Never" (timeout 0) |
| `requestAppLockUnlock(pw)` | `app_lock_request_unlock` | `password` | `{ ok: true }` or `{ ok: false, error: "empty" \| "incorrect" }` |
| `getAppLockSystemUnlockStatus()` | `app_lock_get_system_unlock_status` | — | `{ supported, available, enabled, platform: "darwin"\|"win32"\|"unsupported", label: "Touch ID"\|"Windows Hello"\|null, reason }` |
| `setAppLockSystemUnlockEnabled(input)` | `app_lock_set_system_unlock_enabled` | `input: { enabled, autoPromptEnabled?, currentPassword? }` | settings or `{ ok: false, error: "unavailable"\|"unsupported"\|"locked"\|"empty-current"\|"incorrect"\|"cancelled"\|"failed" }`; enabling runs one OS prompt |
| `requestAppLockSystemUnlock()` | `app_lock_request_system_unlock` | — | `{ ok: true }` or `{ ok: false, error: "disabled"\|"not-locked"\|"unsupported"\|"unavailable"\|"cancelled"\|"failed" }` |
| `reportAppLockActivity()` | `app_lock_report_activity` | — | `void` (moves the idle deadline) |

Events (broadcast to every window, so settings, editor, popup and session
windows gate exactly like the main window):

| Event | Payload |
| --- | --- |
| `netcatty:appLock:runtimeStateChanged` | runtime state (lock / unlock / idle lock) |
| `netcatty:appLock:settingsChanged` | public settings after every saved mutation |
| `netcatty:app-lock:reopen` | `null`: the main window was brought back (Dock click, tray, hotkey, second instance); the gate auto-prompts Touch ID / Windows Hello after a background lock |

### Behaviour

* Startup: enabled → locked with reason `startup` before any window renders
  content (`AppLockGate` withholds children until unlock).
* Idle: a timer task locks with reason `idle` once `lastActivityAt + timeout`
  passes; activity reports move the deadline; timeout 0 = never.
* Background: hiding the main window to the tray or with the global hotkey
  (`tray::hide_main_window`) locks with reason `background` (not with
  "Never").
* Password attempts: one in-flight attempt shared by concurrent callers;
  calls while unlocked fail fast; wrong passwords back off 250, 500, 1000,
  2000 ms (cap); an attempt whose lock epoch (`version`) or verifier changed
  meanwhile is rejected. OS prompts are shared the same way and dropped when
  the lock was re-applied while the dialog was open.
* While locked every window shows the title `Netcatty`; `window_set_title`
  calls are remembered and applied on unlock.
* Touch ID: `LAContext` (`LAPolicyDeviceOwnerAuthenticationWithBiometrics`,
  reason "Unlock Netcatty"); any rejection → `cancelled` (as Electron).
  Windows Hello: WinRT `UserConsentVerifier` in-process (availability names
  as the Electron helper), the dialog owned by the focused / main window via
  `IUserConsentVerifierInterop::RequestVerificationForWindowAsync`.
  Other platforms: `unsupported`.

Not ported: macOS `Cmd+H` app hide has no Tauri event (Electron locked on
`app.on("hide")`); devtools are not force-closed while locked; the macOS
"window-all-closed → re-lock" path does not apply (the Tauri app quits).

## FIDO2 security keys

Electron: `fidoAgentManager.cjs`, `fidoAskpass.cjs`, `fidoPromptHandler.cjs`,
`fidoSignFlow.cjs`, `fidoSshKeygen.cjs`, `fidoNativeAgent.cjs`,
`attachFidoAgentRelease.cjs`, FIDO parts of `systemSshAgent.cjs` and
`sshAuthHelper.cjs`.

Same architecture as Electron: the platform OpenSSH (libfido2 / Windows
WebAuthn) talks to the hardware.

1. `netcatty-ssh` recognises `sk-ssh-ed25519@openssh.com` /
   `sk-ecdsa-sha2-nistp256@openssh.com` handles (vault key or identity file,
   plus `-cert.pub` / vault certificate) and asks the callbacks to
   `prepare_security_key`.
2. The app starts (or joins) one Netcatty-owned `ssh-agent -D -a <socket>`
   (Homebrew OpenSSH preferred on macOS, Git's on Windows,
   `NETCATTY_SSH_AGENT_PATH` / `NETCATTY_SSH_ADD_PATH` /
   `NETCATTY_SSH_KEYGEN_PATH` override) with `SSH_ASKPASS` = the Netcatty
   executable in helper mode (`NETCATTY_FIDO_ASKPASS=1`,
   `SSH_ASKPASS_REQUIRE=force`), stages the handle under the app temp
   directory (0700 / 0600) and `ssh-add`s it. Identities are reference
   counted per `(socket, public blob)`; the last holder removes them
   (`ssh-add -d -k`), the last agent user stops the agent; app exit stops it.
   On Windows, when no user-mode agent can serve a named pipe, the
   Win32-OpenSSH service pipe is used (not owned, never stopped; Windows shows
   its own PIN / touch UI).
3. russh signs through the agent (`authenticate_publickey_with` /
   `authenticate_certificate_with`; the agent reply carries the sk flags and
   counter). Signatures are serialised app-wide; askpass prompts from the
   agent's `ssh-sk-helper` are attributed to the running signature.
4. A failed signature opens the recovery dialog (`kind: "recovery"`,
   `reason`, `allowPasswordFallback` when a password is saved): `retry`
   signs again, `fallback` continues with the remaining auth methods, cancel
   (or a cancelled PIN prompt) fails the connection with `CANCELLED`
   "Security key authentication cancelled.".

Askpass protocol (Unix socket in `<temp>/netcatty-fido-askpass-*/askpass.sock`
or `\\.\pipe\netcatty-fido-askpass-*`): one JSON line
`{ prompt, type: "askpass", leaseId, mode }` → `{ ok, response }`.
`mode: "none"` (OpenSSH `notify_start`) becomes a touch notification
(`notificationOnly: true`) that is dismissed with reason `helper-exited` when
OpenSSH kills the helper after the touch. Prompt classification follows
Electron (`PIN` wins over "confirm user presence"; unknown → PIN).

| Bridge method | Command / event | Payload |
| --- | --- | --- |
| `onFidoPromptRequest(cb)` | `netcatty:fido-prompt-request` | `{ requestId, kind: "pin"\|"touch"\|"confirm"\|"recovery", message, title, keyName, notificationOnly, reason?, allowPasswordFallback }` |
| `respondFidoPrompt(id, response, cancelled?)` | `fido_prompt_respond` | args `requestId, response, cancelled` → `{ success, error? }` (`Request not found`) |
| `onFidoPromptTimeout(cb)` | `netcatty:fido-prompt-timeout` | `{ requestId }` after 3 minutes |
| `onFidoPromptCancelled(cb)` | `netcatty:fido-prompt-cancelled` | `{ requestId, reason }` (`helper-exited`, `lease-released`, `pin-requested`) |
| `generateKeyPair({ type: "ED25519-SK"\|"ECDSA-SK", comment?, resident?, verifyRequired? })` | `fido_generate_key_pair` | `payload` → `{ success, privateKey?, publicKey?, keyType?, error? }`; runs `ssh-keygen -t ed25519-sk\|ecdsa-sk [-O resident] [-O verify-required] -N ""` with the askpass bridge; errors keep Electron's text and libfido2 hint. The adapter routes the other key types to `ssh_generate_key_pair`. |

Mosh / EternalTerminal: when the host uses an sk key (vault key, sk public
key, or sk identity file) and the auth method is not `password`, `mosh_start`
/ `et_start` load it into the same owned agent and point the bootstrap `ssh`
at it (`IdentityAgent`); the agent hold is released once the session has
left the registry.

Differences from Electron: there is no `ssh-sk-helper` error observer
(Electron's Unix-only wrapper), so recovery reasons are `failed` rather than
`device-unavailable` / `pin-failed` / `timeout` (Electron's Windows path
behaves the same); prompts are broadcast to all windows (like the other
Tauri prompt events) instead of the requesting window only; Mosh / ET use the
shared agent socket directly instead of a per-caller proxy socket. Real
devices still need manual testing (see `docs/fido2-validation.md`).

## TOTP QR from screen

| Bridge method | Command | Returns |
| --- | --- | --- |
| `scanTotpQrFromScreen()` | `totp_scan_screen` | the `previewTotp` shape (`{ ok: true, uri, code, secondsRemaining, period, algorithm, digits, issuer, label }`) or `{ ok: false, error }` |

Every display is captured (`xcap`), converted to luma and decoded with
`rqrr`; the first payload that parses as a TOTP wins (same parser as
`totp_preview`), else `hotp` / `migration` when only those were seen, else
`not-found`. macOS: without Screen Recording permission the system prompt is
requested (`CGRequestScreenCaptureAccess`) and `screen-permission-denied` is
returned; capture errors mentioning denied / permission map to the same code,
other failures to `unavailable`. Linux: `unavailable` (xcap needs PipeWire /
XCB development libraries the Linux bundle does not ship).

## SSH debug log

| Bridge method | Command | Returns |
| --- | --- | --- |
| `getSshDebugLogInfo()` | `ssh_debug_log_info` | `{ enabled, path, exists, size }`; `enabled` reflects `NETCATTY_SSH_DEBUG=1` like Electron (the per-session toggle lives in the renderer settings) |
| `openSshDebugLogDir()` | `ssh_debug_log_open_dir` | `{ success, error? }` (reveals the folder) |

Sessions started with `sshDebugLogEnabled: true` (Settings → System → SSH
debug logs) or any session with `NETCATTY_SSH_DEBUG=1` append to
`<app temp dir>/netcatty-ssh.log` while the connection is being established:
a start line with non-secret facts (host, port, user, auth method, which
credential kinds are present, jump count), the outcome, `netcatty_ssh`
events at DEBUG+ and `russh` DEBUG events matching Electron's
`auth|publickey|keyboard|handshake|kex|newkeys|dh gex` filter. TRACE events
(packet dumps) are never written; the file rotates to `netcatty-ssh.log.1`
at 5 MiB. The layer is installed in `lib.rs::init_tracing` with its own
per-layer filter, so the console output (`NETCATTY_LOG`) is unchanged.

## Manual checks

* App lock: enable, quit, relaunch (locked at startup in every window),
  idle timeout, close-to-tray → background lock, Dock click → Touch ID
  auto-prompt, Windows Hello on Windows.
* FIDO: ED25519-SK and ECDSA-SK keys (touch-only and `verify-required`),
  device absent → recovery, PIN cancel, password fallback, certificate, Mosh
  / ET with an sk key, key generation (resident / verify-required).
* TOTP scan with a QR on another display; first run without Screen Recording
  permission.
