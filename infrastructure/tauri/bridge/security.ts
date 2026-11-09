/**
 * Security part of the Tauri `NetcattyBridge` adapter (see
 * `rust/docs/ipc-security.md`):
 *
 * - App lock (Electron `appLockRuntimeBridge.cjs`, `netcatty:appLock:*`),
 *   including the `netcatty:app-lock:reopen` signal.
 * - FIDO2 security-key prompts (`netcatty:fido-prompt-*`) and sk key
 *   generation: `generateKeyPair` routes `ED25519-SK` / `ECDSA-SK` to
 *   `fido_generate_key_pair` (ssh-keygen + askpass), other types to the
 *   regular `ssh_generate_key_pair`.
 * - `scanTotpQrFromScreen`, `getSshDebugLogInfo`, `openSshDebugLogDir`.
 *
 * Payload shapes are the Electron ones, so `useAppLockBridge`,
 * `AppLockGate`, the FIDO modal and Settings → System are unchanged.
 */
import { EventHub, invoke as invokeCommand } from '../tauriApi';

export const SECURITY_EVENTS = {
  appLockRuntimeStateChanged: 'netcatty:appLock:runtimeStateChanged',
  appLockSettingsChanged: 'netcatty:appLock:settingsChanged',
  appLockReopen: 'netcatty:app-lock:reopen',
  fidoPromptRequest: 'netcatty:fido-prompt-request',
  fidoPromptTimeout: 'netcatty:fido-prompt-timeout',
  fidoPromptCancelled: 'netcatty:fido-prompt-cancelled',
} as const;

const SK_KEY_TYPES = new Set(['ED25519-SK', 'ECDSA-SK']);

type SecurityBridgeKeys =
  | 'getAppLockRuntimeState'
  | 'getAppLockSettings'
  | 'setAppLockTimeoutMinutes'
  | 'requestAppLockEnable'
  | 'requestAppLockDisable'
  | 'requestAppLockReset'
  | 'requestAppLockPasswordChange'
  | 'setAppLockRuntimeLocked'
  | 'requestAppLockUnlock'
  | 'getAppLockSystemUnlockStatus'
  | 'setAppLockSystemUnlockEnabled'
  | 'requestAppLockSystemUnlock'
  | 'reportAppLockActivity'
  | 'onAppLockSettingsChanged'
  | 'onAppLockRuntimeStateChanged'
  | 'onAppLockReopen'
  | 'onFidoPromptRequest'
  | 'respondFidoPrompt'
  | 'onFidoPromptTimeout'
  | 'onFidoPromptCancelled'
  | 'generateKeyPair'
  | 'scanTotpQrFromScreen'
  | 'getSshDebugLogInfo'
  | 'openSshDebugLogDir';

export type SecurityBridge = Required<Pick<NetcattyBridge, SecurityBridgeKeys>>;

type Result<K extends SecurityBridgeKeys> = Awaited<ReturnType<SecurityBridge[K]>>;

export interface SecurityBridgeDeps {
  hub: EventHub;
  /** Injected for tests; defaults to the Tauri `invoke` wrapper. */
  invoke?: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
}

export function createSecurityBridge(deps: SecurityBridgeDeps): SecurityBridge {
  const { hub } = deps;
  const invoke = deps.invoke ?? invokeCommand;

  return {
    // -- App lock -----------------------------------------------------------
    getAppLockRuntimeState: () => invoke<Result<'getAppLockRuntimeState'>>('app_lock_get_runtime_state'),
    getAppLockSettings: () => invoke<Result<'getAppLockSettings'>>('app_lock_get_settings'),
    setAppLockTimeoutMinutes: (timeoutMinutes) =>
      invoke<Result<'setAppLockTimeoutMinutes'>>('app_lock_set_timeout_minutes', { timeoutMinutes }),
    requestAppLockEnable: () => invoke<Result<'requestAppLockEnable'>>('app_lock_request_enable'),
    requestAppLockDisable: (currentPassword) =>
      invoke<Result<'requestAppLockDisable'>>('app_lock_request_disable', { currentPassword }),
    requestAppLockReset: (currentPassword) =>
      invoke<Result<'requestAppLockReset'>>('app_lock_request_reset', { currentPassword }),
    requestAppLockPasswordChange: (input) =>
      invoke<Result<'requestAppLockPasswordChange'>>('app_lock_request_password_change', { input }),
    setAppLockRuntimeLocked: (reason) =>
      invoke<Result<'setAppLockRuntimeLocked'>>('app_lock_set_locked', { reason }),
    requestAppLockUnlock: (password) =>
      invoke<Result<'requestAppLockUnlock'>>('app_lock_request_unlock', { password }),
    getAppLockSystemUnlockStatus: () =>
      invoke<Result<'getAppLockSystemUnlockStatus'>>('app_lock_get_system_unlock_status'),
    setAppLockSystemUnlockEnabled: (input) =>
      invoke<Result<'setAppLockSystemUnlockEnabled'>>('app_lock_set_system_unlock_enabled', { input }),
    requestAppLockSystemUnlock: () =>
      invoke<Result<'requestAppLockSystemUnlock'>>('app_lock_request_system_unlock'),
    reportAppLockActivity: async () => {
      await invoke<void>('app_lock_report_activity');
    },
    onAppLockSettingsChanged: (cb) =>
      hub.subscribe<Parameters<typeof cb>[0]>(SECURITY_EVENTS.appLockSettingsChanged, cb),
    onAppLockRuntimeStateChanged: (cb) =>
      hub.subscribe<Parameters<typeof cb>[0]>(SECURITY_EVENTS.appLockRuntimeStateChanged, cb),
    onAppLockReopen: (listener) => hub.subscribe(SECURITY_EVENTS.appLockReopen, () => listener()),

    // -- FIDO2 prompts ------------------------------------------------------
    onFidoPromptRequest: (cb) =>
      hub.subscribe<Parameters<typeof cb>[0]>(SECURITY_EVENTS.fidoPromptRequest, cb),
    respondFidoPrompt: (requestId, response, cancelled = false) =>
      invoke<Result<'respondFidoPrompt'>>('fido_prompt_respond', {
        requestId,
        response,
        cancelled: cancelled === true,
      }),
    onFidoPromptTimeout: (cb) =>
      hub.subscribe<Parameters<typeof cb>[0]>(SECURITY_EVENTS.fidoPromptTimeout, cb),
    onFidoPromptCancelled: (cb) =>
      hub.subscribe<Parameters<typeof cb>[0]>(SECURITY_EVENTS.fidoPromptCancelled, cb),
    generateKeyPair: (options) =>
      SK_KEY_TYPES.has(options.type)
        ? invoke<Result<'generateKeyPair'>>('fido_generate_key_pair', { payload: { ...options } })
        : invoke<Result<'generateKeyPair'>>('ssh_generate_key_pair', { payload: { ...options } }),

    // -- TOTP QR scan / SSH debug log ----------------------------------------
    scanTotpQrFromScreen: () => invoke<Result<'scanTotpQrFromScreen'>>('totp_scan_screen'),
    getSshDebugLogInfo: () => invoke<Result<'getSshDebugLogInfo'>>('ssh_debug_log_info'),
    openSshDebugLogDir: () => invoke<Result<'openSshDebugLogDir'>>('ssh_debug_log_open_dir'),
  };
}
