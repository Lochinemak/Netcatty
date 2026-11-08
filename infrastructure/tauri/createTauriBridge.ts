/**
 * Builds a `NetcattyBridge` on top of the Tauri 2 commands and events specified
 * in `rust/docs/ipc-contract.md`, so the renderer keeps talking to
 * `window.netcatty` exactly as it does under Electron.
 *
 * Mapping rules:
 *  - one bridge method ↔ one `invoke` (complex inputs travel as `payload`);
 *  - event listeners go through a single `EventHub` subscription per event and
 *    are filtered per session / tunnel / scan in here;
 *  - methods with no Rust counterpart stay `undefined` (the renderer already
 *    treats them as optional); the few deliberate stubs are commented inline.
 */

import {
  EventHub,
  SessionDataBacklog,
  TauriBridgeError,
  createChannel,
  currentWindowLabel,
  invoke,
  invokeBinary,
} from './tauriApi';
import {
  decodeRemoteDesktopBinaryMessage,
  isRemoteDesktopControlEvent,
} from '../../domain/remoteDesktop';
import { createUpdateBridge } from './bridge/update';
import { pluginClipboard, pluginDialog, pluginOpener } from './plugins';
import { cancelStagedUpload, stageUploadFile } from './uploadStaging';
import { createAiBridge } from './bridge/ai';

// ---------------------------------------------------------------------------
// Contract constants (see `netcatty_core::ipc::events`)
// ---------------------------------------------------------------------------

export const TAURI_EVENTS = {
  sessionData: 'netcatty:data',
  sessionExit: 'netcatty:exit',
  authFailed: 'netcatty:auth:failed',
  keyboardInteractive: 'netcatty:keyboard-interactive',
  keyboardInteractiveCancelled: 'netcatty:keyboard-interactive-cancelled',
  hostKeyVerify: 'netcatty:host-key:verify',
  passphraseRequest: 'netcatty:passphrase-request',
  passphraseTimeout: 'netcatty:passphrase-timeout',
  passphraseCancelled: 'netcatty:passphrase-cancelled',
  passphraseAuthFailed: 'netcatty:passphrase-auth-failed',
  chainProgress: 'netcatty:chain:progress',
  portForwardStatus: 'netcatty:portforward:status',
  portForwardRuntime: 'netcatty:portforward:runtime',
  sftpConnectionProgress: 'netcatty:sftp:connection-progress',
  sftpGlobalTransfer: 'netcatty:sftp:global-transfer',
  localTreeProgress: 'netcatty:local:tree-progress',
  cloudSyncPasswordAvailable: 'netcatty:cloudsync:password-available',
  settingsChanged: 'netcatty:settings:changed',
  languageChanged: 'netcatty:language-changed',
  windowFullscreenChanged: 'netcatty:window:fullscreen-changed',
  vaultBackupsChanged: 'netcatty:vault-backups:changed',
  fileWatchSynced: 'netcatty:filewatch:synced',
  fileWatchError: 'netcatty:filewatch:error',
  fileWatchStopped: 'netcatty:filewatch:stopped',
  trayFocusSession: 'netcatty:tray:focusSession',
  trayTogglePortForward: 'netcatty:tray:togglePortForward',
  trayPanelJumpToSession: 'netcatty:trayPanel:jumpToSession',
  trayPanelConnectToHost: 'netcatty:trayPanel:connectToHost',
  trayPanelCloseSession: 'netcatty:trayPanel:closeSession',
  trayPanelStartPortForward: 'netcatty:trayPanel:startPortForward',
  trayPanelMenuData: 'netcatty:trayPanel:setMenuData',
  trayPanelRefresh: 'netcatty:trayPanel:refresh',
} as const;

/** Label of the main window (tray actions are delivered there only). */
const MAIN_WINDOW_LABEL = 'main';

/**
 * Events of telnet / serial / Mosh / EternalTerminal sessions (see the
 * "Telnet, serial, Mosh and EternalTerminal" section of the IPC contract).
 */
export const TERMINAL_PROTOCOL_EVENTS = {
  telnetEchoMode: 'netcatty:telnet:echo-mode',
  telnetAutoLoginComplete: 'netcatty:telnet:auto-login-complete',
  telnetAutoLoginCancelled: 'netcatty:telnet:auto-login-cancelled',
  moshReady: 'netcatty:mosh:ready',
} as const;

/** Terminal output kept per session until a display listener attaches (JS string length). */
export const SESSION_BACKLOG_MAX_CHARS = 2 * 1024 * 1024;

/**
 * After `local_list_tree` resolves, wait this long for the trailing
 * `done: true` progress event: Tauri does not order events relative to the
 * command response, and the last `entries` batch may still be in flight.
 */
const LOCAL_TREE_DONE_GRACE_MS = 250;

// ---------------------------------------------------------------------------
// Helper types
// ---------------------------------------------------------------------------

type BridgeMethod<K extends keyof NetcattyBridge> = NonNullable<NetcattyBridge[K]>;
type BridgeArgs<K extends keyof NetcattyBridge> = Parameters<BridgeMethod<K>>;
type BridgeResult<K extends keyof NetcattyBridge> = Awaited<ReturnType<BridgeMethod<K>>>;

type SessionDataCallback = BridgeArgs<'onSessionData'>[1];
type SessionExitCallback = BridgeArgs<'onSessionExit'>[1];
type SessionExitPayload = Parameters<SessionExitCallback>[0];

/**
 * The scripting bridge (`netcatty-bridge-script.d.ts`) declares its members as
 * required although every renderer call site guards them with `?.` — there is
 * no Rust counterpart yet, so the adapter omits them and widens once at the end.
 */
type ScriptBridgeKeys =
  | 'scriptRun'
  | 'scriptStop'
  | 'scriptPause'
  | 'scriptResume'
  | 'scriptGetRuns'
  | 'scriptDialogResponse'
  | 'scriptScreenSnapshotResponse'
  | 'scriptRecordingStart'
  | 'scriptRecordingStop'
  | 'scriptRecordingAppendStep'
  | 'onScriptRunsUpdated'
  | 'onScriptDialogRequest'
  | 'onScriptScreenSnapshotRequest'
  | 'onScriptSessionInput';

type TauriBridgeShape = Omit<NetcattyBridge, ScriptBridgeKeys>;

// ---------------------------------------------------------------------------
// Wire shapes (what Rust emits / returns; camelCase, see `ipc.rs`)
// ---------------------------------------------------------------------------

interface StartSessionResult { sessionId: string }
interface OpenSftpResult { sftpId: string; homeDir?: string; reusedConnection?: boolean }
interface SuccessResult { success: boolean; error?: string }

interface SessionDataEvent { sessionId: string; data: string; meta?: SessionDataMeta }
type SessionDataMeta = Parameters<SessionDataCallback>[1];
interface SessionExitEvent {
  sessionId: string;
  exitCode?: number;
  signal?: number;
  exitSignal?: string;
  error?: string;
  reason: 'exited' | 'error' | 'timeout' | 'closed' | 'signaled';
  remoteClosedWithoutExitStatus?: boolean;
}
interface AuthFailedEvent { sessionId: string; error: string; hostname: string }
interface ChainProgressEvent {
  sessionId: string;
  /** 0-based index of the hop being connected. */
  hopIndex: number;
  hopCount: number;
  hostname: string;
  status: string;
  error?: string;
}
interface SftpConnectionProgressEvent { sessionId: string; label: string; status: string; detail?: string }
interface RemoteInfoResult { success: boolean; serverBanner?: string; software?: string; error?: string }
interface PathValidation { exists: boolean; isFile: boolean; isDirectory: boolean }

type WireForwardStatus = 'inactive' | 'connecting' | 'active' | 'error' | 'unknown';
type RendererForwardStatus = Exclude<WireForwardStatus, 'unknown'>;

interface PortForwardStartResult {
  tunnelId: string;
  success: boolean;
  reused?: boolean;
  status?: WireForwardStatus;
  error?: string;
}
interface PortForwardStatusEvent {
  tunnelId: string;
  status: WireForwardStatus;
  error?: string | null;
  ruleId?: string;
  epoch: number;
  revision: number;
  cleanupRequired?: boolean;
}
interface PortForwardTunnelInfo {
  tunnelId: string;
  ruleId?: string;
  type: 'local' | 'remote' | 'dynamic';
  status: WireForwardStatus;
  error?: string;
  localPort: number;
  bindAddress: string;
  remoteHost?: string;
  remotePort?: number;
  hostId?: string;
  hostname: string;
  updatedAt: number;
}
interface PortForwardSnapshotWire { epoch: number; revision: number; tunnels: PortForwardTunnelInfo[] }
type PortForwardRuntimeWire =
  | { kind: 'upsert'; epoch: number; revision: number; tunnel: PortForwardTunnelInfo }
  | { kind: 'remove'; epoch: number; revision: number; tunnelId: string }
  | { kind: 'reset'; epoch: number; revision: number };

interface LocalTreeEntry {
  localPath: string;
  relativePath: string;
  type: 'file' | 'directory';
  size: number;
  lastModified: number;
}
interface LocalTreeProgressEvent {
  scanId: string;
  fileCount: number;
  directoryCount: number;
  entryCount: number;
  entries?: LocalTreeEntry[];
  done?: boolean;
}

/** Settings relayed between windows; `source` is the sender's window label. */
interface SettingsChangedEvent { source: string; payload: { key: string; value: unknown } }
interface FullscreenChangedEvent { label: string; fullscreen: boolean }
interface TrayFocusSessionEvent { sessionId: string; label: string }
interface TrayTogglePortForwardEvent { ruleId: string; start: boolean }
type TrayMenuData = Parameters<BridgeArgs<'onTrayPanelMenuData'>[0]>[0];

interface WireKnownHost {
  id: string;
  hostname: string;
  port: number;
  keyType: string;
  publicKey: string;
  fingerprint?: string;
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

const warn = (label: string, error: unknown): void => {
  console.warn(`[tauri-bridge] ${label}`, error);
};

/** Fire-and-forget invoke for the `void`-returning bridge methods. */
const fireAndForget = (label: string, promise: Promise<unknown>): void => {
  promise.catch((error: unknown) => warn(`${label} failed`, error));
};

/**
 * Decides when a session's output pump is paused. Two things can want it
 * paused: the renderer's own backpressure (`setSessionFlowPaused`) and any
 * number of short-lived leases (`acquireSessionFlowPauseLease`). The backend
 * only knows one boolean, so the pump is paused while either holds and
 * resumed when neither does; the command is sent only when that changes.
 */
export class FlowPauseCoordinator {
  private readonly sessions = new Map<string, { explicit: boolean; leases: Set<string>; applied: boolean }>();

  constructor(private readonly apply: (sessionId: string, paused: boolean) => Promise<void>) {}

  private state(sessionId: string) {
    let state = this.sessions.get(sessionId);
    if (!state) {
      state = { explicit: false, leases: new Set(), applied: false };
      this.sessions.set(sessionId, state);
    }
    return state;
  }

  private sync(sessionId: string): Promise<void> {
    const state = this.sessions.get(sessionId);
    if (!state) return Promise.resolve();
    const wanted = state.explicit || state.leases.size > 0;
    if (!wanted && state.leases.size === 0) this.sessions.delete(sessionId);
    if (wanted === state.applied) return Promise.resolve();
    state.applied = wanted;
    return this.apply(sessionId, wanted);
  }

  setExplicit(sessionId: string, paused: boolean): Promise<void> {
    this.state(sessionId).explicit = paused;
    return this.sync(sessionId);
  }

  /** Take a lease; resolves with its id once the pump is paused. */
  async acquire(sessionId: string): Promise<string> {
    const leaseId = generateId();
    const state = this.state(sessionId);
    state.leases.add(leaseId);
    try {
      await this.sync(sessionId);
    } catch (error) {
      // The pause never took effect: do not leave a lease (or a stale
      // "applied" flag) behind that would block a later resume.
      state.leases.delete(leaseId);
      state.applied = false;
      if (!state.explicit && state.leases.size === 0) this.sessions.delete(sessionId);
      throw error;
    }
    return leaseId;
  }

  holds(sessionId: string, leaseId: string): boolean {
    return this.sessions.get(sessionId)?.leases.has(leaseId) === true;
  }

  /**
   * Give a lease back. With `keepPaused` the pump is left as it is (the
   * session is being replaced and must not be resumed by a stale owner).
   */
  release(sessionId: string, leaseId: string, keepPaused: boolean): Promise<void> {
    const state = this.sessions.get(sessionId);
    if (!state?.leases.delete(leaseId)) return Promise.resolve();
    if (keepPaused) {
      if (!state.explicit && state.leases.size === 0) this.sessions.delete(sessionId);
      return Promise.resolve();
    }
    return this.sync(sessionId);
  }

  /** Drop all bookkeeping of a closed session. */
  forget(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}

const generateId = (): string => {
  const webCrypto = typeof crypto !== 'undefined' ? crypto : undefined;
  if (webCrypto && typeof webCrypto.randomUUID === 'function') return webCrypto.randomUUID();
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
};

/** Base64-encode an xterm `onBinary` string (every char code is a byte 0–255). */
export const encodeByteStringBase64 = (data: string): string => {
  if (typeof btoa === 'function') return btoa(data);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < data.length; i += 3) {
    const a = data.charCodeAt(i) & 0xff;
    const b = i + 1 < data.length ? data.charCodeAt(i + 1) & 0xff : 0;
    const c = i + 2 < data.length ? data.charCodeAt(i + 2) & 0xff : 0;
    const triple = (a << 16) | (b << 8) | c;
    out += alphabet[(triple >> 18) & 63] + alphabet[(triple >> 12) & 63];
    out += i + 1 < data.length ? alphabet[(triple >> 6) & 63] : '=';
    out += i + 2 < data.length ? alphabet[triple & 63] : '=';
  }
  return out;
};

/** Binary command responses arrive as `ArrayBuffer`; tolerate typed arrays / byte arrays. */
const toArrayBuffer = (value: unknown): ArrayBuffer => {
  if (value instanceof ArrayBuffer) return value;
  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
  }
  if (Array.isArray(value) && value.every((item) => typeof item === 'number')) {
    return Uint8Array.from(value as number[]).buffer;
  }
  throw new TauriBridgeError('INTERNAL', 'Expected a binary response from the backend');
};

/** `process.platform`-style string for the About screen (Electron parity). */
export const detectPlatform = (): string => {
  if (typeof navigator === 'undefined') return 'linux';
  const uaData = (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData;
  const raw = uaData?.platform || navigator.platform || navigator.userAgent || '';
  if (/mac|iphone|ipad|ipod/i.test(raw)) return 'darwin';
  if (/win/i.test(raw)) return 'win32';
  return 'linux';
};

const toRendererForwardStatus = (status: WireForwardStatus | undefined): RendererForwardStatus =>
  // The contract's extra `unknown` state has no renderer equivalent; treat it as
  // "not running" so the UI never shows a phantom active tunnel.
  status === undefined || status === 'unknown' ? 'inactive' : status;

const toRuntimeRecord = (tunnel: PortForwardTunnelInfo, revision: number): PortForwardRuntimeRecord => ({
  ruleId: tunnel.ruleId,
  tunnelId: tunnel.tunnelId,
  phase: toRendererForwardStatus(tunnel.status),
  error: tunnel.error,
  revision,
  updatedAt: tunnel.updatedAt,
});

const toRuntimeSnapshot = (snapshot: PortForwardSnapshotWire): PortForwardRuntimeSnapshot => ({
  epoch: String(snapshot.epoch),
  revision: snapshot.revision,
  records: snapshot.tunnels.map((tunnel) => toRuntimeRecord(tunnel, snapshot.revision)),
});

const toRuntimeEvent = (event: PortForwardRuntimeWire): PortForwardRuntimeEvent => {
  const epoch = String(event.epoch);
  switch (event.kind) {
    case 'upsert':
      return { epoch, revision: event.revision, kind: 'upsert', record: toRuntimeRecord(event.tunnel, event.revision) };
    case 'remove':
      return { epoch, revision: event.revision, kind: 'remove', tunnelId: event.tunnelId };
    case 'reset':
      // The renderer union has no `reset`; its only consumer re-syncs from the
      // snapshot on any epoch/revision change, so surface it as a tunnel-less
      // remove to trigger that reconciliation.
      return { epoch, revision: event.revision, kind: 'remove', tunnelId: '' };
  }
};

/** Re-serialize parsed known hosts into OpenSSH `known_hosts` lines for the renderer's text parser. */
export const knownHostsToText = (hosts: WireKnownHost[]): string => hosts
  .filter((host) => host.hostname && host.keyType && host.publicKey)
  .map((host) => {
    const pattern = host.port && host.port !== 22 ? `[${host.hostname}]:${host.port}` : host.hostname;
    const prefix = `${host.keyType} `;
    const blob = host.publicKey.startsWith(prefix) ? host.publicKey.slice(prefix.length) : host.publicKey;
    return `${pattern} ${host.keyType} ${blob}`;
  })
  .join('\n');

// ---------------------------------------------------------------------------
// Session event routing (per-session fan-out + replay backlog)
// ---------------------------------------------------------------------------

class SessionEventRouter {
  private readonly dataListeners = new Map<string, Set<SessionDataCallback>>();
  /** Subset of data listeners that opted into `replayBacklog`. */
  private readonly displayListeners = new Map<string, Set<SessionDataCallback>>();
  private readonly exitListeners = new Map<string, Set<SessionExitCallback>>();
  private readonly backlog: SessionDataBacklog;

  constructor(hub: EventHub, backlog: SessionDataBacklog) {
    this.backlog = backlog;
    hub.subscribe<SessionDataEvent>(TAURI_EVENTS.sessionData, (event) => this.handleData(event));
    hub.subscribe<SessionExitEvent>(TAURI_EVENTS.sessionExit, (event) => this.handleExit(event));
  }

  onData(sessionId: string, cb: SessionDataCallback, replayBacklog: boolean): () => void {
    addTo(this.dataListeners, sessionId, cb);
    if (replayBacklog) {
      addTo(this.displayListeners, sessionId, cb);
      const pending = this.backlog.take(sessionId);
      if (pending) {
        try {
          cb(pending);
        } catch (error) {
          warn('session data callback failed', error);
        }
      }
    }
    return () => {
      removeFrom(this.dataListeners, sessionId, cb);
      if (replayBacklog) removeFrom(this.displayListeners, sessionId, cb);
    };
  }

  onExit(sessionId: string, cb: SessionExitCallback): () => void {
    addTo(this.exitListeners, sessionId, cb);
    return () => removeFrom(this.exitListeners, sessionId, cb);
  }

  private handleData(event: SessionDataEvent | undefined): void {
    if (!event || typeof event.sessionId !== 'string' || !event.data) return;
    if ((this.displayListeners.get(event.sessionId)?.size ?? 0) === 0) {
      this.backlog.append(event.sessionId, event.data);
    }
    const listeners = this.dataListeners.get(event.sessionId);
    if (!listeners || listeners.size === 0) return;
    for (const cb of Array.from(listeners)) {
      try {
        cb(event.data, event.meta);
      } catch (error) {
        warn('session data callback failed', error);
      }
    }
  }

  private handleExit(event: SessionExitEvent | undefined): void {
    if (!event || typeof event.sessionId !== 'string') return;
    const payload: SessionExitPayload = {
      exitCode: event.exitCode,
      signal: event.signal,
      exitSignal: event.exitSignal,
      error: event.error,
      reason: event.reason,
      remoteClosedWithoutExitStatus: event.remoteClosedWithoutExitStatus,
    };
    const listeners = this.exitListeners.get(event.sessionId);
    if (listeners) {
      for (const cb of Array.from(listeners)) {
        try {
          cb(payload);
        } catch (error) {
          warn('session exit callback failed', error);
        }
      }
    }
    this.backlog.clear(event.sessionId);
  }
}

function addTo<T>(map: Map<string, Set<T>>, key: string, value: T): void {
  let set = map.get(key);
  if (!set) {
    set = new Set<T>();
    map.set(key, set);
  }
  set.add(value);
}

function removeFrom<T>(map: Map<string, Set<T>>, key: string, value: T): void {
  const set = map.get(key);
  if (!set) return;
  set.delete(value);
  if (set.size === 0) map.delete(key);
}

// ---------------------------------------------------------------------------
// Bridge factory
// ---------------------------------------------------------------------------

export interface CreateTauriBridgeOptions {
  /** Injected for tests; defaults to the real `window.__TAURI__` hub. */
  hub?: EventHub;
  /** Plugin namespaces; defaults to `window.__TAURI__`. */
  plugins?: Pick<NetcattyTauriGlobal, 'dialog' | 'clipboardManager' | 'opener'>;
}

export function createTauriBridge(options: CreateTauriBridgeOptions = {}): NetcattyBridge {
  const hub = options.hub ?? new EventHub();
  const plugins = options.plugins ?? (typeof window !== 'undefined' ? window.__TAURI__ : undefined) ?? {};
  const backlog = new SessionDataBacklog(SESSION_BACKLOG_MAX_CHARS);
  const sessions = new SessionEventRouter(hub, backlog);

  // Subscribe eagerly so output emitted right after a start command cannot be
  // lost while the async `listen` registration is still pending.
  const sessionEventsReady = Promise.all([
    hub.ensure(TAURI_EVENTS.sessionData),
    hub.ensure(TAURI_EVENTS.sessionExit),
    hub.ensure(TAURI_EVENTS.authFailed),
  ]).then(() => undefined);

  const protocolEventsReady = Promise.all(
    Object.values(TERMINAL_PROTOCOL_EVENTS).map((event) => hub.ensure(event)),
  ).then(() => undefined);

  const startSession = async (command: string, payload: Record<string, unknown>): Promise<string> => {
    await sessionEventsReady;
    const result = await invoke<StartSessionResult>(command, { payload });
    return result.sessionId;
  };

  const subscribeFiltered = <T extends { sessionId?: string }>(
    event: string,
    sessionId: string,
    cb: (payload: T) => void,
  ): (() => void) => hub.subscribe<T>(event, (payload) => {
    if (payload?.sessionId === sessionId) cb(payload);
  });

  // Plugin globals are optional overrides (tests); by default the plugins are
  // reached through `invoke("plugin:…")`, which is always available.
  const dialog: NonNullable<NetcattyTauriGlobal['dialog']> = plugins.dialog ?? pluginDialog;
  const clipboard: NonNullable<NetcattyTauriGlobal['clipboardManager']> = plugins.clipboardManager ?? pluginClipboard;
  const opener: NonNullable<NetcattyTauriGlobal['opener']> = plugins.opener ?? pluginOpener;

  const openerResult = async (run: () => Promise<void>): Promise<{ success: boolean; error?: string }> => {
    try {
      await run();
      return { success: true };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) };
    }
  };

  /** Tray panel → main window actions carry a bare id. */
  const subscribeMainWindowString = (event: string, cb: (value: string) => void): (() => void) => {
    if (currentWindowLabel() !== MAIN_WINDOW_LABEL) return () => {};
    return hub.subscribe<string>(event, (value) => {
      if (typeof value === 'string') cb(value);
    });
  };

  const flowPause = new FlowPauseCoordinator((sessionId, paused) =>
    invoke<void>('session_set_flow_paused', { sessionId, paused }));

  const bridge: TauriBridgeShape = {
    // -----------------------------------------------------------------------
    // Sessions and terminal
    // -----------------------------------------------------------------------
    startSSHSession: (sshOptions) => startSession('session_start_ssh', { ...sshOptions }),
    testConnection: (sshOptions) => startSession('session_test_connection', { ...sshOptions }),
    cancelTestConnection: (sessionId) =>
      invoke<SuccessResult>('session_cancel_test_connection', { sessionId }),
    startLocalSession: (localOptions) => startSession('session_start_local', { ...localOptions }),

    writeToSession: (sessionId, data, writeOptions) => {
      const binary = writeOptions?.binary === true;
      const lineDelayMs = Number(writeOptions?.lineDelayMs);
      fireAndForget('session_write', invoke<void>('session_write', {
        payload: {
          sessionId,
          data: binary ? encodeByteStringBase64(data) : data,
          binary,
          automated: writeOptions?.automated === true,
          sensitive: writeOptions?.sensitive === true,
          pasteRequestId: typeof writeOptions?.pasteRequestId === 'string' ? writeOptions.pasteRequestId : undefined,
          // Serial Backspace expansion; only sent when set.
          ...(typeof writeOptions?.serialEraseChar === 'string' ? { serialEraseChar: writeOptions.serialEraseChar } : {}),
          lineDelayMs: Number.isFinite(lineDelayMs) && lineDelayMs > 0 ? lineDelayMs : undefined,
          // Session logs show `displayCommand` instead of this command's echo;
          // only sent when set.
          ...(typeof writeOptions?.logRewrite?.sentCommand === 'string' && writeOptions.logRewrite.sentCommand
            ? {
              logRewrite: {
                sentCommand: writeOptions.logRewrite.sentCommand,
                displayCommand: String(writeOptions.logRewrite.displayCommand ?? ''),
              },
            }
            : {}),
        },
      }));
    },
    resizeSession: (sessionId, cols, rows) => {
      fireAndForget('session_resize', invoke<void>('session_resize', { payload: { sessionId, cols, rows } }));
    },
    interruptSession: (sessionId, _trace, interruptOptions) => {
      // `cancelPendingWritesOnly` asks Electron to drop queued paste chunks
      // without sending ^C; the Rust backend has no write queue to cancel, so
      // that variant is a deliberate no-op.
      if (interruptOptions?.cancelPendingWritesOnly === true) return;
      fireAndForget('session_interrupt', invoke<void>('session_interrupt', { sessionId }));
    },
    setSessionFlowPaused: (sessionId, paused) => {
      fireAndForget('session_set_flow_paused', flowPause.setExplicit(sessionId, paused));
    },
    setSessionFlowPausedAndWait: async (sessionId, paused) => {
      try {
        await flowPause.setExplicit(sessionId, paused);
        return { success: true };
      } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : String(error) };
      }
    },
    // Pause leases: the terminal takes one around a resize while output is
    // still being written, so the PTY is not resized under in-flight data.
    acquireSessionFlowPauseLease: async (sessionId) => {
      try {
        return { success: true, leaseId: await flowPause.acquire(sessionId) };
      } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : String(error) };
      }
    },
    // `session_set_flow_paused` resolves once the output pump is paused, so a
    // held lease is already drained on the backend side.
    waitSessionFlowPauseLease: async (sessionId, leaseId) => (
      flowPause.holds(sessionId, leaseId)
        ? { success: true }
        : { success: false, error: 'Unknown flow pause lease' }
    ),
    releaseSessionFlowPauseLease: async (sessionId, leaseId, releaseOptions) => {
      try {
        await flowPause.release(sessionId, leaseId, releaseOptions?.keepPaused === true);
        return { success: true };
      } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : String(error) };
      }
    },
    ackSessionFlow: (sessionId, bytes) => {
      fireAndForget('session_ack_flow', invoke<void>('session_ack_flow', { sessionId, bytes }));
    },
    closeSession: (sessionId) => {
      flowPause.forget(sessionId);
      return invoke<void>('session_close', { sessionId });
    },

    // -----------------------------------------------------------------------
    // Remote desktop (VNC / RDP)
    // -----------------------------------------------------------------------
    startRemoteDesktopSession: async (desktopOptions, onEvent) => {
      // Frames are binary messages, everything else is JSON; both arrive on
      // the per-session channel in backend order.
      const channel = createChannel<unknown>((message) => {
        if (message instanceof ArrayBuffer) {
          const frame = decodeRemoteDesktopBinaryMessage(message);
          if (frame) onEvent(frame);
          return;
        }
        if (isRemoteDesktopControlEvent(message)) onEvent(message);
      });
      const result = await invoke<StartSessionResult>('rdesktop_connect', {
        payload: { ...desktopOptions },
        onEvent: channel,
      });
      return result.sessionId;
    },
    sendRemoteDesktopInput: (sessionId, events) => {
      if (events.length === 0) return;
      fireAndForget('rdesktop_input', invoke<void>('rdesktop_input', { payload: { sessionId, events } }));
    },
    closeRemoteDesktopSession: (sessionId) => invoke<void>('rdesktop_close', { sessionId }),

    onSessionData: (sessionId, cb, dataOptions) =>
      sessions.onData(sessionId, cb, dataOptions?.replayBacklog === true),
    onSessionExit: (sessionId, cb) => sessions.onExit(sessionId, cb),
    onAuthFailed: (sessionId, cb) =>
      subscribeFiltered<AuthFailedEvent>(TAURI_EVENTS.authFailed, sessionId, cb),

    execCommand: (execOptions) => invoke<BridgeResult<'execCommand'>>('session_exec', { payload: { ...execOptions } }),
    getSessionPwd: (sessionId) => invoke<BridgeResult<'getSessionPwd'>>('session_pwd', { sessionId }),
    getSessionRemoteInfo: async (sessionId) => {
      const info = await invoke<RemoteInfoResult>('session_remote_info', { sessionId });
      return {
        success: info.success,
        // Electron exposes the `software` part of the SSH-2.0 banner.
        remoteSshVersion: info.software ?? info.serverBanner,
        error: info.error,
      };
    },

    getDefaultShell: () => invoke<string>('local_get_default_shell'),
    discoverShells: () => invoke<DiscoveredShell[]>('local_discover_shells'),
    validatePath: async (path, type) => {
      const result = await invoke<PathValidation>('local_validate_path', { path, kind: type });
      // The contract does not report executability; callers only read
      // exists / isFile / isDirectory.
      return { ...result, isExecutable: false };
    },
    generateKeyPair: (keyOptions) =>
      invoke<BridgeResult<'generateKeyPair'>>('ssh_generate_key_pair', { payload: { ...keyOptions } }),
    checkSshAgent: (agentOptions) =>
      invoke<BridgeResult<'checkSshAgent'>>('ssh_check_agent', { payload: { ...(agentOptions ?? {}) } }),
    getDefaultKeys: () => invoke<BridgeResult<'getDefaultKeys'>>('ssh_get_default_keys'),
    readKnownHosts: async () => {
      // Rust returns parsed entries; the renderer expects the raw file text and
      // parses it itself, so rebuild canonical known_hosts lines.
      const hosts = await invoke<WireKnownHost[] | null>('ssh_read_known_hosts');
      if (!hosts || hosts.length === 0) return null;
      const text = knownHostsToText(hosts);
      return text.length > 0 ? text : null;
    },

    // -----------------------------------------------------------------------
    // Telnet, serial, Mosh and EternalTerminal sessions. They share the
    // session commands above (write / resize / close / flow pause); these are
    // the start commands and protocol events. The protocol events are
    // subscribed before the start command resolves so an early echo-mode /
    // auto-login / Mosh-ready event cannot be missed.
    // -----------------------------------------------------------------------
    startTelnetSession: async (telnetOptions) => {
      await protocolEventsReady;
      return startSession('telnet_start', { ...telnetOptions });
    },
    startSerialSession: async (serialOptions) => {
      await protocolEventsReady;
      return startSession('serial_start', { ...serialOptions });
    },
    listSerialPorts: () => invoke<BridgeResult<'listSerialPorts'>>('serial_list_ports'),
    startMoshSession: async (moshOptions) => {
      await protocolEventsReady;
      return startSession('mosh_start', { ...moshOptions });
    },
    startEtSession: async (etOptions) => {
      await protocolEventsReady;
      return startSession('et_start', { ...etOptions });
    },
    onTelnetEchoMode: (sessionId, cb) =>
      subscribeFiltered(TERMINAL_PROTOCOL_EVENTS.telnetEchoMode, sessionId, cb),
    getTelnetEchoMode: (sessionId) =>
      invoke<BridgeResult<'getTelnetEchoMode'>>('telnet_get_echo_mode', { sessionId }),
    onTelnetAutoLoginComplete: (sessionId, cb) =>
      subscribeFiltered(TERMINAL_PROTOCOL_EVENTS.telnetAutoLoginComplete, sessionId, cb),
    onTelnetAutoLoginCancelled: (sessionId, cb) =>
      subscribeFiltered(TERMINAL_PROTOCOL_EVENTS.telnetAutoLoginCancelled, sessionId, cb),
    onMoshSessionReady: (sessionId, cb) =>
      subscribeFiltered(TERMINAL_PROTOCOL_EVENTS.moshReady, sessionId, cb),
    notifySessionUserInput: (sessionId) => {
      fireAndForget('session_notify_user_input', invoke<void>('session_notify_user_input', { sessionId }));
    },
    setSessionEncoding: (sessionId, encoding) =>
      invoke<BridgeResult<'setSessionEncoding'>>('session_set_encoding', { sessionId, encoding }),

    // -----------------------------------------------------------------------
    // SSH prompts
    // -----------------------------------------------------------------------
    onKeyboardInteractive: (cb) => hub.subscribe(TAURI_EVENTS.keyboardInteractive, cb),
    onKeyboardInteractiveCancelled: (cb) => hub.subscribe(TAURI_EVENTS.keyboardInteractiveCancelled, cb),
    respondKeyboardInteractive: (requestId, responses, cancelled) =>
      invoke<SuccessResult>('ssh_respond_keyboard_interactive', {
        payload: { requestId, responses, cancelled: cancelled === true },
      }),

    onHostKeyVerification: (cb) => hub.subscribe(TAURI_EVENTS.hostKeyVerify, cb),
    respondHostKeyVerification: (requestId, accept, addToKnownHosts) =>
      invoke<SuccessResult>('ssh_respond_host_key', {
        payload: { requestId, accept, addToKnownHosts: addToKnownHosts === true },
      }),

    onPassphraseRequest: (cb) => hub.subscribe(TAURI_EVENTS.passphraseRequest, cb),
    respondPassphrase: (requestId, passphrase, cancelled) =>
      invoke<SuccessResult>('ssh_respond_passphrase', {
        payload: {
          requestId,
          passphrase: cancelled === true ? undefined : passphrase,
          cancelled: cancelled === true,
          skip: false,
        },
      }),
    respondPassphraseSkip: (requestId) =>
      invoke<SuccessResult>('ssh_respond_passphrase', {
        payload: { requestId, cancelled: false, skip: true },
      }),
    onPassphraseTimeout: (cb) => hub.subscribe(TAURI_EVENTS.passphraseTimeout, cb),
    onPassphraseCancelled: (cb) => hub.subscribe(TAURI_EVENTS.passphraseCancelled, cb),
    onPassphraseAuthFailed: (cb) => hub.subscribe(TAURI_EVENTS.passphraseAuthFailed, cb),

    onChainProgress: (cb) => hub.subscribe<ChainProgressEvent>(TAURI_EVENTS.chainProgress, (event) => {
      // Electron reports 1-based hop numbers.
      cb(event.sessionId, event.hopIndex + 1, event.hopCount, event.hostname, event.status, event.error);
    }),

    // -----------------------------------------------------------------------
    // SFTP
    // -----------------------------------------------------------------------
    openSftp: async (sshOptions) => {
      const result = await invoke<OpenSftpResult>('sftp_open', { payload: { ...sshOptions } });
      return result.sftpId;
    },
    openSftpForSession: async (sessionId, sshOptions) => {
      const result = await invoke<OpenSftpResult>('sftp_open_for_session', {
        sessionId,
        payload: sshOptions ? { ...sshOptions } : undefined,
      });
      return result.sftpId;
    },
    listSftp: (sftpId, path, encoding) =>
      invoke<BridgeResult<'listSftp'>>('sftp_list', { sftpId, path, encoding }),
    realpathSftp: (sftpId, path, encoding) => invoke<string>('sftp_realpath', { sftpId, path, encoding }),
    readSftp: (sftpId, path, encoding) => invoke<string>('sftp_read', { sftpId, path, encoding }),
    readSftpBinary: async (sftpId, path, encoding) =>
      toArrayBuffer(await invoke<unknown>('sftp_read_binary', { sftpId, path, encoding })),
    writeSftp: (sftpId, path, content, encoding) =>
      invoke<void>('sftp_write', { sftpId, path, content, encoding }),
    writeSftpBinary: (sftpId, path, content, encoding) =>
      invokeBinary<void>('sftp_write_binary', content, { sftpId, path, encoding }),
    closeSftp: (sftpId) => invoke<{ success?: boolean }>('sftp_close', { sftpId }),
    // The Rust backend has no transfer lease bookkeeping: `sftp_close` closes
    // immediately, so leases are acknowledged without effect.
    retainSftpTransferSession: async () => ({ success: true }),
    releaseSftpTransferSession: async () => ({ success: true }),
    mkdirSftp: (sftpId, path, encoding) => invoke<void>('sftp_mkdir', { sftpId, path, encoding }),
    deleteSftp: (sftpId, path, encoding, expectedType) =>
      invoke<void>('sftp_delete', { sftpId, path, encoding, expectedType }),
    renameSftp: (sftpId, oldPath, newPath, encoding) =>
      invoke<void>('sftp_rename', { sftpId, oldPath, newPath, encoding }),
    statSftp: (sftpId, path, encoding) => invoke<SftpStatResult>('sftp_stat', { sftpId, path, encoding }),
    lstatSftp: (sftpId, path, encoding) =>
      invoke<SftpStatResult | null>('sftp_lstat', { sftpId, path, encoding }),
    chmodSftp: (sftpId, path, mode, encoding) => invoke<void>('sftp_chmod', { sftpId, path, mode, encoding }),
    extractSftpArchive: (sftpId, path, encoding) =>
      invoke<{ success: boolean }>('sftp_extract', { sftpId, path, encoding }),
    getSftpHomeDir: (sftpId, encoding) =>
      invoke<BridgeResult<'getSftpHomeDir'>>('sftp_home_dir', { sftpId, encoding }),
    onSftpConnectionProgress: (cb) =>
      hub.subscribe<SftpConnectionProgressEvent>(TAURI_EVENTS.sftpConnectionProgress, (event) => {
        cb(event.sessionId, event.label, event.status, event.detail);
      }),

    // -----------------------------------------------------------------------
    // Open remote files with external applications
    // -----------------------------------------------------------------------
    selectApplication: () => invoke<BridgeResult<'selectApplication'>>('app_select_application'),
    openWithApplication: (filePath, appPath) =>
      invoke<boolean>('app_open_with_application', { filePath, appPath }),
    downloadSftpToTempWithProgress: (sftpId, remotePath, fileName, encoding, transferId) =>
      invoke<BridgeResult<'downloadSftpToTempWithProgress'>>('sftp_download_to_temp', {
        sftpId, remotePath, fileName, encoding, transferId,
      }),
    confirmCloseBusy: (payload) => invoke<boolean>('dialog_confirm_close_busy', { payload }),
    // `cp -ra` on the remote; `{ success: false }` makes the renderer fall
    // back to its per-file copy.
    sameHostCopyDirectory: (sftpId, sourcePath, targetPath) =>
      invoke<BridgeResult<'sameHostCopyDirectory'>>('sftp_same_host_copy_dir', { sftpId, sourcePath, targetPath }),

    // -----------------------------------------------------------------------
    // Edit-and-sync: watch a downloaded temp file and upload saves
    // -----------------------------------------------------------------------
    startFileWatch: (localPath, remotePath, sftpId, encoding) =>
      invoke<BridgeResult<'startFileWatch'>>('filewatch_start', { localPath, remotePath, sftpId, encoding }),
    stopFileWatch: (watchId, cleanupTempFile) =>
      invoke<BridgeResult<'stopFileWatch'>>('filewatch_stop', { watchId, cleanupTempFile }),
    listFileWatches: () => invoke<BridgeResult<'listFileWatches'>>('filewatch_list'),
    registerTempFile: (sftpId, localPath) =>
      invoke<BridgeResult<'registerTempFile'>>('filewatch_register_temp_file', { sftpId, localPath }),
    unregisterTempFile: (sftpId, localPath) =>
      invoke<BridgeResult<'unregisterTempFile'>>('filewatch_unregister_temp_file', { sftpId, localPath }),
    onFileWatchSynced: (cb) => hub.subscribe(TAURI_EVENTS.fileWatchSynced, cb),
    onFileWatchError: (cb) => hub.subscribe(TAURI_EVENTS.fileWatchError, cb),
    onFileWatchStopped: (cb) => hub.subscribe(TAURI_EVENTS.fileWatchStopped, cb),

    // -----------------------------------------------------------------------
    // Transfers
    // -----------------------------------------------------------------------
    startStreamTransfer: (transferOptions) =>
      invoke<BridgeResult<'startStreamTransfer'>>('transfer_start', { payload: { ...transferOptions } }),
    cancelTransfer: (transferId) => invoke<void>('transfer_cancel', { transferId }),
    pauseTransfer: (transferId) => invoke<BridgeResult<'pauseTransfer'>>('transfer_pause', { transferId }),
    // The contract defines no resume command (a paused transfer is restarted
    // through `startStreamTransfer` with its checkpoint), so report the gap.
    resumeTransfer: async () => ({ success: false, reason: 'not-supported' }),
    // Electron keeps a pre-start cancel latch in the main process; Rust has none.
    clearPendingTransferCancel: async () => ({ success: true }),
    onGlobalSftpTransferEvent: (cb) => hub.subscribe(TAURI_EVENTS.sftpGlobalTransfer, cb),

    // -----------------------------------------------------------------------
    // Port forwarding
    // -----------------------------------------------------------------------
    startPortForward: async (forwardOptions) => {
      const result = await invoke<PortForwardStartResult>('portforward_start', { payload: { ...forwardOptions } });
      return {
        tunnelId: result.tunnelId,
        success: result.success,
        reused: result.reused,
        status: result.status === undefined ? undefined : toRendererForwardStatus(result.status),
        error: result.error,
      };
    },
    stopPortForward: async (tunnelId) => {
      const result = await invoke<SuccessResult>('portforward_stop', { tunnelId });
      return { tunnelId, success: result.success, error: result.error };
    },
    stopPortForwardByRuleId: async (ruleId) => {
      // The contract only reports success; Electron returns real counts.
      const result = await invoke<SuccessResult>('portforward_stop_by_rule', { ruleId });
      return result.success
        ? { stopped: 1, failed: 0 }
        : { stopped: 0, failed: 1, errors: result.error ? [result.error] : undefined };
    },
    stopAllPortForwards: async () => {
      await invoke<SuccessResult>('portforward_stop_all');
    },
    getPortForwardStatus: async (tunnelId) => {
      const result = await invoke<{ status: WireForwardStatus; error?: string }>('portforward_status', { tunnelId });
      return { tunnelId, status: toRendererForwardStatus(result.status), error: result.error };
    },
    subscribePortForward: async (tunnelId) => {
      // Status events are already broadcast; a subscription is just a status read.
      const result = await invoke<{ status: WireForwardStatus; error?: string }>('portforward_status', { tunnelId });
      return { tunnelId, status: toRendererForwardStatus(result.status), error: result.error };
    },
    listPortForwards: async () => {
      const tunnels = await invoke<PortForwardTunnelInfo[]>('portforward_list');
      return tunnels.map((tunnel) => ({
        ruleId: tunnel.ruleId,
        tunnelId: tunnel.tunnelId,
        type: tunnel.type,
        status: toRendererForwardStatus(tunnel.status),
        error: tunnel.error,
      }));
    },
    getPortForwardSnapshot: async () => toRuntimeSnapshot(await invoke<PortForwardSnapshotWire>('portforward_snapshot')),
    subscribePortForwardRuntime: async () =>
      toRuntimeSnapshot(await invoke<PortForwardSnapshotWire>('portforward_snapshot')),
    // Runtime events are always broadcast by Rust; nothing to tear down.
    unsubscribePortForwardRuntime: async () => ({ success: true }),
    onPortForwardStatus: (tunnelId, cb) =>
      hub.subscribe<PortForwardStatusEvent>(TAURI_EVENTS.portForwardStatus, (event) => {
        if (event?.tunnelId !== tunnelId) return;
        cb(toRendererForwardStatus(event.status), event.error ?? undefined);
      }),
    onPortForwardRuntime: (cb) =>
      hub.subscribe<PortForwardRuntimeWire>(TAURI_EVENTS.portForwardRuntime, (event) => {
        if (!event || typeof event.kind !== 'string') return;
        cb(toRuntimeEvent(event));
      }),

    // -----------------------------------------------------------------------
    // Local filesystem
    // -----------------------------------------------------------------------
    listLocalDir: (path) => invoke<BridgeResult<'listLocalDir'>>('local_list_dir', { path }),
    readLocalFile: async (path, readOptions) =>
      toArrayBuffer(await invoke<unknown>('local_read_file', { path, maxBytes: readOptions?.maxBytes })),
    writeLocalFile: (path, content) => invokeBinary<void>('local_write_file', content, { path }),
    deleteLocalFile: (path, expectedType) => invoke<void>('local_delete', { path, expectedType }),
    renameLocalFile: (oldPath, newPath) => invoke<void>('local_rename', { oldPath, newPath }),
    extractLocalArchive: async (path) => {
      await invoke<void>('local_extract', { path });
      return { success: true };
    },
    mkdirLocal: (path) => invoke<void>('local_mkdir', { path }),
    statLocal: (path) => invoke<SftpStatResult>('local_stat', { path }),
    lstatLocal: (path) => invoke<SftpStatResult>('local_lstat', { path }),
    realpathLocal: (path) => invoke<string>('local_realpath', { path }),
    listLocalTree: async (path, treeOptions) => {
      const scanId = typeof treeOptions?.scanId === 'string' && treeOptions.scanId ? treeOptions.scanId : generateId();
      const onProgress = treeOptions?.onProgress;
      const onEntries = treeOptions?.onEntries;
      let unsubscribe: (() => void) | undefined;
      let settleDone: (() => void) | undefined;
      const done = new Promise<void>((resolve) => {
        settleDone = resolve;
      });
      if (onProgress || onEntries) {
        unsubscribe = hub.subscribe<LocalTreeProgressEvent>(TAURI_EVENTS.localTreeProgress, (event) => {
          if (!event || event.scanId !== scanId) return;
          if (onEntries && event.entries && event.entries.length > 0) {
            try {
              onEntries(event.entries);
            } catch (error) {
              warn('listLocalTree onEntries failed', error);
            }
          }
          if (onProgress) {
            try {
              onProgress({
                fileCount: event.fileCount,
                directoryCount: event.directoryCount,
                entryCount: event.entryCount,
              });
            } catch (error) {
              warn('listLocalTree onProgress failed', error);
            }
          }
          if (event.done) settleDone?.();
        });
        await hub.ensure(TAURI_EVENTS.localTreeProgress);
      } else {
        settleDone?.();
      }
      try {
        const entries = await invoke<LocalTreeEntry[]>('local_list_tree', {
          scanId,
          path,
          limits: treeOptions?.limits,
        });
        // Let a trailing progress batch land before the listener goes away.
        await Promise.race([
          done,
          new Promise<void>((resolve) => setTimeout(resolve, LOCAL_TREE_DONE_GRACE_MS)),
        ]);
        return entries;
      } finally {
        unsubscribe?.();
      }
    },
    cancelLocalTreeScan: (scanId) => invoke<void>('local_cancel_tree_scan', { scanId }),
    getHomeDir: () => invoke<string>('local_home_dir'),
    listDrives: () => invoke<string[]>('local_list_drives'),
    getSystemInfo: () => invoke<BridgeResult<'getSystemInfo'>>('system_info'),

    // -----------------------------------------------------------------------
    // App lock (not ported yet). The AppLockGate renders nothing until the
    // runtime state reports `initialized: true`, so an initialized, unlocked
    // state is required for the UI to appear at all. Mutations are refused.
    // -----------------------------------------------------------------------
    getAppLockRuntimeState: async () => unlockedAppLockRuntimeState(),
    onAppLockRuntimeStateChanged: () => () => {},
    onAppLockSettingsChanged: () => () => {},
    setAppLockRuntimeLocked: async () => unlockedAppLockRuntimeState(),
    reportAppLockActivity: async () => {},
    requestAppLockUnlock: async () => ({ ok: true }),

    // -----------------------------------------------------------------------
    // Temp files / upload staging. The webview has no local path for a
    // dropped or picked File, so its bytes are streamed into the Rust temp
    // directory first (see uploadStaging.ts); `getPathForFile` stays
    // undefined on purpose so callers take the staging path.
    // -----------------------------------------------------------------------
    stageUploadFile: (file, transferId) => stageUploadFile(file, transferId),
    cancelStagedUploadFile: async (transferId) => cancelStagedUpload(transferId),
    deleteTempFile: (filePath) => invoke<BridgeResult<'deleteTempFile'>>('temp_delete_file', { filePath }),

    // -----------------------------------------------------------------------
    // Credentials
    // -----------------------------------------------------------------------
    credentialsAvailable: () => invoke<boolean>('credentials_available'),
    credentialsEncrypt: (plaintext) => invoke<string>('credentials_encrypt', { plaintext }),
    credentialsDecrypt: (value) => invoke<string>('credentials_decrypt', { value }),

    // -----------------------------------------------------------------------
    // Cloud sync (netcatty-sync). The renderer keeps the sync engine; Rust
    // moves the encrypted file and makes the calls CORS blocks in a WebView.
    // -----------------------------------------------------------------------
    cloudSyncSetSessionPassword: (password) => invoke<boolean>('cloudsync_password_set', { password }),
    cloudSyncGetSessionPassword: () => invoke<string | null>('cloudsync_password_get'),
    cloudSyncClearSessionPassword: () => invoke<boolean>('cloudsync_password_clear'),
    onCloudSyncSessionPasswordAvailable: (cb) =>
      hub.subscribe<unknown>(TAURI_EVENTS.cloudSyncPasswordAvailable, () => cb()),

    cloudSyncWebdavInitialize: (config) =>
      invoke<BridgeResult<'cloudSyncWebdavInitialize'>>('webdav_initialize', { config }),
    cloudSyncWebdavUpload: (config, syncedFile) =>
      invoke<BridgeResult<'cloudSyncWebdavUpload'>>('webdav_upload', { config, syncedFile }),
    cloudSyncWebdavDownload: (config) =>
      invoke<BridgeResult<'cloudSyncWebdavDownload'>>('webdav_download', { config }),
    cloudSyncWebdavDelete: (config) => invoke<BridgeResult<'cloudSyncWebdavDelete'>>('webdav_delete', { config }),
    cloudSyncS3Initialize: (config) => invoke<BridgeResult<'cloudSyncS3Initialize'>>('s3_initialize', { config }),
    cloudSyncS3Upload: (config, syncedFile) =>
      invoke<BridgeResult<'cloudSyncS3Upload'>>('s3_upload', { config, syncedFile }),
    cloudSyncS3Download: (config) => invoke<BridgeResult<'cloudSyncS3Download'>>('s3_download', { config }),
    cloudSyncS3Delete: (config) => invoke<BridgeResult<'cloudSyncS3Delete'>>('s3_delete', { config }),

    prepareOAuthCallback: () => invoke<BridgeResult<'prepareOAuthCallback'>>('oauth_prepare_callback'),
    awaitOAuthCallback: (expectedState, sessionId) =>
      invoke<BridgeResult<'awaitOAuthCallback'>>('oauth_await_callback', { expectedState, sessionId }),
    cancelOAuthCallback: (sessionId) => invoke<void>('oauth_cancel_callback', { sessionId }),

    githubStartDeviceFlow: (flowOptions) =>
      invoke<BridgeResult<'githubStartDeviceFlow'>>('github_device_flow_start', { payload: flowOptions ?? {} }),
    githubPollDeviceFlowToken: (pollOptions) =>
      invoke<BridgeResult<'githubPollDeviceFlowToken'>>('github_device_flow_poll', { payload: pollOptions }),
    githubCancelDeviceFlowPoll: (pollId) => invoke<void>('github_device_flow_cancel', { pollId }),
    githubDownloadGistRawContent: (gistOptions) =>
      invoke<string>('github_gist_raw_content', { payload: gistOptions }),

    googleExchangeCodeForTokens: (tokenOptions) =>
      invoke<BridgeResult<'googleExchangeCodeForTokens'>>('google_oauth_exchange', { payload: tokenOptions }),
    googleRefreshAccessToken: (tokenOptions) =>
      invoke<BridgeResult<'googleRefreshAccessToken'>>('google_oauth_refresh', { payload: tokenOptions }),
    googleGetUserInfo: (userOptions) =>
      invoke<BridgeResult<'googleGetUserInfo'>>('google_oauth_userinfo', { payload: userOptions }),
    googleDriveFindSyncFile: (driveOptions) =>
      invoke<BridgeResult<'googleDriveFindSyncFile'>>('google_drive_find_sync_file', { payload: driveOptions }),
    googleDriveCreateSyncFile: (driveOptions) =>
      invoke<BridgeResult<'googleDriveCreateSyncFile'>>('google_drive_create_sync_file', { payload: driveOptions }),
    googleDriveUpdateSyncFile: (driveOptions) =>
      invoke<BridgeResult<'googleDriveUpdateSyncFile'>>('google_drive_update_sync_file', { payload: driveOptions }),
    googleDriveDownloadSyncFile: (driveOptions) =>
      invoke<BridgeResult<'googleDriveDownloadSyncFile'>>('google_drive_download_sync_file', { payload: driveOptions }),
    googleDriveDeleteSyncFile: (driveOptions) =>
      invoke<BridgeResult<'googleDriveDeleteSyncFile'>>('google_drive_delete_sync_file', { payload: driveOptions }),

    onedriveExchangeCodeForTokens: (tokenOptions) =>
      invoke<BridgeResult<'onedriveExchangeCodeForTokens'>>('onedrive_oauth_exchange', { payload: tokenOptions }),
    onedriveRefreshAccessToken: (tokenOptions) =>
      invoke<BridgeResult<'onedriveRefreshAccessToken'>>('onedrive_oauth_refresh', { payload: tokenOptions }),
    onedriveGetUserInfo: (userOptions) =>
      invoke<BridgeResult<'onedriveGetUserInfo'>>('onedrive_oauth_userinfo', { payload: userOptions }),
    onedriveFindSyncFile: (driveOptions) =>
      invoke<BridgeResult<'onedriveFindSyncFile'>>('onedrive_find_sync_file', { payload: driveOptions }),
    onedriveUploadSyncFile: (driveOptions) =>
      invoke<BridgeResult<'onedriveUploadSyncFile'>>('onedrive_upload_sync_file', { payload: driveOptions }),
    onedriveDownloadSyncFile: (driveOptions) =>
      invoke<BridgeResult<'onedriveDownloadSyncFile'>>('onedrive_download_sync_file', { payload: driveOptions }),
    onedriveDeleteSyncFile: (driveOptions) =>
      invoke<BridgeResult<'onedriveDeleteSyncFile'>>('onedrive_delete_sync_file', { payload: driveOptions }),

    // -----------------------------------------------------------------------
    // Clipboard / dialogs / opener (Tauri plugins; absent when not registered)
    // -----------------------------------------------------------------------
    readClipboardText: clipboard?.readText
      ? () => clipboard.readText!()
      : undefined,
    writeClipboardText: clipboard?.writeText
      ? async (text) => {
        try {
          await clipboard.writeText!(text);
          return true;
        } catch (error) {
          warn('clipboard write failed', error);
          return false;
        }
      }
      : undefined,

    selectDirectory: dialog?.open
      ? async (title, defaultPath) => firstPath(await dialog.open!({ directory: true, multiple: false, title, defaultPath }))
      : undefined,
    selectFile: dialog?.open
      ? async (title, defaultPath, filters) =>
        firstPath(await dialog.open!({ multiple: false, title, defaultPath, filters }))
      : undefined,
    showSaveDialog: dialog?.save
      ? async (defaultPath, filters) => (await dialog.save!({ defaultPath, filters })) ?? null
      : undefined,

    openExternal: opener?.openUrl
      ? (url) => opener.openUrl!(url)
      : undefined,
    openPath: opener?.openPath
      ? (path) => openerResult(() => opener.openPath!(path))
      : undefined,
    openWithSystemDefault: opener?.openPath
      ? (filePath) => openerResult(() => opener.openPath!(filePath))
      : undefined,

    // -----------------------------------------------------------------------
    // Windows: settings window, custom title-bar controls, native theme,
    // language and cross-window settings sync. Commands act on the calling
    // window. Tauri delivers events to every window, so the ones aimed at a
    // single window are filtered by label here.
    // -----------------------------------------------------------------------
    openSettingsWindow: () => invoke<boolean>('window_open_settings'),
    closeSettingsWindow: () => invoke<void>('window_close_settings').then(() => undefined),
    rendererReady: () => {
      fireAndForget('window_renderer_ready', invoke<void>('window_renderer_ready'));
    },
    windowMinimize: () => invoke<void>('window_minimize'),
    windowMaximize: () => invoke<boolean>('window_maximize'),
    windowClose: () => invoke<void>('window_close'),
    windowIsMaximized: () => invoke<boolean>('window_is_maximized'),
    windowIsFullscreen: () => invoke<boolean>('window_is_fullscreen'),
    windowFocus: () => invoke<boolean>('window_focus'),
    setWindowTitle: (title) => invoke<boolean>('window_set_title', { title }),
    onWindowFullScreenChanged: (cb) => {
      const label = currentWindowLabel();
      return hub.subscribe<FullscreenChangedEvent>(TAURI_EVENTS.windowFullscreenChanged, (event) => {
        if (event?.label === label) cb(event.fullscreen === true);
      });
    },
    openMainWindow: async () => ({ success: await invoke<boolean>('window_open_main') }),
    quitApp: async () => {
      await invoke<void>('app_quit');
      return { success: true };
    },
    setTheme: (theme) => invoke<boolean>('app_set_theme', { theme }),
    setBackgroundColor: (color) => invoke<boolean>('app_set_background_color', { color }),
    setLanguage: (language) => invoke<boolean>('app_set_language', { language }),
    onLanguageChanged: (cb) => hub.subscribe<string>(TAURI_EVENTS.languageChanged, (language) => {
      if (typeof language === 'string' && language) cb(language);
    }),
    notifySettingsChanged: (payload) => {
      fireAndForget('app_broadcast_settings_changed', invoke<void>('app_broadcast_settings_changed', { payload }));
    },
    onSettingsChanged: (cb) => {
      const label = currentWindowLabel();
      return hub.subscribe<SettingsChangedEvent>(TAURI_EVENTS.settingsChanged, (event) => {
        if (!event || event.source === label || !event.payload) return;
        cb(event.payload);
      });
    },

    // -----------------------------------------------------------------------
    // Local vault backups (Electron record format; payload encrypted with the
    // credential cipher instead of safeStorage)
    // -----------------------------------------------------------------------
    getVaultBackupCapabilities: () =>
      invoke<BridgeResult<'getVaultBackupCapabilities'>>('vault_backup_capabilities'),
    createVaultBackup: (payload) => invoke<BridgeResult<'createVaultBackup'>>('vault_backup_create', { payload }),
    listVaultBackups: () => invoke<BridgeResult<'listVaultBackups'>>('vault_backup_list'),
    readVaultBackup: (payload) => invoke<BridgeResult<'readVaultBackup'>>('vault_backup_read', { payload }),
    trimVaultBackups: (payload) => invoke<BridgeResult<'trimVaultBackups'>>('vault_backup_trim', { payload }),
    clearVaultBackups: () => invoke<BridgeResult<'clearVaultBackups'>>('vault_backup_clear'),
    openVaultBackupDir: () => invoke<BridgeResult<'openVaultBackupDir'>>('vault_backup_open_dir'),
    onVaultBackupsChanged: (handler) => hub.subscribe<unknown>(TAURI_EVENTS.vaultBackupsChanged, () => handler()),

    // -----------------------------------------------------------------------
    // Temp directory management (info / clear / open / custom root)
    // -----------------------------------------------------------------------
    getTempDirInfo: () => invoke<BridgeResult<'getTempDirInfo'>>('tempdir_info'),
    clearTempDir: () => invoke<BridgeResult<'clearTempDir'>>('tempdir_clear'),
    openTempDir: () => invoke<BridgeResult<'openTempDir'>>('tempdir_open'),
    chooseTempDir: dialog?.open
      ? async () => firstPath(await dialog.open!({ directory: true, multiple: false }))
      : undefined,
    setCustomTempDir: (dir) => invoke<BridgeResult<'setCustomTempDir'>>('tempdir_set_custom', { dir }),
    resetCustomTempDir: () => invoke<BridgeResult<'resetCustomTempDir'>>('tempdir_reset_custom'),

    // -----------------------------------------------------------------------
    // App-level HTTP proxy for backend HTTP calls (cloud sync, OAuth)
    // -----------------------------------------------------------------------
    setHttpNetworkProxy: (settings) => invoke<BridgeResult<'setHttpNetworkProxy'>>('app_set_http_proxy', { settings }),
    getHttpNetworkProxy: () => invoke<BridgeResult<'getHttpNetworkProxy'>>('app_get_http_proxy'),

    // TOTP preview for the host editor (same parser / error codes as
    // domain/totp.shared.cjs). Screen QR scanning is not ported.
    previewTotp: (payload) => invoke<BridgeResult<'previewTotp'>>('totp_preview', { payload }),

    // -----------------------------------------------------------------------
    // Crash logs / diagnostics (Rust panics and logDiagnostic entries)
    // -----------------------------------------------------------------------
    getCrashLogs: () => invoke<BridgeResult<'getCrashLogs'>>('crash_logs_list'),
    readCrashLog: (fileName) => invoke<BridgeResult<'readCrashLog'>>('crash_logs_read', { fileName }),
    clearCrashLogs: () => invoke<BridgeResult<'clearCrashLogs'>>('crash_logs_clear'),
    openCrashLogsDir: () => invoke<BridgeResult<'openCrashLogsDir'>>('crash_logs_open_dir'),
    logDiagnostic: (payload) => invoke<BridgeResult<'logDiagnostic'>>('app_log_diagnostic', { payload }),

    // -----------------------------------------------------------------------
    // Clipboard files / images (arboard; text uses the clipboard plugin)
    // -----------------------------------------------------------------------
    readClipboardFiles: () => invoke<BridgeResult<'readClipboardFiles'>>('clipboard_read_files'),
    readClipboardImage: () => invoke<BridgeResult<'readClipboardImage'>>('clipboard_read_image'),
    hasClipboardImage: () => invoke<boolean>('clipboard_has_image'),

    // -----------------------------------------------------------------------
    // Tray, tray panel, global hotkey, auto launch, system notifications
    // (`commands/{tray,hotkey,autostart,notification}.rs`). Tray / panel
    // actions are broadcast by Rust; only the main window acts on them
    // (`focusSession` names its target window). `openMainWindow` / `quitApp`
    // are in the Windows section above.
    // -----------------------------------------------------------------------
    registerGlobalHotkey: (hotkey) =>
      invoke<BridgeResult<'registerGlobalHotkey'>>('hotkey_register', { hotkey }),
    unregisterGlobalHotkey: () => invoke<BridgeResult<'unregisterGlobalHotkey'>>('hotkey_unregister'),
    getGlobalHotkeyStatus: () => invoke<BridgeResult<'getGlobalHotkeyStatus'>>('hotkey_status'),
    setCloseToTray: (enabled) =>
      invoke<BridgeResult<'setCloseToTray'>>('tray_set_close_to_tray', { enabled: enabled === true }),
    isCloseToTray: () => invoke<BridgeResult<'isCloseToTray'>>('tray_is_close_to_tray'),
    setShowTrayIcon: (enabled) =>
      invoke<BridgeResult<'setShowTrayIcon'>>('tray_set_show_icon', { enabled: enabled === true }),
    isShowTrayIcon: () => invoke<BridgeResult<'isShowTrayIcon'>>('tray_is_show_icon'),
    getAutoLaunch: () => invoke<BridgeResult<'getAutoLaunch'>>('autostart_get'),
    setAutoLaunch: (enabled) =>
      invoke<BridgeResult<'setAutoLaunch'>>('autostart_set', { enabled: enabled === true }),
    updateTrayMenuData: (data) =>
      invoke<BridgeResult<'updateTrayMenuData'>>('tray_update_menu_data', { payload: data ?? {} }),
    onTrayFocusSession: (cb) => {
      const label = currentWindowLabel();
      return hub.subscribe<TrayFocusSessionEvent>(TAURI_EVENTS.trayFocusSession, (event) => {
        if (event?.label === label && typeof event.sessionId === 'string') cb(event.sessionId);
      });
    },
    onTrayTogglePortForward: (cb) => {
      if (currentWindowLabel() !== MAIN_WINDOW_LABEL) return () => {};
      const offToggle = hub.subscribe<TrayTogglePortForwardEvent>(TAURI_EVENTS.trayTogglePortForward, (event) => {
        if (typeof event?.ruleId === 'string') cb(event.ruleId, event.start === true);
      });
      const offStart = hub.subscribe<string>(TAURI_EVENTS.trayPanelStartPortForward, (ruleId) => {
        if (typeof ruleId === 'string') cb(ruleId, true);
      });
      return () => {
        offToggle();
        offStart();
      };
    },
    onTrayPanelJumpToSession: (cb) => subscribeMainWindowString(TAURI_EVENTS.trayPanelJumpToSession, cb),
    onTrayPanelConnectToHost: (cb) => subscribeMainWindowString(TAURI_EVENTS.trayPanelConnectToHost, cb),
    onTrayPanelCloseSession: (cb) => subscribeMainWindowString(TAURI_EVENTS.trayPanelCloseSession, cb),
    hideTrayPanel: () => invoke<BridgeResult<'hideTrayPanel'>>('tray_panel_hide'),
    jumpToSessionFromTrayPanel: (sessionId) =>
      invoke<BridgeResult<'jumpToSessionFromTrayPanel'>>('tray_panel_jump_to_session', { sessionId }),
    connectToHostFromTrayPanel: (hostId) =>
      invoke<BridgeResult<'connectToHostFromTrayPanel'>>('tray_panel_connect_to_host', { hostId }),
    startPortForwardFromTrayPanel: (ruleId) =>
      invoke<BridgeResult<'startPortForwardFromTrayPanel'>>('tray_panel_start_port_forward', { ruleId }),
    closeSessionFromTrayPanel: (sessionId) =>
      invoke<BridgeResult<'closeSessionFromTrayPanel'>>('tray_panel_close_session', { sessionId }),
    onTrayPanelRefresh: (cb) => hub.subscribe<unknown>(TAURI_EVENTS.trayPanelRefresh, () => cb()),
    onTrayPanelMenuData: (cb) => {
      // Rust pushes the data when the panel opens, possibly before this
      // listener exists (Electron's preload replays its buffer for the same
      // reason): read the current data once unless a push already arrived.
      let pushed = false;
      const off = hub.subscribe<TrayMenuData>(TAURI_EVENTS.trayPanelMenuData, (data) => {
        pushed = true;
        if (data) cb(data);
      });
      invoke<TrayMenuData>('tray_get_menu_data').then(
        (data) => {
          if (!pushed && data) cb(data);
        },
        (error) => warn('tray_get_menu_data failed', error),
      );
      return off;
    },
    showSystemNotification: (payload) =>
      invoke<BridgeResult<'showSystemNotification'>>('notification_show', { payload: payload ?? {} }),

    // -----------------------------------------------------------------------
    // System manager, server stats, monitor and PTY children
    // (rust/apps/netcatty-desktop/src/commands/system.rs + monitor.rs, logic in
    // the netcatty-sysmgr crate). Inputs travel as the Electron IPC payload and
    // the replies are the Electron bridge objects verbatim, so no mapping here.
    // -----------------------------------------------------------------------
    getServerStats: (sessionId) =>
      invoke<BridgeResult<'getServerStats'>>('session_server_stats', { sessionId }),
    getSessionDistroInfo: (sessionId) =>
      invoke<BridgeResult<'getSessionDistroInfo'>>('session_distro_info', { sessionId }),
    readRemoteHistory: (sessionId, limit) =>
      invoke<BridgeResult<'readRemoteHistory'>>('session_read_remote_history', { sessionId, limit }),
    probeSystemCapabilities: (sessionId) =>
      invoke<BridgeResult<'probeSystemCapabilities'>>('system_probe_capabilities', { payload: { sessionId } }),
    listSystemProcesses: (sessionId) =>
      invoke<BridgeResult<'listSystemProcesses'>>('system_list_processes', { payload: { sessionId } }),
    signalSystemProcess: (options) =>
      invoke<BridgeResult<'signalSystemProcess'>>('system_signal_process', { payload: { ...options } }),
    setupOsc7Tracking: (sessionId, command) =>
      invoke<BridgeResult<'setupOsc7Tracking'>>('system_setup_osc7_tracking', { payload: { sessionId, command } }),
    listTmuxSessions: (sessionId) =>
      invoke<BridgeResult<'listTmuxSessions'>>('system_list_tmux_sessions', { payload: { sessionId } }),
    createTmuxSession: (options) =>
      invoke<BridgeResult<'createTmuxSession'>>('system_create_tmux_session', { payload: { ...options } }),
    listTmuxWindows: (options) =>
      invoke<BridgeResult<'listTmuxWindows'>>('system_list_tmux_windows', { payload: { ...options } }),
    listTmuxPanes: (options) =>
      invoke<BridgeResult<'listTmuxPanes'>>('system_list_tmux_panes', { payload: { ...options } }),
    listTmuxClients: (options) =>
      invoke<BridgeResult<'listTmuxClients'>>('system_list_tmux_clients', { payload: { ...options } }),
    tmuxAction: (options) =>
      invoke<BridgeResult<'tmuxAction'>>('system_tmux_action', { payload: { ...options } }),
    listDockerContainers: (sessionId, runtime) =>
      invoke<BridgeResult<'listDockerContainers'>>('system_list_docker_containers', { payload: { sessionId, runtime } }),
    listDockerImages: (sessionId, runtime) =>
      invoke<BridgeResult<'listDockerImages'>>('system_list_docker_images', { payload: { sessionId, runtime } }),
    getDockerStats: (options) =>
      invoke<BridgeResult<'getDockerStats'>>('system_docker_stats', { payload: { ...options } }),
    dockerInspect: (options) =>
      invoke<BridgeResult<'dockerInspect'>>('system_docker_inspect', { payload: { ...options } }),
    dockerImageInspect: (options) =>
      invoke<BridgeResult<'dockerImageInspect'>>('system_docker_image_inspect', { payload: { ...options } }),
    dockerAction: (options) =>
      invoke<BridgeResult<'dockerAction'>>('system_docker_action', { payload: { ...options } }),
    dockerImageAction: (options) =>
      invoke<BridgeResult<'dockerImageAction'>>('system_docker_image_action', { payload: { ...options } }),
    kubectl: (options) => invoke<BridgeResult<'kubectl'>>('system_kubectl', { payload: { ...options } }),
    listAccelerators: (sessionId) =>
      invoke<BridgeResult<'listAccelerators'>>('system_list_accelerators', { payload: { sessionId } }),
    listListeningPorts: (sessionId) =>
      invoke<BridgeResult<'listListeningPorts'>>('system_list_listening_ports', { payload: { sessionId } }),
    listSystemServices: (sessionId) =>
      invoke<BridgeResult<'listSystemServices'>>('system_list_services', { payload: { sessionId } }),
    systemServiceAction: (options) =>
      invoke<BridgeResult<'systemServiceAction'>>('system_service_action', { payload: { ...options } }),
    // Monitor panels are owned by the calling window (Electron: webContents).
    monitorUpdate: (panels) => invoke<BridgeResult<'monitorUpdate'>>('monitor_update', { panels }),
    monitorSnapshot: (cursor) => invoke<BridgeResult<'monitorSnapshot'>>('monitor_snapshot', { cursor }),
    monitorStopAll: () => invoke<void>('monitor_stop_all'),
    monitorRetry: (hostId) => invoke<void>('monitor_retry', { hostId }),
    // Local terminals only: direct children of the shell (busy check on close).
    ptyGetChildProcesses: (sessionId) =>
      invoke<BridgeResult<'ptyGetChildProcesses'>>('pty_child_processes', { sessionId }),

    // -----------------------------------------------------------------------
    // Session logs: export / auto-save / logs directory, manual recording and
    // automatic per-session logs. Save / folder dialogs run in Rust; a manual
    // log path never leaves Rust (the renderer only holds a selectionToken).
    // -----------------------------------------------------------------------
    exportSessionLog: (payload) => invoke<BridgeResult<'exportSessionLog'>>('session_log_export', { payload }),
    selectSessionLogsDir: () => invoke<BridgeResult<'selectSessionLogsDir'>>('session_log_select_dir'),
    autoSaveSessionLog: (payload) =>
      invoke<BridgeResult<'autoSaveSessionLog'>>('session_log_auto_save', { payload }),
    openSessionLogsDir: (directory) =>
      invoke<BridgeResult<'openSessionLogsDir'>>('session_log_open_dir', { directory }),
    clearSessionLogsDir: (directory) =>
      invoke<BridgeResult<'clearSessionLogsDir'>>('session_log_clear_dir', { directory }),
    chooseManualSessionLogPath: (payload) =>
      invoke<BridgeResult<'chooseManualSessionLogPath'>>('session_log_manual_choose_path', { payload }),
    startManualSessionLog: (payload) =>
      invoke<BridgeResult<'startManualSessionLog'>>('session_log_manual_start', { payload }),
    stopManualSessionLog: (payload) =>
      invoke<BridgeResult<'stopManualSessionLog'>>('session_log_manual_stop', { payload }),
    getManualSessionLogStatus: (payload) =>
      invoke<BridgeResult<'getManualSessionLogStatus'>>('session_log_manual_status', { payload }),
    prepareSessionLog: (payload) =>
      invoke<BridgeResult<'prepareSessionLog'>>('session_log_prepare', { payload: { sessionId: payload.sessionId } }),
    revealSessionLog: (payload) =>
      invoke<BridgeResult<'revealSessionLog'>>('session_log_reveal', { payload: { sessionId: payload.sessionId } }),

    // -----------------------------------------------------------------------
    // App
    // -----------------------------------------------------------------------
    getAppInfo: async () => ({
      name: 'Netcatty',
      version: await invoke<string>('app_get_version'),
      platform: detectPlatform(),
    }),
    getTempDirPath: () => invoke<string>('app_get_temp_dir_path'),

    // Auto-update + dirty-editor round trip (bridge/update.ts).
    ...createUpdateBridge({ hub }),
    // AI core (provider proxy, chat streaming, privacy, skills, sessions backup).
    ...createAiBridge({ hub }),
  };

  return bridge as NetcattyBridge;
}

/** App lock is not available in the Tauri build: always initialized and unlocked. */
const unlockedAppLockRuntimeState = (): BridgeResult<'getAppLockRuntimeState'> => {
  const now = Date.now();
  return {
    initialized: true,
    locked: false,
    reason: null,
    version: 0,
    lastLockedAt: null,
    lastUnlockedAt: now,
    lastActivityAt: now,
  };
};

const firstPath = (selection: string | string[] | null): string | null => {
  if (Array.isArray(selection)) return selection.length > 0 ? selection[0] : null;
  return selection ?? null;
};
