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
  invoke,
  invokeBinary,
} from './tauriApi';
import { cancelStagedUpload, stageUploadFile } from './uploadStaging';

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

interface SessionDataEvent { sessionId: string; data: string }
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
        cb(event.data);
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

  const dialog = plugins.dialog;
  const clipboard = plugins.clipboardManager;
  const opener = plugins.opener;

  const openerResult = async (run: () => Promise<void>): Promise<{ success: boolean; error?: string }> => {
    try {
      await run();
      return { success: true };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) };
    }
  };

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
          lineDelayMs: Number.isFinite(lineDelayMs) && lineDelayMs > 0 ? lineDelayMs : undefined,
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
      fireAndForget('session_set_flow_paused', invoke<void>('session_set_flow_paused', { sessionId, paused }));
    },
    setSessionFlowPausedAndWait: async (sessionId, paused) => {
      try {
        await invoke<void>('session_set_flow_paused', { sessionId, paused });
        return { success: true };
      } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : String(error) };
      }
    },
    ackSessionFlow: (sessionId, bytes) => {
      fireAndForget('session_ack_flow', invoke<void>('session_ack_flow', { sessionId, bytes }));
    },
    closeSession: (sessionId) => invoke<void>('session_close', { sessionId }),

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
    // App
    // -----------------------------------------------------------------------
    getAppInfo: async () => ({
      name: 'Netcatty',
      version: await invoke<string>('app_get_version'),
      platform: detectPlatform(),
    }),
    getTempDirPath: () => invoke<string>('app_get_temp_dir_path'),
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
