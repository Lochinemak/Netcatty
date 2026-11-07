/**
 * Thin typed wrappers over the global Tauri 2 API (`window.__TAURI__`), plus a
 * small event hub that subscribes to each Tauri event once and fans out to
 * renderer callbacks.
 *
 * Transport conventions come from `rust/docs/ipc-contract.md`:
 *  - commands reject with `{ code, message }` → normalised into `TauriBridgeError`;
 *  - raw-body commands receive the bytes as the args value and metadata as
 *    percent-encoded `headers`.
 */

export type TauriErrorCode =
  | 'INVALID_ARGUMENT'
  | 'NOT_FOUND'
  | 'AUTH_FAILED'
  | 'HOST_KEY_REJECTED'
  | 'NETWORK'
  | 'TIMEOUT'
  | 'CANCELLED'
  | 'IO'
  | 'UNSUPPORTED'
  | 'INTERNAL'
  | (string & {});

export class TauriBridgeError extends Error {
  readonly code: TauriErrorCode;

  constructor(code: TauriErrorCode, message: string) {
    super(message);
    this.name = 'TauriBridgeError';
    this.code = code;
  }
}

export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

export function getTauriGlobal(): NetcattyTauriGlobal {
  const tauri = typeof window !== 'undefined' ? window.__TAURI__ : undefined;
  if (!tauri) {
    throw new TauriBridgeError('UNSUPPORTED', 'Tauri global API (window.__TAURI__) is unavailable');
  }
  return tauri;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

/** Turn whatever a rejected `invoke` produced into a `TauriBridgeError`. */
export function normalizeTauriError(error: unknown): TauriBridgeError {
  if (error instanceof TauriBridgeError) return error;
  if (error instanceof Error) {
    const code = isRecord(error) && typeof error.code === 'string' ? error.code : 'INTERNAL';
    const wrapped = new TauriBridgeError(code, error.message);
    wrapped.stack = error.stack;
    return wrapped;
  }
  if (isRecord(error)) {
    const code = typeof error.code === 'string' ? error.code : 'INTERNAL';
    const message = typeof error.message === 'string'
      ? error.message
      : (() => {
        try {
          return JSON.stringify(error);
        } catch {
          return String(error);
        }
      })();
    return new TauriBridgeError(code, message);
  }
  return new TauriBridgeError('INTERNAL', typeof error === 'string' ? error : String(error));
}

export async function invoke<T>(
  cmd: string,
  args?: Record<string, unknown>,
  options?: NetcattyTauriInvokeOptions,
): Promise<T> {
  const core = getTauriGlobal().core;
  if (!core?.invoke) {
    throw new TauriBridgeError('UNSUPPORTED', 'Tauri core.invoke is unavailable');
  }
  try {
    return await core.invoke<T>(cmd, args, options);
  } catch (error) {
    throw normalizeTauriError(error);
  }
}

/** Percent-encode header values so non-ASCII paths survive the HTTP-ish header transport. */
export function encodeInvokeHeaders(headers: Record<string, string | undefined>): Record<string, string> {
  const encoded: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    encoded[key] = encodeURIComponent(value);
  }
  return encoded;
}

/**
 * Invoke a *(raw body)* command: the bytes travel as the args value and the
 * metadata as encoded headers (`invoke("local_write_file", bytes, { headers: { path } })`).
 */
export async function invokeBinary<T = void>(
  cmd: string,
  bytes: ArrayBuffer | Uint8Array,
  headers: Record<string, string | undefined>,
): Promise<T> {
  const core = getTauriGlobal().core;
  if (!core?.invoke) {
    throw new TauriBridgeError('UNSUPPORTED', 'Tauri core.invoke is unavailable');
  }
  try {
    return await core.invoke<T>(cmd, bytes, { headers: encodeInvokeHeaders(headers) });
  } catch (error) {
    throw normalizeTauriError(error);
  }
}

/**
 * Create a backend → renderer channel for one command invocation. Pass the
 * returned object as a command argument; `onMessage` receives parsed JSON for
 * JSON messages and an `ArrayBuffer` for raw ones, in the order they were sent.
 */
export function createChannel<T>(onMessage: (message: T) => void): NetcattyTauriChannel<T> {
  const Channel = getTauriGlobal().core?.Channel;
  if (!Channel) {
    throw new TauriBridgeError('UNSUPPORTED', 'Tauri core.Channel is unavailable');
  }
  const channel = new Channel<T>();
  channel.onmessage = onMessage;
  return channel;
}

export async function listen<T>(event: string, cb: (payload: T) => void): Promise<() => void> {
  const eventApi = getTauriGlobal().event;
  if (!eventApi?.listen) {
    throw new TauriBridgeError('UNSUPPORTED', 'Tauri event.listen is unavailable');
  }
  return eventApi.listen<T>(event, (evt) => cb(evt.payload));
}

type HubListener = (payload: unknown) => void;

interface HubChannel {
  listeners: Set<HubListener>;
  /** Resolves once the Tauri-side subscription exists (or failed). */
  ready: Promise<void>;
}

/**
 * Subscribes to each Tauri event lazily and exactly once, then fans the payload
 * out to every registered callback. Unsubscribe functions are synchronous as
 * the `NetcattyBridge` contract demands; the underlying async `listen` promise is
 * buffered internally and the Tauri listener stays alive for the page lifetime
 * (events are cheap and re-subscribing would race with early emissions).
 */
export class EventHub {
  private readonly channels = new Map<string, HubChannel>();
  private readonly listenImpl: <T>(event: string, cb: (payload: T) => void) => Promise<() => void>;
  private readonly onError: (message: string, error: unknown) => void;

  constructor(options?: {
    listen?: <T>(event: string, cb: (payload: T) => void) => Promise<() => void>;
    onError?: (message: string, error: unknown) => void;
  }) {
    this.listenImpl = options?.listen ?? listen;
    this.onError = options?.onError ?? ((message, error) => console.error(message, error));
  }

  /** Make sure the Tauri listener for `event` exists (eager subscription). */
  ensure(event: string): Promise<void> {
    return this.channel(event).ready;
  }

  subscribe<T>(event: string, cb: (payload: T) => void): () => void {
    const channel = this.channel(event);
    const listener = cb as HubListener;
    channel.listeners.add(listener);
    return () => {
      channel.listeners.delete(listener);
    };
  }

  private channel(event: string): HubChannel {
    const existing = this.channels.get(event);
    if (existing) return existing;
    const listeners = new Set<HubListener>();
    const ready = this.listenImpl<unknown>(event, (payload) => {
      for (const listener of Array.from(listeners)) {
        try {
          listener(payload);
        } catch (error) {
          this.onError(`[tauri] ${event} listener failed`, error);
        }
      }
    })
      .then(() => undefined)
      .catch((error: unknown) => {
        this.onError(`[tauri] failed to subscribe to ${event}`, error);
      });
    const channel: HubChannel = { listeners, ready };
    this.channels.set(event, channel);
    return channel;
  }
}

/**
 * Per-session terminal output that arrived before a display listener attached.
 * Mirrors `electron/preload/terminalDataBacklog.cjs`: the newest `maxChars`
 * (JS string length, like the Electron flow-control accounting) are kept, the
 * backlog is handed over on the first `replayBacklog` subscription and dropped
 * when the session exits.
 */
export class SessionDataBacklog {
  private readonly pending = new Map<string, string>();
  private readonly maxChars: number;

  constructor(maxChars = 2 * 1024 * 1024) {
    this.maxChars = maxChars;
  }

  append(sessionId: string, data: string): void {
    if (!sessionId || !data) return;
    const next = (this.pending.get(sessionId) ?? '') + data;
    this.pending.set(
      sessionId,
      next.length <= this.maxChars ? next : next.slice(next.length - this.maxChars),
    );
  }

  take(sessionId: string): string {
    const data = this.pending.get(sessionId) ?? '';
    this.pending.delete(sessionId);
    return data;
  }

  clear(sessionId: string): void {
    this.pending.delete(sessionId);
  }

  size(sessionId: string): number {
    return this.pending.get(sessionId)?.length ?? 0;
  }
}
