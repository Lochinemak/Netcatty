/**
 * Terminal plumbing and autocomplete bridge methods on top of the Tauri
 * commands in `rust/docs/ipc-terminal.md`. Signatures are the Electron ones
 * (`electron/preload/api.cjs`, the `figSpecApi` of `electron/preload.cjs`).
 *
 * Electron-only mechanics and what replaces them here:
 *  - `onTerminalOutputDrainRequest` / `respondTerminalOutputDrain`: Electron's
 *    main process asks the renderer to drain its MessagePort output queue
 *    before a flow pause is confirmed. Tauri delivers output as ordinary
 *    events and `session_set_flow_paused` already resolves once the pump is
 *    paused, so no drain request is ever issued: the subscription is kept
 *    (and disposable) but never fires, and the response is a no-op.
 *  - `notifyTerminalSessionDisplayReady`: retries output routed to a not yet
 *    mounted window in Electron's multi-window port routing. Tauri emits to
 *    every window and the bridge keeps a replay backlog, so it is a no-op.
 *  - `clearSessionPtyBuffer`: node-pty's ConPTY `clear()`. portable-pty
 *    exposes no ConPTY handle to clear, and SSH / non-Windows sessions were a
 *    no-op in Electron too, so it is a no-op.
 *  - `clearTerminalOutputSessionState` is not a bridge method: Electron's
 *    preload clears its MCP marker filter when a session closes; the Tauri
 *    bridge does the same on `netcatty:exit` (`McpMarkerFilter.clear`).
 */

import type { EventHub } from '../tauriApi';
import { invoke as tauriInvoke } from '../tauriApi';

export const TERMINAL_EVENTS = {
  pasteWrite: 'netcatty:paste-write',
  connectionReuseFallback: 'netcatty:connection-reuse:fallback',
} as const;

export interface AutocompleteDirEntry {
  name: string;
  type: 'file' | 'directory' | 'symlink';
}

export interface AutocompleteDirResult {
  success: boolean;
  entries: AutocompleteDirEntry[];
  error?: string;
}

/** `figSpecApi` of the Electron preload (not part of `NetcattyBridge`). */
export interface FigSpecBridge {
  listFigSpecs(): Promise<string[]>;
  loadFigSpec(commandName: string): Promise<unknown>;
  listAutocompleteRemoteDir(
    sessionId: string,
    dirPath: string,
    foldersOnly?: boolean,
    filterPrefix?: string,
    limit?: number,
  ): Promise<AutocompleteDirResult>;
  listAutocompleteLocalDir(
    dirPath: string,
    foldersOnly?: boolean,
    filterPrefix?: string,
    limit?: number,
  ): Promise<AutocompleteDirResult>;
}

export type TerminalBridge = Pick<
  NetcattyBridge,
  | 'getWindowsPtyInfo'
  | 'clearSessionPtyBuffer'
  | 'onTerminalPasteWrite'
  | 'onTerminalOutputDrainRequest'
  | 'respondTerminalOutputDrain'
  | 'notifyTerminalSessionDisplayReady'
  | 'onConnectionReuseFallback'
> & FigSpecBridge;

type PasteWriteCallback = Parameters<NonNullable<NetcattyBridge['onTerminalPasteWrite']>>[0];
type PasteWritePayload = Parameters<PasteWriteCallback>[0];

export interface TerminalBridgeDeps {
  hub: EventHub;
  /** Injected for tests; defaults to the real `invoke`. */
  invoke?: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
  /** Evaluate a spec module's source and return its default export. */
  evaluateSpecModule?: (source: string) => Promise<unknown>;
  /** Whether to prefetch the Windows PTY info (defaults to a UA check). */
  isWindows?: boolean;
}

/**
 * Import an ES module from source through a blob URL and return its default
 * export (`mod.default?.default ?? mod.default`, as Electron's main process
 * resolved `import(specFile)`).
 */
export async function importSpecModule(source: string): Promise<unknown> {
  const url = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }));
  try {
    const mod = (await import(/* @vite-ignore */ url)) as { default?: unknown };
    const first = mod.default;
    if (first && typeof first === 'object' && 'default' in first) {
      return (first as { default?: unknown }).default ?? first;
    }
    return first ?? null;
  } finally {
    URL.revokeObjectURL(url);
  }
}

const detectWindows = (): boolean =>
  typeof navigator !== 'undefined' && /Windows/i.test(navigator.userAgent ?? '');

export function createTerminalBridge(deps: TerminalBridgeDeps): TerminalBridge {
  const { hub } = deps;
  const invoke = deps.invoke ?? tauriInvoke;
  const evaluate = deps.evaluateSpecModule ?? importSpecModule;

  void hub.ensure(TERMINAL_EVENTS.pasteWrite);
  void hub.ensure(TERMINAL_EVENTS.connectionReuseFallback);

  // `getWindowsPtyInfo` is synchronous; fetch the answer once up front.
  // Until it arrives `null` makes the renderer fall back to `conpty`, which
  // is also what the backend reports.
  let windowsPtyInfo: NetcattyWindowsPtyInfo | null = null;
  if (deps.isWindows ?? detectWindows()) {
    invoke<NetcattyWindowsPtyInfo | null>('terminal_windows_pty_info')
      .then((info) => { windowsPtyInfo = info ?? null; })
      .catch(() => undefined);
  }

  const listDir = async (cmd: string, payload: Record<string, unknown>): Promise<AutocompleteDirResult> => {
    try {
      return await invoke<AutocompleteDirResult>(cmd, { payload });
    } catch (error) {
      return { success: false, entries: [], error: error instanceof Error ? error.message : String(error) };
    }
  };

  return {
    getWindowsPtyInfo: () => windowsPtyInfo,
    clearSessionPtyBuffer: () => {},
    onTerminalPasteWrite: (cb) => hub.subscribe<PasteWritePayload>(TERMINAL_EVENTS.pasteWrite, (payload) => {
      if (payload && typeof payload.requestId === 'string') cb(payload);
    }),
    onTerminalOutputDrainRequest: () => () => {},
    respondTerminalOutputDrain: () => {},
    notifyTerminalSessionDisplayReady: () => {},
    onConnectionReuseFallback: (cb) =>
      hub.subscribe<{ sessionId: string; sourceSessionId?: string }>(
        TERMINAL_EVENTS.connectionReuseFallback,
        (payload) => {
          if (payload?.sessionId) cb(payload.sessionId, payload.sourceSessionId);
        },
      ),

    listFigSpecs: async () => {
      try {
        return await invoke<string[]>('figspec_list');
      } catch (error) {
        console.warn('[tauri] figspec_list failed', error);
        return [];
      }
    },
    loadFigSpec: async (commandName) => {
      try {
        const source = await invoke<string | null>('figspec_load', { commandName });
        if (!source) return null;
        const spec = await evaluate(source);
        // Same JSON round-trip as Electron's IPC: data only, no generators.
        return spec ? JSON.parse(JSON.stringify(spec)) : null;
      } catch (error) {
        console.warn('[tauri] failed to load fig spec', commandName, error);
        return null;
      }
    },
    listAutocompleteRemoteDir: (sessionId, dirPath, foldersOnly, filterPrefix, limit) =>
      listDir('autocomplete_remote_listdir', { sessionId, path: dirPath, foldersOnly, filterPrefix, limit }),
    listAutocompleteLocalDir: (dirPath, foldersOnly, filterPrefix, limit) =>
      listDir('autocomplete_local_listdir', { path: dirPath, foldersOnly, filterPrefix, limit }),
  };
}
