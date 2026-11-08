/**
 * Multi-window part of the Tauri `NetcattyBridge` adapter (Electron:
 * `windowManager/editorWindow.cjs`, `terminalPopupWindow.cjs`, the
 * `netcatty:window:*` preload API, the attach / snapshot handlers of
 * `terminalBridge.cjs`). Contract: `rust/docs/ipc-windows.md`.
 *
 * Electron delivers to one `webContents`; Tauri's default `listen()` hears
 * events targeted at *any* window, so this adapter listens through a hub
 * bound to the current window (`listenToCurrentWindow`): it receives
 * broadcasts and the events Rust addressed to this window only.
 *
 * Request / response pairs (`editorOpenTab` → `editorOpenTabResult`, …) are
 * answered with `windows_report(channel, payload)`; Rust only accepts the
 * reply of the window it asked.
 */
import { EventHub, currentWindowLabel, getTauriGlobal, invoke as invokeCommand } from '../tauriApi';

export const WINDOWS_EVENTS = {
  editorOpenTab: 'netcatty:window:editorOpenTab',
  editorActivateTab: 'netcatty:window:editorActivateTab',
  editorCloseTabs: 'netcatty:window:editorCloseTabs',
  editorSaveRequest: 'netcatty:window:editorSaveRequest',
  editorDockRequest: 'netcatty:window:editorDockRequest',
  editorDirtyChanged: 'netcatty:window:editorDirtyChanged',
  editorTabsClosed: 'netcatty:window:editorTabsClosed',
  editorRemapSession: 'netcatty:window:editorRemapSession',
  terminalPopupConfig: 'netcatty:window:terminalPopupConfig',
  terminalPopupPrepareClose: 'netcatty:terminal-popup:prepare-close',
  openSession: 'netcatty:window:openSession',
  snapshotRequest: 'netcatty:terminal:snapshot-request',
  applySnapshot: 'netcatty:terminal:apply-snapshot',
  windowShown: 'netcatty:window:shown',
  windowWillHide: 'netcatty:window:will-hide',
  windowFocusRequested: 'netcatty:window:focus-requested',
  windowCommandClose: 'netcatty:window:command-close',
  sessionOutputRoute: 'netcatty:window:session-output-route',
} as const;

/** Reply channels accepted by `windows_report`. */
export const WINDOWS_REPLY_CHANNELS = {
  editorOpenTabResult: 'netcatty:window:editorOpenTabResult',
  editorCloseTabsResult: 'netcatty:window:editorCloseTabsResult',
  editorSaveResult: 'netcatty:window:editorSaveResult',
  editorDockResult: 'netcatty:window:editorDockResult',
  snapshotResponse: 'netcatty:terminal:snapshot-response',
  applySnapshotResponse: 'netcatty:terminal:apply-snapshot-response',
} as const;

type WindowsBridgeKeys =
  | 'openEditorWindow'
  | 'focusEditorWindow'
  | 'closeEditorWindowTabs'
  | 'saveEditorWindowTab'
  | 'dockEditorWindowTab'
  | 'reportEditorWindowDirty'
  | 'reportEditorWindowTabsClosed'
  | 'remapEditorWindowSession'
  | 'onEditorWindowOpenTab'
  | 'onEditorWindowActivateTab'
  | 'onEditorWindowCloseTabs'
  | 'reportEditorWindowCloseTabsResult'
  | 'onEditorWindowRemapSession'
  | 'onEditorWindowSaveRequest'
  | 'reportEditorWindowSaveResult'
  | 'onEditorWindowDockRequest'
  | 'reportEditorWindowDockResult'
  | 'onEditorWindowDirtyChanged'
  | 'onEditorWindowTabsClosed'
  | 'openTerminalPopup'
  | 'onTerminalPopupConfig'
  | 'onTerminalPopupPrepareClose'
  | 'markAttachPopupClosePrepared'
  | 'openSessionInNewWindow'
  | 'onOpenSessionInNewWindow'
  | 'rebindTerminalSessionOutput'
  | 'restoreTerminalSessionOutput'
  | 'requestTerminalSessionSnapshot'
  | 'onTerminalSessionSnapshotRequest'
  | 'respondTerminalSessionSnapshot'
  | 'applyTerminalSessionSnapshot'
  | 'onTerminalSessionApplySnapshot'
  | 'onWindowShown'
  | 'onWindowWillHide'
  | 'onWindowFocusRequested'
  | 'onWindowCommandCloseRequested'
  | 'setWindowOpacity'
  | 'setWindowBackgroundBlur'
  | 'setTerminalKeyboardFocus';

export type WindowsBridge = Required<Pick<NetcattyBridge, WindowsBridgeKeys>>;

type Bridge = WindowsBridge;
type Result<K extends WindowsBridgeKeys> = Awaited<ReturnType<Bridge[K]>>;
type Payload<K extends WindowsBridgeKeys> = Parameters<Bridge[K]>[0];
type CallbackPayload<K extends WindowsBridgeKeys> = Parameters<Bridge[K]>[0] extends (payload: infer P) => unknown
  ? P
  : never;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

/**
 * `listen()` restricted to events broadcast to every window or addressed to
 * this one (`emit_to(label, …)` in Rust).
 */
export function listenToCurrentWindow<T>(event: string, cb: (payload: T) => void): Promise<() => void> {
  const eventApi = getTauriGlobal().event as {
    listen?: (
      event: string,
      handler: (evt: { payload: T }) => void,
      options?: { target?: { kind: string; label?: string } },
    ) => Promise<() => void>;
  } | undefined;
  if (!eventApi?.listen) return Promise.reject(new Error('Tauri event.listen is unavailable'));
  return eventApi.listen(event, (evt) => cb(evt.payload), {
    target: { kind: 'WebviewWindow', label: currentWindowLabel() },
  });
}

// ---------------------------------------------------------------------------
// Session output routing
// ---------------------------------------------------------------------------

interface RouteChange {
  sessionId: string;
  label: string | null;
  revision: number;
}

const toRouteChange = (value: unknown): RouteChange | null => {
  if (!isRecord(value) || typeof value.sessionId !== 'string' || !value.sessionId) return null;
  const revision = typeof value.revision === 'number' && Number.isFinite(value.revision) ? value.revision : 0;
  const label = typeof value.label === 'string' && value.label ? value.label : null;
  return { sessionId: value.sessionId, label, revision };
};

/**
 * Which window displays each session's output. Tauri broadcasts
 * `netcatty:data` to every window; output of a session displayed by another
 * window (started there, or moved to an attach popup) is dropped here, like
 * Electron's per-`webContents` output port. Unknown sessions are accepted.
 */
export class SessionOutputRoutes {
  private readonly routes = new Map<string, { label: string | null; revision: number }>();
  private readonly label: string;
  private readonly invoke: InvokeFn;
  private readonly onRoutedAway: (sessionId: string) => void;
  private readonly warn: (label: string, error: unknown) => void;

  constructor(options: {
    hub: EventHub;
    label?: string;
    invoke?: InvokeFn;
    /** Output of `sessionId` now belongs to another window (drop its backlog). */
    onRoutedAway?: (sessionId: string) => void;
    warn?: (label: string, error: unknown) => void;
  }) {
    this.label = options.label ?? currentWindowLabel();
    this.invoke = options.invoke ?? invokeCommand;
    this.onRoutedAway = options.onRoutedAway ?? (() => {});
    this.warn = options.warn ?? ((label, error) => console.warn(`[tauri] ${label} failed`, error));
    options.hub.subscribe<unknown>(WINDOWS_EVENTS.sessionOutputRoute, (payload) => {
      const change = toRouteChange(payload);
      if (change) this.apply(change);
    });
    this.invoke<{ routes?: unknown[] }>('windows_output_routes')
      .then((snapshot) => {
        for (const entry of Array.isArray(snapshot?.routes) ? snapshot.routes : []) {
          const change = toRouteChange(entry);
          if (change) this.apply(change);
        }
      })
      .catch((error: unknown) => this.warn('windows_output_routes', error));
  }

  /** Apply a backend change unless a newer one was already seen. */
  apply(change: RouteChange): void {
    const current = this.routes.get(change.sessionId);
    if (current && current.revision >= change.revision) return;
    this.routes.set(change.sessionId, { label: change.label, revision: change.revision });
    if (change.label && change.label !== this.label) this.onRoutedAway(change.sessionId);
  }

  /** This window now displays `sessionId` (attach rebind / restore result). */
  claimLocally(sessionId: string, label: string = this.label): void {
    const current = this.routes.get(sessionId);
    this.routes.set(sessionId, { label, revision: current?.revision ?? 0 });
  }

  accepts(sessionId: string): boolean {
    const route = this.routes.get(sessionId);
    return !route || route.label === null || route.label === this.label;
  }

  /** This window started `sessionId` (owner: closed with this window). */
  track(sessionId: string): void {
    if (!sessionId) return;
    this.invoke<void>('windows_track_session', { sessionId })
      .catch((error: unknown) => this.warn('windows_track_session', error));
  }

  forget(sessionId: string): void {
    this.routes.delete(sessionId);
  }
}

// ---------------------------------------------------------------------------
// Bridge
// ---------------------------------------------------------------------------

export interface WindowsBridgeDeps {
  /** Hub bound to the current window (see `listenToCurrentWindow`). */
  hub: EventHub;
  routes?: SessionOutputRoutes;
  /** Injected for tests; defaults to the Tauri `invoke` wrapper. */
  invoke?: InvokeFn;
  label?: string;
  warn?: (label: string, error: unknown) => void;
}

const stringOrNullish = (value: unknown): string | null | undefined =>
  value === null ? null : typeof value === 'string' ? value : undefined;

const boolOrUndefined = (value: unknown): boolean | undefined =>
  typeof value === 'boolean' ? value : undefined;

export function createWindowsBridge(deps: WindowsBridgeDeps): WindowsBridge {
  const { hub } = deps;
  const invoke = deps.invoke ?? invokeCommand;
  const label = deps.label ?? currentWindowLabel();
  const warn = deps.warn ?? ((name, error) => console.warn(`[tauri] ${name} failed`, error));
  const fireAndForget = (name: string, promise: Promise<unknown>): void => {
    promise.catch((error: unknown) => warn(name, error));
  };
  const report = (channel: string, payload: unknown): void => {
    fireAndForget('windows_report', invoke<boolean>('windows_report', { channel, payload }));
  };
  const on = <T>(event: string, cb: (payload: T) => void): (() => void) =>
    hub.subscribe<T>(event, (payload) => cb(payload));
  const onSignal = (event: string, cb: () => void): (() => void) => hub.subscribe(event, () => cb());

  // Editor window: open-tab payloads arriving while no receiver is mounted
  // are buffered (Electron preload `editorOpenTabState`).
  type OpenTabPayload = CallbackPayload<'onEditorWindowOpenTab'> & { requestId?: string };
  const openTab = {
    pending: [] as OpenTabPayload[],
    listeners: new Set<(payload: OpenTabPayload) => void>(),
    subscribed: false,
  };
  const deliverOpenTab = (payload: OpenTabPayload): void => {
    let error: string | undefined;
    for (const cb of Array.from(openTab.listeners)) {
      try {
        cb(payload);
      } catch (err) {
        error = err instanceof Error ? err.message : 'Failed to open editor tab';
      }
    }
    report(
      WINDOWS_REPLY_CHANNELS.editorOpenTabResult,
      error ? { requestId: payload?.requestId, ok: false, error } : { requestId: payload?.requestId, ok: true },
    );
  };

  // Terminal popup config: pulled once, replayed to remounted listeners.
  type PopupConfig = CallbackPayload<'onTerminalPopupConfig'>;
  const popupConfig = {
    last: null as PopupConfig | null,
    listeners: new Set<(payload: PopupConfig) => void>(),
    requested: false,
  };
  const deliverPopupConfig = (payload: PopupConfig): void => {
    popupConfig.last = payload;
    for (const cb of Array.from(popupConfig.listeners)) {
      try {
        cb(payload);
      } catch (error) {
        warn('terminal popup config callback', error);
      }
    }
  };

  // Session window: the duplicated tab is taken once and held until a
  // listener is mounted.
  type OpenSessionPayload = CallbackPayload<'onOpenSessionInNewWindow'>;
  const openSession = {
    pending: null as OpenSessionPayload | null,
    listeners: new Set<(payload: OpenSessionPayload) => void>(),
    requested: false,
  };
  const deliverOpenSession = (payload: OpenSessionPayload): void => {
    if (openSession.listeners.size === 0) {
      openSession.pending = payload;
      return;
    }
    for (const cb of Array.from(openSession.listeners)) cb(payload);
  };

  return {
    // -------------------------------------------------------------------
    // Detached editor window
    // -------------------------------------------------------------------
    openEditorWindow: (payload) =>
      invoke<Result<'openEditorWindow'>>('windows_open_editor', { payload }),
    focusEditorWindow: (editorId) =>
      invoke<Result<'focusEditorWindow'>>('windows_focus_editor', { editorId }),
    closeEditorWindowTabs: (payload) =>
      invoke<Result<'closeEditorWindowTabs'>>('windows_close_editor_tabs', { payload }),
    saveEditorWindowTab: (payload) =>
      invoke<Result<'saveEditorWindowTab'>>('windows_save_editor_tab', { payload }),
    dockEditorWindowTab: (payload) =>
      invoke<Result<'dockEditorWindowTab'>>('windows_dock_editor_tab', { payload }),
    reportEditorWindowDirty: (payload) => {
      fireAndForget('windows_report_editor_dirty', invoke<void>('windows_report_editor_dirty', { payload }));
    },
    reportEditorWindowTabsClosed: (payload) => {
      fireAndForget(
        'windows_report_editor_tabs_closed',
        invoke<void>('windows_report_editor_tabs_closed', { payload }),
      );
    },
    remapEditorWindowSession: (payload) => {
      fireAndForget('windows_remap_editor_session', invoke<void>('windows_remap_editor_session', { payload }));
    },
    onEditorWindowOpenTab: (cb) => {
      const receive = cb as (payload: OpenTabPayload) => void;
      openTab.listeners.add(receive);
      for (const payload of openTab.pending.splice(0)) deliverOpenTab(payload);
      const ready = (): void => {
        fireAndForget('windows_editor_ready', invoke<void>('windows_editor_ready'));
      };
      if (!openTab.subscribed) {
        openTab.subscribed = true;
        hub.subscribe<OpenTabPayload>(WINDOWS_EVENTS.editorOpenTab, (payload) => {
          if (openTab.listeners.size === 0) {
            openTab.pending.push(payload);
            return;
          }
          deliverOpenTab(payload);
        });
      }
      // Tell Rust the receiver exists only once the Tauri listener is live.
      void hub.ensure(WINDOWS_EVENTS.editorOpenTab).then(ready);
      return () => {
        openTab.listeners.delete(receive);
      };
    },
    onEditorWindowActivateTab: (cb) => on(WINDOWS_EVENTS.editorActivateTab, cb),
    onEditorWindowCloseTabs: (cb) => on(WINDOWS_EVENTS.editorCloseTabs, cb),
    reportEditorWindowCloseTabsResult: (payload) => report(WINDOWS_REPLY_CHANNELS.editorCloseTabsResult, payload),
    onEditorWindowRemapSession: (cb) => on(WINDOWS_EVENTS.editorRemapSession, cb),
    onEditorWindowSaveRequest: (cb) => on(WINDOWS_EVENTS.editorSaveRequest, cb),
    reportEditorWindowSaveResult: (payload) => report(WINDOWS_REPLY_CHANNELS.editorSaveResult, payload),
    onEditorWindowDockRequest: (cb) => on(WINDOWS_EVENTS.editorDockRequest, cb),
    reportEditorWindowDockResult: (payload) => report(WINDOWS_REPLY_CHANNELS.editorDockResult, payload),
    onEditorWindowDirtyChanged: (cb) => on(WINDOWS_EVENTS.editorDirtyChanged, cb),
    onEditorWindowTabsClosed: (cb) => on(WINDOWS_EVENTS.editorTabsClosed, cb),

    // -------------------------------------------------------------------
    // Terminal popups and session windows
    // -------------------------------------------------------------------
    openTerminalPopup: (payload) =>
      invoke<Result<'openTerminalPopup'>>('windows_open_terminal_popup', { payload }),
    onTerminalPopupConfig: (cb) => {
      popupConfig.listeners.add(cb);
      const replay = popupConfig.last;
      if (replay) {
        queueMicrotask(() => {
          if (!popupConfig.listeners.has(cb)) return;
          try {
            cb(replay);
          } catch (error) {
            warn('terminal popup config callback', error);
          }
        });
      } else if (!popupConfig.requested) {
        popupConfig.requested = true;
        hub.subscribe<PopupConfig>(WINDOWS_EVENTS.terminalPopupConfig, (payload) => {
          if (isRecord(payload)) deliverPopupConfig(payload);
        });
        invoke<PopupConfig | null>('windows_terminal_popup_config')
          .then((payload) => {
            if (isRecord(payload) && !popupConfig.last) deliverPopupConfig(payload);
          })
          .catch((error: unknown) => warn('windows_terminal_popup_config', error));
      }
      return () => {
        popupConfig.listeners.delete(cb);
      };
    },
    onTerminalPopupPrepareClose: (cb) => on(WINDOWS_EVENTS.terminalPopupPrepareClose, cb),
    markAttachPopupClosePrepared: (sessionId, authorization) =>
      invoke<Result<'markAttachPopupClosePrepared'>>('windows_mark_attach_close_prepared', {
        sessionId,
        authorization,
      }),
    openSessionInNewWindow: (payload) =>
      invoke<Result<'openSessionInNewWindow'>>('windows_open_session', { payload }),
    onOpenSessionInNewWindow: (cb) => {
      openSession.listeners.add(cb);
      if (openSession.pending) {
        const payload = openSession.pending;
        openSession.pending = null;
        cb(payload);
      } else if (!openSession.requested) {
        openSession.requested = true;
        invoke<OpenSessionPayload | null>('windows_take_open_session')
          .then((payload) => {
            if (isRecord(payload)) deliverOpenSession(payload);
          })
          .catch((error: unknown) => warn('windows_take_open_session', error));
      }
      return () => {
        openSession.listeners.delete(cb);
      };
    },

    // -------------------------------------------------------------------
    // Attach popups: snapshot hand-over and output rebinding
    // -------------------------------------------------------------------
    rebindTerminalSessionOutput: async (sessionId, authorization) => {
      const result = await invoke<Result<'rebindTerminalSessionOutput'>>('windows_rebind_output', {
        sessionId,
        authorization,
      });
      // The route broadcast may land after this reply: claim the display now
      // so the first live bytes are not dropped.
      if (result?.success) deps.routes?.claimLocally(sessionId, label);
      return result;
    },
    restoreTerminalSessionOutput: async (sessionId, webContentsId, authorization) => {
      const result = await invoke<Result<'restoreTerminalSessionOutput'>>('windows_restore_output', {
        sessionId,
        webContentsId: typeof webContentsId === 'number' ? webContentsId : null,
        authorization,
      });
      if (result?.success && result.restored) deps.routes?.claimLocally(sessionId, 'main');
      return result;
    },
    requestTerminalSessionSnapshot: (sessionId, authorization) =>
      invoke<Result<'requestTerminalSessionSnapshot'>>('windows_request_snapshot', { sessionId, authorization }),
    onTerminalSessionSnapshotRequest: (cb) => on<CallbackPayload<'onTerminalSessionSnapshotRequest'>>(
      WINDOWS_EVENTS.snapshotRequest,
      (payload) => {
        try {
          cb(payload);
        } catch {
          // Provider failures must not break the request; Rust times out.
        }
      },
    ),
    respondTerminalSessionSnapshot: (
      requestId,
      snapshot,
      kittyKeyboardModeState,
      kittyKeyboardProtocolEnabled,
      passwordPromptActive,
      cwd,
      title,
      perCharacterInput,
    ) => {
      report(WINDOWS_REPLY_CHANNELS.snapshotResponse, {
        requestId,
        snapshot: typeof snapshot === 'string' ? snapshot : '',
        perCharacterInput: boolOrUndefined(perCharacterInput),
        kittyKeyboardModeState: isRecord(kittyKeyboardModeState) ? kittyKeyboardModeState : undefined,
        kittyKeyboardProtocolEnabled: boolOrUndefined(kittyKeyboardProtocolEnabled),
        passwordPromptActive: boolOrUndefined(passwordPromptActive),
        cwd: stringOrNullish(cwd),
        title: stringOrNullish(title),
      });
    },
    applyTerminalSessionSnapshot: (sessionId, snapshot, context, authorization) =>
      invoke<Result<'applyTerminalSessionSnapshot'>>('windows_apply_snapshot', {
        payload: {
          sessionId,
          snapshot: typeof snapshot === 'string' ? snapshot : '',
          contextSnapshot: typeof context?.contextSnapshot === 'string' ? context.contextSnapshot : '',
          contextViewportSnapshot: typeof context?.contextViewportSnapshot === 'string'
            ? context.contextViewportSnapshot
            : '',
          contextScrollbackSnapshot: typeof context?.contextScrollbackSnapshot === 'string'
            ? context.contextScrollbackSnapshot
            : '',
          alternateScreen: context?.alternateScreen === true,
          perCharacterInput: boolOrUndefined(context?.perCharacterInput),
          kittyKeyboardModeState: isRecord(context?.kittyKeyboardModeState) ? context.kittyKeyboardModeState : undefined,
          kittyKeyboardProtocolEnabled: boolOrUndefined(context?.kittyKeyboardProtocolEnabled),
          passwordPromptActive: boolOrUndefined(context?.passwordPromptActive),
          cwd: stringOrNullish(context?.cwd),
          title: stringOrNullish(context?.title),
          authorization,
        },
      }),
    onTerminalSessionApplySnapshot: (cb) => on<CallbackPayload<'onTerminalSessionApplySnapshot'> & { requestId?: string }>(
      WINDOWS_EVENTS.applySnapshot,
      (payload) => {
        Promise.resolve()
          .then(() => cb(payload))
          .then(
            (handled) => {
              if (handled !== true) return;
              report(WINDOWS_REPLY_CHANNELS.applySnapshotResponse, { requestId: payload?.requestId, success: true });
            },
            (error: unknown) => report(WINDOWS_REPLY_CHANNELS.applySnapshotResponse, {
              requestId: payload?.requestId,
              success: false,
              error: error instanceof Error ? error.message : String(error),
            }),
          );
      },
    ),

    // -------------------------------------------------------------------
    // Window state and chrome
    // -------------------------------------------------------------------
    onWindowShown: (cb) => onSignal(WINDOWS_EVENTS.windowShown, cb),
    onWindowWillHide: (cb) => onSignal(WINDOWS_EVENTS.windowWillHide, cb),
    onWindowFocusRequested: (cb) => onSignal(WINDOWS_EVENTS.windowFocusRequested, cb),
    onWindowCommandCloseRequested: (cb) => onSignal(WINDOWS_EVENTS.windowCommandClose, cb),
    setWindowOpacity: (opacity: Payload<'setWindowOpacity'>) => {
      const value = Number(opacity);
      return invoke<boolean>('windows_set_opacity', { opacity: Number.isFinite(value) ? value : null });
    },
    setWindowBackgroundBlur: (enabled) =>
      invoke<boolean>('windows_set_background_blur', { enabled: enabled === true }),
    setTerminalKeyboardFocus: (focused) => {
      fireAndForget(
        'windows_set_terminal_keyboard_focus',
        invoke<void>('windows_set_terminal_keyboard_focus', { focused: focused === true }),
      );
    },
  };
}
