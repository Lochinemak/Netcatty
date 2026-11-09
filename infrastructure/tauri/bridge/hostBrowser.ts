/**
 * Host browser part of the Tauri `NetcattyBridge` (Electron preload:
 * `electron/preload/api.cjs`, host-browser section). Commands and events are
 * specified in `rust/docs/ipc-hostbrowser.md`.
 *
 * Tauri delivers every event to every `listen()` subscriber, so the events
 * carry the window they are meant for and are filtered here:
 *  - `netcatty:host-browser:panel-event` → `ownerLabel` (stripped before the
 *    callback, so the renderer sees Electron's payload);
 *  - `netcatty:host-browser:request-panel` → `{ targetLabel, request }`.
 * Panel requests that arrive before the terminal layer subscribes are kept
 * and replayed to the first subscriber, like the Electron preload does.
 */

import { EventHub, currentWindowLabel, invoke as tauriInvoke } from '../tauriApi';

export const HOST_BROWSER_EVENTS = {
  panelEvent: 'netcatty:host-browser:panel-event',
  panelRequest: 'netcatty:host-browser:request-panel',
  bookmarksChanged: 'netcatty:host-browser:bookmarks-changed',
} as const;

type Method<K extends keyof NetcattyBridge> = NonNullable<NetcattyBridge[K]>;
type Result<K extends keyof NetcattyBridge> = Awaited<ReturnType<Method<K>>>;
type PanelRequest = Parameters<Parameters<Method<'onHostBrowserPanelRequest'>>[0]>[0];
type PanelEvent = Parameters<Parameters<Method<'onHostBrowserPanelEvent'>>[0]>[0];

interface PanelRequestEnvelope { targetLabel?: string; request?: PanelRequest }

export interface HostBrowserBridgeDeps {
  hub: EventHub;
  /** Defaults to the real `invoke`; injected by tests. */
  invoke?: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
  /** Label of this window; defaults to the Tauri metadata. */
  windowLabel?: () => string;
}

export function createHostBrowserBridge(deps: HostBrowserBridgeDeps): Partial<NetcattyBridge> {
  const { hub } = deps;
  const invoke = deps.invoke ?? tauriInvoke;
  const label = deps.windowLabel ?? currentWindowLabel;

  // Panel requests are retained until the terminal layer subscribes.
  const requestListeners = new Set<(request: PanelRequest) => void>();
  const pendingRequests: PanelRequest[] = [];
  hub.subscribe<PanelRequestEnvelope>(HOST_BROWSER_EVENTS.panelRequest, (envelope) => {
    if (!envelope?.request || (envelope.targetLabel && envelope.targetLabel !== label())) return;
    if (!requestListeners.size) {
      pendingRequests.push(envelope.request);
      return;
    }
    for (const listener of Array.from(requestListeners)) listener(envelope.request);
  });

  return {
    openHostBrowser: (options) => invoke<Result<'openHostBrowser'>>('hostbrowser_open', { payload: { ...options } }),
    openHostBrowserUrl: (options) =>
      invoke<Result<'openHostBrowserUrl'>>('hostbrowser_panel_url', { payload: { ...options } }),
    focusHostBrowser: (hostId) => invoke<Result<'focusHostBrowser'>>('hostbrowser_focus', { hostId }),
    requestHostBrowserPanel: (request) =>
      invoke<Result<'requestHostBrowserPanel'>>('hostbrowser_request_panel', { payload: request }),
    onHostBrowserPanelRequest: (callback) => {
      requestListeners.add(callback);
      for (const request of pendingRequests.splice(0)) callback(request);
      return () => {
        requestListeners.delete(callback);
      };
    },
    setHostBrowserPanelLayout: (options) =>
      invoke<Result<'setHostBrowserPanelLayout'>>('hostbrowser_panel_layout', { payload: { ...options } }),
    closeHostBrowserPanel: (browserId) =>
      invoke<Result<'closeHostBrowserPanel'>>('hostbrowser_panel_close', { browserId }),
    getHostBrowserPanelState: (browserId) =>
      invoke<Result<'getHostBrowserPanelState'>>('hostbrowser_snapshot', { browserId }),
    commandHostBrowserPanel: (browserId, command) =>
      invoke<Result<'commandHostBrowserPanel'>>('hostbrowser_command', { browserId, command }),
    listHostBrowserPanelBookmarks: (browserId) =>
      invoke<Result<'listHostBrowserPanelBookmarks'>>('hostbrowser_bookmarks_list', { browserId }),
    saveHostBrowserPanelBookmark: (browserId, bookmark) =>
      invoke<Result<'saveHostBrowserPanelBookmark'>>('hostbrowser_bookmarks_upsert', { browserId, bookmark }),
    removeHostBrowserPanelBookmark: (browserId, id) =>
      invoke<Result<'removeHostBrowserPanelBookmark'>>('hostbrowser_bookmarks_remove', { browserId, id }),
    listHostBrowserPanelDownloads: (browserId) =>
      invoke<Result<'listHostBrowserPanelDownloads'>>('hostbrowser_downloads_list', { browserId }),
    commandHostBrowserPanelDownload: (browserId, command) =>
      invoke<Result<'commandHostBrowserPanelDownload'>>('hostbrowser_downloads_command', { browserId, command }),
    onHostBrowserPanelEvent: (callback) =>
      hub.subscribe<PanelEvent & { ownerLabel?: string }>(HOST_BROWSER_EVENTS.panelEvent, (event) => {
        if (!event || (event.ownerLabel && event.ownerLabel !== label())) return;
        const { ownerLabel: _ownerLabel, ...rest } = event;
        callback(rest as PanelEvent);
      }),
    getHostBrowserBookmarks: () => invoke<Result<'getHostBrowserBookmarks'>>('hostbrowser_bookmarks_get_all'),
    applyHostBrowserBookmarks: (items) =>
      invoke<Result<'applyHostBrowserBookmarks'>>('hostbrowser_bookmarks_apply', { items }),
    onHostBrowserBookmarksChanged: (callback) =>
      hub.subscribe<unknown>(HOST_BROWSER_EVENTS.bookmarksChanged, () => callback()),
  };
}
