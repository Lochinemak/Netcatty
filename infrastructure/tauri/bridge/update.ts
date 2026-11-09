/**
 * Auto-update part of the Tauri `NetcattyBridge` adapter
 * (Electron: `autoUpdateBridge.cjs` + the `netcatty:update:*` preload API).
 *
 * Every method is one `invoke` of a `update_*` command and every listener a
 * subscription to the Electron channel name re-emitted by Rust; payload shapes
 * are the Electron ones, so `application/state/useUpdateCheck.ts` is unchanged.
 *
 * The dirty-editor round trip (`onCheckDirtyEditors` /
 * `reportDirtyEditorsResult`) lives here too: Rust asks the main window
 * about unsaved work before an update install (`app:query-dirty-editors`) and
 * the renderer answers with `app_report_dirty_editors`. The same pair serves a
 * future before-quit guard.
 */
import { EventHub, invoke as invokeCommand } from '../tauriApi';

export const UPDATE_EVENTS = {
  available: 'netcatty:update:update-available',
  notAvailable: 'netcatty:update:update-not-available',
  downloadProgress: 'netcatty:update:download-progress',
  downloaded: 'netcatty:update:downloaded',
  error: 'netcatty:update:error',
  needsSave: 'netcatty:update:needs-save',
  queryDirtyEditors: 'app:query-dirty-editors',
} as const;

type UpdateBridgeKeys =
  | 'checkForUpdate'
  | 'downloadUpdate'
  | 'installUpdate'
  | 'getUpdateStatus'
  | 'getAutoUpdate'
  | 'setAutoUpdate'
  | 'onUpdateAvailable'
  | 'onUpdateNotAvailable'
  | 'onUpdateDownloadProgress'
  | 'onUpdateDownloaded'
  | 'onUpdateError'
  | 'onUpdateNeedsSave'
  | 'onCheckDirtyEditors'
  | 'reportDirtyEditorsResult';

export type UpdateBridge = Required<Pick<NetcattyBridge, UpdateBridgeKeys>>;

type Result<K extends UpdateBridgeKeys> = Awaited<ReturnType<UpdateBridge[K]>>;

export interface UpdateBridgeDeps {
  hub: EventHub;
  /** Injected for tests; defaults to the Tauri `invoke` wrapper. */
  invoke?: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
  /** Where fire-and-forget failures are reported; defaults to `console.warn`. */
  warn?: (label: string, error: unknown) => void;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

/** `{ requestId, deadline }` as emitted by Rust; tolerate a missing deadline. */
export const toDirtyEditorsRequest = (payload: unknown): { requestId: string; deadline: number } | null => {
  if (!isRecord(payload) || typeof payload.requestId !== 'string' || !payload.requestId) return null;
  const deadline = typeof payload.deadline === 'number' && Number.isFinite(payload.deadline)
    ? payload.deadline
    : Date.now() + 5000;
  return { requestId: payload.requestId, deadline };
};

export function createUpdateBridge(deps: UpdateBridgeDeps): UpdateBridge {
  const { hub } = deps;
  const invoke = deps.invoke ?? invokeCommand;
  const warn = deps.warn ?? ((label, error) => console.warn(`[tauri] ${label} failed`, error));
  const fireAndForget = (label: string, promise: Promise<unknown>): void => {
    promise.catch((error: unknown) => warn(label, error));
  };

  return {
    checkForUpdate: () => invoke<Result<'checkForUpdate'>>('update_check'),
    downloadUpdate: () => invoke<Result<'downloadUpdate'>>('update_download'),
    // Electron returns nothing: install either quits the app, broadcasts
    // `needs-save`, or broadcasts an `error` event.
    installUpdate: () => {
      fireAndForget('update_install', invoke<void>('update_install'));
    },
    getUpdateStatus: () => invoke<Result<'getUpdateStatus'>>('update_get_status'),
    getAutoUpdate: () => invoke<Result<'getAutoUpdate'>>('update_get_auto_update'),
    setAutoUpdate: (enabled) =>
      invoke<Result<'setAutoUpdate'>>('update_set_auto_update', { enabled: enabled === true }),

    onUpdateAvailable: (cb) => hub.subscribe<Parameters<typeof cb>[0]>(UPDATE_EVENTS.available, (info) => {
      cb({
        version: typeof info?.version === 'string' ? info.version : '',
        releaseNotes: typeof info?.releaseNotes === 'string' ? info.releaseNotes : '',
        releaseDate: typeof info?.releaseDate === 'string' ? info.releaseDate : null,
      });
    }),
    onUpdateNotAvailable: (cb) => hub.subscribe(UPDATE_EVENTS.notAvailable, () => cb()),
    onUpdateDownloadProgress: (cb) =>
      hub.subscribe<Partial<Parameters<typeof cb>[0]> | undefined>(UPDATE_EVENTS.downloadProgress, (progress) => {
        cb({
          percent: Number(progress?.percent ?? 0),
          bytesPerSecond: Number(progress?.bytesPerSecond ?? 0),
          transferred: Number(progress?.transferred ?? 0),
          total: Number(progress?.total ?? 0),
        });
      }),
    onUpdateDownloaded: (cb) => hub.subscribe(UPDATE_EVENTS.downloaded, () => cb()),
    onUpdateError: (cb) => hub.subscribe<{ error?: unknown } | undefined>(UPDATE_EVENTS.error, (payload) => {
      cb({ error: typeof payload?.error === 'string' ? payload.error : 'Unknown update error' });
    }),
    onUpdateNeedsSave: (cb) => hub.subscribe(UPDATE_EVENTS.needsSave, () => cb()),

    onCheckDirtyEditors: (listener) => hub.subscribe<unknown>(UPDATE_EVENTS.queryDirtyEditors, (payload) => {
      const request = toDirtyEditorsRequest(payload);
      if (request) listener(request);
    }),
    reportDirtyEditorsResult: (hasDirty, reason, options) => {
      fireAndForget('app_report_dirty_editors', invoke<void>('app_report_dirty_editors', {
        payload: {
          requestId: options?.requestId,
          hasDirty: hasDirty === true,
          reason,
          pending: options?.pending === true,
        },
      }));
    },
  };
}
