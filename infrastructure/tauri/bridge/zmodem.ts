/**
 * ZMODEM (`rz` / `sz`) and serial YMODEM bridge methods on top of the Tauri
 * commands in `rust/docs/ipc-zmodem.md`. Signatures and event payloads are
 * the Electron ones (`electron/preload/api.cjs`, `electron/preload.cjs`), so
 * `useZmodemTransfer`, `useTerminalDragDrop` and the serial YMODEM UI are
 * unchanged.
 */

import type { EventHub } from '../tauriApi';
import { invoke as tauriInvoke } from '../tauriApi';
import { stageUploadFile } from '../uploadStaging';

/** Event names (Electron's IPC channels). */
export const ZMODEM_EVENTS = {
  detect: 'netcatty:zmodem:detect',
  progress: 'netcatty:zmodem:progress',
  complete: 'netcatty:zmodem:complete',
  error: 'netcatty:zmodem:error',
  overwriteRequest: 'netcatty:zmodem:overwrite-request',
} as const;

export type ZmodemBridge = Pick<
  NetcattyBridge,
  | 'onZmodemEvent'
  | 'cancelZmodem'
  | 'startZmodemDragDropUpload'
  | 'onZmodemOverwriteRequest'
  | 'respondZmodemOverwrite'
  | 'sendSerialYmodem'
  | 'receiveSerialYmodem'
>;

type ZmodemEventCallback = Parameters<NonNullable<NetcattyBridge['onZmodemEvent']>>[1];
type ZmodemEvent = Parameters<ZmodemEventCallback>[0];
type OverwriteCallback = Parameters<NonNullable<NetcattyBridge['onZmodemOverwriteRequest']>>[1];
type OverwritePayload = Parameters<OverwriteCallback>[0];
type DragDropFiles = Parameters<NonNullable<NetcattyBridge['startZmodemDragDropUpload']>>[1];
type Result<K extends keyof ZmodemBridge> = Awaited<ReturnType<NonNullable<ZmodemBridge[K]>>>;

/** What the Rust command takes per file: a local path (staged copies are `temp`). */
interface DragDropWireFile {
  path: string;
  remoteName: string;
  temp?: boolean;
}

export interface ZmodemBridgeDeps {
  hub: EventHub;
  /** Injected for tests; defaults to the real `invoke`. */
  invoke?: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
  /** Injected for tests; copies an in-memory file to a temp path. */
  stageFile?: (file: File, transferId: string) => Promise<string>;
}

const errorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

export function createZmodemBridge(deps: ZmodemBridgeDeps): ZmodemBridge {
  const { hub } = deps;
  const invoke = deps.invoke ?? tauriInvoke;
  const stageFile = deps.stageFile ?? stageUploadFile;

  // Subscribe eagerly: `detect` follows the remote's `sz` / `rz` within
  // milliseconds, before a lazy `listen` registration would have finished.
  for (const event of Object.values(ZMODEM_EVENTS)) {
    void hub.ensure(event);
  }

  const typed: Array<[string, ZmodemEvent['type']]> = [
    [ZMODEM_EVENTS.detect, 'detect'],
    [ZMODEM_EVENTS.progress, 'progress'],
    [ZMODEM_EVENTS.complete, 'complete'],
    [ZMODEM_EVENTS.error, 'error'],
  ];

  const fireAndForget = (cmd: string, promise: Promise<unknown>): void => {
    promise.catch((error: unknown) => console.warn(`[tauri] ${cmd} failed`, error));
  };

  /** Paths for every dropped file; in-memory files are staged to temp copies. */
  const toWireFiles = async (sessionId: string, files: DragDropFiles): Promise<DragDropWireFile[]> => {
    const wire: DragDropWireFile[] = [];
    for (const file of files ?? []) {
      if (!file?.name) continue;
      const remoteName = file.remoteName || file.name;
      if (file.path) {
        wire.push({ path: file.path, remoteName });
      } else if (file.data) {
        const staged = await stageFile(new File([file.data], file.name), `zmodem-${sessionId}-${wire.length}`);
        wire.push({ path: staged, remoteName, temp: true });
      }
    }
    return wire;
  };

  return {
    onZmodemEvent: (sessionId, cb) => {
      const disposers = typed.map(([event, type]) =>
        hub.subscribe<Omit<ZmodemEvent, 'type'>>(event, (payload) => {
          if (payload?.sessionId !== sessionId) return;
          cb({ ...payload, type } as ZmodemEvent);
        }));
      return () => disposers.forEach((dispose) => dispose());
    },
    cancelZmodem: (sessionId, options) => {
      fireAndForget('zmodem_cancel', invoke<void>('zmodem_cancel', {
        sessionId,
        options: options ?? null,
      }));
    },
    startZmodemDragDropUpload: async (sessionId, files, uploadCommand) => {
      let wire: DragDropWireFile[] = [];
      try {
        wire = await toWireFiles(sessionId, files);
        return await invoke<Result<'startZmodemDragDropUpload'>>('zmodem_drag_drop_upload', {
          payload: { sessionId, files: wire, uploadCommand },
        });
      } catch (error) {
        // The backend removes staged copies itself once it saw them; a
        // failure before that leaves them to us.
        for (const file of wire) {
          if (file.temp) void invoke('temp_delete_file', { filePath: file.path }).catch(() => undefined);
        }
        return { success: false, error: errorMessage(error) };
      }
    },
    onZmodemOverwriteRequest: (sessionId, cb) =>
      hub.subscribe<OverwritePayload>(ZMODEM_EVENTS.overwriteRequest, (payload) => {
        if (payload?.sessionId === sessionId) cb(payload);
      }),
    respondZmodemOverwrite: (payload) => {
      fireAndForget('zmodem_overwrite_response', invoke<void>('zmodem_overwrite_response', {
        payload: {
          requestId: payload.requestId,
          action: payload.action,
          applyToRest: payload.applyToRest === true,
        },
      }));
    },
    sendSerialYmodem: async (sessionId, filePath) => {
      try {
        return await invoke<Result<'sendSerialYmodem'>>('serial_ymodem_send', {
          payload: { sessionId, filePath },
        });
      } catch (error) {
        return { success: false, error: errorMessage(error) };
      }
    },
    receiveSerialYmodem: async (sessionId, destinationDir) => {
      try {
        return await invoke<Result<'receiveSerialYmodem'>>('serial_ymodem_receive', {
          payload: { sessionId, destinationDir },
        });
      } catch (error) {
        return { success: false, error: errorMessage(error) };
      }
    },
  };
}
