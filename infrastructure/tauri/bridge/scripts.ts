/**
 * Script automation bridge methods (`types/global/netcatty-bridge-script.d.ts`)
 * on top of the Tauri commands in `rust/docs/ipc-scripts.md`. Signatures and
 * event payloads are the Electron ones (`electron/preload/api.cjs`), so the
 * renderer (`components/scripts/`, `application/state/*script*`) is unchanged.
 */

import type { EventHub } from '../tauriApi';
import { invoke as tauriInvoke } from '../tauriApi';

/** Event names (Electron's IPC channels). */
export const SCRIPT_EVENTS = {
  runsUpdated: 'netcatty:script:runs-updated',
  dialogRequest: 'netcatty:script:dialog-request',
  screenSnapshotRequest: 'netcatty:script:screen-snapshot-request',
  sessionInput: 'netcatty:script:session-input',
} as const;

export type ScriptBridge = Pick<
  NetcattyBridge,
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
  | 'onScriptSessionInput'
>;

type Result<K extends keyof ScriptBridge> = Awaited<ReturnType<ScriptBridge[K]>>;
type EventKey =
  | 'onScriptRunsUpdated'
  | 'onScriptDialogRequest'
  | 'onScriptScreenSnapshotRequest'
  | 'onScriptSessionInput';
type Payload<K extends EventKey> = Parameters<Parameters<ScriptBridge[K]>[0]>[0];

export interface ScriptsBridgeDeps {
  hub: EventHub;
  /** Injected for tests; defaults to the real `invoke`. */
  invoke?: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
}

export function createScriptsBridge(deps: ScriptsBridgeDeps): ScriptBridge {
  const { hub } = deps;
  const invoke = deps.invoke ?? tauriInvoke;

  // Subscribe eagerly: a dialog or snapshot request can arrive right after
  // a run starts, before a lazy `listen` registration would have finished.
  for (const event of Object.values(SCRIPT_EVENTS)) {
    void hub.ensure(event);
  }

  const on = <K extends EventKey>(event: string) =>
    (cb: (payload: Payload<K>) => void): (() => void) => hub.subscribe<Payload<K>>(event, cb);

  return {
    scriptRun: (params) => invoke<Result<'scriptRun'>>('script_run', { payload: { ...params } }),
    scriptStop: (runId) => invoke<Result<'scriptStop'>>('script_stop', { runId }),
    scriptPause: (runId) => invoke<Result<'scriptPause'>>('script_pause', { runId }),
    scriptResume: (runId) => invoke<Result<'scriptResume'>>('script_resume', { runId }),
    scriptGetRuns: (sessionId) =>
      invoke<Result<'scriptGetRuns'>>('script_get_runs', sessionId ? { sessionId } : {}),
    scriptDialogResponse: (requestId, value, cancelled) =>
      invoke<Result<'scriptDialogResponse'>>('script_dialog_response', {
        payload: { requestId, value, cancelled },
      }),
    scriptScreenSnapshotResponse: (requestId, snapshot) =>
      invoke<Result<'scriptScreenSnapshotResponse'>>('script_screen_snapshot_response', {
        payload: { requestId, snapshot },
      }),
    scriptRecordingStart: (sessionId) =>
      invoke<Result<'scriptRecordingStart'>>('script_recording_start', { sessionId }),
    scriptRecordingStop: (sessionId) =>
      invoke<Result<'scriptRecordingStop'>>('script_recording_stop', { sessionId }),
    scriptRecordingAppendStep: (sessionId, step) =>
      invoke<Result<'scriptRecordingAppendStep'>>('script_recording_append_step', {
        payload: { sessionId, step },
      }),
    onScriptRunsUpdated: on<'onScriptRunsUpdated'>(SCRIPT_EVENTS.runsUpdated),
    onScriptDialogRequest: on<'onScriptDialogRequest'>(SCRIPT_EVENTS.dialogRequest),
    onScriptScreenSnapshotRequest: on<'onScriptScreenSnapshotRequest'>(SCRIPT_EVENTS.screenSnapshotRequest),
    onScriptSessionInput: on<'onScriptSessionInput'>(SCRIPT_EVENTS.sessionInput),
  };
}
