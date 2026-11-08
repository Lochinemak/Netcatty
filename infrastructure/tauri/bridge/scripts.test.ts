import assert from 'node:assert/strict';
import test from 'node:test';

import { EventHub } from '../tauriApi';
import { SCRIPT_EVENTS, createScriptsBridge } from './scripts';

interface InvokeRecord {
  cmd: string;
  args: Record<string, unknown> | undefined;
}

type HubCallback = (payload: unknown) => void;

/** A fake `invoke` + event hub: records calls, lets a test emit events. */
const setup = (responses: Record<string, unknown> = {}) => {
  const invokes: InvokeRecord[] = [];
  const listeners = new Map<string, Set<HubCallback>>();
  const listened: string[] = [];
  const hub = new EventHub({
    listen: async <T>(event: string, cb: (payload: T) => void) => {
      listened.push(event);
      let set = listeners.get(event);
      if (!set) {
        set = new Set();
        listeners.set(event, set);
      }
      set.add(cb as HubCallback);
      return () => set?.delete(cb as HubCallback);
    },
  });
  const invoke = async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
    invokes.push({ cmd, args });
    return responses[cmd] as T;
  };
  const bridge = createScriptsBridge({ hub, invoke });
  const emit = (event: string, payload: unknown) => {
    for (const cb of Array.from(listeners.get(event) ?? [])) cb(payload);
  };
  return { bridge, invokes, emit, listened };
};

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

test('script events are subscribed eagerly', async () => {
  const { listened } = setup();
  await flush();
  assert.deepEqual([...listened].sort(), Object.values(SCRIPT_EVENTS).sort());
});

test('scriptRun sends the params as payload and returns the run ids', async () => {
  const { bridge, invokes } = setup({ script_run: { runId: 'r1', runIds: ['r1'] } });
  const params = {
    runId: 'r1',
    returnWhenQueued: true,
    scriptId: 's',
    scriptLabel: 'Script',
    content: 'nct.log(1)',
    sessionId: 'sess',
    permissionMode: 'confirm' as const,
    sessionMeta: { connected: true, name: 'Prod' },
  };
  assert.deepEqual(await bridge.scriptRun(params), { runId: 'r1', runIds: ['r1'] });
  assert.deepEqual(invokes[0], { cmd: 'script_run', args: { payload: params } });
});

test('run control commands carry the run id', async () => {
  const { bridge, invokes } = setup({
    script_stop: { ok: true },
    script_pause: { ok: true },
    script_resume: { ok: false },
  });
  assert.deepEqual(await bridge.scriptStop('r1'), { ok: true });
  assert.deepEqual(await bridge.scriptPause('r1'), { ok: true });
  assert.deepEqual(await bridge.scriptResume('r2'), { ok: false });
  assert.deepEqual(invokes, [
    { cmd: 'script_stop', args: { runId: 'r1' } },
    { cmd: 'script_pause', args: { runId: 'r1' } },
    { cmd: 'script_resume', args: { runId: 'r2' } },
  ]);
});

test('scriptGetRuns filters by session only when one is given', async () => {
  const runs = [{ runId: 'r1', sessionId: 's1', status: 'running', startedAt: 1, logs: [] }];
  const { bridge, invokes } = setup({ script_get_runs: runs });
  assert.deepEqual(await bridge.scriptGetRuns(), runs);
  await bridge.scriptGetRuns('s1');
  assert.deepEqual(invokes.map((i) => i.args), [{}, { sessionId: 's1' }]);
});

test('dialog and snapshot responses travel as payload objects', async () => {
  const { bridge, invokes } = setup({
    script_dialog_response: { ok: true },
    script_screen_snapshot_response: { ok: true },
  });
  await bridge.scriptDialogResponse('d1', { env: 'prod' });
  await bridge.scriptDialogResponse('d2', undefined, true);
  const snapshot = { rows: 24, cols: 80, currentRow: 3, lines: ['a', 'b'] };
  await bridge.scriptScreenSnapshotResponse('q1', snapshot);
  assert.deepEqual(invokes, [
    { cmd: 'script_dialog_response', args: { payload: { requestId: 'd1', value: { env: 'prod' }, cancelled: undefined } } },
    { cmd: 'script_dialog_response', args: { payload: { requestId: 'd2', value: undefined, cancelled: true } } },
    { cmd: 'script_screen_snapshot_response', args: { payload: { requestId: 'q1', snapshot } } },
  ]);
});

test('recording commands map to the recording commands', async () => {
  const stopped = { steps: [{ type: 'send', value: 'ls' }], code: 'await main();' };
  const { bridge, invokes } = setup({
    script_recording_start: { ok: true },
    script_recording_stop: stopped,
    script_recording_append_step: { ok: true },
  });
  assert.deepEqual(await bridge.scriptRecordingStart('s1'), { ok: true });
  assert.deepEqual(await bridge.scriptRecordingAppendStep('s1', { type: 'send', value: 'ls' }), { ok: true });
  assert.deepEqual(await bridge.scriptRecordingStop('s1'), stopped);
  assert.deepEqual(invokes, [
    { cmd: 'script_recording_start', args: { sessionId: 's1' } },
    { cmd: 'script_recording_append_step', args: { payload: { sessionId: 's1', step: { type: 'send', value: 'ls' } } } },
    { cmd: 'script_recording_stop', args: { sessionId: 's1' } },
  ]);
});

test('event listeners receive the Electron payloads and unsubscribe synchronously', async () => {
  const { bridge, emit } = setup();
  await flush();
  const runs: unknown[] = [];
  const dialogs: unknown[] = [];
  const snapshots: unknown[] = [];
  const inputs: unknown[] = [];
  const offRuns = bridge.onScriptRunsUpdated((p) => runs.push(p));
  bridge.onScriptDialogRequest((p) => dialogs.push(p));
  bridge.onScriptScreenSnapshotRequest((p) => snapshots.push(p));
  const offInputs = bridge.onScriptSessionInput((p) => inputs.push(p));

  emit(SCRIPT_EVENTS.runsUpdated, { runs: [] });
  emit(SCRIPT_EVENTS.dialogRequest, { requestId: 'd', type: 'confirm', message: 'ok?' });
  emit(SCRIPT_EVENTS.screenSnapshotRequest, { requestId: 'q', sessionId: 's' });
  emit(SCRIPT_EVENTS.sessionInput, { sessionId: 's', data: 'ls' });
  offRuns();
  offInputs();
  emit(SCRIPT_EVENTS.runsUpdated, { runs: [1] });
  emit(SCRIPT_EVENTS.sessionInput, { sessionId: 's', data: 'pwd' });

  assert.deepEqual(runs, [{ runs: [] }]);
  assert.deepEqual(dialogs, [{ requestId: 'd', type: 'confirm', message: 'ok?' }]);
  assert.deepEqual(snapshots, [{ requestId: 'q', sessionId: 's' }]);
  assert.deepEqual(inputs, [{ sessionId: 's', data: 'ls' }]);
});
