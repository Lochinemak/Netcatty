import assert from 'node:assert/strict';
import test from 'node:test';

import { EventHub } from '../tauriApi';
import { ZMODEM_EVENTS, createZmodemBridge } from './zmodem';

interface InvokeRecord {
  cmd: string;
  args: Record<string, unknown> | undefined;
}

type HubCallback = (payload: unknown) => void;

const setup = (
  responses: Record<string, unknown> = {},
  options: { failInvoke?: string; staged?: string[] } = {},
) => {
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
    if (cmd === options.failInvoke) throw new Error(`${cmd} exploded`);
    return responses[cmd] as T;
  };
  const stageFile = async (file: File, transferId: string): Promise<string> => {
    options.staged?.push(`${transferId}:${file.name}:${file.size}`);
    return `/tmp/staged/${file.name}`;
  };
  const bridge = createZmodemBridge({ hub, invoke, stageFile });
  const emit = (event: string, payload: unknown) => {
    for (const cb of Array.from(listeners.get(event) ?? [])) cb(payload);
  };
  return { bridge, invokes, emit, listened };
};

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

test('zmodem events are subscribed eagerly', async () => {
  const { listened } = setup();
  await flush();
  assert.deepEqual([...listened].sort(), Object.values(ZMODEM_EVENTS).sort());
});

test('onZmodemEvent tags events with their type and filters by session', async () => {
  const { bridge, emit } = setup();
  await flush();
  const seen: unknown[] = [];
  const dispose = bridge.onZmodemEvent!('s1', (event) => seen.push(event));
  emit(ZMODEM_EVENTS.detect, { sessionId: 's1', transferType: 'download' });
  emit(ZMODEM_EVENTS.detect, { sessionId: 'other', transferType: 'upload' });
  emit(ZMODEM_EVENTS.progress, {
    sessionId: 's1', filename: 'a.bin', transferred: 5, total: 10, fileIndex: 0, fileCount: -1, transferType: 'download',
  });
  emit(ZMODEM_EVENTS.complete, { sessionId: 's1' });
  emit(ZMODEM_EVENTS.error, { sessionId: 's1', error: 'Transfer cancelled' });
  dispose();
  emit(ZMODEM_EVENTS.complete, { sessionId: 's1' });
  assert.deepEqual(seen, [
    { sessionId: 's1', transferType: 'download', type: 'detect' },
    {
      sessionId: 's1', filename: 'a.bin', transferred: 5, total: 10, fileIndex: 0, fileCount: -1,
      transferType: 'download', type: 'progress',
    },
    { sessionId: 's1', type: 'complete' },
    { sessionId: 's1', error: 'Transfer cancelled', type: 'error' },
  ]);
});

test('cancel and overwrite answers go to their commands', async () => {
  const { bridge, invokes, emit } = setup();
  await flush();
  bridge.cancelZmodem!('s1', { interrupt: false });
  bridge.cancelZmodem!('s2');
  const requests: unknown[] = [];
  bridge.onZmodemOverwriteRequest!('s1', (p) => requests.push(p));
  emit(ZMODEM_EVENTS.overwriteRequest, { sessionId: 's1', requestId: 'r1', filename: 'f.txt' });
  emit(ZMODEM_EVENTS.overwriteRequest, { sessionId: 's9', requestId: 'r9', filename: 'g.txt' });
  bridge.respondZmodemOverwrite!({ requestId: 'r1', action: 'overwrite', applyToRest: true });
  await flush();
  assert.deepEqual(requests, [{ sessionId: 's1', requestId: 'r1', filename: 'f.txt' }]);
  assert.deepEqual(invokes, [
    { cmd: 'zmodem_cancel', args: { sessionId: 's1', options: { interrupt: false } } },
    { cmd: 'zmodem_cancel', args: { sessionId: 's2', options: null } },
    {
      cmd: 'zmodem_overwrite_response',
      args: { payload: { requestId: 'r1', action: 'overwrite', applyToRest: true } },
    },
  ]);
});

test('drag-drop upload stages in-memory files and passes paths', async () => {
  const staged: string[] = [];
  const { bridge, invokes } = setup({ zmodem_drag_drop_upload: { success: true } }, { staged });
  const data = new TextEncoder().encode('hello').buffer;
  const result = await bridge.startZmodemDragDropUpload!('s1', [
    { path: '/home/me/a.txt', name: 'a.txt', remoteName: 'a.txt' },
    { name: 'b.txt', remoteName: 'renamed.txt', data },
    { name: '', remoteName: 'skipped' },
  ], 'rz -y\r');
  assert.deepEqual(result, { success: true });
  assert.deepEqual(staged, ['zmodem-s1-1:b.txt:5']);
  assert.deepEqual(invokes, [{
    cmd: 'zmodem_drag_drop_upload',
    args: {
      payload: {
        sessionId: 's1',
        files: [
          { path: '/home/me/a.txt', remoteName: 'a.txt' },
          { path: '/tmp/staged/b.txt', remoteName: 'renamed.txt', temp: true },
        ],
        uploadCommand: 'rz -y\r',
      },
    },
  }]);
});

test('a failed drag-drop invoke reports the error and removes staged copies', async () => {
  const { bridge, invokes } = setup({}, { failInvoke: 'zmodem_drag_drop_upload' });
  const result = await bridge.startZmodemDragDropUpload!('s1', [
    { name: 'b.txt', remoteName: 'b.txt', data: new Uint8Array([1]).buffer },
  ]);
  await flush();
  assert.deepEqual(result, { success: false, error: 'zmodem_drag_drop_upload exploded' });
  assert.deepEqual(invokes.at(-1), { cmd: 'temp_delete_file', args: { filePath: '/tmp/staged/b.txt' } });
});

test('serial YMODEM commands pass payloads and turn rejections into results', async () => {
  const { bridge, invokes } = setup({
    serial_ymodem_send: { success: true, fileName: 'fw.bin', totalBytes: 3, writtenBytes: 3 },
  }, { failInvoke: 'serial_ymodem_receive' });
  assert.deepEqual(await bridge.sendSerialYmodem!('s1', '/fw.bin'), {
    success: true, fileName: 'fw.bin', totalBytes: 3, writtenBytes: 3,
  });
  assert.deepEqual(await bridge.receiveSerialYmodem!('s1', '/dl'), {
    success: false, error: 'serial_ymodem_receive exploded',
  });
  assert.deepEqual(invokes.map((i) => [i.cmd, i.args]), [
    ['serial_ymodem_send', { payload: { sessionId: 's1', filePath: '/fw.bin' } }],
    ['serial_ymodem_receive', { payload: { sessionId: 's1', destinationDir: '/dl' } }],
  ]);
});
