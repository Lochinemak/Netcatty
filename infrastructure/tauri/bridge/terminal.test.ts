import assert from 'node:assert/strict';
import test from 'node:test';

import { EventHub } from '../tauriApi';
import { TERMINAL_EVENTS, createTerminalBridge } from './terminal';

interface InvokeRecord {
  cmd: string;
  args: Record<string, unknown> | undefined;
}

type HubCallback = (payload: unknown) => void;

const setup = (
  responses: Record<string, unknown> = {},
  options: { isWindows?: boolean; evaluate?: (source: string) => Promise<unknown>; failInvoke?: string } = {},
) => {
  const invokes: InvokeRecord[] = [];
  const listeners = new Map<string, Set<HubCallback>>();
  const hub = new EventHub({
    listen: async <T>(event: string, cb: (payload: T) => void) => {
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
  const bridge = createTerminalBridge({
    hub,
    invoke,
    isWindows: options.isWindows ?? false,
    evaluateSpecModule: options.evaluate,
  });
  const emit = (event: string, payload: unknown) => {
    for (const cb of Array.from(listeners.get(event) ?? [])) cb(payload);
  };
  return { bridge, invokes, emit };
};

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

test('Windows PTY info is prefetched once and returned synchronously', async () => {
  const { bridge, invokes } = setup(
    { terminal_windows_pty_info: { backend: 'conpty', buildNumber: 19045 } },
    { isWindows: true },
  );
  assert.equal(bridge.getWindowsPtyInfo!(), null);
  await flush();
  assert.deepEqual(bridge.getWindowsPtyInfo!(), { backend: 'conpty', buildNumber: 19045 });
  assert.deepEqual(invokes.map((i) => i.cmd), ['terminal_windows_pty_info']);

  const other = setup();
  await flush();
  assert.equal(other.bridge.getWindowsPtyInfo!(), null);
  assert.equal(other.invokes.length, 0);
});

test('paste receipts and connection-reuse fallbacks are forwarded', async () => {
  const { bridge, emit } = setup();
  await flush();
  const receipts: unknown[] = [];
  const fallbacks: unknown[] = [];
  const disposeReceipts = bridge.onTerminalPasteWrite!((r) => receipts.push(r));
  bridge.onConnectionReuseFallback!((sessionId, sourceSessionId) => fallbacks.push([sessionId, sourceSessionId]));
  emit(TERMINAL_EVENTS.pasteWrite, { sessionId: 's', requestId: 'p', index: 0 });
  emit(TERMINAL_EVENTS.pasteWrite, { sessionId: 's', requestId: 'p', done: true });
  emit(TERMINAL_EVENTS.connectionReuseFallback, { sessionId: 'new', sourceSessionId: 'old' });
  disposeReceipts();
  emit(TERMINAL_EVENTS.pasteWrite, { sessionId: 's', requestId: 'q', done: true });
  assert.deepEqual(receipts, [
    { sessionId: 's', requestId: 'p', index: 0 },
    { sessionId: 's', requestId: 'p', done: true },
  ]);
  assert.deepEqual(fallbacks, [['new', 'old']]);
});

test('Electron-only plumbing is a safe no-op', () => {
  const { bridge, invokes } = setup();
  bridge.clearSessionPtyBuffer!('s');
  bridge.respondTerminalOutputDrain!('r');
  bridge.notifyTerminalSessionDisplayReady!('s');
  const dispose = bridge.onTerminalOutputDrainRequest!('s', () => {
    throw new Error('never called');
  });
  assert.equal(typeof dispose, 'function');
  dispose();
  assert.equal(invokes.length, 0);
});

test('fig specs are listed, evaluated and JSON round-tripped', async () => {
  const evaluated: string[] = [];
  const { bridge, invokes } = setup(
    { figspec_list: ['git', 'yum'], figspec_load: 'export default { name: "git" }' },
    {
      evaluate: async (source) => {
        evaluated.push(source);
        return { name: 'git', generators: { script: () => 'x' }, subcommands: [{ name: 'add' }] };
      },
    },
  );
  assert.deepEqual(await bridge.listFigSpecs(), ['git', 'yum']);
  assert.deepEqual(await bridge.loadFigSpec('git'), { name: 'git', generators: {}, subcommands: [{ name: 'add' }] });
  assert.deepEqual(evaluated, ['export default { name: "git" }']);
  assert.deepEqual(invokes.map((i) => [i.cmd, i.args]), [
    ['figspec_list', undefined],
    ['figspec_load', { commandName: 'git' }],
  ]);
});

test('a missing or broken fig spec loads as null', async () => {
  const missing = setup({ figspec_load: null });
  assert.equal(await missing.bridge.loadFigSpec('nope'), null);
  const broken = setup({ figspec_load: 'syntax error(' }, {
    evaluate: async () => {
      throw new SyntaxError('bad');
    },
  });
  const warn = console.warn;
  console.warn = () => {};
  try {
    assert.equal(await broken.bridge.loadFigSpec('bad'), null);
    const failing = setup({}, { failInvoke: 'figspec_list' });
    assert.deepEqual(await failing.bridge.listFigSpecs(), []);
  } finally {
    console.warn = warn;
  }
});

test('directory listings for autocomplete', async () => {
  const entries = [{ name: 'src', type: 'directory' }];
  const { bridge, invokes } = setup({
    autocomplete_local_listdir: { success: true, entries },
    autocomplete_remote_listdir: { success: true, entries },
  });
  assert.deepEqual(await bridge.listAutocompleteLocalDir('~/p', true, 's', 20), { success: true, entries });
  assert.deepEqual(await bridge.listAutocompleteRemoteDir('sess', '/srv', false, '', 100), { success: true, entries });
  assert.deepEqual(invokes.map((i) => [i.cmd, i.args]), [
    ['autocomplete_local_listdir', { payload: { path: '~/p', foldersOnly: true, filterPrefix: 's', limit: 20 } }],
    ['autocomplete_remote_listdir', {
      payload: { sessionId: 'sess', path: '/srv', foldersOnly: false, filterPrefix: '', limit: 100 },
    }],
  ]);
  const failing = setup({}, { failInvoke: 'autocomplete_remote_listdir' });
  assert.deepEqual(await failing.bridge.listAutocompleteRemoteDir('s', '/', false), {
    success: false, entries: [], error: 'autocomplete_remote_listdir exploded',
  });
});
