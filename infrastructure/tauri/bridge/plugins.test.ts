import assert from 'node:assert/strict';
import test from 'node:test';

import { EventHub } from '../tauriApi';
import { PLUGIN_EVENTS, createPluginsBridge } from './plugins';
import { encodeRuntimeMessage, fromBase64, toBase64 } from './pluginRuntimeHost';

type Call = { cmd: string; args?: Record<string, unknown> };

function setup(responses: Record<string, unknown> = {}) {
  const calls: Call[] = [];
  const listeners = new Map<string, (payload: unknown) => void>();
  const hub = new EventHub({
    listen: async <T,>(event: string, cb: (payload: T) => void) => {
      listeners.set(event, cb as (payload: unknown) => void);
      return () => undefined;
    },
  });
  const invoke = async <T,>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
    calls.push({ cmd, args });
    const method = (args?.method as string) ?? cmd;
    return (responses[method] ?? null) as T;
  };
  const bridge = createPluginsBridge({ hub, invoke, runtimeHost: false }) as Record<string, (...args: unknown[]) => unknown>;
  return { bridge, calls, listeners };
}

test('management calls map onto plugin_call with Electron payloads', async () => {
  const { bridge, calls } = setup({ list: [{ id: 'com.netcatty.hello' }] });
  assert.deepEqual(await bridge.listPlugins(), [{ id: 'com.netcatty.hello' }]);
  await bridge.installPluginPackage('/tmp/a.ncpkg', { enable: true });
  await bridge.updatePluginSetting('p.id', 'p.id.s', 'v');
  await bridge.executePluginCommand('p.id.cmd', undefined, { a: 1 });
  const methods = calls.filter((c) => c.cmd === 'plugin_call').map((c) => [c.args?.method, c.args?.payload]);
  assert.deepEqual(methods.slice(-4), [
    ['list', null],
    ['install', { archivePath: '/tmp/a.ncpkg', enable: true }],
    ['update-setting', { pluginId: 'p.id', settingId: 'p.id.s', value: 'v' }],
    ['execute-command', { command: 'p.id.cmd', context: { a: 1 } }],
  ]);
});

test('binary fields cross IPC as base64', async () => {
  const { bridge, calls } = setup({ 'importer-select-file': { selectionToken: 't', fileName: 'a', sampleBase64: toBase64(new Uint8Array([1, 2, 3])) } });
  await bridge.writePluginConnection('s1', new Uint8Array([104, 105]));
  const write = calls.find((c) => c.args?.method === 'connection-write');
  assert.deepEqual(write?.args?.payload, { sessionId: 's1', dataBase64: 'aGk=' });
  const selected = (await bridge.selectPluginImporterFile()) as { sample: Uint8Array };
  assert.deepEqual(Array.from(selected.sample), [1, 2, 3]);
  await bridge.pluginSyncWriteObject({ providerId: 'p', key: 'k', data: new Uint8Array([0]) });
  const sync = calls.find((c) => c.args?.method === 'sync-write-object');
  const payload = sync?.args?.payload as Record<string, unknown>;
  assert.equal(payload.dataBase64, 'AA==');
  assert.equal(typeof payload.requestId, 'string');
});

test('events keep Electron channel names', async () => {
  const { bridge, listeners } = setup();
  const seen: unknown[] = [];
  bridge.onPluginContributionsChanged((event: unknown) => seen.push(event));
  await new Promise((resolve) => setTimeout(resolve, 0));
  listeners.get(PLUGIN_EVENTS.contributionsChanged)?.({ reason: 'plugin-enabled', pluginId: 'x', revision: 1 });
  assert.deepEqual(seen, [{ reason: 'plugin-enabled', pluginId: 'x', revision: 1 }]);
});

test('runtime relay encodes stream transfers', () => {
  const buffer = new Uint8Array([7, 8]).buffer;
  const encoded = encodeRuntimeMessage({ frame: { kind: 'chunk' }, transfer: buffer }) as Record<string, unknown>;
  assert.equal(encoded.transferBase64, 'Bwg=');
  assert.equal('transfer' in encoded, false);
  assert.deepEqual(Array.from(fromBase64('Bwg=')), [7, 8]);
});
