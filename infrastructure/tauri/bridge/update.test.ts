import assert from 'node:assert/strict';
import test from 'node:test';

import { EventHub } from '../tauriApi';
import { UPDATE_EVENTS, createUpdateBridge, toDirtyEditorsRequest } from './update';

interface InvokeRecord {
  cmd: string;
  args: unknown;
}

const setup = () => {
  const invokes: InvokeRecord[] = [];
  const responses = new Map<string, (args: unknown) => unknown>();
  const listeners = new Map<string, Set<(payload: unknown) => void>>();
  const warnings: string[] = [];

  const hub = new EventHub({
    listen: async <T>(event: string, cb: (payload: T) => void) => {
      let set = listeners.get(event);
      if (!set) {
        set = new Set();
        listeners.set(event, set);
      }
      const listener = cb as (payload: unknown) => void;
      set.add(listener);
      return () => {
        set?.delete(listener);
      };
    },
  });
  const emit = (event: string, payload?: unknown) => {
    for (const listener of Array.from(listeners.get(event) ?? [])) listener(payload);
  };
  const bridge = createUpdateBridge({
    hub,
    invoke: async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
      invokes.push({ cmd, args });
      const responder = responses.get(cmd);
      if (!responder) return undefined as T;
      return responder(args) as T;
    },
    warn: (label) => {
      warnings.push(label);
    },
  });
  const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
  return {
    bridge,
    invokes,
    warnings,
    emit,
    flush,
    respond: (cmd: string, fn: (args: unknown) => unknown) => responses.set(cmd, fn),
    last: (cmd: string) => {
      const record = [...invokes].reverse().find((entry) => entry.cmd === cmd);
      assert.ok(record, `expected an invoke of ${cmd}`);
      return record;
    },
  };
};

test('check / download / status / preference map to the update_* commands', async () => {
  const t = setup();
  t.respond('update_check', () => ({ available: true, supported: true, version: '1.3.0', releaseNotes: 'n' }));
  t.respond('update_download', () => ({ success: true }));
  t.respond('update_get_status', () => ({ status: 'downloading', percent: 42, error: null, version: '1.3.0', isChecking: false }));
  t.respond('update_get_auto_update', () => ({ enabled: false }));
  t.respond('update_set_auto_update', () => ({ success: true }));

  assert.deepEqual(await t.bridge.checkForUpdate(), { available: true, supported: true, version: '1.3.0', releaseNotes: 'n' });
  assert.deepEqual(await t.bridge.downloadUpdate(), { success: true });
  assert.equal((await t.bridge.getUpdateStatus()).percent, 42);
  assert.deepEqual(await t.bridge.getAutoUpdate(), { enabled: false });
  assert.deepEqual(await t.bridge.setAutoUpdate(true), { success: true });
  assert.deepEqual(t.last('update_set_auto_update').args, { enabled: true });
  assert.equal(t.last('update_check').args, undefined);
});

test('unsupported platforms surface the manual-download result untouched', async () => {
  const t = setup();
  const result = {
    available: false,
    supported: false,
    error: 'Auto-update is not supported on this platform/package format.',
    releasesUrl: 'https://github.com/Lochinemak/Netcatty/releases',
  };
  t.respond('update_check', () => result);
  assert.deepEqual(await t.bridge.checkForUpdate(), result);
});

test('installUpdate is fire-and-forget and reports failures through warn', async () => {
  const t = setup();
  t.respond('update_install', () => {
    throw new Error('nope');
  });
  assert.equal(t.bridge.installUpdate(), undefined);
  await t.flush();
  assert.equal(t.last('update_install').cmd, 'update_install');
  assert.deepEqual(t.warnings, ['update_install']);
});

test('update events are forwarded with the Electron payload shapes', async () => {
  const t = setup();
  const seen: Array<[string, unknown]> = [];
  const offs = [
    t.bridge.onUpdateAvailable((info) => seen.push(['available', info])),
    t.bridge.onUpdateNotAvailable(() => seen.push(['not-available', undefined])),
    t.bridge.onUpdateDownloadProgress((p) => seen.push(['progress', p])),
    t.bridge.onUpdateDownloaded(() => seen.push(['downloaded', undefined])),
    t.bridge.onUpdateError((e) => seen.push(['error', e])),
    t.bridge.onUpdateNeedsSave(() => seen.push(['needs-save', undefined])),
  ];
  await t.flush();

  t.emit(UPDATE_EVENTS.available, { version: '1.3.0', releaseNotes: 'notes', releaseDate: '2026-11-07T00:00:00Z' });
  t.emit(UPDATE_EVENTS.available, { version: '1.4.0' });
  t.emit(UPDATE_EVENTS.notAvailable, {});
  t.emit(UPDATE_EVENTS.downloadProgress, { percent: 12.5, bytesPerSecond: 1024, transferred: 100, total: 800 });
  t.emit(UPDATE_EVENTS.downloaded, null);
  t.emit(UPDATE_EVENTS.error, { error: 'boom' });
  t.emit(UPDATE_EVENTS.error, {});
  t.emit(UPDATE_EVENTS.needsSave, null);

  assert.deepEqual(seen, [
    ['available', { version: '1.3.0', releaseNotes: 'notes', releaseDate: '2026-11-07T00:00:00Z' }],
    ['available', { version: '1.4.0', releaseNotes: '', releaseDate: null }],
    ['not-available', undefined],
    ['progress', { percent: 12.5, bytesPerSecond: 1024, transferred: 100, total: 800 }],
    ['downloaded', undefined],
    ['error', { error: 'boom' }],
    ['error', { error: 'Unknown update error' }],
    ['needs-save', undefined],
  ]);

  for (const off of offs) off();
  t.emit(UPDATE_EVENTS.downloaded, null);
  assert.equal(seen.length, 8, 'unsubscribed listeners receive nothing');
});

test('dirty-editor query round trip', async () => {
  const t = setup();
  const requests: Array<{ requestId: string; deadline: number }> = [];
  t.bridge.onCheckDirtyEditors((request) => requests.push(request));
  await t.flush();

  t.emit(UPDATE_EVENTS.queryDirtyEditors, { requestId: 'req-1', deadline: 123 });
  t.emit(UPDATE_EVENTS.queryDirtyEditors, { nope: true });
  t.emit(UPDATE_EVENTS.queryDirtyEditors, 'garbage');
  assert.deepEqual(requests, [{ requestId: 'req-1', deadline: 123 }]);

  t.bridge.reportDirtyEditorsResult(true, 'transfers', { requestId: 'req-1', pending: true });
  t.bridge.reportDirtyEditorsResult(false, undefined, { requestId: 'req-1' });
  await t.flush();
  const reports = t.invokes.filter((entry) => entry.cmd === 'app_report_dirty_editors').map((entry) => entry.args);
  assert.deepEqual(reports, [
    { payload: { requestId: 'req-1', hasDirty: true, reason: 'transfers', pending: true } },
    { payload: { requestId: 'req-1', hasDirty: false, reason: undefined, pending: false } },
  ]);
});

test('toDirtyEditorsRequest fills in a deadline when Rust omits it', () => {
  const before = Date.now();
  const request = toDirtyEditorsRequest({ requestId: 'x' });
  assert.ok(request);
  assert.equal(request.requestId, 'x');
  assert.ok(request.deadline >= before + 5000);
  assert.equal(toDirtyEditorsRequest({ requestId: '' }), null);
  assert.equal(toDirtyEditorsRequest(null), null);
});
