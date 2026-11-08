import assert from 'node:assert/strict';
import test from 'node:test';

import { EventHub } from '../tauriApi';
import { SessionOutputRoutes, WINDOWS_EVENTS, WINDOWS_REPLY_CHANNELS, createWindowsBridge } from './windows';

interface InvokeRecord {
  cmd: string;
  args: unknown;
}

const setup = (label = 'main') => {
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
  const invoke = async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
    invokes.push({ cmd, args });
    const responder = responses.get(cmd);
    return (responder ? responder(args) : undefined) as T;
  };
  const warn = (name: string) => {
    warnings.push(name);
  };
  const routedAway: string[] = [];
  const routes = new SessionOutputRoutes({ hub, label, invoke, warn, onRoutedAway: (id) => routedAway.push(id) });
  const bridge = createWindowsBridge({ hub, routes, invoke, label, warn });
  const emit = (event: string, payload?: unknown) => {
    for (const listener of Array.from(listeners.get(event) ?? [])) listener(payload);
  };
  const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
  return {
    bridge,
    routes,
    invokes,
    warnings,
    routedAway,
    emit,
    flush,
    respond: (cmd: string, fn: (args: unknown) => unknown) => responses.set(cmd, fn),
    calls: (cmd: string) => invokes.filter((entry) => entry.cmd === cmd),
  };
};

test('output routes drop sessions displayed by another window and respect revisions', async () => {
  const ctx = setup('main');
  await ctx.flush();
  assert.equal(ctx.calls('windows_output_routes').length, 1);
  assert.equal(ctx.routes.accepts('s1'), true, 'unknown sessions are accepted');

  ctx.emit(WINDOWS_EVENTS.sessionOutputRoute, { sessionId: 's1', label: 'session-1', revision: 5 });
  assert.equal(ctx.routes.accepts('s1'), false);
  assert.deepEqual(ctx.routedAway, ['s1']);

  // An older change cannot override a newer one.
  ctx.emit(WINDOWS_EVENTS.sessionOutputRoute, { sessionId: 's1', label: 'main', revision: 4 });
  assert.equal(ctx.routes.accepts('s1'), false);
  ctx.emit(WINDOWS_EVENTS.sessionOutputRoute, { sessionId: 's1', label: 'main', revision: 6 });
  assert.equal(ctx.routes.accepts('s1'), true);
  // Unrouted (`label: null`) sessions are accepted everywhere.
  ctx.emit(WINDOWS_EVENTS.sessionOutputRoute, { sessionId: 's2', label: null, revision: 7 });
  assert.equal(ctx.routes.accepts('s2'), true);

  ctx.routes.track('s3');
  ctx.routes.track('');
  await ctx.flush();
  assert.deepEqual(ctx.calls('windows_track_session').map((c) => c.args), [{ sessionId: 's3' }]);
});

test('the start-up snapshot seeds routes without undoing newer events', async () => {
  const ctx = setup('main');
  // Rebuild with a snapshot response.
  const invokes: string[] = [];
  const hub = new EventHub({ listen: async () => () => {} });
  let resolveSnapshot: (value: unknown) => void = () => {};
  const routes = new SessionOutputRoutes({
    hub,
    label: 'main',
    invoke: async <T>(cmd: string): Promise<T> => {
      invokes.push(cmd);
      return new Promise<T>((resolve) => {
        resolveSnapshot = resolve as (value: unknown) => void;
      });
    },
  });
  routes.apply({ sessionId: 'a', label: 'main', revision: 9 });
  resolveSnapshot({
    routes: [
      { sessionId: 'a', label: 'terminal-popup-1', revision: 3 },
      { sessionId: 'b', label: 'session-2', revision: 4 },
    ],
  });
  await ctx.flush();
  assert.deepEqual(invokes, ['windows_output_routes']);
  assert.equal(routes.accepts('a'), true);
  assert.equal(routes.accepts('b'), false);
});

test('editor open-tab payloads are buffered, acknowledged and signal readiness', async () => {
  const ctx = setup('editor');
  const received: unknown[] = [];
  const off = ctx.bridge.onEditorWindowOpenTab((snapshot) => received.push(snapshot.editorId));
  await ctx.flush();
  assert.equal(ctx.calls('windows_editor_ready').length, 1);

  ctx.emit(WINDOWS_EVENTS.editorOpenTab, { requestId: 'r1', editorId: 'e1' });
  assert.deepEqual(received, ['e1']);
  await ctx.flush();
  assert.deepEqual(ctx.calls('windows_report').at(-1)?.args, {
    channel: WINDOWS_REPLY_CHANNELS.editorOpenTabResult,
    payload: { requestId: 'r1', ok: true },
  });

  // No receiver mounted: buffered until the next subscription.
  off();
  ctx.emit(WINDOWS_EVENTS.editorOpenTab, { requestId: 'r2', editorId: 'e2' });
  assert.deepEqual(received, ['e1']);
  ctx.bridge.onEditorWindowOpenTab(() => {
    throw new Error('boom');
  });
  await ctx.flush();
  assert.deepEqual(ctx.calls('windows_report').at(-1)?.args, {
    channel: WINDOWS_REPLY_CHANNELS.editorOpenTabResult,
    payload: { requestId: 'r2', ok: false, error: 'boom' },
  });
});

test('editor commands and fire-and-forget reports map to the windows_* commands', async () => {
  const ctx = setup('main');
  ctx.respond('windows_open_editor', () => ({ success: true, reused: false }));
  const snapshot = {
    editorId: 'e', sessionId: 's', sftpTabId: 't', hostId: 'h', remotePath: '/a', fileName: 'a',
    languageId: 'plaintext', content: '', baselineContent: '', wordWrap: false, viewState: null,
  };
  assert.deepEqual(await ctx.bridge.openEditorWindow(snapshot), { success: true, reused: false });
  assert.deepEqual(ctx.calls('windows_open_editor')[0].args, { payload: snapshot });
  await ctx.bridge.focusEditorWindow('e');
  assert.deepEqual(ctx.calls('windows_focus_editor')[0].args, { editorId: 'e' });
  ctx.bridge.reportEditorWindowDirty({ editorId: 'e', dirty: true });
  ctx.bridge.reportEditorWindowTabsClosed({ editorIds: ['e'] });
  ctx.bridge.remapEditorWindowSession({ fromSessionId: 'a', toSessionId: 'b' });
  ctx.bridge.reportEditorWindowSaveResult({ requestId: 'x', ok: true });
  await ctx.flush();
  assert.equal(ctx.calls('windows_report_editor_dirty').length, 1);
  assert.equal(ctx.calls('windows_report_editor_tabs_closed').length, 1);
  assert.equal(ctx.calls('windows_remap_editor_session').length, 1);
  assert.deepEqual(ctx.calls('windows_report').at(-1)?.args, {
    channel: WINDOWS_REPLY_CHANNELS.editorSaveResult,
    payload: { requestId: 'x', ok: true },
  });
});

test('terminal popup config is pulled once and replayed to remounted listeners', async () => {
  const ctx = setup('terminal-popup-1');
  ctx.respond('windows_terminal_popup_config', () => ({ title: 'htop', popupId: 'p1' }));
  const first: unknown[] = [];
  const off = ctx.bridge.onTerminalPopupConfig((config) => first.push(config.title));
  await ctx.flush();
  assert.deepEqual(first, ['htop']);
  off();
  const second: unknown[] = [];
  ctx.bridge.onTerminalPopupConfig((config) => second.push(config.title));
  await ctx.flush();
  assert.deepEqual(second, ['htop']);
  assert.equal(ctx.calls('windows_terminal_popup_config').length, 1);
});

test('the duplicated session is taken once and held until a listener mounts', async () => {
  const ctx = setup('session-1');
  ctx.respond('windows_take_open_session', () => ({ title: 'web', sourceSession: { id: 'x' } }));
  const off = ctx.bridge.onOpenSessionInNewWindow(() => assert.fail('unmounted listener must not run'));
  off();
  await ctx.flush();
  const seen: string[] = [];
  ctx.bridge.onOpenSessionInNewWindow((payload) => seen.push(payload.title));
  assert.deepEqual(seen, ['web']);
  assert.equal(ctx.calls('windows_take_open_session').length, 1);
});

test('snapshot hand-over replies on the Electron channels', async () => {
  const ctx = setup('main');
  const requests: unknown[] = [];
  ctx.bridge.onTerminalSessionSnapshotRequest((payload) => requests.push(payload));
  ctx.emit(WINDOWS_EVENTS.snapshotRequest, { sessionId: 's', requestId: 'q' });
  assert.deepEqual(requests, [{ sessionId: 's', requestId: 'q' }]);
  ctx.bridge.respondTerminalSessionSnapshot('q', 'data', undefined, true, false, null, 'title', true);
  await ctx.flush();
  assert.deepEqual(ctx.calls('windows_report').at(-1)?.args, {
    channel: WINDOWS_REPLY_CHANNELS.snapshotResponse,
    payload: {
      requestId: 'q',
      snapshot: 'data',
      perCharacterInput: true,
      kittyKeyboardModeState: undefined,
      kittyKeyboardProtocolEnabled: true,
      passwordPromptActive: false,
      cwd: null,
      title: 'title',
    },
  });

  let handled: boolean | Error = true;
  ctx.bridge.onTerminalSessionApplySnapshot(async () => {
    if (handled instanceof Error) throw handled;
    return handled;
  });
  ctx.emit(WINDOWS_EVENTS.applySnapshot, { sessionId: 's', requestId: 'a1' });
  await ctx.flush();
  assert.deepEqual(ctx.calls('windows_report').at(-1)?.args, {
    channel: WINDOWS_REPLY_CHANNELS.applySnapshotResponse,
    payload: { requestId: 'a1', success: true },
  });
  const before = ctx.calls('windows_report').length;
  handled = false;
  ctx.emit(WINDOWS_EVENTS.applySnapshot, { sessionId: 's', requestId: 'a2' });
  await ctx.flush();
  assert.equal(ctx.calls('windows_report').length, before, 'unhandled applies are not answered');
  handled = new Error('nope');
  ctx.emit(WINDOWS_EVENTS.applySnapshot, { sessionId: 's', requestId: 'a3' });
  await ctx.flush();
  assert.deepEqual(ctx.calls('windows_report').at(-1)?.args, {
    channel: WINDOWS_REPLY_CHANNELS.applySnapshotResponse,
    payload: { requestId: 'a3', success: false, error: 'nope' },
  });
});

test('a successful rebind claims the display before the route broadcast arrives', async () => {
  const ctx = setup('terminal-popup-1');
  ctx.emit(WINDOWS_EVENTS.sessionOutputRoute, { sessionId: 's', label: 'main', revision: 2 });
  assert.equal(ctx.routes.accepts('s'), false);
  ctx.respond('windows_rebind_output', () => ({ success: true, previousWebContentsId: 1, webContentsId: 2 }));
  const result = await ctx.bridge.rebindTerminalSessionOutput('s', 'tok');
  assert.equal(result.previousWebContentsId, 1);
  assert.deepEqual(ctx.calls('windows_rebind_output')[0].args, { sessionId: 's', authorization: 'tok' });
  assert.equal(ctx.routes.accepts('s'), true);
  // The broadcast confirms; restoring hands the display back to main.
  ctx.emit(WINDOWS_EVENTS.sessionOutputRoute, { sessionId: 's', label: 'terminal-popup-1', revision: 3 });
  ctx.respond('windows_restore_output', () => ({ success: true, restored: true, webContentsId: 1 }));
  await ctx.bridge.restoreTerminalSessionOutput('s', undefined, 'tok');
  assert.deepEqual(ctx.calls('windows_restore_output')[0].args, {
    sessionId: 's',
    webContentsId: null,
    authorization: 'tok',
  });
  assert.equal(ctx.routes.accepts('s'), false);
});

test('window chrome commands coerce their inputs', async () => {
  const ctx = setup('main');
  await ctx.bridge.setWindowOpacity(0.8);
  await ctx.bridge.setWindowOpacity('bad' as unknown as number);
  await ctx.bridge.setWindowBackgroundBlur(true);
  ctx.bridge.setTerminalKeyboardFocus(true);
  await ctx.flush();
  assert.deepEqual(ctx.calls('windows_set_opacity').map((c) => c.args), [{ opacity: 0.8 }, { opacity: null }]);
  assert.deepEqual(ctx.calls('windows_set_background_blur')[0].args, { enabled: true });
  assert.deepEqual(ctx.calls('windows_set_terminal_keyboard_focus')[0].args, { focused: true });

  let closes = 0;
  const off = ctx.bridge.onWindowCommandCloseRequested(() => {
    closes += 1;
  });
  ctx.emit(WINDOWS_EVENTS.windowCommandClose);
  off();
  ctx.emit(WINDOWS_EVENTS.windowCommandClose);
  assert.equal(closes, 1);
  assert.deepEqual(ctx.warnings, []);
});
