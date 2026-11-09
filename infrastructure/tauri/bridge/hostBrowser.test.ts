import assert from 'node:assert/strict';
import test from 'node:test';

import { EventHub } from '../tauriApi';
import { HOST_BROWSER_EVENTS, createHostBrowserBridge } from './hostBrowser';

type Handler = (payload: unknown) => void;

const setup = (windowLabel = 'main') => {
  const handlers = new Map<string, Set<Handler>>();
  const hub = new EventHub({
    listen: async <T>(event: string, cb: (payload: T) => void) => {
      let set = handlers.get(event);
      if (!set) {
        set = new Set();
        handlers.set(event, set);
      }
      set.add(cb as Handler);
      return () => set?.delete(cb as Handler);
    },
    onError: () => {},
  });
  const invokes: Array<{ cmd: string; args?: Record<string, unknown> }> = [];
  const responses = new Map<string, unknown>();
  const invoke = async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
    invokes.push({ cmd, args });
    return responses.get(cmd) as T;
  };
  const bridge = createHostBrowserBridge({ hub, invoke, windowLabel: () => windowLabel });
  const emit = (event: string, payload: unknown) => {
    for (const handler of Array.from(handlers.get(event) ?? [])) handler(payload);
  };
  return { bridge, invokes, responses, emit };
};

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const host = { id: 'h1', label: 'web', hostname: 'web.example', username: 'root', port: 22 } as unknown as
  import('../../../domain/models').Host;

test('commands map to hostbrowser_* invokes with Electron argument shapes', async () => {
  const { bridge, invokes, responses } = setup();
  responses.set('hostbrowser_open', { reused: false });
  responses.set('hostbrowser_panel_layout', { layers: [] });

  assert.deepEqual(await bridge.openHostBrowser!({
    browserId: 't:s', embedded: true, local: true, hostId: 'h1', label: 'web', theme: 'dark',
  }), { reused: false });
  await bridge.openHostBrowserUrl!({ browserId: 't:s', url: 'example.com' });
  await bridge.focusHostBrowser!('h1');
  await bridge.requestHostBrowserPanel!({ host, sessionId: 's', url: 'https://example.com/' });
  assert.deepEqual(await bridge.setHostBrowserPanelLayout!({
    browserId: 't:s', visible: true, occluded: true, bounds: { x: 1, y: 2, width: 3, height: 4 },
  }), { layers: [] });
  await bridge.closeHostBrowserPanel!('t:s');
  await bridge.getHostBrowserPanelState!('t:s');
  await bridge.commandHostBrowserPanel!('t:s', { type: 'navigate', url: 'https://example.com/' });
  await bridge.listHostBrowserPanelBookmarks!('t:s');
  await bridge.saveHostBrowserPanelBookmark!('t:s', { title: 'App', url: 'https://example.com/' });
  await bridge.removeHostBrowserPanelBookmark!('t:s', 'b1');
  await bridge.listHostBrowserPanelDownloads!('t:s');
  await bridge.commandHostBrowserPanelDownload!('t:s', { type: 'reveal', id: 'd1' });
  await bridge.getHostBrowserBookmarks!();
  await bridge.applyHostBrowserBookmarks!([]);

  assert.deepEqual(invokes.map(({ cmd, args }) => [cmd, args]), [
    ['hostbrowser_open', { payload: { browserId: 't:s', embedded: true, local: true, hostId: 'h1', label: 'web', theme: 'dark' } }],
    ['hostbrowser_panel_url', { payload: { browserId: 't:s', url: 'example.com' } }],
    ['hostbrowser_focus', { hostId: 'h1' }],
    ['hostbrowser_request_panel', { payload: { host, sessionId: 's', url: 'https://example.com/' } }],
    ['hostbrowser_panel_layout', { payload: { browserId: 't:s', visible: true, occluded: true, bounds: { x: 1, y: 2, width: 3, height: 4 } } }],
    ['hostbrowser_panel_close', { browserId: 't:s' }],
    ['hostbrowser_snapshot', { browserId: 't:s' }],
    ['hostbrowser_command', { browserId: 't:s', command: { type: 'navigate', url: 'https://example.com/' } }],
    ['hostbrowser_bookmarks_list', { browserId: 't:s' }],
    ['hostbrowser_bookmarks_upsert', { browserId: 't:s', bookmark: { title: 'App', url: 'https://example.com/' } }],
    ['hostbrowser_bookmarks_remove', { browserId: 't:s', id: 'b1' }],
    ['hostbrowser_downloads_list', { browserId: 't:s' }],
    ['hostbrowser_downloads_command', { browserId: 't:s', command: { type: 'reveal', id: 'd1' } }],
    ['hostbrowser_bookmarks_get_all', undefined],
    ['hostbrowser_bookmarks_apply', { items: [] }],
  ]);
});

test('panel events reach only the owner window, without the routing field', async () => {
  const { bridge, emit } = setup('main');
  const seen: unknown[] = [];
  const unsubscribe = bridge.onHostBrowserPanelEvent!((event) => seen.push(event));
  await flush();
  emit(HOST_BROWSER_EVENTS.panelEvent, { browserId: 't:s', ownerLabel: 'main', type: 'bookmarks' });
  emit(HOST_BROWSER_EVENTS.panelEvent, { browserId: 'x:y', ownerLabel: 'other', type: 'bookmarks' });
  assert.deepEqual(seen, [{ browserId: 't:s', type: 'bookmarks' }]);
  unsubscribe();
  emit(HOST_BROWSER_EVENTS.panelEvent, { browserId: 't:s', ownerLabel: 'main', type: 'bookmarks' });
  assert.equal(seen.length, 1);
});

test('panel requests are retained until the terminal layer subscribes', async () => {
  const { bridge, emit } = setup('main');
  await flush();
  const first = { host, url: 'https://a.example/' };
  const second = { host, sessionId: 's2' };
  emit(HOST_BROWSER_EVENTS.panelRequest, { targetLabel: 'main', request: first });
  emit(HOST_BROWSER_EVENTS.panelRequest, { targetLabel: 'settings', request: second });
  emit(HOST_BROWSER_EVENTS.panelRequest, { targetLabel: 'main', request: second });

  const received: unknown[] = [];
  const unsubscribe = bridge.onHostBrowserPanelRequest!((request) => received.push(request));
  assert.deepEqual(received, [first, second], 'backlog replayed in order, other windows ignored');

  const later = { host, url: 'https://b.example/' };
  emit(HOST_BROWSER_EVENTS.panelRequest, { targetLabel: 'main', request: later });
  assert.deepEqual(received, [first, second, later]);

  // A second subscriber does not see the already delivered backlog.
  const other: unknown[] = [];
  const unsubscribeOther = bridge.onHostBrowserPanelRequest!((request) => other.push(request));
  assert.deepEqual(other, []);
  unsubscribe();
  unsubscribeOther();
  emit(HOST_BROWSER_EVENTS.panelRequest, { targetLabel: 'main', request: first });
  const resubscribed: unknown[] = [];
  bridge.onHostBrowserPanelRequest!((request) => resubscribed.push(request));
  assert.deepEqual(resubscribed, [first], 'requests without listeners are kept again');
});

test('bookmark changes notify without a payload', async () => {
  const { bridge, emit } = setup();
  let calls = 0;
  const unsubscribe = bridge.onHostBrowserBookmarksChanged!(() => { calls += 1; });
  await flush();
  emit(HOST_BROWSER_EVENTS.bookmarksChanged, null);
  assert.equal(calls, 1);
  unsubscribe();
  emit(HOST_BROWSER_EVENTS.bookmarksChanged, null);
  assert.equal(calls, 1);
});
