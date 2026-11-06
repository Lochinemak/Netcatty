import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { JSDOM } from 'jsdom';
import type { Host } from '../../domain/models';
import { collectSessionIds } from '../../domain/workspace';
import { activeTabStore } from './activeTabStore';
import { useSessionState } from './useSessionState';

const host = (id: string): Host => ({
  id,
  label: id.toUpperCase(),
  hostname: `${id}.example.test`,
  username: 'user',
  port: 22,
  protocol: 'ssh',
} as Host);

async function mountSessionState(t: TestContext) {
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost' });
  const globals = {
    window: dom.window,
    document: dom.window.document,
    localStorage: dom.window.localStorage,
    CustomEvent: dom.window.CustomEvent,
    Event: dom.window.Event,
    IS_REACT_ACT_ENVIRONMENT: true,
  };
  const previous = new Map<string, PropertyDescriptor | undefined>();
  for (const [key, value] of Object.entries(globals)) {
    previous.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { configurable: true, value });
  }
  const root = createRoot(document.getElementById('root')!);
  t.after(async () => {
    // Reset the shared store while `window` still exists: its notification
    // is scheduled through the window.
    await act(async () => {
      activeTabStore.setActiveTabId('vault');
      root.unmount();
    });
    dom.window.close();
    for (const [key, descriptor] of previous) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
  });
  const ref: { state: ReturnType<typeof useSessionState> } = { state: undefined as never };
  function Probe() {
    ref.state = useSessionState({ persistSessionRestore: false });
    return null;
  }
  // StrictMode double-invokes state updaters, like the dev app does.
  await act(async () => root.render(React.createElement(React.StrictMode, null, React.createElement(Probe))));
  return ref;
}

test('splitting a host into a standalone tab turns the tab into a two-pane workspace', async (t) => {
  const ref = await mountSessionState(t);
  let baseId = '';
  await act(async () => { baseId = ref.state.connectToHost(host('a')); });

  let newId: string | null = null;
  await act(async () => { newId = ref.state.splitHostIntoTab(baseId, host('b'), 'vertical'); });

  assert.ok(newId);
  assert.equal(ref.state.workspaces.length, 1);
  const ws = ref.state.workspaces[0];
  assert.deepEqual(collectSessionIds(ws.root), [baseId, newId]);
  assert.equal(ws.root.type === 'split' ? ws.root.direction : null, 'vertical');
  assert.equal(ws.focusedSessionId, newId);
  assert.equal(ws.title, 'A/B');
  assert.equal(ref.state.sessions.length, 2);
  assert.ok(ref.state.sessions.every((s) => s.workspaceId === ws.id));
  assert.equal(ref.state.sessions.find((s) => s.id === newId)?.hostId, 'b');
  assert.equal(activeTabStore.getActiveTabId(), ws.id);
  assert.deepEqual(ref.state.orderedTabs, [ws.id]);
});

test('splitting a host into a workspace tab inserts it beside the focused pane', async (t) => {
  const ref = await mountSessionState(t);
  let workspaceId: string | null = null;
  await act(async () => {
    workspaceId = ref.state.createWorkspaceFromTargets([
      { kind: 'host', host: host('a') },
      { kind: 'host', host: host('b') },
    ]);
  });
  assert.ok(workspaceId);
  // "New workspace" lands in focus mode, where only one session is shown.
  assert.equal(ref.state.workspaces[0].viewMode, 'focus');
  const [firstId, secondId] = collectSessionIds(ref.state.workspaces[0].root);
  await act(async () => { ref.state.setWorkspaceFocusedSession(workspaceId!, firstId); });

  let newId: string | null = null;
  await act(async () => { newId = ref.state.splitHostIntoTab(workspaceId!, host('c'), 'horizontal'); });

  assert.ok(newId);
  const ws = ref.state.workspaces[0];
  // The new pane sits right after the focused pane, not at the end.
  assert.deepEqual(collectSessionIds(ws.root), [firstId, newId, secondId]);
  assert.equal(ws.viewMode, 'split', 'the split must be visible');
  assert.equal(ws.focusedSessionId, newId);
  assert.equal(ref.state.sessions.filter((s) => s.id === newId).length, 1);
  assert.equal(ref.state.sessions.find((s) => s.id === newId)?.workspaceId, workspaceId);
});

test('splitting a host into a tab that is not a terminal tab opens nothing', async (t) => {
  const ref = await mountSessionState(t);
  let result: string | null = 'unset';
  await act(async () => { result = ref.state.splitHostIntoTab('vault', host('a'), 'vertical'); });

  assert.equal(result, null);
  assert.equal(ref.state.sessions.length, 0);
  assert.equal(ref.state.workspaces.length, 0);
});

test('a workspace pane can be moved into another tab', async (t) => {
  const ref = await mountSessionState(t);
  let workspaceId: string | null = null;
  let soloId = '';
  await act(async () => {
    workspaceId = ref.state.createWorkspaceFromTargets([
      { kind: 'host', host: host('a') },
      { kind: 'host', host: host('b') },
      { kind: 'host', host: host('c') },
    ]);
  });
  await act(async () => { soloId = ref.state.connectToHost(host('solo')); });
  const [aId, bId, cId] = collectSessionIds(ref.state.workspaces[0].root);
  // Standalone tabs are listed before workspace tabs by default.
  assert.deepEqual(ref.state.orderedTabs, [soloId, workspaceId]);

  let moved = false;
  await act(async () => { moved = ref.state.moveSessionToTab(cId, soloId); });

  assert.equal(moved, true);
  assert.equal(ref.state.workspaces.length, 2);
  const source = ref.state.workspaces.find((ws) => ws.id === workspaceId)!;
  const created = ref.state.workspaces.find((ws) => ws.id !== workspaceId)!;
  assert.deepEqual(collectSessionIds(source.root), [aId, bId]);
  assert.deepEqual(collectSessionIds(created.root), [soloId, cId]);
  assert.equal(activeTabStore.getActiveTabId(), created.id);
  // The new workspace takes over the standalone tab's slot.
  assert.deepEqual(ref.state.orderedTabs, [created.id, workspaceId]);

  // Moving the last-but-one pane dissolves the source workspace.
  await act(async () => { moved = ref.state.moveSessionToTab(bId, created.id); });

  assert.equal(moved, true);
  assert.deepEqual(ref.state.workspaces.map((ws) => ws.id), [created.id]);
  assert.deepEqual(collectSessionIds(ref.state.workspaces[0].root), [soloId, cId, bId]);
  assert.equal(ref.state.sessions.find((s) => s.id === aId)?.workspaceId, undefined);
  // The dissolved workspace's slot goes to its one remaining pane.
  assert.deepEqual(ref.state.orderedTabs, [created.id, aId]);
  assert.equal(ref.state.sessions.length, 4, 'no session is lost or duplicated');

  // A pane cannot be dropped onto its own tab.
  await act(async () => { moved = ref.state.moveSessionToTab(bId, created.id); });
  assert.equal(moved, false);
});
