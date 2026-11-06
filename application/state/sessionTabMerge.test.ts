import assert from 'node:assert/strict';
import test from 'node:test';

import type { TerminalSession, Workspace } from '../../domain/models';
import { collectSessionIds } from '../../domain/workspace';
import {
  applyMovedWorkspaceSessionTabOrder,
  canMoveWorkspaceSessionToTab,
  moveWorkspaceSessionToTabState,
} from './sessionTabMerge';
import { getTopTabMergeTarget } from './terminalDragData';

const session = (id: string, workspaceId?: string): TerminalSession => ({
  id,
  hostId: `host-${id}`,
  hostLabel: id.toUpperCase(),
  hostname: `${id}.example.test`,
  username: 'user',
  status: 'connected',
  workspaceId,
});

const workspace = (id: string, sessionIds: string[], extra: Partial<Workspace> = {}): Workspace => ({
  id,
  title: 'Workspace',
  focusedSessionId: sessionIds[0],
  root: sessionIds.length === 1
    ? { id: `${id}-pane-0`, type: 'pane', sessionId: sessionIds[0] }
    : {
        id: `${id}-split`,
        type: 'split',
        direction: 'horizontal',
        sizes: sessionIds.map(() => 1),
        children: sessionIds.map((sessionId, index) => ({
          id: `${id}-pane-${index}`,
          type: 'pane' as const,
          sessionId,
        })),
      },
  ...extra,
});

test('a pane moves into another workspace tab and takes focus there', () => {
  const sessions = [session('a', 'ws-1'), session('b', 'ws-1'), session('c', 'ws-1'), session('d', 'ws-2'), session('e', 'ws-2')];
  const workspaces = [workspace('ws-1', ['a', 'b', 'c']), workspace('ws-2', ['d', 'e'])];

  const result = moveWorkspaceSessionToTabState({ sessions, workspaces, sessionId: 'b', targetTabId: 'ws-2' });

  assert.equal(result.changed, true);
  assert.equal(result.activeTabId, 'ws-2');
  assert.equal(result.sessions.find((s) => s.id === 'b')?.workspaceId, 'ws-2');
  const [source, target] = result.workspaces;
  assert.deepEqual(collectSessionIds(source.root), ['a', 'c']);
  assert.deepEqual(collectSessionIds(target.root), ['d', 'e', 'b']);
  assert.equal(target.focusedSessionId, 'b');
  // The target's existing split direction is kept, so the pane joins as a peer.
  assert.equal(target.root.type === 'split' ? target.root.direction : null, 'horizontal');
  assert.deepEqual(applyMovedWorkspaceSessionTabOrder(['ws-1', 'ws-2'], result), ['ws-1', 'ws-2']);
});

test('moving a pane keeps a focus-mode target in focus mode with the pane shown', () => {
  const sessions = [session('a', 'ws-1'), session('b', 'ws-1'), session('c', 'ws-1'), session('d', 'ws-2')];
  const workspaces = [workspace('ws-1', ['a', 'b', 'c']), workspace('ws-2', ['d'], { viewMode: 'focus' })];

  const result = moveWorkspaceSessionToTabState({ sessions, workspaces, sessionId: 'a', targetTabId: 'ws-2' });

  const target = result.workspaces.find((ws) => ws.id === 'ws-2');
  assert.equal(target?.viewMode, 'focus');
  assert.equal(target?.focusedSessionId, 'a');
  assert.deepEqual(target?.focusSessionOrder, ['d', 'a']);
});

test('a pane dropped on a standalone tab pairs with it in a new workspace', () => {
  const sessions = [session('a', 'ws-1'), session('b', 'ws-1'), session('c', 'ws-1'), session('solo')];
  const workspaces = [workspace('ws-1', ['a', 'b', 'c'])];

  const result = moveWorkspaceSessionToTabState({ sessions, workspaces, sessionId: 'c', targetTabId: 'solo' });

  assert.equal(result.changed, true);
  assert.equal(result.replacedSessionTabId, 'solo');
  const created = result.workspaces.find((ws) => ws.id === result.activeTabId);
  assert.ok(created, 'the new workspace becomes the active tab');
  assert.deepEqual(collectSessionIds(created.root), ['solo', 'c']);
  assert.equal(created.focusedSessionId, 'c');
  assert.equal(created.title, 'SOLO/C');
  assert.equal(result.sessions.find((s) => s.id === 'solo')?.workspaceId, created.id);
  assert.equal(result.sessions.find((s) => s.id === 'c')?.workspaceId, created.id);
  // The new workspace takes over the standalone tab's slot.
  assert.deepEqual(
    applyMovedWorkspaceSessionTabOrder(['solo', 'ws-1'], result),
    [created.id, 'ws-1'],
  );
});

test('moving a pane out of a two-pane workspace leaves its sibling as a plain tab', () => {
  const sessions = [session('a', 'ws-1'), session('b', 'ws-1'), session('d', 'ws-2'), session('e', 'ws-2')];
  const workspaces = [workspace('ws-1', ['a', 'b']), workspace('ws-2', ['d', 'e'])];

  const result = moveWorkspaceSessionToTabState({ sessions, workspaces, sessionId: 'a', targetTabId: 'ws-2' });

  assert.equal(result.dissolvedWorkspaceId, 'ws-1');
  assert.deepEqual(result.workspaces.map((ws) => ws.id), ['ws-2']);
  assert.equal(result.sessions.find((s) => s.id === 'b')?.workspaceId, undefined);
  assert.equal(result.sessions.find((s) => s.id === 'a')?.workspaceId, 'ws-2');
  // The dissolved workspace's slot goes to the remaining pane only: the moved
  // pane lives in the target tab and must not get a tab of its own.
  assert.deepEqual(applyMovedWorkspaceSessionTabOrder(['ws-1', 'ws-2'], result), ['b', 'ws-2']);
});

test('a pane cannot be merged into its own tab, a hidden session, or a non-terminal tab', () => {
  const hidden: TerminalSession = { ...session('hidden'), hiddenFromTabs: true };
  const sessions = [session('a', 'ws-1'), session('b', 'ws-1'), session('solo'), hidden];
  const workspaces = [workspace('ws-1', ['a', 'b'])];
  const base = { sessions, workspaces, sessionId: 'a' };

  assert.equal(canMoveWorkspaceSessionToTab({ ...base, targetTabId: 'ws-1' }), false);
  assert.equal(canMoveWorkspaceSessionToTab({ ...base, targetTabId: 'b' }), false);
  assert.equal(canMoveWorkspaceSessionToTab({ ...base, targetTabId: 'hidden' }), false);
  assert.equal(canMoveWorkspaceSessionToTab({ ...base, targetTabId: 'log-1' }), false);
  assert.equal(canMoveWorkspaceSessionToTab({ ...base, sessionId: 'solo', targetTabId: 'ws-1' }), false);
  assert.equal(canMoveWorkspaceSessionToTab({ ...base, targetTabId: 'solo' }), true);

  const refused = moveWorkspaceSessionToTabState({ ...base, targetTabId: 'ws-1' });
  assert.equal(refused.changed, false);
  assert.equal(refused.sessions, sessions);
  assert.equal(refused.workspaces, workspaces);
  assert.deepEqual(applyMovedWorkspaceSessionTabOrder(['ws-1', 'solo'], refused), ['ws-1', 'solo']);
});

type FakeRect = { left: number; right: number; top: number; bottom: number };
const fakeTab = (tabId: string, tabType: string, left: number, right: number) => ({
  dataset: { tabId, tabType },
  getBoundingClientRect: (): FakeRect => ({ left, right, top: 0, bottom: 30 }),
});
const fakeTopTabsRoot = (tabs: ReturnType<typeof fakeTab>[]) => ({
  getBoundingClientRect: (): FakeRect => ({ left: 0, right: 1000, top: 0, bottom: 30 }),
  querySelectorAll: () => tabs,
}) as unknown as HTMLElement;

test('only the middle of a terminal tab is a merge target for a dragged pane', () => {
  const root = fakeTopTabsRoot([
    fakeTab('vault', 'root', 0, 100),
    fakeTab('s1', 'session', 100, 300),
    fakeTab('ws-1', 'workspace', 300, 500),
    fakeTab('log-1', 'logView', 500, 700),
  ]);
  const at = (clientX: number, clientY = 15) => getTopTabMergeTarget({ clientX, clientY }, root);

  assert.equal(at(200), 's1');
  assert.equal(at(400), 'ws-1');
  // Edge quarters keep the "insert as a standalone tab" behaviour.
  assert.equal(at(120), null);
  assert.equal(at(290), null);
  // Non-terminal tabs and the area outside the tab bar never merge.
  assert.equal(at(50), null);
  assert.equal(at(600), null);
  assert.equal(at(200, 200), null);
  assert.equal(getTopTabMergeTarget({ clientX: 200, clientY: 15 }, null), null);
});
