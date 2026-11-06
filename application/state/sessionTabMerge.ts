import type { TerminalSession, Workspace } from "../../domain/models";
import {
  appendPaneToWorkspaceRoot,
  collectSessionIds,
  createWorkspaceFromSessions,
} from "../../domain/workspace";
import { buildMergedWorkspaceTitle, getSessionConnectionLabel } from "../../domain/sessionTabTitle";
import {
  detachSessionFromWorkspaceState,
  replaceDissolvedWorkspaceTabOrder,
} from "./sessionWorkspaceDetach";

export type MoveWorkspaceSessionToTabResult = {
  changed: boolean;
  sessions: TerminalSession[];
  workspaces: Workspace[];
  /** Tab that owns the moved pane afterwards (an existing or a new workspace). */
  activeTabId?: string;
  /** Source workspace that fell back to plain tabs because one pane was left. */
  dissolvedWorkspaceId?: string;
  replacementTabIds?: string[];
  /** Standalone tab whose slot the newly created workspace takes over. */
  replacedSessionTabId?: string;
  movedSessionId?: string;
};

type MoveWorkspaceSessionToTabOptions = {
  sessions: TerminalSession[];
  workspaces: Workspace[];
  sessionId: string;
  targetTabId: string;
};

/**
 * Whether a pane dragged out of a workspace may be merged into `targetTabId`.
 * Only other terminal tabs qualify: another workspace, or a standalone session.
 */
export function canMoveWorkspaceSessionToTab({
  sessions,
  workspaces,
  sessionId,
  targetTabId,
}: MoveWorkspaceSessionToTabOptions): boolean {
  const session = sessions.find((candidate) => candidate.id === sessionId);
  if (!session?.workspaceId || session.workspaceId === targetTabId || sessionId === targetTabId) {
    return false;
  }
  if (workspaces.some((workspace) => workspace.id === targetTabId)) return true;
  return sessions.some((candidate) => (
    candidate.id === targetTabId && !candidate.workspaceId && !candidate.hiddenFromTabs
  ));
}

/**
 * Move a workspace pane into another tab: append it to the target workspace,
 * or pair it with the target standalone session in a new workspace.
 */
export function moveWorkspaceSessionToTabState(
  options: MoveWorkspaceSessionToTabOptions,
): MoveWorkspaceSessionToTabResult {
  const { sessions, workspaces, sessionId, targetTabId } = options;
  const unchanged: MoveWorkspaceSessionToTabResult = { changed: false, sessions, workspaces };
  if (!canMoveWorkspaceSessionToTab(options)) return unchanged;

  const detached = detachSessionFromWorkspaceState({ sessions, workspaces, sessionId });
  if (!detached.changed) return unchanged;

  const base = {
    changed: true,
    dissolvedWorkspaceId: detached.dissolvedWorkspaceId,
    replacementTabIds: detached.replacementTabIds,
    movedSessionId: sessionId,
  };

  const targetWorkspace = detached.workspaces.find((workspace) => workspace.id === targetTabId);
  if (targetWorkspace) {
    const direction = targetWorkspace.root.type === "split" ? targetWorkspace.root.direction : "vertical";
    const focusSessionOrder = [
      ...(targetWorkspace.focusSessionOrder ?? collectSessionIds(targetWorkspace.root))
        .filter((id) => id !== sessionId),
      sessionId,
    ];
    return {
      ...base,
      sessions: detached.sessions.map((candidate) => (
        candidate.id === sessionId ? { ...candidate, workspaceId: targetTabId } : candidate
      )),
      workspaces: detached.workspaces.map((workspace) => (
        workspace.id === targetTabId
          ? {
              ...workspace,
              root: appendPaneToWorkspaceRoot(workspace.root, sessionId, direction),
              focusedSessionId: sessionId,
              focusSessionOrder,
            }
          : workspace
      )),
      activeTabId: targetTabId,
    };
  }

  const targetSession = detached.sessions.find((candidate) => (
    candidate.id === targetTabId && !candidate.workspaceId && !candidate.hiddenFromTabs
  ));
  const movedSession = detached.sessions.find((candidate) => candidate.id === sessionId);
  if (!targetSession || !movedSession) return unchanged;

  const created = createWorkspaceFromSessions(targetTabId, sessionId, {
    direction: "vertical",
    position: "right",
  });
  const mergedTitle = buildMergedWorkspaceTitle(
    getSessionConnectionLabel(targetSession),
    getSessionConnectionLabel(movedSession),
  );
  const newWorkspace: Workspace = {
    ...(mergedTitle
      ? { ...created, title: mergedTitle, autoTitle: false, generatedTitle: true }
      : created),
    focusedSessionId: sessionId,
  };

  return {
    ...base,
    sessions: detached.sessions.map((candidate) => (
      candidate.id === sessionId || candidate.id === targetTabId
        ? { ...candidate, workspaceId: newWorkspace.id }
        : candidate
    )),
    workspaces: [...detached.workspaces, newWorkspace],
    activeTabId: newWorkspace.id,
    replacedSessionTabId: targetTabId,
  };
}

/**
 * Tab order after a pane move: restore the tabs of a dissolved source
 * workspace, drop the moved pane's own slot, and let a newly created
 * workspace take the slot of the standalone tab it absorbed.
 */
export function applyMovedWorkspaceSessionTabOrder(
  tabOrder: readonly string[],
  result: MoveWorkspaceSessionToTabResult,
): string[] {
  if (!result.changed || !result.movedSessionId) return [...tabOrder];

  const restored = replaceDissolvedWorkspaceTabOrder(
    tabOrder,
    result.dissolvedWorkspaceId,
    result.replacementTabIds,
  ).filter((tabId) => tabId !== result.movedSessionId);

  const { replacedSessionTabId, activeTabId } = result;
  if (!replacedSessionTabId || !activeTabId) return restored;
  if (restored.includes(activeTabId)) {
    return restored.filter((tabId) => tabId !== replacedSessionTabId);
  }
  if (!restored.includes(replacedSessionTabId)) return [...restored, activeTabId];
  return restored.map((tabId) => (tabId === replacedSessionTabId ? activeTabId : tabId));
}
