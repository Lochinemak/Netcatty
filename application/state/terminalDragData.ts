export const WORKSPACE_SESSION_DRAG_TYPE = 'application/x-netcatty-workspace-session';

type DataTransferLike = {
  types: DOMStringList | readonly string[];
  getData: (format: string) => string;
};

export function dataTransferHasType(dataTransfer: Pick<DataTransferLike, 'types'>, type: string): boolean {
  return Array.prototype.includes.call(dataTransfer.types, type);
}

export function hasWorkspaceSessionDrag(dataTransfer: Pick<DataTransferLike, 'types'>): boolean {
  return dataTransferHasType(dataTransfer, WORKSPACE_SESSION_DRAG_TYPE);
}

export function getWorkspaceSessionDragId(dataTransfer: DataTransferLike): string {
  return dataTransfer.getData(WORKSPACE_SESSION_DRAG_TYPE) || dataTransfer.getData('session-id');
}

export function isPointInsideRect(
  point: { clientX: number; clientY: number },
  rect: Pick<DOMRect, 'left' | 'right' | 'top' | 'bottom'>,
): boolean {
  return point.clientX >= rect.left
    && point.clientX <= rect.right
    && point.clientY >= rect.top
    && point.clientY <= rect.bottom;
}

export type TopTabInsertionTarget = {
  tabId: string;
  position: 'before' | 'after';
};

export function getTopTabInsertionTarget(
  point: { clientX: number; clientY: number },
  topTabsRoot: HTMLElement | null,
): TopTabInsertionTarget | null {
  if (!topTabsRoot || !isPointInsideRect(point, topTabsRoot.getBoundingClientRect())) return null;

  const tabs = Array.from(topTabsRoot.querySelectorAll<HTMLElement>('[data-tab-id]'))
    .filter((tab) => tab.dataset.tabType !== 'root');

  if (tabs.length === 0) return null;

  for (const tab of tabs) {
    const rect = tab.getBoundingClientRect();
    const midpoint = rect.left + rect.width / 2;
    const tabId = tab.dataset.tabId;
    if (!tabId) continue;
    if (point.clientX <= midpoint) {
      return { tabId, position: 'before' };
    }
    if (point.clientX <= rect.right) {
      return { tabId, position: 'after' };
    }
  }

  const lastTab = tabs[tabs.length - 1];
  const lastTabId = lastTab?.dataset.tabId;
  return lastTabId ? { tabId: lastTabId, position: 'after' } : null;
}

/** Tab kinds a workspace pane can be merged into. */
const PANE_MERGE_TAB_TYPES = new Set(['session', 'workspace']);

/**
 * Fraction of a tab's width, on each side, that keeps the "insert as a
 * standalone tab before/after" behaviour. The middle is the merge zone.
 */
export const TOP_TAB_MERGE_EDGE_RATIO = 0.25;

/**
 * Terminal tab whose middle zone is under the pointer, i.e. the tab a dragged
 * workspace pane should be moved into. Returns null near a tab's edges, over
 * non-terminal tabs, and outside the tab bar.
 */
export function getTopTabMergeTarget(
  point: { clientX: number; clientY: number },
  topTabsRoot: HTMLElement | null,
): string | null {
  if (!topTabsRoot || !isPointInsideRect(point, topTabsRoot.getBoundingClientRect())) return null;

  const tabs = Array.from(topTabsRoot.querySelectorAll<HTMLElement>('[data-tab-id]'));
  for (const tab of tabs) {
    const tabId = tab.dataset.tabId;
    if (!tabId || !PANE_MERGE_TAB_TYPES.has(tab.dataset.tabType ?? '')) continue;
    const rect = tab.getBoundingClientRect();
    const edge = (rect.right - rect.left) * TOP_TAB_MERGE_EDGE_RATIO;
    if (point.clientX >= rect.left + edge && point.clientX <= rect.right - edge) return tabId;
  }
  return null;
}
