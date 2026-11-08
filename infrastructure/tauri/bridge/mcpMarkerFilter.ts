/**
 * Hides the internal `__NCMCP_` marker lines of AI command execution from
 * terminal display (port of `filterMcpChunk` in `electron/preload.cjs`).
 *
 * PTY output arrives in arbitrary chunks and a marker may be split across
 * them, so the trailing fragment of each chunk is held back and prepended to
 * the next one; complete lines containing a marker are dropped. Held text
 * that is not followed by more data is released after a short delay.
 * Chunks emitted with `syntheticEcho` (the visible echo of an AI command)
 * bypass the filter.
 */

const MARKER = '__NCMCP_';
const PROBE_PREFIX = ' true __NCMCP_';
const MAX_BUFFERED_LINE_CHARS = 64 * 1024;
export const MCP_FLUSH_DELAY_MS = 80;

/** True when `s` ends with a non-empty prefix of a marker (or the probe prefix). */
export function endsWithMarkerPrefix(s: string): boolean {
  for (let i = 1; i < MARKER.length; i++) {
    if (s.endsWith(MARKER.slice(0, i))) return true;
  }
  for (let i = 2; i < PROBE_PREFIX.length; i++) {
    if (s.endsWith(PROBE_PREFIX.slice(0, i))) return true;
  }
  return false;
}

export interface McpMarkerFilterOptions<M> {
  /** Deliver filtered output (also used by the delayed flush). */
  deliver: (sessionId: string, data: string, meta: M | undefined) => void;
  setTimer?: (cb: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
}

export class McpMarkerFilter<M = unknown> {
  private readonly lineBufs = new Map<string, string>();
  private readonly lineMetas = new Map<string, M | undefined>();
  private readonly timers = new Map<string, unknown>();
  private readonly droppingWrapped = new Set<string>();
  private readonly probePrompts = new Map<string, string>();
  private readonly abortedProbes = new Map<string, Set<string>>();
  private readonly deliverFn: McpMarkerFilterOptions<M>['deliver'];
  private readonly setTimer: (cb: () => void, ms: number) => unknown;
  private readonly clearTimer: (handle: unknown) => void;

  constructor(options: McpMarkerFilterOptions<M>) {
    this.deliverFn = options.deliver;
    this.setTimer = options.setTimer ?? ((cb, ms) => setTimeout(cb, ms));
    this.clearTimer = options.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));
  }

  /** Route one output chunk of `sessionId`. */
  push(sessionId: string, chunk: string, meta?: M, syntheticEcho = false): void {
    if (syntheticEcho) {
      this.deliverFn(sessionId, chunk, meta);
      return;
    }
    const out = this.filter(sessionId, chunk, meta);
    if (out) this.deliverFn(sessionId, out, meta);
    if (this.lineBufs.has(sessionId)) {
      this.timers.set(sessionId, this.setTimer(() => this.flush(sessionId), MCP_FLUSH_DELAY_MS));
    }
  }

  /** Forget all state of a closed session. */
  clear(sessionId: string): void {
    const t = this.timers.get(sessionId);
    if (t !== undefined) this.clearTimer(t);
    this.timers.delete(sessionId);
    this.lineBufs.delete(sessionId);
    this.lineMetas.delete(sessionId);
    this.droppingWrapped.delete(sessionId);
    this.probePrompts.delete(sessionId);
    this.abortedProbes.delete(sessionId);
  }

  private probeFragment(sessionId: string, fragment: string): boolean {
    const reset = fragment.match(/(__NCMCP_(?:(?!__NCMCP_)[A-Za-z0-9_])+)_R/);
    if (reset) {
      const aborted = this.abortedProbes.get(sessionId) ?? new Set<string>();
      aborted.add(reset[1]);
      if (aborted.size > 32) aborted.delete(aborted.values().next().value as string);
      this.abortedProbes.set(sessionId, aborted);
      if (this.probePrompts.get(sessionId) === reset[1]) this.probePrompts.delete(sessionId);
      return true;
    }
    const completion = fragment.match(/^\r?(__NCMCP_[A-Za-z0-9_]+)_[IQ]/);
    if (completion && !this.abortedProbes.get(sessionId)?.has(completion[1])) {
      this.probePrompts.set(sessionId, completion[1]);
    }
    const marker = this.probePrompts.get(sessionId);
    if (!marker) return false;
    const line = fragment.replace(/^\r/, '');
    if (line.startsWith(`${marker}_S`) || line.startsWith(`${marker}_E`)) {
      this.probePrompts.delete(sessionId);
    }
    return true;
  }

  private filter(sessionId: string, chunk: string, meta: M | undefined): string {
    const pending = this.timers.get(sessionId);
    if (pending !== undefined) {
      this.clearTimer(pending);
      this.timers.delete(sessionId);
    }
    const held = this.lineBufs.get(sessionId) ?? '';
    this.lineBufs.delete(sessionId);
    this.lineMetas.delete(sessionId);
    const data = held + chunk;
    if (!this.droppingWrapped.has(sessionId) && !this.probePrompts.has(sessionId) && !data.includes(MARKER) && !endsWithMarkerPrefix(data)) {
      return data;
    }
    let result = '';
    let droppedAny = this.droppingWrapped.has(sessionId);
    let pos = 0;
    while (pos < data.length) {
      const nl = data.indexOf('\n', pos);
      if (nl === -1) {
        const tail = data.slice(pos);
        const probe = this.probeFragment(sessionId, tail);
        if (probe || droppedAny || tail.includes(MARKER) || endsWithMarkerPrefix(tail)) {
          if (tail.length <= MAX_BUFFERED_LINE_CHARS) {
            this.lineBufs.set(sessionId, tail);
            this.lineMetas.set(sessionId, meta);
          } else {
            this.droppingWrapped.add(sessionId);
          }
          if (probe || droppedAny || tail.includes(MARKER)) this.droppingWrapped.add(sessionId);
        } else {
          result += tail;
        }
        break;
      }
      const line = data.slice(pos, nl + 1);
      const probe = this.probeFragment(sessionId, line);
      if (probe || droppedAny || line.includes(MARKER)) {
        droppedAny = false;
        this.droppingWrapped.delete(sessionId);
      } else {
        result += line;
      }
      pos = nl + 1;
    }
    return result;
  }

  private flush(sessionId: string): void {
    this.timers.delete(sessionId);
    const held = this.lineBufs.get(sessionId);
    const meta = this.lineMetas.get(sessionId);
    this.lineBufs.delete(sessionId);
    this.lineMetas.delete(sessionId);
    if (this.droppingWrapped.has(sessionId)) {
      // Keep a bounded partial marker so a late suffix still updates the
      // probe lifecycle; otherwise keep discarding until the newline.
      if (held && /^\r?__NCMCP_[A-Za-z0-9_]*$/.test(held) && held.length <= 256) {
        this.lineBufs.set(sessionId, held);
        this.lineMetas.set(sessionId, meta);
      }
      return;
    }
    if (held) this.deliverFn(sessionId, held, meta);
  }
}
