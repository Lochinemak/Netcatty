import { useMemo } from "react";
import { netcattyBridge } from "../../infrastructure/services/netcattyBridge";
import type { RemoteDesktopEvent, RemoteDesktopInputEvent } from "../../domain/remoteDesktop";

export interface RemoteDesktopBackend {
  /** Whether this runtime can host VNC / RDP sessions at all. */
  available(): boolean;
  /**
   * Open a session. Resolves with the backend session id; connection
   * progress, frames and the final `closed` are delivered to `onEvent`.
   */
  start(options: NetcattyRemoteDesktopOptions, onEvent: (event: RemoteDesktopEvent) => void): Promise<string>;
  sendInput(sessionId: string, events: RemoteDesktopInputEvent[]): void;
  /** Close a session. Never throws: closing races with the session ending. */
  close(sessionId: string): void;
  /** Best-effort write of remote clipboard text to the local clipboard. */
  writeClipboardText(text: string): void;
}

/** Bridge access for remote desktop (VNC / RDP) panes. Stable across renders. */
export const remoteDesktopBackend: RemoteDesktopBackend = {
  available: () => !!netcattyBridge.get()?.startRemoteDesktopSession,
  start: (options, onEvent) => {
    const start = netcattyBridge.get()?.startRemoteDesktopSession;
    if (!start) return Promise.reject(new Error("Remote desktop sessions are unavailable"));
    return start(options, onEvent);
  },
  sendInput: (sessionId, events) => {
    netcattyBridge.get()?.sendRemoteDesktopInput?.(sessionId, events);
  },
  close: (sessionId) => {
    void netcattyBridge.get()?.closeRemoteDesktopSession?.(sessionId)?.catch(() => {});
  },
  writeClipboardText: (text) => {
    void netcattyBridge.get()?.writeClipboardText?.(text)?.catch(() => {});
  },
};

export const useRemoteDesktopBackend = (): RemoteDesktopBackend => useMemo(() => remoteDesktopBackend, []);
