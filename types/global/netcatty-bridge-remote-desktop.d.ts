declare global {
  /** `startRemoteDesktopSession` options (`RemoteDesktopOptions` in Rust). */
  interface NetcattyRemoteDesktopOptions {
    sessionId?: string;
    protocol: import("../../domain/remoteDesktop").RemoteDesktopProtocol;
    hostname: string;
    /** Defaults to 5900 (VNC) / 3389 (RDP). */
    port?: number;
    /** RDP user name. */
    username?: string;
    password?: string;
    /** RDP logon domain. */
    domain?: string;
    /** Desktop size to request (RDP). */
    width?: number;
    height?: number;
  }

  interface NetcattyBridge {
    /**
     * Open an embedded VNC / RDP session. Resolves with the session id once
     * the backend task is running; everything that follows — `connected`,
     * frames, and a final `closed` (which also reports connection failures) —
     * is delivered to `onEvent`, in order.
     */
    startRemoteDesktopSession?(
      options: NetcattyRemoteDesktopOptions,
      onEvent: (event: import("../../domain/remoteDesktop").RemoteDesktopEvent) => void,
    ): Promise<string>;
    /** Forward pointer / keyboard / clipboard input. Fire-and-forget. */
    sendRemoteDesktopInput?(
      sessionId: string,
      events: import("../../domain/remoteDesktop").RemoteDesktopInputEvent[],
    ): void;
    /** Close a session. Idempotent; `closed` is still delivered to `onEvent`. */
    closeRemoteDesktopSession?(sessionId: string): Promise<void>;
  }
}

export {};
