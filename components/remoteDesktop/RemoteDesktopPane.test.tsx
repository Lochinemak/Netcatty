import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { JSDOM } from 'jsdom';

import type { RemoteDesktopEvent, RemoteDesktopInputEvent } from '../../domain/remoteDesktop';
import type { Host } from '../../types';
import { RemoteDesktopPane, resolveRequestedDesktopSize } from './RemoteDesktopPane';

const rdpHost = {
  id: 'rdp-1',
  label: 'Build box',
  hostname: 'win.example.test',
  port: 3389,
  username: 'alice',
  password: 'pw',
  rdpDomain: 'CORP',
  tags: [],
  os: 'windows',
  protocol: 'rdp',
} as unknown as Host;

const vncHost = {
  id: 'vnc-1',
  label: 'Lab desk',
  hostname: 'desk.example.test',
  port: 5901,
  username: '',
  tags: [],
  os: 'linux',
  protocol: 'vnc',
} as unknown as Host;

interface FakeBackend {
  starts: Array<{ options: NetcattyRemoteDesktopOptions; emit: (event: RemoteDesktopEvent) => void }>;
  inputs: Array<{ sessionId: string; events: RemoteDesktopInputEvent[] }>;
  closes: string[];
  clipboard: string[];
}

/** JSDOM + a fake `window.netcatty` remote desktop bridge. */
function mountEnvironment(t: TestContext, options: { withBridge?: boolean } = {}) {
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost', pretendToBeVisual: true });
  const backend: FakeBackend = { starts: [], inputs: [], closes: [], clipboard: [] };
  // Run animation frames on demand so input batching is deterministic.
  const frames: FrameRequestCallback[] = [];
  dom.window.requestAnimationFrame = (callback: FrameRequestCallback) => frames.push(callback);
  dom.window.cancelAnimationFrame = () => {};
  // JSDOM has no canvas implementation; painting is not under test here.
  dom.window.HTMLCanvasElement.prototype.getContext = (() => null) as never;
  if (options.withBridge !== false) {
    (dom.window as unknown as { netcatty: Partial<NetcattyBridge> }).netcatty = {
      startRemoteDesktopSession: async (startOptions, onEvent) => {
        backend.starts.push({ options: startOptions, emit: onEvent });
        return `backend-${backend.starts.length}`;
      },
      sendRemoteDesktopInput: (sessionId, events) => {
        backend.inputs.push({ sessionId, events });
      },
      closeRemoteDesktopSession: async (sessionId) => {
        backend.closes.push(sessionId);
      },
      writeClipboardText: async (text) => {
        backend.clipboard.push(text);
        return true;
      },
    };
  }

  const globals = {
    window: dom.window,
    document: dom.window.document,
    navigator: dom.window.navigator,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
  };
  const previous = new Map<string, PropertyDescriptor | undefined>();
  for (const [key, value] of Object.entries(globals)) {
    previous.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { configurable: true, value });
  }
  const root = createRoot(dom.window.document.getElementById('root')!);
  let unmounted = false;
  const unmount = async () => {
    if (unmounted) return;
    unmounted = true;
    await act(async () => root.unmount());
  };
  t.after(async () => {
    await unmount();
    dom.window.close();
    for (const [key, descriptor] of previous) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
  });

  const runFrames = async () => {
    await act(async () => {
      for (const callback of frames.splice(0)) callback(0);
    });
  };
  const canvas = () => dom.window.document.querySelector('canvas') as HTMLCanvasElement;
  const pane = () => dom.window.document.querySelector('[data-section="remote-desktop-pane"]') as HTMLElement;
  return { dom, backend, root, unmount, runFrames, canvas, pane };
}

const statusRecorder = () => {
  const statuses: string[] = [];
  return { statuses, onStatusChange: (_id: string, status: string) => { statuses.push(status); } };
};

test('an RDP pane connects with the host credentials and forwards input until it closes', async (t) => {
  const env = mountEnvironment(t);
  const { statuses, onStatusChange } = statusRecorder();

  await act(async () => {
    env.root.render(
      <RemoteDesktopPane
        host={rdpHost}
        protocol="rdp"
        sessionId="session-1"
        keys={[]}
        identities={[]}
        isVisible
        isFocused
        inWorkspace={false}
        onStatusChange={onStatusChange}
      />,
    );
  });

  assert.equal(env.backend.starts.length, 1);
  assert.deepEqual(env.backend.starts[0].options, {
    protocol: 'rdp',
    hostname: 'win.example.test',
    port: 3389,
    username: 'alice',
    password: 'pw',
    domain: 'CORP',
    // The pane has no layout in JSDOM, so the default desktop size is requested.
    width: 1280,
    height: 800,
  });
  assert.equal(env.pane().dataset.remoteDesktopStatus, 'connecting');

  await act(async () => env.backend.starts[0].emit({ type: 'connected', width: 1024, height: 768 }));
  assert.equal(env.pane().dataset.remoteDesktopStatus, 'connected');
  assert.deepEqual(statuses, ['connecting', 'connected']);
  assert.equal(env.canvas().width, 1024);
  assert.equal(env.canvas().height, 768);

  // Key presses are batched per animation frame and carry both keyspaces.
  const KeyboardEvent = env.dom.window.KeyboardEvent;
  await act(async () => {
    env.canvas().dispatchEvent(new KeyboardEvent('keydown', { key: 'a', code: 'KeyA', bubbles: true, cancelable: true }));
    env.canvas().dispatchEvent(new KeyboardEvent('keyup', { key: 'a', code: 'KeyA', bubbles: true, cancelable: true }));
  });
  assert.equal(env.backend.inputs.length, 0, 'nothing is sent before the frame');
  await env.runFrames();
  assert.deepEqual(env.backend.inputs, [{
    sessionId: 'backend-1',
    events: [
      { type: 'key', down: true, keysym: 0x61, scancode: 0x1e },
      { type: 'key', down: false, keysym: 0x61, scancode: 0x1e },
    ],
  }]);

  // A key still held when focus leaves is released on the remote side.
  await act(async () => {
    env.canvas().dispatchEvent(new KeyboardEvent('keydown', { key: 'Shift', code: 'ShiftLeft', bubbles: true, cancelable: true }));
    // React's onBlur is driven by the bubbling `focusout` event.
    env.canvas().dispatchEvent(new env.dom.window.FocusEvent('focusout', { bubbles: true }));
  });
  await env.runFrames();
  assert.deepEqual(env.backend.inputs[1].events, [
    { type: 'key', down: true, keysym: 0xffe1, scancode: 0x2a },
    { type: 'key', down: false, keysym: 0xffe1, scancode: 0x2a },
  ]);

  await act(async () => env.backend.starts[0].emit({ type: 'clipboard', text: 'copied remotely' }));
  assert.deepEqual(env.backend.clipboard, ['copied remotely']);

  await act(async () => env.backend.starts[0].emit({ type: 'closed', error: 'RDP session ended: logoff' }));
  assert.equal(env.pane().dataset.remoteDesktopStatus, 'disconnected');
  assert.deepEqual(statuses, ['connecting', 'connected', 'disconnected']);
  assert.match(env.pane().textContent ?? '', /RDP session ended: logoff/);
  // The backend session is gone: nothing left to close on unmount.
  await env.unmount();
  assert.deepEqual(env.backend.closes, []);
});

test('a VNC pane sends no user name, and unmounting closes the live session', async (t) => {
  const env = mountEnvironment(t);

  await act(async () => {
    env.root.render(
      <RemoteDesktopPane
        host={vncHost}
        protocol="vnc"
        sessionId="session-2"
        keys={[]}
        identities={[]}
        isVisible
        isFocused={false}
        inWorkspace
        onDetachPointerDown={() => {}}
      />,
    );
  });

  const options = env.backend.starts[0].options;
  assert.equal(options.protocol, 'vnc');
  assert.equal(options.port, 5901);
  assert.equal(options.username, undefined);
  assert.equal(options.domain, undefined);
  assert.equal(options.password, undefined);
  // In a workspace the pane exposes the same drag handle terminals do.
  assert.ok(env.pane().querySelector('[data-terminal-detach-drag-handle="true"]'));

  await act(async () => env.backend.starts[0].emit({ type: 'connected', width: 800, height: 600 }));
  await env.unmount();
  assert.deepEqual(env.backend.closes, ['backend-1']);
});

test('reconnect closes the current session and opens a new one', async (t) => {
  const env = mountEnvironment(t);
  await act(async () => {
    env.root.render(
      <RemoteDesktopPane
        host={vncHost}
        protocol="vnc"
        sessionId="session-3"
        keys={[]}
        identities={[]}
        isVisible
        isFocused
        inWorkspace={false}
      />,
    );
  });
  await act(async () => env.backend.starts[0].emit({ type: 'connected', width: 800, height: 600 }));

  const reconnect = env.pane().querySelector('button[aria-label="remoteDesktop.reconnect"]') as HTMLButtonElement;
  await act(async () => reconnect.click());

  assert.deepEqual(env.backend.closes, ['backend-1']);
  assert.equal(env.backend.starts.length, 2);
  assert.equal(env.pane().dataset.remoteDesktopStatus, 'connecting');
  // Late events of the replaced session must not touch the new attempt.
  await act(async () => env.backend.starts[0].emit({ type: 'closed', error: 'stale' }));
  assert.equal(env.pane().dataset.remoteDesktopStatus, 'connecting');
});

test('nothing is dialed when the credentials are unusable or the runtime lacks support', async (t) => {
  const env = mountEnvironment(t);
  const { statuses, onStatusChange } = statusRecorder();

  // RDP without a user name.
  await act(async () => {
    env.root.render(
      <RemoteDesktopPane
        host={{ ...rdpHost, username: ' ' } as Host}
        protocol="rdp"
        sessionId="session-4"
        keys={[]}
        identities={[]}
        isVisible
        isFocused
        inWorkspace={false}
        onStatusChange={onStatusChange}
      />,
    );
  });
  assert.equal(env.backend.starts.length, 0);
  assert.equal(env.pane().dataset.remoteDesktopStatus, 'disconnected');
  assert.match(env.pane().textContent ?? '', /remoteDesktop\.error\.usernameRequired/);
  assert.deepEqual(statuses, ['connecting', 'disconnected']);

  // A password that is still an encrypted vault blob must never be sent.
  const blob = `enc:v1:${Buffer.concat([Buffer.from('v10'), Buffer.alloc(32, 1)]).toString('base64')}`;
  await act(async () => {
    env.root.render(
      <RemoteDesktopPane
        key="blob"
        host={{ ...vncHost, password: blob } as Host}
        protocol="vnc"
        sessionId="session-5"
        keys={[]}
        identities={[]}
        isVisible
        isFocused
        inWorkspace={false}
      />,
    );
  });
  assert.equal(env.backend.starts.length, 0);
  assert.match(env.pane().textContent ?? '', /remoteDesktop\.error\.credentialsUnavailable/);
});

test('a runtime without remote desktop support reports it instead of connecting', async (t) => {
  const env = mountEnvironment(t, { withBridge: false });
  await act(async () => {
    env.root.render(
      <RemoteDesktopPane
        host={vncHost}
        protocol="vnc"
        sessionId="session-6"
        keys={[]}
        identities={[]}
        isVisible
        isFocused
        inWorkspace={false}
      />,
    );
  });
  assert.equal(env.pane().dataset.remoteDesktopStatus, 'disconnected');
  assert.match(env.pane().textContent ?? '', /remoteDesktop\.error\.unsupported/);
});

test('the requested desktop size follows the pane, clamped and even', () => {
  assert.deepEqual(resolveRequestedDesktopSize(null), { width: 1280, height: 800 });
  assert.deepEqual(resolveRequestedDesktopSize({ width: 0, height: 500 }), { width: 1280, height: 800 });
  assert.deepEqual(resolveRequestedDesktopSize({ width: 1437, height: 901 }), { width: 1436, height: 900 });
  assert.deepEqual(resolveRequestedDesktopSize({ width: 300, height: 200 }), { width: 800, height: 600 });
  assert.deepEqual(resolveRequestedDesktopSize({ width: 9000, height: 9000 }), { width: 4096, height: 4096 });
});

test('StrictMode double mounting dials the server exactly once', async (t) => {
  // React StrictMode mounts, unmounts and remounts every effect in development.
  // An RDP server allows one session per account, so a second throw-away
  // connection would disconnect the real one.
  const env = mountEnvironment(t);
  await act(async () => {
    env.root.render(
      <React.StrictMode>
        <RemoteDesktopPane
          host={rdpHost}
          protocol="rdp"
          sessionId="session-strict"
          keys={[]}
          identities={[]}
          isVisible
          isFocused
          inWorkspace={false}
        />
      </React.StrictMode>,
    );
  });

  assert.equal(env.backend.starts.length, 1);
  assert.deepEqual(env.backend.closes, []);
  assert.equal(env.pane().dataset.remoteDesktopStatus, 'connecting');

  await act(async () => env.backend.starts[0].emit({ type: 'connected', width: 800, height: 600 }));
  assert.equal(env.pane().dataset.remoteDesktopStatus, 'connected');
});
