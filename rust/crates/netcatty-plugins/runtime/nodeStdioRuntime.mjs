// Netcatty plugin runtime bootstrap for a Node sidecar (Tauri host).
//
// Equivalent of electron/plugins/runtime/utilityRuntime.mjs, but the host
// link is newline-delimited JSON over stdin/stdout instead of an Electron
// utilityProcess parentPort. The same runtimePeer.mjs speaks the plugin
// JSON-RPC contract on top of a MessagePort-shaped shim, so plugins built
// with @netcatty/plugin-sdk run unchanged.
//
// Wire format (one JSON object per line):
//   { "data": <message>, "transferBase64"?: "...", "ports"?: ["p1"], "port"?: "p1", "close"?: true }
// - `transferBase64` carries the single ArrayBuffer transfer of a stream or
//   interceptor chunk;
// - `ports` lists virtual MessagePorts transferred with a message (terminal
//   interceptor attachment); messages addressed to a virtual port carry
//   `port`; `close` closes a virtual port.
// console output is redirected to stderr so stdout stays a protocol channel.

import { register } from "node:module";
import process from "node:process";
import { createInterface } from "node:readline";

for (const method of ["log", "info", "debug", "trace", "dir", "table"]) {
  // eslint-disable-next-line no-console
  console[method] = (...args) => process.stderr.write(`${args.map(String).join(" ")}\n`);
}

const stdoutWrite = process.stdout.write.bind(process.stdout);
process.stdout.write = (chunk, ...rest) => process.stderr.write(chunk, ...rest);

function toBase64(buffer) {
  return Buffer.from(new Uint8Array(buffer)).toString("base64");
}

function fromBase64(text) {
  const bytes = Buffer.from(text, "base64");
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

const virtualPorts = new Map();

function send(envelope) {
  stdoutWrite(`${JSON.stringify(envelope)}\n`);
}

function encodeOutbound(message, transfer, portId) {
  const envelope = { data: message };
  if (portId !== undefined) envelope.port = portId;
  for (const item of transfer ?? []) {
    if (item instanceof ArrayBuffer) {
      envelope.transferBase64 = toBase64(item);
      if (message && typeof message === "object" && "transfer" in message) {
        envelope.data = { ...message };
        delete envelope.data.transfer;
      }
    } else if (item && typeof item === "object" && item.__virtualPortId !== undefined) {
      (envelope.ports ??= []).push(item.__virtualPortId);
    }
  }
  return envelope;
}

function createPort(portId) {
  const listeners = new Set();
  const port = {
    __virtualPortId: portId,
    addEventListener(type, listener) { if (type === "message") listeners.add(listener); },
    removeEventListener(type, listener) { if (type === "message") listeners.delete(listener); },
    on(type, listener) { if (type === "message") listeners.add(listener); },
    start() {},
    close() {
      listeners.clear();
      if (portId !== undefined) {
        virtualPorts.delete(portId);
        send({ port: portId, close: true });
      }
    },
    postMessage(message, transfer = []) { send(encodeOutbound(message, transfer, portId)); },
    dispatch(data, ports) {
      for (const listener of [...listeners]) listener({ data, ports });
    },
  };
  return port;
}

const hostPort = createPort(undefined);

function decodeInbound(envelope) {
  let data = envelope.data;
  if (typeof envelope.transferBase64 === "string") {
    data = { ...data, transfer: fromBase64(envelope.transferBase64) };
  }
  const ports = (envelope.ports ?? []).map((id) => {
    const port = createPort(String(id));
    virtualPorts.set(String(id), port);
    return port;
  });
  return { data, ports };
}

let resolveBootstrap;
const bootstrapPromise = new Promise((resolve) => { resolveBootstrap = resolve; });
const queued = [];
let started = false;

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on("line", (line) => {
  if (!line) return;
  let envelope;
  try { envelope = JSON.parse(line); } catch { process.exit(70); }
  if (!started) {
    if (envelope?.data?.type === "netcatty-plugin:bootstrap") {
      resolveBootstrap(envelope.data);
      return;
    }
    queued.push(envelope);
    return;
  }
  route(envelope);
});
lines.on("close", () => process.exit(0));

function route(envelope) {
  if (envelope.port !== undefined) {
    const port = virtualPorts.get(String(envelope.port));
    if (!port) return;
    if (envelope.close) { virtualPorts.delete(String(envelope.port)); return; }
    const { data } = decodeInbound(envelope);
    port.dispatch(data, []);
    return;
  }
  const { data, ports } = decodeInbound(envelope);
  hostPort.dispatch(data, ports);
}

const bootstrap = await bootstrapPromise;
register(new URL(bootstrap.loaderUrl), {
  parentURL: import.meta.url,
  data: { mappings: bootstrap.config.moduleMappings },
});
const { startPluginRuntime } = await import(bootstrap.runtimePeerUrl);
const startup = startPluginRuntime({
  port: hostPort,
  config: bootstrap.config,
  loadPlugin: (entryUrl) => import(entryUrl),
});
started = true;
for (const envelope of queued.splice(0)) route(envelope);
await startup;
send({ data: { type: "netcatty-plugin:ready" } });
