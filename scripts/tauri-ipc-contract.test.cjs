/**
 * Guard for the hand-written Tauri IPC contract.
 *
 * Nothing ties its two sides together: `commands::handler()` in the Rust app
 * registers the commands, and the renderer adapter in `infrastructure/tauri`
 * invokes them by name. Rename one side only and nothing complains until a
 * user reaches that feature, so a method no test exercises can stay broken
 * indefinitely. The same gap let `clearPendingTransferCancel` and
 * `retainSftpTransferSession` sit in the adapter as hard-coded answers that
 * never reached the backend.
 *
 * Every scan here parses strictly and asserts its own yield: a scanner that
 * silently matches nothing would make the whole file pass for the wrong
 * reason (the first draft of this guard did exactly that -- its regex for
 * `invoke<T>(...)` broke on the nested generics in `invoke<Result<'x'>>(...)`
 * and quietly lost 250 call sites).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.join(__dirname, "..");
const read = (relative) => fs.readFileSync(path.join(repoRoot, relative), "utf8");

const listFiles = (relativeDir, keep) => {
  const absolute = path.join(repoRoot, relativeDir);
  const out = [];
  for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
    const child = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) out.push(...listFiles(child, keep));
    else if (keep(entry.name)) out.push(child);
  }
  return out.sort();
};

// ---------------------------------------------------------------------------
// The Rust side: commands registered in `tauri::generate_handler![...]`
// ---------------------------------------------------------------------------

const registered = (() => {
  const source = read("rust/apps/netcatty-desktop/src/commands/mod.rs");
  const block = source.match(/tauri::generate_handler!\[\n([\s\S]*?)\n\s*\]\n/);
  assert.ok(block, "commands::handler() no longer uses tauri::generate_handler![...]");
  const names = new Map();
  for (const raw of block[1].split("\n")) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (!line) continue;
    const parsed = line.match(/^((?:[a-z_0-9]+::)*)([a-z_0-9]+),$/);
    assert.ok(parsed, `unrecognised line in generate_handler!: ${line}`);
    names.set(parsed[2], `${parsed[1]}${parsed[2]}`);
  }
  return names;
})();

// ---------------------------------------------------------------------------
// The caller side: `invoke("…")` in the renderer adapter and in the host
// browser's own webview adapter (the only other page that invokes commands).
// ---------------------------------------------------------------------------

const callerFiles = [
  ...listFiles("infrastructure/tauri", (name) => name.endsWith(".ts") && !name.endsWith(".test.ts")),
  ...listFiles("rust/apps/netcatty-desktop/hostbrowser", (name) => name.endsWith(".js")),
];

/**
 * Name of the function called at `parenIndex`, skipping a type-argument list.
 * Returns "" when the text before the call is not a plain callee.
 */
const calleeAt = (source, parenIndex) => {
  let i = parenIndex - 1;
  const skipSpace = () => {
    while (i >= 0 && /\s/.test(source[i])) i -= 1;
  };
  skipSpace();
  if (source[i] === ">") {
    let depth = 0;
    for (; i >= 0; i -= 1) {
      if (source[i] === ">") depth += 1;
      else if (source[i] === "<") {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    if (i < 0) return "";
    i -= 1;
    skipSpace();
  }
  const end = i + 1;
  while (i >= 0 && /[A-Za-z0-9_$.]/.test(source[i])) i -= 1;
  return source.slice(i + 1, end);
};

const invoked = new Map();
for (const file of callerFiles) {
  const source = read(file);
  for (const match of source.matchAll(/\(\s*(['"])([a-z][a-z_0-9]*)\1/g)) {
    if (!/(^|\.)invoke[A-Za-z]*$/.test(calleeAt(source, match.index))) continue;
    const callers = invoked.get(match[2]) ?? new Set();
    callers.add(file);
    invoked.set(match[2], callers);
  }
}

/** Does any caller file mention `command` as a string literal at all? */
const namedSomewhere = (() => {
  const sources = callerFiles.map((file) => read(file));
  return (command) => sources.some((source) => source.includes(`'${command}'`) || source.includes(`"${command}"`));
})();

// ---------------------------------------------------------------------------
// Commands with no caller. Each one is either an unfinished renderer path or
// dead weight, so it has to be named here with the reason it is neither.
// ---------------------------------------------------------------------------

const COMMANDS_WITHOUT_A_CALLER = new Map([
  ["store_get", "the renderer persists through localStorageAdapter; this store backs Rust-side callers only"],
  ["store_set", "the renderer persists through localStorageAdapter; this store backs Rust-side callers only"],
  ["store_remove", "the renderer persists through localStorageAdapter; this store backs Rust-side callers only"],
  ["store_keys", "the renderer persists through localStorageAdapter; this store backs Rust-side callers only"],
  ["app_reveal_in_folder", "no renderer path reveals a file yet; Electron's shell.showItemInFolder has no caller either"],
]);

// ---------------------------------------------------------------------------
// Adapter methods that answer with a literal instead of reaching the backend.
// Each one has to be named below: either the contract genuinely has nothing to
// call, or it is a gap, and then it says what the backend is missing.
// ---------------------------------------------------------------------------

/** Nothing to call: the Tauri design does not need the Electron round trip. */
const NOTHING_TO_CALL = new Map([
  [
    "releaseSftpTransferSession",
    "there is no lease to give back: a transfer holds its Arc<SftpClient>, so sftp_close cannot close it underneath",
  ],
  [
    "resumeTransfer",
    "the contract has no resume command; a paused transfer is restarted through startStreamTransfer with its checkpoint",
  ],
  [
    "unsubscribePortForwardRuntime",
    "Rust always broadcasts the runtime events, so there is no subscription to tear down",
  ],
  [
    "onTerminalOutputDrainRequest",
    "Electron's interrupt output gate asks the renderer to confirm it drained the main process's buffered output; Rust buffers nothing per window, so it never asks",
  ],
  [
    "respondTerminalOutputDrain",
    "the answer to a request that is never made (see onTerminalOutputDrainRequest)",
  ],
  [
    "notifyTerminalSessionDisplayReady",
    "Electron retries output it held for a webContents; here the backlog lives in the renderer (tauriApi.ts SessionDataBacklog), so there is nothing to retry",
  ],
]);

/** A real gap: the method answers, but the work does not happen. */
const NOT_IMPLEMENTED = new Map([
  [
    "clearSessionPtyBuffer",
    "Windows only: netcatty-pty has no ConPTY buffer clear (portable-pty exposes none), so after the renderer clears the viewport the shell can reprint from the old cursor row — the gap Electron's terminalBridge.cjs clearSessionPtyBuffer closes",
  ],
]);

const implementationFiles = [
  "infrastructure/tauri/createTauriBridge.ts",
  ...listFiles("infrastructure/tauri/bridge", (name) => name.endsWith(".ts") && !name.endsWith(".test.ts")),
];

/**
 * Methods the contract declares on `window.netcatty`. Only these matter here:
 * the adapter files also build internal objects whose fields are arrows.
 */
const declaredMethods = (() => {
  const names = new Set();
  for (const file of listFiles("types/global", (name) => name.endsWith(".d.ts"))) {
    for (const match of read(file).matchAll(/^[ \t]+([a-zA-Z_][A-Za-z0-9_]*)\??\(/gm)) {
      names.add(match[1]);
    }
  }
  return names;
})();

/**
 * Source of the arrow body that starts after `=>` at `arrowEnd`, up to the
 * comma that ends its property. Type arguments are counted as depth too:
 * `invoke<Record<string, unknown>>(…)` holds a comma that is not one.
 */
const arrowBody = (source, arrowEnd) => {
  let depth = 0;
  let generic = 0;
  for (let i = arrowEnd; i < source.length; i += 1) {
    const char = source[i];
    if (char === "'" || char === '"' || char === "`") {
      for (i += 1; i < source.length; i += 1) {
        if (source[i] === "\\") i += 1;
        else if (source[i] === char) break;
      }
      continue;
    }
    if (char === "/" && source[i + 1] === "/") {
      i = source.indexOf("\n", i);
      if (i < 0) break;
      continue;
    }
    if (char === "/" && source[i + 1] === "*") {
      i = source.indexOf("*/", i);
      if (i < 0) break;
      i += 1;
      continue;
    }
    if ("([{".includes(char)) depth += 1;
    else if (")]}".includes(char)) {
      depth -= 1;
      // The property list's own closing brace: the body ended without a comma.
      if (depth < 0) return source.slice(arrowEnd, i);
    } else if (char === "<" && /[A-Za-z0-9_$]/.test(source[i - 1] ?? "")) generic += 1;
    else if (char === ">" && generic > 0 && source[i - 1] !== "=") generic -= 1;
    else if (char === "," && depth === 0 && generic === 0) return source.slice(arrowEnd, i);
  }
  return source.slice(arrowEnd);
};

/** Index just past the `)` matching the `(` at `open`, or -1. */
const closingParen = (source, open) => {
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === "(") depth += 1;
    else if (source[i] === ")") {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
};

/**
 * A body that answers with a literal and computes nothing: no call, no await.
 * It has to *start* like a value too — a body starting with an identifier is
 * either a return type (`=> Promise<…>`, `=> void`, so the match was a type
 * annotation, not a method) or state the adapter already holds.
 */
const isLiteralAnswer = (body) => {
  const bare = body
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/`(?:\\.|[^`\\])*`/g, "``");
  if (!/^\s*([([{'"`]|-?[0-9]|true\b|false\b|null\b|undefined\b)/.test(bare)) return false;
  return !/[A-Za-z0-9_$>]\s*\(/.test(bare) && !/\bawait\b/.test(bare);
};

const literalAnswers = new Map();
let arrowMethods = 0;
for (const file of implementationFiles) {
  const source = read(file);
  for (const match of source.matchAll(/^[ \t]+([a-zA-Z_][A-Za-z0-9_]*): (?:async )?\(/gm)) {
    const open = match.index + match[0].length - 1;
    const afterParams = closingParen(source, open);
    if (afterParams < 0) continue;
    const arrow = source.slice(afterParams).match(/^\s*=>/);
    if (!arrow) continue;
    if (!declaredMethods.has(match[1])) continue;
    arrowMethods += 1;
    const body = arrowBody(source, afterParams + arrow[0].length);
    if (isLiteralAnswer(body)) literalAnswers.set(match[1], file);
  }
}

// ---------------------------------------------------------------------------

test("the contract scanners still find both sides", () => {
  // Floors, not exact counts: they catch a scanner that stopped matching,
  // which would make every assertion below vacuously true.
  assert.ok(registered.size > 400, `only ${registered.size} registered commands parsed`);
  assert.ok(invoked.size > 350, `only ${invoked.size} invoked commands found`);
  assert.ok(declaredMethods.size > 400, `only ${declaredMethods.size} declared bridge methods parsed`);
  assert.ok(arrowMethods > 250, `only ${arrowMethods} implemented bridge methods found`);
  assert.ok(
    callerFiles.includes("rust/apps/netcatty-desktop/hostbrowser/tauri-adapter.js"),
    "the host browser webview invokes commands too and must be scanned",
  );
});

test("every command the adapter invokes is registered in commands::handler()", () => {
  const missing = [...invoked.keys()]
    .filter((command) => !registered.has(command))
    .sort()
    .map((command) => `${command} (from ${[...invoked.get(command)].join(", ")})`);
  assert.deepEqual(
    missing,
    [],
    "these commands are invoked but not registered — a rename or a typo; the call fails at runtime",
  );
});

test("every registered command has a caller, or says why it has none", () => {
  const uncalled = [...registered.keys()].filter((command) => !namedSomewhere(command)).sort();
  assert.deepEqual(
    uncalled,
    [...COMMANDS_WITHOUT_A_CALLER.keys()].sort(),
    "a registered command nothing calls is an unfinished renderer path or dead weight: " +
      "wire it up, delete it, or add it to COMMANDS_WITHOUT_A_CALLER with the reason",
  );
});

test("every adapter method that answers with a literal is accounted for", () => {
  assert.deepEqual(
    [...literalAnswers.keys()].sort(),
    [...NOTHING_TO_CALL.keys(), ...NOT_IMPLEMENTED.keys()].sort(),
    "a method that answers without reaching the backend silently does nothing: implement it, " +
      "or name it in NOTHING_TO_CALL (there is no command to call) or NOT_IMPLEMENTED (there is, and this is a gap)",
  );
  for (const name of NOT_IMPLEMENTED.keys()) {
    assert.ok(!NOTHING_TO_CALL.has(name), `${name} cannot be both a gap and nothing to call`);
  }
});

test("each documented gap carries a reason", () => {
  for (const [name, reason] of [...COMMANDS_WITHOUT_A_CALLER, ...NOTHING_TO_CALL, ...NOT_IMPLEMENTED]) {
    assert.ok(reason.length > 20, `${name} needs a real reason, not "${reason}"`);
  }
});
