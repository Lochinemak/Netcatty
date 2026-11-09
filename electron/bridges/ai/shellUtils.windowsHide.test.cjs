const test = require("node:test");
const assert = require("node:assert/strict");
const childProcess = require("node:child_process");

// Settings → AI resolves every agent CLI with `where`. Without windowsHide each
// lookup flashes a cmd window on Windows, so the options must always carry it.
function loadShellUtilsWithSpies() {
  const calls = [];
  const originalExecFile = childProcess.execFile;
  const originalExecFileSync = childProcess.execFileSync;
  childProcess.execFileSync = (command, args, options) => {
    calls.push({ command, args, options });
    return "C:\\tools\\claude.exe\r\n";
  };
  childProcess.execFile = (command, args, options, callback) => {
    calls.push({ command, args, options });
    process.nextTick(() => callback(null, "C:\\tools\\claude.exe\r\n", ""));
  };
  const modulePath = require.resolve("./shellUtils.cjs");
  delete require.cache[modulePath];
  try {
    return { shellUtils: require("./shellUtils.cjs"), calls };
  } finally {
    childProcess.execFile = originalExecFile;
    childProcess.execFileSync = originalExecFileSync;
    delete require.cache[modulePath];
  }
}

test("resolveCliFromPath hides the console window of the PATH lookup", () => {
  const { shellUtils, calls } = loadShellUtilsWithSpies();
  shellUtils.resolveCliFromPath("claude", { PATH: "C:\\tools" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.windowsHide, true);
});

test("resolveCliFromPathAsync hides the console window of the PATH lookup", async () => {
  const { shellUtils, calls } = loadShellUtilsWithSpies();
  await shellUtils.resolveCliFromPathAsync("codex", { PATH: "C:\\tools" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.windowsHide, true);
});
