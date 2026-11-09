# Script automation — IPC contract

Port of the Electron script automation (`electron/bridges/scriptBridge.cjs`,
`electron/scripts/*.cjs`). User scripts are JavaScript; they run in an
embedded QuickJS engine with the same `nct` API, the same argument shapes and
the same error messages, so existing user scripts and recorded scripts keep
working unchanged.

* Logic: `crates/netcatty-scripts` (no Tauri dependency, tested against a fake
  session host).
* Commands: `apps/netcatty-desktop/src/commands/scripts.rs`.
* Renderer adapter: `infrastructure/tauri/bridge/scripts.ts`
  (`createScriptsBridge`, spread into `createTauriBridge`).

General conventions (transport, `{ code, message }` errors, camelCase JSON)
are in [`ipc-contract.md`](ipc-contract.md).

## Commands

Run-control results are the Electron ones (`{ ok }`); only `script_run` and
`script_recording_start` reject (`INVALID_ARGUMENT` with the Electron message).

| Bridge method | Command | Args | Returns |
| --- | --- | --- | --- |
| `scriptRun(params)` | `script_run` | `payload: ScriptRunParams` | `{ runId, runIds }` |
| `scriptStop(runId)` | `script_stop` | `runId` | `{ ok }` |
| `scriptPause(runId)` | `script_pause` | `runId` | `{ ok }` |
| `scriptResume(runId)` | `script_resume` | `runId` | `{ ok }` |
| `scriptGetRuns(sessionId?)` | `script_get_runs` | `sessionId?` | `ScriptRun[]` |
| `scriptDialogResponse(requestId, value?, cancelled?)` | `script_dialog_response` | `payload: { requestId, value?, cancelled? }` | `{ ok }` |
| `scriptScreenSnapshotResponse(requestId, snapshot)` | `script_screen_snapshot_response` | `payload: { requestId, snapshot }` | `{ ok }` |
| `scriptRecordingStart(sessionId)` | `script_recording_start` | `sessionId` | `{ ok: true }` |
| `scriptRecordingStop(sessionId)` | `script_recording_stop` | `sessionId` | `{ steps, code }` |
| `scriptRecordingAppendStep(sessionId, step)` | `script_recording_append_step` | `payload: { sessionId, step }` | `{ ok, stopped?, reason?, error?, steps?, code? }` |

`script_run` (`ScriptRunParams`, `types/global/netcatty-bridge-script.d.ts`):

* Targets: `sessionIds` (non-empty) or `sessionId`; none → `No target
  session for script run`. Empty `content` → `Script content is empty`.
* `runId` (caller-chosen, ≤ 128 chars, unique) needs exactly one target,
  like `returnWhenQueued`. Errors: `A caller-provided runId requires exactly
  one target session`, `returnWhenQueued requires exactly one target
  session`, `Invalid script run id`, `Script run id already exists: <id>`.
* Runs on the same session are queued in call order (Electron's per-session
  promise chain). `mode: "sequential"` runs the targets one after another,
  otherwise in parallel. The command resolves when all runs ended, or right
  after queueing with `returnWhenQueued`.
* `script_stop` on a run that is still queued cancels it (`{ ok: true }`; it
  never starts or appears in `script_get_runs`).
* `permissionMode`: `observer` rejects every write
  (`Observer mode: screen.send is disabled. Switch to Confirm or Auto mode.`,
  also for `screen.sendLine`, `screen.clear`, `session.startLog`,
  `session.disconnect`); `confirm` / `auto` (default) allow them.
* `sessionMeta` is merged into what `nct.session` reports for sessions the
  registry does not know.

`ScriptRun` (the `serializeRun` shape): `runId, scriptId?, scriptLabel?,
sessionId, status ("running" | "paused" | "completed" | "failed"), startedAt,
endedAt?, currentStep?, stepIndex, progressMode ("activity" | "determinate"),
activityLabel?, progressLabel?, progressCurrent?, progressTotal?, elapsedMs,
waitingFor?, logs: { at, message }[] (newest 200), error?`. A stopped run
ends `failed` with `error: "Stopped by user"`; a failing script ends `failed`
with the error message, also appended to `logs`. At most 200 completed runs
are kept (oldest dropped first, active runs never).

Recording: steps are `{ type: "send", value, sensitive? } | { type: "waitFor",
value, timeoutMs? } | { type: "waitForPrompt", timeoutMs? } | { type:
"sleep", value }`; a `send` more than 1 s after the previous step gets a
`sleep` step first. Limits 10 000 steps / 2 MiB of step JSON: reaching one
stops the recording and returns `{ ok: false, stopped: true, reason: "limit",
error: "Recording stopped because it reached the safety limit", steps, code
}`. `code` is the Electron codegen output (`async function main() { ... }`
plus `await main();`, sensitive sends become a masked `nct.dialog.prompt`).

## Events

| Event | Payload |
| --- | --- |
| `netcatty:script:runs-updated` | `{ runs: ScriptRun[] }` after every run change |
| `netcatty:script:dialog-request` | `ScriptDialogRequest`: `{ requestId, type: "alert" \| "confirm" \| "prompt" \| "form" \| "waitForTimeout", message, defaultValue?, sensitive?, form?, pattern?, timeoutMs? }` |
| `netcatty:script:screen-snapshot-request` | `{ requestId, sessionId }`; answer with `script_screen_snapshot_response` |
| `netcatty:script:session-input` | `{ sessionId, data }` for every automated write (not `^C`) so the terminal scrolls to the bottom |

Dialogs time out after 120 s (`Dialog timed out`), a cancelled one rejects
with `Dialog cancelled`. Responses are coerced like Electron: `confirm` →
boolean, `prompt` → string, `form` → object, `waitForTimeout` →
`"retry" | "skip" | "abort"`. Snapshot requests fall back to the output
buffer after 3 s. When a run ends, its pending dialog / snapshot requests are
settled (default values; rejected when it was stopped) and a later response
returns `{ ok: false }`. Without any webview window, dialogs resolve with
their defaults and snapshots use the buffer, like Electron without a main
window.

## Script API (`nct`)

Same surface as `scriptExecutionWorker.cjs` / `scriptRuntime.cjs`:

* `nct.session`: `connected`, `name`, `hostname`, `username`;
  `sleep(ms)`, `startLog(path?)` (raw log; default
  `<Documents>/netcatty-script-<ms>.log`; uses the manual session-log stream,
  so it fails with `Stream already active for this session` while a manual
  recording runs), `stopLog()`, `disconnect()`.
* `nct.screen`: `send(text, { sensitive? })`, `sendLine(text, { sensitive?
  })` (body, 30 ms, then `\r`), `waitFor(pattern, timeoutMs = 30000)` (string
  → literal or `"/body/flags"`, `RegExp` → regex), `waitForText(text, 30000)`,
  `waitForRegex(pattern, 30000)` (strings are regex sources with `s`),
  `waitForPrompt(60000)`, `waitForAny(patterns, 30000)` (index),
  `getText(startRow?, endRow?)`, `clear()`, `rows`, `cols`, `currentRow`.
* `nct.dialog`: `alert`, `confirm`, `prompt(message, default, { sensitive?
  })`, `form(spec)` (validated with Electron's `normalizeDialogFormSpec`
  messages, see `docs/script-dialog-form-examples.md`), `select`, `radio`,
  `checkbox`.
* `nct.progress`: `start(label, total)`, `set(current, detail?)`,
  `step(detail?)`, `done()`; `nct.log(message)`, `nct.sleep`, `nct.version`,
  `console.log(...args)`.

A wait that times out pauses the run and asks the renderer
(`waitForTimeout` dialog): `retry` waits again, `skip` returns `""` (`-1` for
`waitForPrompt` / `waitForAny`), anything else fails the script with
`Script stopped by user`. Wait freshness follows `sessionOutputBuffer.cjs`
exactly: only output after earlier matches and within 512 bytes of the end
counts, except for the screen seeded at script start (fetched with a
snapshot request, #1821 / #1960), whose whole viewport is waitable and whose
trailing shell prompt satisfies one `waitForPrompt`.

Sandbox and limits (the worker's): no `SharedArrayBuffer`, no `eval` /
`Function` code generation; 128 pending host requests, 512 log
notifications, 20 000 notifications in total (progress updates beyond the
first 64 are coalesced every 50 ms), 80 MiB heap, 4 MiB JS stack, and
1 000 ms of uninterrupted synchronous JavaScript
(`Script execution timed out after 1000ms`). Stop / timeout interrupt
running JavaScript, including catastrophic regular expressions.

## Engine choice: QuickJS (`rquickjs`)

`rquickjs` 0.14 (QuickJS-ng) was chosen over `boa_engine`:

* promises, async functions and top-level-await wrappers work natively, and
  the job queue is driven explicitly, so host requests map onto promises the
  engine thread settles when results arrive;
* a periodic interrupt handler stops both synchronous loops and runaway
  regular expressions — the equivalent of Electron's heartbeat watchdog and
  `worker.terminate()` (Boa offers no comparable hook for regex backtracking);
* memory and stack limits match the worker's `resourceLimits`;
* small binary and fast start-up (one runtime per run, no pre-warmed pool
  needed).

Each run gets its own OS thread and QuickJS runtime. `RegExp` values passed
to `waitFor*` cross the boundary as `{ source, flags }` and are executed on
the host with `regress`, an ECMAScript regex engine, so their semantics are
JavaScript's.

## Session output tap

`SessionRegistry` (`sessions.rs`) exposes generic taps fed from the same
point as the session-log tap (every decoded chunk, also while flow control
paused the session):

* `subscribe_output(session_id) -> UnboundedReceiver<String>` — one
  session; the receiver ends with the session.
* `subscribe_all_output() -> UnboundedReceiver<OutputTapEvent>` —
  `Data { session_id, text }` / `Closed { session_id }` for every session.

Script automation subscribes once to all output: like Electron, every
session keeps a script buffer (newest 1 MiB) so connection banners are
waitable when a script starts later; it is released when the session ends.

## Differences from Electron

* Engine-generated error texts follow QuickJS, not V8 (`SyntaxError`
  wording, `new SharedArrayBuffer()` → `TypeError: not a constructor`,
  stack format). Messages produced by the script API are identical.
* Wait offsets are UTF-8 bytes instead of UTF-16 code units; the 512-unit
  live-tail window therefore covers fewer characters of CJK output.
* Requests go to all windows (`emit`) rather than the session's owning
  `webContents`; only the main window listens.
* The Electron bridge's re-initialisation path (`Script runtime
  reinitialized`) has no counterpart: the Tauri state lives as long as the
  app.
