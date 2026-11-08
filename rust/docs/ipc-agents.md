# Managed SDK agents — IPC contract

Commands and events behind the AI panel's external agents (Claude Code,
Codex, GitHub Copilot, Cursor, CodeBuddy, OpenCode, Grok Build, MiMo Code),
agent discovery, CLI resolution and Codex login. Logic lives in
`crates/netcatty-agents`; the commands are in
`apps/netcatty-desktop/src/commands/agents.rs`; the renderer adapter is
`infrastructure/tauri/bridge/agents.ts`. Electron reference:
`electron/bridges/aiBridge/sdk/*`, `agentDiscoveryHandlers.cjs`,
`codexAppServer/*`.

Conventions are those of [ipc-contract.md](ipc-contract.md). Every command
resolves with the Electron response object (`{ ok, ... }`); none rejects for
an agent failure. Turn failures arrive as `netcatty:ai:sdk-agent:error`.
Credentials, API keys, tokens and prompt / response text are never logged.

## How the backends are driven

Electron uses each vendor's Node SDK. The Rust build drives the user's CLI
directly over the wire protocol those SDKs use:

| Backend | Transport |
| --- | --- |
| `claude` | `claude --output-format stream-json --verbose --input-format stream-json [--effort E] [--model M] [--resume S] --disallowedTools EnterPlanMode,ExitPlanMode,AskUserQuestion --tools ""\|Bash,Skill [--mcp-config {...}] --permission-mode bypassPermissions --allow-dangerously-skip-permissions --include-partial-messages [--settings ...]` with the `initialize` control request, one `user` message, stdin closed after `result`. `~/.claude.json` is repaired once per process. |
| `codex` (`sdk`) | `codex exec --experimental-json --config mcp_servers.*=... --config model_reasoning_summary="concise" [--model M] --sandbox danger-full-access --cd DIR --skip-git-repo-check [--config model_reasoning_effort=...] --config approval_policy="never" [resume ID] [--image P]`, prompt on stdin (the codex-sdk transport). |
| `codex` (`app-server`) | one warm `codex app-server --stdio` per binary + env fingerprint, JSONL JSON-RPC: `initialize`, `thread/start\|resume`, `turn/start`, `turn/steer`, `turn/interrupt`, `model/list`; server approval / user-input requests become `codex-app-server` interactions. |
| `copilot` | `copilot --headless --no-auto-update --stdio`, `Content-Length` JSON-RPC: `connect`, `session.create\|resume`, `session.send`, `session.event`, `session.permissions.handlePendingPermissionRequest`, `session.abort`, `models.list`. |
| `cursor` (CLI login) | `cursor-agent --print --trust --approve-mcps --output-format stream-json --stream-partial-output --model M --workspace DIR [--resume S] (--mode ask\|--force) PROMPT`, Netcatty MCP merged into `<workspace>/.cursor/mcp.json` for the turn. |
| `codebuddy` | `codebuddy --input-format=stream-json --output-format=stream-json --verbose ... --setting-sources none --dangerously-skip-permissions` (JS entries run through `node`, `bin/codebuddy` maps to `dist/codebuddy-headless.js`), `initialize` with hooks, `hook_callback` / `can_use_tool` / `elicitation_create` answered by Netcatty. |
| `opencode` | 1.x: `opencode serve` (config in `OPENCODE_CONFIG_CONTENT`), `GET /global/event` SSE, `POST /session`, `POST /session/{id}/prompt_async`, `POST /session/{id}/abort`, `GET /config/providers`. 2.x (from `opencode --version`): basic-auth `/api/*`. |
| `grok` | ACP (default): `grok --no-auto-update [--disallowed-tools ...] agent [--always-approve] [-m M] [--reasoning-effort E] stdio`, `initialize` → `authenticate` → `session/resume\|load\|new` → `session/prompt`. `NETCATTY_GROK_RUNTIME=streaming-json`: `grok -p PROMPT --output-format streaming-json ...` with MCP merged into `.grok/config.toml`. |
| `mimo` | `mimo serve` (`MIMOCODE_CONFIG_CONTENT`, basic auth), OpenCode 1.x API; native `permission.*` events go through the approval provider in confirm mode. |

Child processes get the login-shell environment (captured once with
`$SHELL -ilc env`, Windows: registry PATH) merged with the agent env from
Settings; `LD_PRELOAD`, `DYLD_*`, `NODE_OPTIONS`, `BASH_FUNC_*` and the other
injection variables are dropped. `NETCATTY_TOOL_CLI_DISCOVERY_FILE` and
`NETCATTY_CLI_CHAT_SESSION_ID` bind the Netcatty tool CLI to the chat.

## Commands

| Command | Args | Returns |
| --- | --- | --- |
| `ai_sdk_agent_stream` | `payload: { requestId, chatSessionId, sdkBackend, prompt, cwd?, providerId?, model?, existingSessionId?, historyMessages?, images?, toolIntegrationMode?, defaultTargetSession?, userSkillsContext?, agentEnv?, agentCommand?, codexRuntime?, permissionMode?, effort?, maxTurns?, maxBudgetUsd?, fallbackModel?, sandbox?, enableFileCheckpointing?, persistSession? }` | `{ ok, error? }` once the turn has ended. Unknown backend: `{ ok: false, error: "Unknown SDK backend" }` plus an error event. |
| `ai_sdk_agent_steer` | `payload: { requestId, chatSessionId, prompt, images?, clientUserMessageId }` | `{ status: accepted\|not-steerable\|busy\|inactive\|unsupported\|cancelled\|failed, message?, turnKind? }` — Codex App Server only. |
| `ai_sdk_agent_list_models` | `payload: { sdkBackend, cwd?, providerId?, chatSessionId?, agentEnv?, agentCommand?, codexRuntime?, force? }` | `{ ok: true, models, currentModelId, source?: live\|last-known-good, fetchedAt?, warning? }` — 5 min TTL cache (32 entries, keyed by backend, binary, runtime and a hash of the catalog-relevant env), then the persisted last-known-good catalog (`<data>/model-catalog-last-known.json`), then a live fetch (10 s; OpenCode 40 s; MiMo 30 s). `force` always goes live. |
| `ai_sdk_agent_cancel` | `requestId, chatSessionId?` | `{ ok, error? }` (`"Stream not found"`, `"Agent request ownership mismatch"`) |
| `ai_sdk_agent_cleanup` | `chatSessionId` | `{ ok: true }` — aborts the chat's turns, drops its resume ids, cancels its elicitations and App Server turns. |
| `ai_sdk_agent_elicitation_response` | `payload: { elicitationId, action, content? }` | `{ ok, error? }` |
| `ai_sdk_agent_mcp_status` | `payload?: { agentEnv?, agentCommand? }` | `{ ok, servers }` — CodeBuddy `mcp_status`. |
| `ai_sdk_agent_account_info` | `payload?: { agentEnv?, agentCommand? }` | `{ ok, account }` — CodeBuddy `initialize.account`. |
| `ai_sdk_agent_plugin_install` | `payload: { options: { name, marketplace } }` | `{ ok, result: { success, message } }` — edits `~/.codebuddy/settings.json` |
| `ai_sdk_agent_plugin_enable` / `_disable` | `payload: { name, marketplace }` | same |
| `ai_sdk_agent_marketplace_install` | `payload: { options: { name, repo, autoUpdate? } }` | same |
| `ai_sdk_agent_marketplace_remove` | `payload: { options: { name, removePlugins? } }` | same |
| `ai_agents_discover` | `options?: { refreshShellEnv?, apiKeyPresent? }` | `DiscoveredAgent[]` (`command, name, icon, description, sdkBackend, args, path, binPath, version, installed, available, authenticated, authSource`, Cursor extras `cliEmail, cliBinPath, cliLoginOk, apiKeyOk, sdkInstalled`) |
| `ai_resolve_cli` | `payload: { command, customPath?, refreshShellEnv?, apiKeyPresent? }` | `{ path, binPath, version, available, installed, ... }` |
| `ai_shell_env_prewarm` | — | `{ ok }` |
| `ai_codex_get_integration` | `options?: { refreshShellEnv?, validateChatGptAuth?, codexPath?, agentEnv? }` | `{ state, isConnected, rawOutput, exitCode, customConfig }` |
| `ai_codex_start_login` | `options?: { codexPath?, agentEnv? }` | `{ ok, session?: { sessionId, state, url, output, error, exitCode, codexPath }, error? }` |
| `ai_codex_get_login_session` / `ai_codex_cancel_login` | `sessionId` | `{ ok, session?, found?, error? }` |
| `ai_codex_logout` | `options?: { codexPath?, agentEnv? }` | `{ ok, state, isConnected, rawOutput, logoutOutput }` |
| `codex_app_server_status` | `payload?: { agentCommand?, agentEnv? }` | `{ ok: true, available, error? }` (`codex app-server --help`) |
| `codex_app_server_respond` | `payload: { interactionId, decision?: once\|session\|reject\|cancel, answers? }` | `{ ok, error? }` |
| `codex_app_server_cancel_timeout` | `interactionId` | `{ ok: true, cancelled }` — stops the idle auto-reject, keeps the absolute 5 min deadline. |

## Events

| Event | Payload |
| --- | --- |
| `netcatty:ai:sdk-agent:event` | `{ requestId, event }`, `event` ∈ `text-delta {textDelta}`, `reasoning-delta {delta}`, `reasoning-end`, `tool-call {toolName, args, toolCallId}`, `tool-result {toolCallId, output, toolName}`, `file-change {itemId, changes, status}`, `web-search {itemId, query, status}`, `plan-update {itemId, items, status}`, `warning {itemId, message}`, `usage {inputTokens, cachedInputTokens, outputTokens, reasoningTokens, totalTokens}`, `status {message}`, `session-id {sessionId, sdkBackend, binPath, runtime, authMode?, cliMode?}`, `hook {...}` and `elicitation-create` / `elicitation-complete` (CodeBuddy). |
| `netcatty:ai:sdk-agent:done` | `{ requestId }` |
| `netcatty:ai:sdk-agent:error` | `{ requestId, error }` |
| `netcatty:ai:codex-app-server:interaction-request` | `{ interactionId, source: "codex-app-server", kind: command\|file-change\|permissions\|user-input, requestId, chatSessionId, itemId?, toolName?, args?, availableDecisions?, questions?, autoResolutionMs? }` |
| `netcatty:ai:codex-app-server:interaction-cleared` | `{ interactionIds, chatSessionId }` |
| `netcatty:ai:agent:stdout` / `stderr` / `exit` | reserved (raw agent processes are not used); the adapter subscribes but nothing emits them. |

## Resume identity

The renderer persists `session-id` events as
`netcatty-sdk-session:<encodeURIComponent(JSON{v:1,id,backend,binPath,runtime,authMode?,cliMode?})>`.
A persisted id is resumed only for the same backend, binary, runtime and
(Cursor) auth / ask-vs-agent mode; bare legacy ids only on the default `sdk`
runtime without a configured command. Grok ACP vs streaming-json and Cursor
ask vs agent never resume each other's sessions.

## MCP injection and approvals

`netcatty_agents::McpInjectionProvider` turns a chat into the neutral
`[{ name, type: "stdio", command, args, env: [{name, value}] }]` list that
each driver converts (Claude / CodeBuddy `--mcp-config`, Codex
`mcp_servers.*` overrides, Copilot `mcpServers`, Grok ACP `mcpServers` /
`.grok/config.toml`, OpenCode / MiMo `mcp`, Cursor `.cursor/mcp.json`). The
app currently installs `NoopMcpInjectionProvider` and
`NoopApprovalProvider` (`TODO(mcp-injection)` in `commands/agents.rs`):
until the netcatty MCP server port lands, agents get no Netcatty tools and
confirm-mode native permission prompts (CodeBuddy `can_use_tool`, MiMo
`permission.*`) are denied.

## Not ported

* Cursor API-key mode (`@cursor/sdk` is a Node package): only the Cursor
  Agent CLI login path runs; discovery reports `sdkInstalled: false`.
* CodeBuddy's warm V2 session (the CLI is spawned per turn, resumed with
  `--resume`); `maxBudgetUsd`, `sandbox` and `enableFileCheckpointing` are
  accepted but, as in the SDK's process transport, not passed to the CLI.
* AI privacy redaction (`aiPrivacyService`) and delegated plugin-agent
  conversations.
* OpenCode's pooled catalog server (each catalog fetch starts a short-lived
  `serve`; the TTL cache and last-known-good store absorb repeats).
