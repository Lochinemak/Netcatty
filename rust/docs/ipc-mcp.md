# AI control plane — Catty exec, capabilities, MCP, External MCP

Companion to [`ipc-contract.md`](ipc-contract.md). Ports the Electron
`mcpServerBridge`, `capabilities/`, `ptyExec`, `mcp/` stdio server,
`cli/netcatty-tool-cli`, `externalMcpController` and `externalMcp/` modules.

Crates:

| Crate | Contents |
|---|---|
| `netcatty-ptyexec` | Marker-wrapped PTY exec engine (`start_pty_job`, `exec_via_pty`, raw exec), prompt tracking, live shell probe, shell-kind detection, command blocklist, per-chat cancellation registry. |
| `netcatty-capabilities` | Capability catalog (`data/catalog.json`, same ids / MCP tool names / schemas / descriptions as Electron), policy (observer / confirm / auto), permission grants, `CapabilityDispatcher`, NDJSON RPC client. |
| `netcatty-mcp` | `McpHost` (scopes, ownership, approvals, exec, background jobs, SFTP, loopback NDJSON TCP host + discovery), MCP protocol session, stdio server, tool CLI, privacy redaction, tool-output store, External MCP controller + streamable HTTP. |

Desktop glue: `apps/netcatty-desktop/src/commands/{mcp,catty}.rs`,
`mcp_helper.rs`, the AI output tap in `sessions.rs`. Renderer adapter:
`infrastructure/tauri/bridge/mcp.ts` (+ `mcpMarkerFilter.ts`).

## Commands

Arguments are camelCase on the JS side (Tauri converts). All return JSON
with the Electron result shapes; failures that Electron reported as
`{ ok: false, error }` keep that shape, only "state not initialised" rejects
with `CoreError`.

| Bridge method | Command | Args |
|---|---|---|
| `aiExec` | `ai_exec` | `sessionId, command, chatSessionId?` |
| `aiCattyCancelExec` | `ai_catty_cancel_exec` | `chatSessionId` |
| `aiCapability` | `ai_capability` | `rpcMethod, params, chatSessionId?` |
| `respondVaultAgent` | `ai_vault_agent_respond` | `requestId, result` |
| `aiMcpUpdateSessions` | `ai_mcp_update_sessions` | `sessions, chatSessionId?` |
| `aiMcpUpdateLiveSessions` | `ai_mcp_update_live_sessions` | `sessions` |
| `aiMcpMergeSessions` | `ai_mcp_merge_sessions` | `sessions, chatSessionId` |
| `aiMcpUpdateAttachments` | `ai_mcp_update_attachments` | `attachments, chatSessionId` |
| `aiMcpSetCommandBlocklist` | `ai_mcp_set_command_blocklist` | `blocklist` |
| `aiMcpSetCommandTimeout` | `ai_mcp_set_command_timeout` | `timeout` (seconds) |
| `aiMcpSetMaxIterations` | `ai_mcp_set_max_iterations` | `maxIterations` |
| `aiMcpSetPermissionMode` | `ai_mcp_set_permission_mode` | `mode` |
| `aiMcpSetToolIntegrationMode` | `ai_mcp_set_tool_integration_mode` | `mode` (`mcp` / `skills`) |
| `aiMcpSyncPermissionGrants` | `ai_mcp_sync_permission_grants` | `grants` |
| `respondMcpApproval` | `ai_mcp_approval_respond` | `approvalId, approved, scope?` |
| `cancelMcpApprovalTimeout` | `ai_mcp_approval_cancel_timeout` | `approvalId` |
| `setExternalMcpApprovalAlertMode` | `mcp_set_approval_alert_mode` | `payload: { mode }` |
| `getToolOutputPersistenceStatus` | `tool_output_persistence_status` | — |
| `writeToolOutputTemp` | `tool_output_write` | `record, content` |
| `restoreToolOutputTemp` | `tool_output_restore` | `handleId, chatSessionId` |
| `readToolOutputTemp` | `tool_output_read` | `path, request?` |
| `deleteToolOutputTemp` | `tool_output_delete` | `path` |
| `deleteChatToolOutputsTemp` | `tool_output_delete_chat` | `chatSessionId` |
| `deleteTerminalToolOutputsTemp` | `tool_output_delete_terminal_session` | `chatSessionId, terminalSessionId` |
| `deleteTerminalToolOutputsEverywhereTemp` | `tool_output_delete_terminal` | `terminalSessionId` |
| `externalMcpGetStatus` | `external_mcp_get_status` | — |
| `externalMcpSetEnabled` | `external_mcp_set_enabled` | `enabled` |
| `externalMcpSetConfig` | `external_mcp_set_config` | `config` |
| `externalMcpGetUniversalSetupPrompt` | `external_mcp_get_universal_setup_prompt` | — |
| `externalMcp{Codex,Claude,Grok}GetStatus` | `external_mcp_client_status` | `client` (`codex` / `claude` / `grok`) |
| `externalMcp{Codex,Claude,Grok}Add` | `external_mcp_client_add` | `client` |

`externalMcpSetConfig` accepts `mode`, `idleTimeoutMinutes`,
`sessionIdleTimeoutMinutes`, `redaction`, `httpEnabled`, `httpPort`,
`httpAllowCustomBind`, `httpListenAddress`, `httpClientHost`,
`rotateHttpToken`; an invalid privacy policy returns
`{ ...status, ok: false, error }`. The status carries `http`
(`enabled, listening, port, listenAddress, allowCustomBind, clientHost,
url, bearerToken, state, error, errorCode`) and `redaction`.

## Events

| Event | Payload |
|---|---|
| `netcatty:ai:vault-agent:request` | `{ requestId, op, params }` — answer with `ai_vault_agent_respond` |
| `netcatty:ai:mcp:approval-request` | `{ approvalId, toolName, args, allowSession, chatSessionId?, target? }` |
| `netcatty:ai:mcp:approval-cleared` | `{ approvalIds }` |
| `netcatty:sftp:global-transfer` | AI SFTP transfers (same shape as user transfers) |
| `netcatty:data` | AI command echo is emitted with `syntheticEcho: true` |

Approvals auto-deny after 110 s (absolute), or earlier when the idle timer
fires; `cancelMcpApprovalTimeout` stops the idle timer only.

The renderer hides `__NCMCP_…` marker lines from terminal display
(`McpMarkerFilter`, port of the preload `filterMcpChunk`); chunks flagged
`syntheticEcho` bypass it.

## Helper modes of the executable

`main.rs` calls `mcp_helper::run_if_requested()` before any window:

* `netcatty --mcp-server` — stdio MCP server for SDK agents (env from
  `build_injected_mcp_servers`: `NETCATTY_MCP_PORT`, `NETCATTY_MCP_TOKEN`,
  `NETCATTY_MCP_SESSION_IDS` (only without a chat), `NETCATTY_MCP_CHAT_SESSION_ID`,
  `NETCATTY_MCP_PERMISSION_MODE`).
* `netcatty` with `NETCATTY_MCP_HELPER=external` and
  `NETCATTY_EXTERNAL_MCP_DISCOVERY_FILE` (or `--external-mcp-server`) —
  External MCP stdio server; this is what Codex / Claude Code / Grok are
  configured to launch (command = executable, no args).
* `netcatty --tool-cli <subcommand> ...` — tool CLI (same subcommands,
  flags and output as `netcatty-tool-cli.cjs`), discovery from
  `NETCATTY_TOOL_CLI_DISCOVERY_FILE` or `<data_dir>/netcatty-tool-cli/discovery.json`.

## MCP tool surface

What an MCP client sees (`netcatty --mcp-server`, External MCP over stdio
and over HTTP). Tool names, descriptions and the RPC behind each tool come
from the catalog; the points below are layered on top in
`netcatty-capabilities::mcp_schema`, `netcatty-mcp::protocol` and
`host/target.rs`, and none of them touches `data/catalog.json`.

* **Real input types.** The catalog types every input as a string or a
  number (`newTab: "true"`, `hosts: "[{…}]"`). `tools/list` advertises
  booleans, arrays, objects and enums instead, and the call is folded back
  into the catalog's string form before it is dispatched, so the backend
  contract is unchanged. The string form is still accepted. Two tests keep
  the overlay honest: every overlay entry must match a catalog field, and
  every field the catalog documents as a flag or as JSON must have one.
* **Annotations.** Each tool carries `title` and `annotations`
  (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`)
  derived from the capability policy, so a client can auto-approve reads and
  flag destructive calls. They are hints for the client; the permission mode
  and the approval flow in the host are what is enforced.
* **Sessions by name.** A `sessionId` argument may be a session's exact
  label, hostname or `user@hostname` (case-insensitive) instead of its id.
  One match in the caller's scope resolves; several are rejected with the
  candidates (`sessions`) and never guessed between; none gives the usual
  scope error, now with the scope's sessions attached. Resolution happens at
  the top of `McpHost::dispatch`, before permissions and approvals, and so
  also applies to the tool CLI. For the External MCP scope an unknown target
  first refreshes the scope from the live tabs, so a tab opened after the
  last `get_environment` is addressable.
* **Toolsets.** 15 core tools and `load_netcatty_tools` are listed at
  first; the other 57 are grouped in toolsets. Calling a deferred tool by
  name loads it (toolsets shorten the list, they are not a permission
  boundary); a delegated tool set (`NETCATTY_MCP_DELEGATED_TOOLS`) stays
  fixed. The loader's answer includes a one-line summary of each tool. For a
  client that never re-reads the tool list, toolsets can be loaded up
  front: `NETCATTY_MCP_TOOLSETS=sftp_advanced,vault_hosts` (or `all`) for a
  stdio server, `…/mcp?toolsets=all` on the `initialize` request over HTTP.
* **`sftp_read_file` in pieces.** `netcatty/sftp/read` takes `offset` and
  `maxBytes` and reports `bytesRead`, `totalBytes`, `truncated` and
  `nextOffset`. A piece never ends inside a UTF-8 character. Without
  `maxBytes` the RPC still reads the whole file (the tool CLI's `sftp read`
  relies on that; it gained `--offset` / `--max-bytes`), but the MCP tool
  defaults to 256 KiB per call, so a model cannot pull a multi-gigabyte log
  into memory by naming it. At most 8 MiB per call.
* **`sftp_find`** (`netcatty/sftp/find`, CLI `sftp find`) searches a
  directory tree for entries whose name matches a glob (`*`, `?`, `[a-z]`,
  `[!abc]`), optionally by type. It runs on one SFTP channel, breadth
  first, never descends into a symlinked directory, and is bounded by
  depth (default 5, max 20), matches (default 200, max 1000), 5000
  directories and three quarters of the command timeout; `truncatedBy`
  names the bound that stopped it. Unreadable directories are skipped and
  counted. This capability and the two read inputs exist only in this
  backend: they are declared in `data/catalog_tauri.json`, which is merged
  over the Electron export at load.
* **`get_environment`** returns its static usage guidance (`description`,
  `tools`) on the first call of an MCP session only; later calls return the
  live sessions and tunnels. The `netcatty://context` resource is always
  complete.

## Public Rust API for other modules

* `netcatty_mcp::build_injected_mcp_servers(&McpHost, chat_session_id,
  tool_integration_mode) -> Vec<InjectedMcpServer>` — serialises as
  `{ name: "netcatty-remote-hosts", type: "stdio", command: <exe>,
  args: ["--mcp-server"], env: [{ name, value }] }`; empty unless the mode
  is `mcp`. Desktop wrapper:
  `commands::mcp::injected_mcp_servers(&AppHandle, chat, mode)`
  (adapter target for the agents crate's `McpInjectionProvider`).
* `commands::mcp::apply_chat_session_cancelled(&AppHandle, chat,
  cancelled)` — sets the flag and, when cancelling, kills PTY execs,
  background jobs, SFTP ops and pending approvals of that chat.
* `McpHost::dispatch(method, params, DispatchContext)` /
  `McpHost::renderer_capability(rpc_method, params, chat)` — capability
  dispatch for every surface (MCP, CLI, renderer harness).
* Session output tap: `SessionRegistry::tap_output(session_id) ->
  Option<UnboundedReceiver<String>>` and `SessionRegistry::flags_of(id)
  .ai` (`OutputTaps`: prompt tracker, shell kind). Fed from the same
  `deliver` point as the session-log tap; to be folded onto
  `subscribe_output` when merged with the script automation port.
* `ExternalMcpController` (`netcatty_mcp::external`) — `status`,
  `set_enabled`, `set_config`, `client_status/add`,
  `universal_setup_prompt`, `cleanup`.

## Differences from Electron

* Tool-output manifests are signed with an HMAC key stored in a 0600 file
  (`<data_dir>/tool-output-signing.key`) instead of `safeStorage`.
* The External MCP HTTP endpoint answers in JSON response mode, except for
  a request that produced a notification (`tools/list_changed` after a
  toolset load): that one is answered as a short `text/event-stream` with
  the notification followed by the response, when the client accepts it.
  The optional standalone SSE stream (`GET /mcp`) returns 405.
* The MCP tool surface is no longer byte-identical to Electron's: see
  "MCP tool surface" above (typed inputs, annotations, sessions by name,
  toolset preloading). Existing tool names and RPC methods are unchanged;
  `sftp_find` and ranged `sftp_read_file` are additions Electron lacks.
* `TODO(ai-privacy)`: `external_mcp_set_config` must forward the
  normalised redaction policy to `commands::ai::configure_privacy` once
  the AI core module is merged.
* Not ported (Electron-only): plugin agent delegation tags, terminal
  worker paths, login-shell PATH resolution for CLI setup (the SDK-agent
  module owns shell-env prewarming).
