# AI core — IPC contract

Commands and events of the AI core (`rust/apps/netcatty-desktop/src/commands/ai.rs`,
logic in `rust/crates/netcatty-ai`), implemented on the renderer side by
`infrastructure/tauri/bridge/ai.ts`. Port of the Electron
`aiBridge/providerHandlers.cjs`, `aiBridge/privacyHandlers.cjs`, the
chat-session cancel flag of `aiBridge/cattyExecHandlers.cjs`,
`ai/userSkills.cjs`, `aiSessionsBackupBridge.cjs`, `shared/aiPrivacyService.cjs`
and `mcp/externalMcpRedaction.cjs`.

Conventions (in addition to [ipc-contract.md](ipc-contract.md)):

* Every command takes the Electron IPC argument object as `payload` and
  answers with the Electron result object. Failures are reported inside that
  object (`{ ok: false, error }`, `{ success: false, error }`); these commands
  do not reject.
* Sender checks mirror Electron: *main* = `validateSender` (main window only),
  *main+settings* = `validateSenderOrSettings`. Other windows get
  `{ ok: false, error: "Unauthorized IPC sender" }` (`"Unauthorized"` for the
  privacy commands, `{ ok: false }` for the two sync commands).
* API keys stay encrypted in the renderer (`enc:v2:` from `credentials_encrypt`;
  plaintext keys are accepted). The renderer sends `__IPC_SECURED__` (provider
  key, headers and URL) / `__WEB_SEARCH_KEY__` (web-search key, headers) and
  the backend substitutes the decrypted value right before the request.
  Encrypted provider `customHeaders` are decrypted and replace headers of the
  same name case-insensitively. Keys, headers, prompts and bodies are never logged.
* Outbound URLs must pass the allowlist: built-in provider / web-search hosts
  (`api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`,
  `openrouter.ai`, `api.tavily.com`, `api.exa.ai`, `api.bochaai.com`,
  `open.bigmodel.cn`), hosts of the synced provider base URLs, the web-search
  host, hosts added for 30 s by `ai_allowlist_add_host`, and `localhost` /
  `127.0.0.1` only on 11434, 1234, 3000, 3001, 5000, 5001, 8000, 8080, 8888 plus
  provider / web-search / temporary ports. `http://` remote hosts only when a
  provider base URL (or the web-search host) uses `http://`. `skipHostCheck`
  allows any public HTTPS host but never private / loopback / link-local /
  CGNAT addresses or `metadata.google.internal`.
* Requests use the app HTTP proxy (`app_set_http_proxy`, `netcatty_sync::proxy`).
  A provider's `skipTLSVerify` (or the `aiFetch` flag) disables certificate
  verification for that request.

## Provider config and allowlist

| Command | Bridge method | Args | Returns | Notes |
| --- | --- | --- | --- | --- |
| `ai_sync_providers` | `aiSyncProviders(providers)` | `payload: { providers: ProviderConfig[] }` | `{ ok }` | main+settings. Replaces the provider list (only `id`, `apiKey`, `baseURL`, `skipTLSVerify`, `customHeaders` are used) and rebuilds the allowlist, keeping live temporary entries. A non-array leaves the list unchanged. |
| `ai_sync_web_search` | `aiSyncWebSearch(apiHost, apiKey)` | `payload: { apiHost: string \| null, apiKey: string \| null }` | `{ ok }` | main+settings. Web-search host (allowlist, `http://` allowed) and its encrypted key. |
| `ai_allowlist_add_host` | `aiAllowlistAddHost(baseURL)` | `payload: { baseURL }` | `{ ok, error? }` | main+settings. Allows the host (or localhost port) for 30 s; the expiry is re-armed on every call; entries owned by a synced provider survive the expiry. `"baseURL must be a string"`, `"Invalid URL"`. |

## Provider HTTP proxy

| Command | Bridge method | Args | Returns | Notes |
| --- | --- | --- | --- | --- |
| `ai_fetch` | `aiFetch(url, method, headers, body, providerId, skipHostCheck, followRedirects, skipTLSVerify, requestId?)` | `payload: { url, method?, headers?, body?, providerId?, skipHostCheck?, followRedirects?, skipTLSVerify?, requestId? }` | `{ ok, status, data, error? }` | main+settings. `ok` = 2xx; `status: 0` with `error` for transport / policy failures (`"Only HTTP(S) URLs are allowed"`, `"Invalid URL"`, `"URL host is not in the allowed list"`, `"Redirect target is not allowed"`, `"Request timeout"` after 30 s of inactivity, `"Response body exceeded maximum size (10MB)"`). `followRedirects` follows up to 5 redirects, re-validating each target. `Content-Length` is always sent (no chunked bodies). `requestId` is only valid for delegated plugin-agent fetches, which need the plugin runtime: `"Delegated Agent unavailable"` / `"Delegated request identity invalid"`. |

## Chat streaming

| Command | Bridge method | Args | Returns | Notes |
| --- | --- | --- | --- | --- |
| `ai_chat_stream` | `aiChatStream(requestId, url, headers, body, providerId, idleTimeoutMs)` | `payload: { requestId, url, headers?, body?, providerId?, idleTimeoutMs? }` | `{ ok: true, statusCode, statusText }` \| `{ ok: false, error }` \| `{ ok: false, aborted: true, error: "Aborted" }` | main. `POST`. Resolves when the response headers arrive; the body follows as events. Non-2xx: the error body (≤ 64 KiB) is read first, then `statusText` is `"<status> <detail>"` (`error.message` / `message` / `detail` / first 500 chars) and a `stream:error` `"HTTP <status>: <detail>"` is emitted. Deadlines: idle `idleTimeoutMs` (default 120 000, clamped to 1 ms – 24 h; every chunk re-arms it) and total 30 min (never less than idle + 90 s). `plugin-model_<runtime>_…` ids are capped at 15 s idle / 60 s total. `agent-model_…` ids (delegated plugin agents) are rejected. |
| `ai_chat_cancel` | `aiChatCancel(requestId)` | `payload: { requestId }` | `boolean` | main. `true` when a running stream was aborted (it then emits `stream:error` `"Aborted"`). |
| `ai_set_chat_session_cancelled` | `aiSetChatSessionCancelled(chatSessionId, cancelled = true)` | `payload: { chatSessionId, cancelled? }` | `{ ok, chatSessionId, cancelled }` \| `{ ok: false, error }` | main. Sets / clears the per-chat cancel flag (`commands::ai::is_chat_session_cancelled` for tool executors). Cancelling PTY execs, background jobs and approvals belongs to the MCP / exec port. |

| Event | Payload | Notes |
| --- | --- | --- |
| `netcatty:ai:stream:data` | `{ requestId, data }` | One per SSE `data:` line (the optional single space after the colon is stripped; `\r\n` tolerated; a trailing line without newline is flushed at the end). UTF-8 split across network chunks is reassembled. |
| `netcatty:ai:stream:end` | `{ requestId }` | Clean end of a 2xx body. |
| `netcatty:ai:stream:error` | `{ requestId, error }` | Abort, deadline (`"AI stream idle deadline exceeded after <n> ms"`, `"AI stream total deadline exceeded after <n> ms"`), transport error, `"Stream buffer exceeded maximum size (10MB)"`, or the HTTP error above. |

Stream events are emitted with `emit_to(<calling window label>)`; JS listeners
registered for any target (the adapter's) still receive them, so callbacks are
filtered by `requestId` as in the Electron preload. The adapter subscribes to the three events before its first `ai_chat_stream`.

## Privacy

Reversible, per-chat pseudonymisation of secrets, host names and public IP
addresses before values cross a model boundary (tokens
`[NC_<nonce>_<IP|HOST|SECRET>_<n>]`). The service starts *still loading* and
fails closed until a policy is applied.

| Command | Bridge method | Args | Returns | Notes |
| --- | --- | --- | --- | --- |
| `ai_privacy_status` | `aiPrivacyStatus()` | — | `{ ok, enabled? , error? }` | main. |
| `ai_privacy_transform` | `aiPrivacyTransform({ chatSessionId, operation, value })` | `payload: { chatSessionId, operation: "redact" \| "restore", value }` | `{ ok, value?, error? }` | main. `redact` pins the chat to the current policy (disabled chats are pinned too) and keeps existing aliases and root object keys; `restore` never creates a chat. Errors: `"Invalid AI privacy operation."`, `"AI privacy settings are still loading; try again"`, `"Invalid AI privacy configuration"`, `"AI privacy session is unavailable or its settings changed; start a new chat"`, `"AI privacy requires a valid chat session"`, `"AI privacy session limit reached; close a chat and try again"` (64 enabled chats), `"Unknown AI privacy token; start a new chat"`, `"AI privacy session limit reached; start a new chat"`, `"AI privacy could not safely process this value"` (binary attachments, NUL, depth > 100, > 100 000 nodes, > 8 MiB). |
| `ai_privacy_clear` | `aiPrivacyClearSession(chatSessionId)` | `chatSessionId` | `{ ok, error? }` | main. Drops the map and tombstones the id (late callbacks cannot recreate it). |
| `ai_privacy_initialize` | *(adapter internal)* | `payload: { redaction: RedactionConfig \| null }` | `{ ok, applied }` \| `{ ok: false, error }` | main+settings. Applies the persisted policy **only while the service is still loading**, so `externalMcpSetConfig({ redaction })` always wins. The adapter sends it once, before its first status / transform call, with the policy read from `netcatty_ai_privacy_v1` (legacy `netcatty_ai_external_mcp_redaction_v1`); `{}` when nothing is stored, `null` (fails closed) when the stored value is corrupt. |

`RedactionConfig` = `{ enabled, redactPrivateIps, cidrs: string[], patterns: string[] }`
(strict: unknown keys, wrong types, invalid CIDRs, regexes that match the empty
string or use lookaround / backreferences are rejected; ≤ 100 entries of ≤ 1024
chars). Policy changes from Settings arrive through `externalMcpSetConfig`,
owned by the External MCP port, which calls
`commands::ai::configure_privacy(&AiState, Some(&redaction))` (`None` / `null`
invalidates).

## User skills and the skills CLI

| Command | Bridge method | Args | Returns | Notes |
| --- | --- | --- | --- | --- |
| `ai_user_skills_status` | `aiUserSkillsGetStatus()` | — | `{ ok, directoryPath, readyCount, warningCount, skills: UserSkill[], warnings: string[] }` | main+settings. Folder `<data dir>/Skills` (created with a `README.txt` when empty). One sub-folder per skill with `SKILL.md` (≤ 24 KiB, front matter `name`, `description` ≤ 500 chars, no symlinks); duplicates of a slug and names without an ASCII slug become warnings. `UserSkill = { id, slug, directoryName, directoryPath, skillPath, name, description, status: "ready" \| "warning", warnings }`. |
| `ai_user_skills_open` | `aiUserSkillsOpenFolder()` | — | same as status, `ok` = folder opened, `error?` | main+settings. Opener plugin `open_path`. |
| `ai_user_skills_build_context` | `aiUserSkillsBuildContext(prompt, selectedSkillSlugs)` | `payload: { prompt, selectedSkillSlugs? }` | `{ ok, context, status }` | main. Index of ≤ 8 ready skills (line ≤ 1400 chars), ≤ 4 explicit selections plus ≤ 2 prompt matches, ≤ 6000 chars per skill, ≤ 12 000 total. `""` when there are no ready skills. |
| `ai_skills_cli_invocation` | `aiSkillsCliGetInvocation()` | — | `{ ok, skillPath, commandPrefix, launcherPath, usesLauncher }` | main+settings. The tool CLI is the Netcatty executable in `--tool-cli` mode: `commandPrefix = "\"<exe>\" --tool-cli"`, `launcherPath = <exe>`, `usesLauncher: true`. `skillPath` = `skills/netcatty-tool-cli/SKILL.md` from the Tauri resources (or the repository in debug builds), `null` when not bundled. |

## AI sessions backup

Rolling generations of the renderer's `netcatty_ai_sessions_v1` store under
`<data dir>/ai-sessions-backup/ai-sessions-<YYYYMMDDTHHMMSS-mmmZ>.json`
(5 kept, atomic temp + rename, ≤ 64 MiB).

| Command | Bridge method | Args | Returns | Notes |
| --- | --- | --- | --- | --- |
| `ai_sessions_backup_write` | `aiSessionsBackupWrite({ json })` | `payload: { json }` | `{ ok, file?, error? }` | `"invalid-json"` (empty / missing), `"payload-too-large"`, `"no-backup-dir"`. |
| `ai_sessions_backup_read_latest` | `aiSessionsBackupReadLatest()` | — | `{ ok, json?, file? }` | Newest generation that is a JSON array with at least one usable session (an empty array wins: intentional wipe); corrupt ones fall back to older ones. |
| `ai_sessions_backup_export` | `aiSessionsBackupExport({ json })` | `payload: { json }` | `{ success, filePath?, canceled?, error? }` | Save dialog (`export-<timestamp>.json`, JSON / All Files filters). |
| `ai_sessions_backup_import` | `aiSessionsBackupImport()` | — | `{ success, json?, canceled?, error? }` | Open dialog. |

## Not ported here

* Delegated plugin-agent model requests (`agent-model_…` ids) and the
  plugin byte budget of `plugin-model_…` streams: they need the plugin
  runtime / MCP bridge.
* `externalMcpSetConfig` (privacy policy changes from Settings): External MCP
  port; it must call `configure_privacy`.
* SDK agents, agent discovery, `aiExec`, `aiCattyCancelExec`, `aiCapability`,
  MCP session metadata and approvals: other ports.
