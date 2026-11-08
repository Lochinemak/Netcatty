/**
 * AI control plane adapter for the Tauri build: Catty exec, capability RPC,
 * vault-agent bridge, MCP host settings / scopes / approvals, tool-output
 * temp store and the External MCP controller. Command and event names are
 * specified in `rust/docs/ipc-mcp.md`; payloads match the Electron preload.
 */

import { EventHub, invoke } from '../tauriApi';

export const MCP_EVENTS = {
  vaultAgentRequest: 'netcatty:ai:vault-agent:request',
  approvalRequest: 'netcatty:ai:mcp:approval-request',
  approvalCleared: 'netcatty:ai:mcp:approval-cleared',
} as const;

type AnyRecord = Record<string, unknown>;

/** Bridge members that exist in the Electron preload but not in `NetcattyBridge`. */
export interface McpExtraBridge {
  aiCapability(rpcMethod: string, params?: AnyRecord, chatSessionId?: string, delegationTag?: string): Promise<unknown>;
  aiMcpUpdateAttachments(attachments: unknown[], chatSessionId: string): Promise<unknown>;
  aiMcpSetCommandBlocklist(blocklist: unknown): Promise<unknown>;
  aiMcpSetCommandTimeout(timeout: unknown): Promise<unknown>;
  aiMcpSetMaxIterations(maxIterations: unknown): Promise<unknown>;
  aiMcpSetPermissionMode(mode: string): Promise<unknown>;
  onMcpApprovalRequest(cb: (payload: AnyRecord) => void): () => void;
  onMcpApprovalCleared(cb: (payload: AnyRecord) => void): () => void;
  respondMcpApproval(approvalId: string, approved: boolean, scope?: string): Promise<unknown>;
  cancelMcpApprovalTimeout(approvalId: string): Promise<unknown>;
}

export interface McpBridgeDeps {
  hub: EventHub;
}

type Bridge = Partial<NetcattyBridge> & McpExtraBridge;
type R<K extends keyof NetcattyBridge> = Awaited<ReturnType<NonNullable<NetcattyBridge[K]>>>;

const client = (name: 'codex' | 'claude' | 'grok') => ({
  status: () => invoke<AnyRecord>('external_mcp_client_status', { client: name }),
  add: () => invoke<AnyRecord>('external_mcp_client_add', { client: name }),
});

export function createMcpBridge({ hub }: McpBridgeDeps): Bridge {
  const codex = client('codex');
  const claude = client('claude');
  const grok = client('grok');
  return {
    // Catty exec
    aiExec: (sessionId, command, chatSessionId) =>
      invoke<R<'aiExec'>>('ai_exec', { sessionId, command, chatSessionId }),
    // Declared twice in the bridge types (overloads); one implementation serves both.
    aiCattyCancelExec: ((chatSessionId: string) =>
      invoke<{ ok: boolean; error?: string }>('ai_catty_cancel_exec', { chatSessionId })) as NetcattyBridge['aiCattyCancelExec'],

    // Capabilities + vault agent
    aiCapability: (rpcMethod, params, chatSessionId) =>
      invoke('ai_capability', { rpcMethod, params: params ?? {}, chatSessionId }),
    onVaultAgentRequest: (cb) => hub.subscribe(MCP_EVENTS.vaultAgentRequest, cb),
    respondVaultAgent: (requestId, result) =>
      invoke<R<'respondVaultAgent'>>('ai_vault_agent_respond', { requestId, result }),

    // Scopes
    aiMcpUpdateSessions: (sessions, chatSessionId) =>
      invoke<R<'aiMcpUpdateSessions'>>('ai_mcp_update_sessions', { sessions, chatSessionId }),
    aiMcpUpdateLiveSessions: (sessions) =>
      invoke<R<'aiMcpUpdateLiveSessions'>>('ai_mcp_update_live_sessions', { sessions }),
    aiMcpMergeSessions: (sessions, chatSessionId) =>
      invoke<R<'aiMcpMergeSessions'>>('ai_mcp_merge_sessions', { sessions, chatSessionId }),
    aiMcpUpdateAttachments: (attachments, chatSessionId) =>
      invoke('ai_mcp_update_attachments', { attachments, chatSessionId }),

    // Settings
    aiMcpSetCommandBlocklist: (blocklist) => invoke('ai_mcp_set_command_blocklist', { blocklist }),
    aiMcpSetCommandTimeout: (timeout) => invoke('ai_mcp_set_command_timeout', { timeout }),
    aiMcpSetMaxIterations: (maxIterations) => invoke('ai_mcp_set_max_iterations', { maxIterations }),
    aiMcpSetPermissionMode: (mode) => invoke('ai_mcp_set_permission_mode', { mode }),
    aiMcpSetToolIntegrationMode: (mode) =>
      invoke<R<'aiMcpSetToolIntegrationMode'>>('ai_mcp_set_tool_integration_mode', { mode }),
    aiMcpSyncPermissionGrants: (grants) =>
      invoke<R<'aiMcpSyncPermissionGrants'>>('ai_mcp_sync_permission_grants', { grants }),

    // Approvals
    onMcpApprovalRequest: (cb) => hub.subscribe(MCP_EVENTS.approvalRequest, cb),
    onMcpApprovalCleared: (cb) => hub.subscribe(MCP_EVENTS.approvalCleared, cb),
    respondMcpApproval: (approvalId, approved, scope) =>
      invoke('ai_mcp_approval_respond', { approvalId, approved, scope }),
    cancelMcpApprovalTimeout: (approvalId) => invoke('ai_mcp_approval_cancel_timeout', { approvalId }),
    setExternalMcpApprovalAlertMode: (payload) =>
      invoke<R<'setExternalMcpApprovalAlertMode'>>('mcp_set_approval_alert_mode', { payload: payload ?? {} }),

    // Tool output temp store
    getToolOutputPersistenceStatus: () =>
      invoke<R<'getToolOutputPersistenceStatus'>>('tool_output_persistence_status'),
    writeToolOutputTemp: (record, content) =>
      invoke<R<'writeToolOutputTemp'>>('tool_output_write', { record, content }),
    restoreToolOutputTemp: (handleId, chatSessionId) =>
      invoke<R<'restoreToolOutputTemp'>>('tool_output_restore', { handleId, chatSessionId }),
    readToolOutputTemp: (filePath, request) =>
      invoke<R<'readToolOutputTemp'>>('tool_output_read', { path: filePath, request }),
    deleteToolOutputTemp: (filePath) =>
      invoke<R<'deleteToolOutputTemp'>>('tool_output_delete', { path: filePath }),
    deleteChatToolOutputsTemp: (chatSessionId) =>
      invoke<R<'deleteChatToolOutputsTemp'>>('tool_output_delete_chat', { chatSessionId }),
    deleteTerminalToolOutputsTemp: (chatSessionId, terminalSessionId) =>
      invoke<R<'deleteTerminalToolOutputsTemp'>>('tool_output_delete_terminal_session', { chatSessionId, terminalSessionId }),
    deleteTerminalToolOutputsEverywhereTemp: (terminalSessionId) =>
      invoke<R<'deleteTerminalToolOutputsEverywhereTemp'>>('tool_output_delete_terminal', { terminalSessionId }),

    // External MCP
    externalMcpGetStatus: () => invoke<R<'externalMcpGetStatus'>>('external_mcp_get_status'),
    externalMcpSetEnabled: (enabled) => invoke<AnyRecord>('external_mcp_set_enabled', { enabled: Boolean(enabled) }),
    externalMcpSetConfig: (config) => invoke<AnyRecord>('external_mcp_set_config', { config: config ?? {} }),
    externalMcpGetUniversalSetupPrompt: () =>
      invoke<R<'externalMcpGetUniversalSetupPrompt'>>('external_mcp_get_universal_setup_prompt'),
    externalMcpCodexGetStatus: codex.status,
    externalMcpCodexAdd: codex.add,
    externalMcpClaudeGetStatus: claude.status,
    externalMcpClaudeAdd: claude.add,
    externalMcpGrokGetStatus: grok.status,
    externalMcpGrokAdd: grok.add,
  };
}
