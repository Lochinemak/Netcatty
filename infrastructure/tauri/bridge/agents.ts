/**
 * Managed SDK agents, agent discovery, CLI resolution, Codex login and the
 * Codex App Server interactions on top of the `netcatty-agents` Rust commands
 * (`rust/docs/ipc-agents.md`). Mirrors `electron/preload/api.cjs` so the AI
 * panel (`infrastructure/ai/sdkAgentAdapter.ts`, settings) is unchanged.
 */
import { invoke, type EventHub } from '../tauriApi';

export const AGENT_EVENTS = {
  sdkEvent: 'netcatty:ai:sdk-agent:event',
  sdkDone: 'netcatty:ai:sdk-agent:done',
  sdkError: 'netcatty:ai:sdk-agent:error',
  agentStdout: 'netcatty:ai:agent:stdout',
  agentStderr: 'netcatty:ai:agent:stderr',
  agentExit: 'netcatty:ai:agent:exit',
  codexInteractionRequest: 'netcatty:ai:codex-app-server:interaction-request',
  codexInteractionCleared: 'netcatty:ai:codex-app-server:interaction-cleared',
} as const;

type Method<K extends keyof NetcattyBridge> = NonNullable<NetcattyBridge[K]>;
type Args<K extends keyof NetcattyBridge> = Parameters<Method<K>>;
type Result<K extends keyof NetcattyBridge> = Awaited<ReturnType<Method<K>>>;

interface RequestScoped { requestId?: string }
interface SdkEventPayload extends RequestScoped { event: Record<string, unknown> }
interface SdkErrorPayload extends RequestScoped { error: string }
interface AgentDataPayload { agentId?: string; data: string }
interface AgentExitPayload { agentId?: string; code: number | null }

export interface AgentsBridgeDeps {
  hub: EventHub;
}

export type AgentsBridge = Pick<NetcattyBridge,
  | 'aiSdkAgentStream'
  | 'aiSdkAgentSteer'
  | 'aiSdkAgentListModels'
  | 'aiSdkAgentCancel'
  | 'aiSdkAgentCleanup'
  | 'aiSdkAgentElicitationResponse'
  | 'aiSdkAgentMcpStatus'
  | 'aiSdkAgentAccountInfo'
  | 'aiSdkAgentPluginInstall'
  | 'aiSdkAgentPluginEnable'
  | 'aiSdkAgentPluginDisable'
  | 'aiSdkAgentMarketplaceInstall'
  | 'aiSdkAgentMarketplaceRemove'
  | 'onAiSdkAgentEvent'
  | 'onAiSdkAgentDone'
  | 'onAiSdkAgentError'
  | 'onAiAgentStdout'
  | 'onAiAgentStderr'
  | 'onAiAgentExit'
  | 'aiDiscoverAgents'
  | 'aiPrewarmShellEnv'
  | 'aiCodexGetIntegration'
  | 'aiCodexStartLogin'
  | 'aiCodexGetLoginSession'
  | 'aiCodexCancelLogin'
  | 'aiCodexLogout'
  | 'codexAppServerGetStatus'
  | 'onCodexAppServerInteractionRequest'
  | 'onCodexAppServerInteractionCleared'
  | 'respondCodexAppServerInteraction'
  | 'cancelCodexAppServerInteractionTimeout'
> & {
  /** Settings → AI CLI path check (typed locally by `components/settings/tabs/ai/types.ts`). */
  aiResolveCli(params: { command: string; customPath?: string; refreshShellEnv?: boolean; apiKeyPresent?: boolean }): Promise<Record<string, unknown>>;
};

export function createAgentsBridge({ hub }: AgentsBridgeDeps): AgentsBridge {
  // Subscribe before the first turn so events emitted right after the
  // stream command starts cannot be lost while `listen` is pending.
  const streamEventsReady = (): Promise<void> => Promise.all([
    hub.ensure(AGENT_EVENTS.sdkEvent),
    hub.ensure(AGENT_EVENTS.sdkDone),
    hub.ensure(AGENT_EVENTS.sdkError),
  ]).then(() => undefined);

  const forRequest = <T extends RequestScoped>(event: string, requestId: string, cb: (payload: T) => void) =>
    hub.subscribe<T>(event, (payload) => {
      if (payload?.requestId === requestId) cb(payload);
    });

  const forAgent = <T extends { agentId?: string }>(event: string, agentId: string, cb: (payload: T) => void) =>
    hub.subscribe<T>(event, (payload) => {
      if (payload?.agentId === agentId) cb(payload);
    });

  return {
    aiSdkAgentStream: async (...[
      requestId, chatSessionId, sdkBackend, prompt, cwd, providerId, model, existingSessionId, historyMessages,
      images, toolIntegrationMode, defaultTargetSession, userSkillsContext, agentEnv, agentCommand, codexRuntime,
      permissionMode, codebuddyOptions,
    ]: Args<'aiSdkAgentStream'>) => {
      await streamEventsReady();
      const advanced = codebuddyOptions && typeof codebuddyOptions === 'object'
        ? {
          effort: codebuddyOptions.effort,
          maxTurns: codebuddyOptions.maxTurns,
          maxBudgetUsd: codebuddyOptions.maxBudgetUsd,
          fallbackModel: codebuddyOptions.fallbackModel,
          sandbox: codebuddyOptions.sandbox,
          enableFileCheckpointing: codebuddyOptions.enableFileCheckpointing,
          persistSession: codebuddyOptions.persistSession,
        }
        : {};
      return invoke<Result<'aiSdkAgentStream'>>('ai_sdk_agent_stream', {
        payload: {
          requestId,
          chatSessionId,
          sdkBackend,
          prompt,
          cwd,
          providerId,
          model,
          existingSessionId,
          historyMessages,
          images,
          toolIntegrationMode,
          defaultTargetSession,
          userSkillsContext,
          agentEnv,
          agentCommand,
          codexRuntime,
          permissionMode,
          ...advanced,
        },
      });
    },
    aiSdkAgentSteer: (requestId, chatSessionId, prompt, images, clientUserMessageId) =>
      invoke<Result<'aiSdkAgentSteer'>>('ai_sdk_agent_steer', {
        payload: { requestId, chatSessionId, prompt, images, clientUserMessageId },
      }),
    aiSdkAgentListModels: (sdkBackend, cwd, providerId, chatSessionId, agentEnv, agentCommand, codexRuntime, force) =>
      invoke<Result<'aiSdkAgentListModels'>>('ai_sdk_agent_list_models', {
        payload: { sdkBackend, cwd, providerId, chatSessionId, agentEnv, agentCommand, codexRuntime, force },
      }),
    aiSdkAgentCancel: (requestId, chatSessionId) =>
      invoke<Result<'aiSdkAgentCancel'>>('ai_sdk_agent_cancel', { requestId, chatSessionId }),
    aiSdkAgentCleanup: (chatSessionId) =>
      invoke<Result<'aiSdkAgentCleanup'>>('ai_sdk_agent_cleanup', { chatSessionId }),
    aiSdkAgentElicitationResponse: (elicitationId, action, content) =>
      invoke<Result<'aiSdkAgentElicitationResponse'>>('ai_sdk_agent_elicitation_response', {
        payload: { elicitationId, action, content },
      }),
    aiSdkAgentMcpStatus: (agentEnv, agentCommand) =>
      invoke<Result<'aiSdkAgentMcpStatus'>>('ai_sdk_agent_mcp_status', { payload: { agentEnv, agentCommand } }),
    aiSdkAgentAccountInfo: (agentEnv, agentCommand) =>
      invoke<Result<'aiSdkAgentAccountInfo'>>('ai_sdk_agent_account_info', { payload: { agentEnv, agentCommand } }),
    aiSdkAgentPluginInstall: (options) =>
      invoke<Result<'aiSdkAgentPluginInstall'>>('ai_sdk_agent_plugin_install', { payload: { options } }),
    aiSdkAgentPluginEnable: (name, marketplace) =>
      invoke<Result<'aiSdkAgentPluginEnable'>>('ai_sdk_agent_plugin_enable', { payload: { name, marketplace } }),
    aiSdkAgentPluginDisable: (name, marketplace) =>
      invoke<Result<'aiSdkAgentPluginDisable'>>('ai_sdk_agent_plugin_disable', { payload: { name, marketplace } }),
    aiSdkAgentMarketplaceInstall: (options) =>
      invoke<Result<'aiSdkAgentMarketplaceInstall'>>('ai_sdk_agent_marketplace_install', { payload: { options } }),
    aiSdkAgentMarketplaceRemove: (options) =>
      invoke<Result<'aiSdkAgentMarketplaceRemove'>>('ai_sdk_agent_marketplace_remove', { payload: { options } }),
    onAiSdkAgentEvent: (requestId, cb) =>
      forRequest<SdkEventPayload>(AGENT_EVENTS.sdkEvent, requestId, (payload) => cb(payload.event)),
    onAiSdkAgentDone: (requestId, cb) =>
      forRequest<RequestScoped>(AGENT_EVENTS.sdkDone, requestId, () => cb()),
    onAiSdkAgentError: (requestId, cb) =>
      forRequest<SdkErrorPayload>(AGENT_EVENTS.sdkError, requestId, (payload) => cb(payload.error)),
    // Raw agent processes are not spawned by this backend (every managed
    // agent runs through the SDK channels); the subscriptions stay available.
    onAiAgentStdout: (agentId, cb) =>
      forAgent<AgentDataPayload>(AGENT_EVENTS.agentStdout, agentId, (payload) => cb(payload.data)),
    onAiAgentStderr: (agentId, cb) =>
      forAgent<AgentDataPayload>(AGENT_EVENTS.agentStderr, agentId, (payload) => cb(payload.data)),
    onAiAgentExit: (agentId, cb) =>
      forAgent<AgentExitPayload>(AGENT_EVENTS.agentExit, agentId, (payload) => cb(payload.code)),
    aiDiscoverAgents: (options) =>
      invoke<Result<'aiDiscoverAgents'>>('ai_agents_discover', { options: options ?? {} }),
    aiResolveCli: (params) => invoke<Record<string, unknown>>('ai_resolve_cli', { payload: params }),
    aiPrewarmShellEnv: () => invoke<Result<'aiPrewarmShellEnv'>>('ai_shell_env_prewarm'),
    aiCodexGetIntegration: (options) =>
      invoke<Result<'aiCodexGetIntegration'>>('ai_codex_get_integration', { options: options ?? {} }),
    aiCodexStartLogin: (options) =>
      invoke<Result<'aiCodexStartLogin'>>('ai_codex_start_login', { options: options ?? {} }),
    aiCodexGetLoginSession: (sessionId) =>
      invoke<Result<'aiCodexGetLoginSession'>>('ai_codex_get_login_session', { sessionId }),
    aiCodexCancelLogin: (sessionId) =>
      invoke<Result<'aiCodexCancelLogin'>>('ai_codex_cancel_login', { sessionId }),
    aiCodexLogout: (options) =>
      invoke<Result<'aiCodexLogout'>>('ai_codex_logout', { options: options ?? {} }),
    codexAppServerGetStatus: (agentCommand, agentEnv) =>
      invoke<Result<'codexAppServerGetStatus'>>('codex_app_server_status', { payload: { agentCommand, agentEnv } }),
    onCodexAppServerInteractionRequest: (cb) =>
      hub.subscribe<Record<string, unknown>>(AGENT_EVENTS.codexInteractionRequest, cb),
    onCodexAppServerInteractionCleared: (cb) =>
      hub.subscribe<{ interactionIds: string[]; chatSessionId?: string }>(AGENT_EVENTS.codexInteractionCleared, cb),
    respondCodexAppServerInteraction: (payload) =>
      invoke<Result<'respondCodexAppServerInteraction'>>('codex_app_server_respond', { payload }),
    cancelCodexAppServerInteractionTimeout: (interactionId) =>
      invoke<Result<'cancelCodexAppServerInteractionTimeout'>>('codex_app_server_cancel_timeout', { interactionId }),
  };
}
