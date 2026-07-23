import type {
  LLMRouterPort,
  RouterChatRequest,
  RouterChatResponse,
  RouterTaskTier,
} from '../../src/analyzer/router.js';

export interface StubRouterCall {
  tier: RouterTaskTier;
  request: RouterChatRequest;
}

export class StubRouter implements LLMRouterPort {
  readonly calls: StubRouterCall[] = [];

  constructor(
    private readonly responder: (
      tier: RouterTaskTier,
      request: RouterChatRequest,
    ) => RouterChatResponse | Promise<RouterChatResponse>,
  ) {}

  async chat(tier: RouterTaskTier, request: RouterChatRequest): Promise<RouterChatResponse> {
    this.calls.push({ tier, request });
    return this.responder(tier, request);
  }
}

export function routerResponse(
  content: string,
  options: {
    model?: string;
    promptTokens?: number;
    completionTokens?: number;
  } = {},
): RouterChatResponse {
  const promptTokens = options.promptTokens ?? 100;
  const completionTokens = options.completionTokens ?? 20;
  return {
    id: 'stub-response',
    model: options.model ?? 'claude-sonnet-5',
    created: 0,
    choices: [{
      index: 0,
      message: { role: 'assistant', content },
      finish_reason: 'stop',
    }],
    usage: {
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      total_tokens: promptTokens + completionTokens,
    },
  };
}

