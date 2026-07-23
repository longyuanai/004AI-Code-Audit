import { describe, expect, it } from 'vitest';
import { analyzeFindings } from '../../src/analyzer/index.js';
import type { Finding, SuspiciousNode } from '../../src/types/index.js';
import { StubRouter, routerResponse } from '../helpers/stub-router.js';

const finding: Finding = {
  id: 'finding-1',
  ruleId: 'CG-001',
  severity: 'critical',
  title: 'SQL Injection',
  description: 'Potential SQL injection.',
  file: 'app.py',
  location: { start: { line: 1, column: 0 }, end: { line: 1, column: 18 } },
  snippet: 'db.execute(query)',
};

const suspiciousNode: SuspiciousNode = {
  file: 'app.py',
  language: 'python',
  ruleId: 'CG-001',
  ruleName: 'SQL Injection',
  node: {
    type: 'function_call',
    rawType: 'call',
    text: 'db.execute(query)',
    location: finding.location,
    children: [],
    parent: null,
    fields: {},
  },
  location: finding.location,
  snippet: finding.snippet,
  context: 'db.execute(query)',
  confidence: 0.9,
  metadata: {},
};

function options(tier: 'cheap' | 'standard' | 'premium' | 'local' = 'standard') {
  return {
    findings: [finding],
    suspiciousNodes: [suspiciousNode],
    llm: {
      tier,
      provider: 'claude' as const,
      model: 'claude-sonnet-5',
      maxConcurrency: 1,
    },
    fix: false,
  };
}

describe('UP-001 LLMRouter integration', () => {
  it('routes Stage 2 through the configured task tier and frozen request shape', async () => {
    const router = new StubRouter(() => routerResponse(JSON.stringify({
      confirmed: true,
      confidence: 0.95,
      reasoning: 'Untrusted input reaches a SQL sink.',
    })));

    await analyzeFindings(options('premium'), { router });

    expect(router.calls).toHaveLength(1);
    expect(router.calls[0].tier).toBe('premium');
    expect(router.calls[0].request.model).toBeUndefined();
    expect(router.calls[0].request.response_format).toEqual({ type: 'json_object' });
    expect(router.calls[0].request.messages.map(message => message.role)).toEqual(['system', 'user']);
  });

  it('does not require a product-level API key when a stub router is injected', async () => {
    const router = new StubRouter(() => routerResponse(JSON.stringify({
      confirmed: false,
      confidence: 0.1,
      reasoning: 'The query is parameterized.',
    })));

    const result = await analyzeFindings(options(), { router });

    expect(result.findings).toHaveLength(0);
    expect(result.dismissed).toHaveLength(1);
    expect(result.llmCalls).toBe(1);
  });

  it('maps router usage into existing cost and call accounting', async () => {
    const router = new StubRouter(() => routerResponse(JSON.stringify({
      confirmed: true,
      confidence: 0.9,
      reasoning: 'Confirmed.',
    }), {
      model: 'claude-sonnet-5',
      promptTokens: 1_000,
      completionTokens: 500,
    }));

    const result = await analyzeFindings(options(), { router });

    expect(result.llmCalls).toBe(1);
    expect(result.estimatedCost).toBe(0.0105);
    expect(result.findings[0].llmAnalysis?.confirmed).toBe(true);
  });

  it('falls back to the Stage 1 finding when the router fails', async () => {
    const router = new StubRouter(async () => {
      throw new Error('stub transport unavailable');
    });

    const result = await analyzeFindings(options(), { router });

    expect(router.calls).toHaveLength(1);
    expect(result.llmCalls).toBe(0);
    expect(result.findings).toEqual([finding]);
  });
});

