import { describe, it, expect } from 'vitest';
import { analyzeFindings } from '../../src/analyzer/index.js';
import type { ASTNode, Finding, SuspiciousNode } from '../../src/types/index.js';

/**
 * Opt-in acceptance test against the REAL shared_llm_core route.
 *
 * Skipped by default so `npm run test:run` stays offline and free. To run it:
 *
 *   CODEGUARD_E2E=1 CODEGUARD_LLM_CONFIG=llm.yml npm run test:run -- tests/integration/llm-provider.test.ts
 *
 * Keep the configured route inexpensive: this test makes one request.
 */
const enabled = process.env.CODEGUARD_E2E === '1'
  && Boolean(process.env.CODEGUARD_LLM_CONFIG || process.env.LLM_PROVIDERS);

const SNIPPET = 'db.query("SELECT * FROM users WHERE id = " + req.params.id)';

function makeNode(): ASTNode {
  return {
    type: 'function_call',
    rawType: 'call_expression',
    text: SNIPPET,
    location: { start: { line: 3, column: 2 }, end: { line: 3, column: 2 + SNIPPET.length } },
    children: [],
    parent: null,
    fields: {},
  };
}

function makeFinding(): Finding {
  return {
    id: 'finding-1',
    ruleId: 'CG-001',
    severity: 'critical',
    title: 'SQL Injection',
    description: 'Potential SQL Injection detected.',
    file: 'src/routes/users.ts',
    location: { start: { line: 3, column: 2 }, end: { line: 3, column: 2 + SNIPPET.length } },
    snippet: SNIPPET,
  };
}

function makeSuspiciousNode(): SuspiciousNode {
  return {
    file: 'src/routes/users.ts',
    language: 'typescript',
    ruleId: 'CG-001',
    ruleName: 'SQL Injection',
    node: makeNode(),
    location: { start: { line: 3, column: 2 }, end: { line: 3, column: 2 + SNIPPET.length } },
    snippet: SNIPPET,
    context: `app.get('/users/:id', (req, res) => {\n  ${SNIPPET}.then(rows => res.json(rows));\n});`,
    confidence: 0.8,
    metadata: { method: 'query', object: 'db' },
  };
}

describe.skipIf(!enabled)('Stage 2 real LLMRouter route (opt-in E2E)', () => {
  it('confirms an obvious SQL injection end-to-end', { timeout: 60_000 }, async () => {
    const result = await analyzeFindings({
      findings: [makeFinding()],
      suspiciousNodes: [makeSuspiciousNode()],
      llm: {
        tier: 'standard',
        provider: 'claude',
        model: 'router-managed',
        maxConcurrency: 1,
      },
      fix: false,
    });

    expect(result.llmCalls).toBe(1);
    expect(result.dismissed).toHaveLength(0);

    const [finding] = result.findings;
    expect(finding.llmAnalysis?.confirmed).toBe(true);
    expect(finding.llmAnalysis?.reasoning).toBeTruthy();
    expect(finding.llmAnalysis?.confidence).toBeGreaterThan(0.5);
  });
});
