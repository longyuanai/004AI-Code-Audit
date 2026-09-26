import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { filterSuppressed, parseDirectives, type Directive } from '../../src/scanner/suppression.js';
import type { SuspiciousNode } from '../../src/types/index.js';

// The same file is read by tests/test_suppression_contract.py, so a change to
// the directive grammar fails both stacks until both follow it.
interface ExpectedDirective {
  kind: 'all' | 'scoped' | 'invalid';
  ids?: string[];
  unrecognized?: string[];
  token?: string;
}

interface DirectiveCase {
  name: string;
  line: string;
  knownRuleIds?: string[];
  sameLine: ExpectedDirective | null;
  nextLine: ExpectedDirective | null;
}

interface FilterCase {
  name: string;
  source: string[];
  lineEnding?: string;
  inlineSuppression?: boolean;
  knownRuleIds?: string[];
  findings: Array<[number, string]>;
  expect: {
    kept: Array<[number, string]>;
    suppressed: number;
    diagnostics: Array<{ line: number; message: string }>;
  };
}

const contract = JSON.parse(
  readFileSync(resolve(__dirname, '../../contracts/suppression.json'), 'utf8'),
) as { directiveCases: DirectiveCase[]; filterCases: FilterCase[] };

function normalize(directive: Directive | null): ExpectedDirective | null {
  if (directive === null) return null;
  if (directive.kind === 'scoped') {
    return { kind: 'scoped', ids: directive.ids, unrecognized: directive.unrecognized };
  }
  if (directive.kind === 'invalid') return { kind: 'invalid', token: directive.token };
  return { kind: 'all' };
}

function node(line: number, ruleId: string): SuspiciousNode {
  const location = { start: { line, column: 0 }, end: { line, column: 1 } };
  return {
    file: 'contract.js',
    language: 'javascript',
    ruleId,
    ruleName: ruleId,
    node: {
      type: 'function_call',
      rawType: 'call_expression',
      text: 'x',
      location,
      children: [],
      parent: null,
      fields: {},
    },
    location,
    snippet: 'x',
    context: '',
    confidence: 0.8,
    metadata: {},
  };
}

describe('suppression contract: directive grammar', () => {
  it('covers the cases the contract requires', () => {
    expect(contract.directiveCases.length).toBeGreaterThanOrEqual(30);
  });

  for (const c of contract.directiveCases) {
    it(c.name, () => {
      const parsed = parseDirectives(c.line, c.knownRuleIds);
      expect(normalize(parsed.sameLine)).toEqual(c.sameLine);
      expect(normalize(parsed.nextLine)).toEqual(c.nextLine);
    });
  }
});

describe('suppression contract: filterSuppressed (the orchestrator entry point)', () => {
  for (const c of contract.filterCases) {
    it(c.name, () => {
      const source = c.source.join(c.lineEnding ?? '\n');
      const nodes = c.findings.map(([line, ruleId]) => node(line, ruleId));
      const result = filterSuppressed(nodes, source, {
        enabled: c.inlineSuppression !== false,
        knownRuleIds: c.knownRuleIds,
      });

      expect(result.kept.map(n => [n.location.start.line, n.ruleId])).toEqual(c.expect.kept);
      expect(result.suppressed).toBe(c.expect.suppressed);
      expect(result.diagnostics).toEqual(c.expect.diagnostics);
      expect(result.kept.length + result.suppressed).toBe(nodes.length);
    });
  }
});
