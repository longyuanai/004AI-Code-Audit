import { describe, expect, it } from 'vitest';
import { resolve } from 'node:path';
import { DEFAULT_CONFIG } from '../../src/config/defaults.js';
import { scan } from '../../src/scanner/orchestrator.js';
import type { Language } from '../../src/types/index.js';
import {
  goAdapter,
  javaAdapter,
  pythonAdapter,
} from '../../src/parser/languages/index.js';

const FIXTURES = resolve(__dirname, '../fixtures');

const languages: Array<{
  language: Language;
  vulnerable: string;
  safe: string;
  expectedRules: string[];
}> = [
  {
    language: 'python',
    vulnerable: 'vulnerable/injection.py',
    safe: 'safe/secure-code.py',
    expectedRules: ['CG-001', 'CG-002', 'CG-041'],
  },
  {
    language: 'go',
    vulnerable: 'vulnerable/injection.go',
    safe: 'safe/secure-code.go',
    expectedRules: ['CG-001', 'CG-002'],
  },
  {
    language: 'java',
    vulnerable: 'vulnerable/Injection.java',
    safe: 'safe/SecureCode.java',
    expectedRules: ['CG-001', 'CG-002'],
  },
];

describe('LANG-001 Python, Go, and Java Stage 1 support', () => {
  it('publishes all three language adapters', () => {
    expect([
      pythonAdapter.language,
      goAdapter.language,
      javaAdapter.language,
    ]).toEqual(['python', 'go', 'java']);
  });

  for (const fixture of languages) {
    it(`detects expected security rules in ${fixture.language} through Tree-sitter`, async () => {
      const result = await scanMuted(resolve(FIXTURES, fixture.vulnerable));
      const ruleIds = new Set(result.findings.map(finding => finding.ruleId));

      expect(result.files).toBe(1);
      expect(result.llmCalls).toBe(0);
      for (const ruleId of fixture.expectedRules) {
        expect(ruleIds, `${fixture.language} should report ${ruleId}`).toContain(ruleId);
      }
    });

    it(`keeps the secure ${fixture.language} fixture clean`, async () => {
      const result = await scanMuted(resolve(FIXTURES, fixture.safe));

      expect(result.files).toBe(1);
      expect(result.findings).toHaveLength(0);
      expect(result.skipped).toHaveLength(0);
    });
  }
});

async function scanMuted(path: string) {
  const originalWrite = process.stdout.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    return await scan({
      paths: [path],
      config: DEFAULT_CONFIG,
      fix: false,
      dryRun: true,
      output: 'json',
      verbose: false,
    });
  } finally {
    process.stdout.write = originalWrite;
  }
}

