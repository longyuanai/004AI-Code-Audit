import { describe, expect, it } from 'vitest';
import { detectLanguage, getSupportedExtensions, parse } from '../../src/parser/index.js';
import { getRules, runRules } from '../../src/rules/index.js';

describe('NEW-001 isolated upgrade baseline', () => {
  it('retains JavaScript, TypeScript, and PHP extension detection', () => {
    expect(detectLanguage('app.js')).toBe('javascript');
    expect(detectLanguage('app.ts')).toBe('typescript');
    expect(detectLanguage('app.php')).toBe('php');
  });

  it('retains the baseline language extension set', () => {
    expect(getSupportedExtensions()).toEqual(expect.arrayContaining([
      '.js',
      '.jsx',
      '.ts',
      '.tsx',
      '.php',
    ]));
  });

  it('retains Stage 1 rule execution without invoking an LLM', async () => {
    const tree = await parse('eval(userInput);', 'javascript');
    const findings = runRules(tree, getRules({ preset: 'all' }), 'fixture.js');

    expect(findings.some(finding => finding.ruleId === 'CG-003')).toBe(true);
  });
});
