import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  buildBaseline,
  canonicalFingerprint,
  filterAgainstBaseline,
  fingerprintFinding,
  normalizeFingerprintSnippet,
} from '../../src/scanner/baseline.js';
import { CANONICAL_WHITESPACE_CODE_POINTS } from '../../src/scanner/whitespace.js';
import type { Finding } from '../../src/types/index.js';

// The same file is read by tests/test_fingerprint_contract.py; its expected
// values come from an independent reference, not from either implementation.
interface Vector { name: string; ruleId: string; path: string; snippet: string; fingerprint: string }
interface Contract {
  key: string;
  baselineVersion: number;
  canonicalWhitespace: string[];
  vectors: Vector[];
  equalities: string[][];
  inequalities: string[][];
  baselineCases: Array<{ name: string; findings: string[]; expect: Record<string, number> }>;
  baselineFilterCases: Array<{
    name: string;
    baseline: Record<string, number>;
    findings: string[];
    expect: { kept: number; baselined: number };
  }>;
}

const contract = JSON.parse(
  readFileSync(resolve(__dirname, '../../contracts/fingerprint.json'), 'utf8'),
) as Contract;
const byName = new Map(contract.vectors.map(v => [v.name, v]));

function vector(name: string): Vector {
  const v = byName.get(name);
  if (!v) throw new Error(`unknown vector ${name}`);
  return v;
}

function findingFor(name: string): Finding {
  const v = vector(name);
  return {
    id: name,
    ruleId: v.ruleId,
    severity: 'high',
    title: name,
    description: name,
    file: v.path,
    location: { start: { line: 1, column: 0 }, end: { line: 1, column: 1 } },
    snippet: v.snippet,
  };
}

describe('fingerprint contract', () => {
  it('declares the whitespace set this module implements', () => {
    expect(CANONICAL_WHITESPACE_CODE_POINTS.map(cp => `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`))
      .toEqual(contract.canonicalWhitespace);
  });

  it('collapses exactly the canonical whitespace code points, across all of Unicode', () => {
    const declared = new Set(CANONICAL_WHITESPACE_CODE_POINTS);
    const mismatches: string[] = [];
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const collapsed = normalizeFingerprintSnippet(`a${String.fromCodePoint(cp)}b`) === 'a b';
      if (collapsed !== declared.has(cp)) mismatches.push(cp.toString(16));
    }
    expect(mismatches).toEqual([]);
  });

  for (const v of contract.vectors) {
    it(`vector ${v.name}`, () => {
      expect(canonicalFingerprint(v.ruleId, v.path, v.snippet)).toBe(v.fingerprint);
      expect(fingerprintFinding({ ruleId: v.ruleId, file: v.path, snippet: v.snippet })).toBe(v.fingerprint);
    });
  }

  it('produces 16 lowercase hex characters', () => {
    for (const v of contract.vectors) expect(v.fingerprint).toMatch(/^[0-9a-f]{16}$/);
  });

  it('holds the declared equalities and inequalities', () => {
    for (const group of contract.equalities) {
      expect(new Set(group.map(name => vector(name).fingerprint)).size).toBe(1);
    }
    for (const [a, b] of contract.inequalities) {
      expect(vector(a).fingerprint).not.toBe(vector(b).fingerprint);
    }
  });

  for (const c of contract.baselineCases) {
    it(`baseline ${c.name}`, () => {
      const baseline = buildBaseline(c.findings.map(findingFor));
      const expected = Object.fromEntries(
        Object.entries(c.expect).map(([name, count]) => [vector(name).fingerprint, count]),
      );
      expect(baseline.version).toBe(contract.baselineVersion);
      expect(baseline.fingerprints).toEqual(expected);
    });
  }

  for (const c of contract.baselineFilterCases) {
    it(`baseline filter ${c.name}`, () => {
      const baseline = {
        version: contract.baselineVersion,
        fingerprints: Object.fromEntries(
          Object.entries(c.baseline).map(([name, count]) => [vector(name).fingerprint, count]),
        ),
      };
      const result = filterAgainstBaseline(c.findings.map(findingFor), baseline);
      expect(result.kept).toHaveLength(c.expect.kept);
      expect(result.baselined).toBe(c.expect.baselined);
    });
  }

  it('keeps the NUL separator visible in the source', () => {
    // A raw NUL made grep and diff treat baseline.ts as binary.
    const source = readFileSync(resolve(__dirname, '../../src/scanner/baseline.ts'));
    expect(source.includes(0)).toBe(false);
  });
});
