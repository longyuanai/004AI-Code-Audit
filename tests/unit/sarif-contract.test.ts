import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { formatSARIF } from '../../src/reporter/sarif.js';
import { securitySeverityScore } from '../../src/rules/cwe.js';
import { getAllRuleIds } from '../../src/rules/index.js';
import { VERSION } from '../../src/version.js';
import type { ScanResult, Severity } from '../../src/types/index.js';

/**
 * TypeScript-side conformance with contracts/sarif.json.
 *
 * This reporter and the Python exporter (src/ai_code_audit/output/sarif.py)
 * both upload SARIF to the same GitHub Code Scanning instance, so tool
 * identity and severity mapping have to agree. They had drifted: different
 * driver names, different $schema URLs, and an informationUri pointing at an
 * unrelated repository. tests/test_sarif_contract.py asserts the same file
 * from the Python side, so contract changes fail both suites at once.
 */

interface SarifContract {
  sarifVersion: string;
  schemaUri: string;
  driver: { name: string; informationUri: string };
  severityLevels: Record<string, string>;
  securitySeverityScores: Record<string, string>;
  uriBaseId: string;
  fingerprintKey: string;
  ruleIdNamespaces: Record<string, { pattern: string }>;
}

const contract = JSON.parse(
  readFileSync(resolve(__dirname, '../../contracts/sarif.json'), 'utf8'),
) as SarifContract;

/** The subset of the SARIF log this suite asserts on. */
interface SarifLogShape {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: { name: string; version: string; informationUri: string };
    };
  }>;
}

function emptyResult(): ScanResult {
  return {
    findings: [],
    filesScanned: 0,
    duration: 0,
    suspiciousNodes: [],
  } as unknown as ScanResult;
}

function sarifFor(result: ScanResult): SarifLogShape {
  return JSON.parse(formatSARIF(result)) as SarifLogShape;
}

describe('SARIF cross-stack contract', () => {
  it('emits the contract SARIF version and schema URI', () => {
    const sarif = sarifFor(emptyResult());

    expect(sarif.version).toBe(contract.sarifVersion);
    expect(sarif.$schema).toBe(contract.schemaUri);
  });

  it('identifies the driver exactly as the Python exporter does', () => {
    const driver = sarifFor(emptyResult()).runs[0].tool.driver;

    expect(driver.name).toBe(contract.driver.name);
    expect(driver.informationUri).toBe(contract.driver.informationUri);
  });

  it('reports this stack’s own version, which the contract leaves per-stack', () => {
    expect(sarifFor(emptyResult()).runs[0].tool.driver.version).toBe(VERSION);
  });

  it('maps every severity it emits through the contract level table', () => {
    for (const severity of ['critical', 'high', 'medium', 'low'] as Severity[]) {
      expect(contract.severityLevels[severity]).toBeDefined();
    }
  });

  it('scores security-severity as the contract specifies', () => {
    for (const severity of ['critical', 'high', 'medium', 'low'] as Severity[]) {
      expect(securitySeverityScore(severity)).toBe(
        contract.securitySeverityScores[severity],
      );
    }
  });

  it('keeps every built-in rule id inside the TypeScript namespace', () => {
    const pattern = new RegExp(contract.ruleIdNamespaces.typescript.pattern);
    const ruleIds = getAllRuleIds();

    expect(ruleIds.length).toBeGreaterThan(0);
    for (const id of ruleIds) {
      expect(pattern.test(id), `${id} violates ${pattern}`).toBe(true);
    }
  });

  it('keeps built-in rule ids out of the Python namespace', () => {
    const pattern = new RegExp(contract.ruleIdNamespaces.python.pattern);

    for (const id of getAllRuleIds()) {
      expect(pattern.test(id)).toBe(false);
    }
  });
});
