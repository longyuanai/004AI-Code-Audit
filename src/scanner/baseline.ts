import { createHash } from 'node:crypto';
import { readFile, stat, writeFile } from 'node:fs/promises';
import type { Finding } from '../types/index.js';
import { WHITESPACE_CHARS } from './whitespace.js';

// A baseline is a snapshot of the findings a team has acknowledged: scans run
// with `--baseline` report (and fail on) only findings NOT in the snapshot,
// so the tool can be adopted on an existing codebase without drowning in
// historical alerts — the ratchet is "no NEW findings".
//
// The fingerprint deliberately excludes line numbers: it hashes the rule, the
// file, and the whitespace-normalized snippet, so unrelated edits that shift
// a finding up or down don't make it look new. Two identical snippets in the
// same file share a fingerprint; the baseline stores a count per fingerprint
// so a *third* copy of an acknowledged-twice finding still surfaces as new.

const BASELINE_VERSION = 1;

export interface Baseline {
  version: number;
  /** fingerprint -> acknowledged occurrence count */
  fingerprints: Record<string, number>;
}

// Canonical codeguardFingerprint/v1, shared with the Python stack
// (contracts/fingerprint.json). Fields are joined by U+0000, which file paths
// cannot contain and rule ids do not use, so e.g. file "ab" + snippet "c" and
// file "a" + snippet "bc" hash differently. Backslashes are normalised here as well as in the
// orchestrator so any caller gets the same value as the Python side.
const WHITESPACE_RUN = new RegExp(`[${WHITESPACE_CHARS}]+`, 'g');
const EDGE_SPACES = /^ +| +$/g;

export function normalizeFingerprintPath(path: string): string {
  return path.replace(/\\/g, '/');
}

export function normalizeFingerprintSnippet(snippet: string): string {
  return snippet.replace(WHITESPACE_RUN, ' ').replace(EDGE_SPACES, '');
}

export function canonicalFingerprint(ruleId: string, path: string, snippet: string): string {
  const payload = `${ruleId}\u0000${normalizeFingerprintPath(path)}\u0000${normalizeFingerprintSnippet(snippet)}`;
  // Node encodes an unpaired surrogate as U+FFFD; the Python side matches it.
  return createHash('sha256').update(payload, 'utf8').digest('hex').slice(0, 16);
}

export function fingerprintFinding(finding: Pick<Finding, 'ruleId' | 'file' | 'snippet'>): string {
  return canonicalFingerprint(finding.ruleId, finding.file, finding.snippet);
}

export function buildBaseline(findings: Pick<Finding, 'ruleId' | 'file' | 'snippet'>[]): Baseline {
  const fingerprints: Record<string, number> = {};
  for (const finding of findings) {
    const fp = fingerprintFinding(finding);
    fingerprints[fp] = (fingerprints[fp] ?? 0) + 1;
  }
  return { version: BASELINE_VERSION, fingerprints };
}

export async function writeBaseline(findings: Finding[], path: string): Promise<void> {
  const content = JSON.stringify(buildBaseline(findings), null, 2).concat('\n');
  await writeFile(path, content, 'utf-8');
}

export async function loadBaseline(path: string): Promise<Baseline> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf-8');
  } catch (error) {
    // Only a missing file means "generate one" — a permissions problem or a
    // directory must surface its real cause, not send the user off to
    // regenerate a baseline they may not be able to write either.
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(`Baseline file not found: ${path}. Generate one with --write-baseline.`);
    }
    throw new Error(`Failed to read baseline file ${path}: ${error instanceof Error ? error.message : error}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`Baseline file is not valid JSON: ${path}`);
  }

  const baseline = parsed as Baseline;
  const validShape = baseline.version === BASELINE_VERSION
    && typeof baseline.fingerprints === 'object'
    && baseline.fingerprints !== null
    && !Array.isArray(baseline.fingerprints)
    && Object.values(baseline.fingerprints).every(v => typeof v === 'number' && Number.isInteger(v) && v >= 0);
  if (!validShape) {
    throw new Error(`Unsupported baseline format in ${path} (expected version ${BASELINE_VERSION}).`);
  }
  return baseline;
}

/**
 * Guards `--write-baseline <target>` against two footguns before any scanning
 * cost is paid: commander's optional option-argument greedily eats the next
 * token, so `scan --write-baseline src` makes `src` the *output file* — which
 * would EISDIR after a full (possibly LLM-paid) scan, or worse, silently
 * overwrite a source file with baseline JSON. Refuses directories and any
 * existing file that isn't itself a baseline.
 */
export async function assertWritableBaselinePath(path: string): Promise<void> {
  let stats;
  try {
    stats = await stat(path);
  } catch {
    return; // doesn't exist — free to create
  }

  if (stats.isDirectory()) {
    throw new Error(
      `--write-baseline target "${path}" is a directory. Did you mean it as a scan path? Use --write-baseline=<file> to name the output file explicitly.`,
    );
  }

  try {
    await loadBaseline(path);
  } catch {
    throw new Error(
      `Refusing to overwrite "${path}" — it exists and is not a baseline file. Use --write-baseline=<file> with a new filename.`,
    );
  }
}

export interface BaselineFilterResult<T> {
  /** Entries whose fingerprint is not (or no longer) covered by the baseline. */
  kept: T[];
  /** How many entries the baseline absorbed. */
  baselined: number;
}

/**
 * Drops entries covered by the baseline, consuming one acknowledged
 * occurrence per match so extra copies beyond the acknowledged count still
 * surface as new.
 *
 * `legacyFile` is the path an older release would have fingerprinted (it
 * used cwd-relative paths, so a baseline written from a subdirectory holds
 * those). It is tried only after the repository-relative fingerprint, so a
 * baseline written by this release never matches through it; new baselines
 * are always written with repository-relative paths.
 */
export function filterAgainstBaseline<
  T extends Pick<Finding, 'ruleId' | 'file' | 'snippet'> & { legacyFile?: string },
>(
  findings: T[],
  baseline: Baseline,
): BaselineFilterResult<T> {
  const remaining = { ...baseline.fingerprints };
  const kept: T[] = [];
  let baselined = 0;

  for (const finding of findings) {
    const fp = fingerprintFinding(finding);
    const legacy = finding.legacyFile !== undefined
      && normalizeFingerprintPath(finding.legacyFile) !== normalizeFingerprintPath(finding.file)
      ? canonicalFingerprint(finding.ruleId, finding.legacyFile, finding.snippet)
      : undefined;
    const match = (remaining[fp] ?? 0) > 0
      ? fp
      : legacy !== undefined && (remaining[legacy] ?? 0) > 0 ? legacy : undefined;
    if (match !== undefined) {
      remaining[match] -= 1;
      baselined += 1;
    } else {
      kept.push(finding);
    }
  }

  return { kept, baselined };
}
