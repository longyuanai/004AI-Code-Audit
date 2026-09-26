import type { SuspiciousNode } from '../types/index.js';
import { WHITESPACE_CHARS } from './whitespace.js';

// Inline suppression directives, written in a comment (any language's comment
// syntax works — the whole line is scanned):
//
//   dangerous(userInput);            // codeguard-ignore
//   dangerous(userInput);            // codeguard-ignore CG-002 -- reviewed, input is constant
//   // codeguard-ignore-next-line CG-002, 004-taint-source-to-sink
//   dangerous(userInput);
//
// The grammar is shared with the Python stack and pinned by
// contracts/suppression.json. In short: a bare directive suppresses every
// rule on the target line; a rule-id list suppresses only those rules; a
// reason goes after `--` (or an em dash). Anything that cannot be parsed
// unambiguously makes the directive invalid: it then suppresses nothing and
// produces a diagnostic, instead of degrading to "suppress everything".

export type Directive =
  | { kind: 'all' }
  | { kind: 'scoped'; ids: string[]; unrecognized: string[] }
  | { kind: 'invalid'; token: string };

export interface ParsedDirectives {
  sameLine: Directive | null;
  nextLine: Directive | null;
}

export interface SuppressionDiagnostic {
  /** 1-based line of the directive itself (the line above, for next-line directives). */
  line: number;
  message: string;
}

export interface SuppressionOptions {
  /** `false` (--no-inline-suppression) keeps every finding and parses nothing. */
  enabled?: boolean;
  /**
   * Rule IDs this engine knows about (e.g. custom rules). IDs in the `CG-` and
   * `004-` namespaces are always recognised; anything else outside this set
   * still parses but produces an "unrecognized rule id" diagnostic.
   */
  knownRuleIds?: Iterable<string>;
}

export interface SuppressionResult {
  /** Findings that survived (no applicable directive). */
  kept: SuspiciousNode[];
  /** How many findings an inline directive silenced. */
  suppressed: number;
  /** Invalid or unrecognized directives that targeted a line with a finding. */
  diagnostics: SuppressionDiagnostic[];
}

// A keyword counts only as a whole word: `xcodeguard-ignore`,
// `codeguard-ignored` or `codeguard-ignore-list.md` are not directives.
const SAME_LINE_KEYWORD = /(?<![A-Za-z0-9_-])codeguard-ignore(?![A-Za-z0-9_-])/;
const NEXT_LINE_KEYWORD = /(?<![A-Za-z0-9_-])codeguard-ignore-next-line(?![A-Za-z0-9_-])/;
const RULE_ID = /^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+$/;
// Starts like a rule id but is not one (`CG-002.`, `CG-`): a typo, not prose.
const RULE_ID_LOOKALIKE = /^[A-Za-z0-9]+-/;
const RECOGNIZED_NAMESPACE = /^(?:CG|004)-/;
const REASON_DELIMITER = /^(?:--|—)/;
const LEADING_WHITESPACE = new RegExp(`^[${WHITESPACE_CHARS}]+`);
const LEADING_SEPARATORS = new RegExp(`^[${WHITESPACE_CHARS},]*`);
const TOKEN = new RegExp(`^[^${WHITESPACE_CHARS},]*`);

function scoped(ids: string[], known: ReadonlySet<string>): Directive {
  const unrecognized = ids.filter(id => !RECOGNIZED_NAMESPACE.test(id) && !known.has(id));
  return { kind: 'scoped', ids, unrecognized };
}

function parseBody(body: string, known: ReadonlySet<string>): Directive {
  let rest = body.replace(LEADING_WHITESPACE, '');
  if (rest === '' || REASON_DELIMITER.test(rest)) return { kind: 'all' };

  const ids: string[] = [];
  let afterComma = false;
  for (;;) {
    const token = TOKEN.exec(rest)![0];
    if (RULE_ID.test(token)) {
      ids.push(token.toUpperCase());
      rest = rest.slice(token.length);
      const separator = LEADING_SEPARATORS.exec(rest)![0];
      afterComma = separator.includes(',');
      rest = rest.slice(separator.length);
      if (rest === '' || REASON_DELIMITER.test(rest)) return scoped(ids, known);
      continue;
    }
    if (ids.length === 0 || afterComma || RULE_ID_LOOKALIKE.test(token)) {
      // An empty token means the list opened with a comma.
      return { kind: 'invalid', token: token === '' ? rest.charAt(0) : token };
    }
    // Whitespace, then prose: the legacy undelimited reason. The list ends here.
    return scoped(ids, known);
  }
}

function parseKeyword(line: string, keyword: RegExp, known: ReadonlySet<string>): Directive | null {
  const match = keyword.exec(line);
  return match ? parseBody(line.slice(match.index + match[0].length), known) : null;
}

function toKnownSet(ids: Iterable<string> | undefined): Set<string> {
  return new Set([...(ids ?? [])].map(id => id.toUpperCase()));
}

export function parseDirectives(line: string, knownRuleIds?: Iterable<string>): ParsedDirectives {
  const known = toKnownSet(knownRuleIds);
  return {
    sameLine: parseKeyword(line, SAME_LINE_KEYWORD, known),
    nextLine: parseKeyword(line, NEXT_LINE_KEYWORD, known),
  };
}

/**
 * Renders a token from source for a diagnostic. Control characters are
 * escaped so a crafted comment cannot inject terminal sequences into CI logs.
 */
export function quoteToken(token: string): string {
  let out = '"';
  for (let i = 0; i < token.length; i++) {
    const code = token.charCodeAt(i);
    const isHigh = code >= 0xd800 && code <= 0xdbff;
    const isLow = code >= 0xdc00 && code <= 0xdfff;
    if (isHigh && i + 1 < token.length) {
      const next = token.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += token[i] + token[i + 1];
        i++;
        continue;
      }
    }
    if (code === 0x5c) out += '\\\\';
    else if (code === 0x22) out += '\\"';
    else if (code <= 0x1f || (code >= 0x7f && code <= 0x9f) || isHigh || isLow) {
      out += `\\u${code.toString(16).padStart(4, '0')}`;
    } else out += token[i];
  }
  return `${out}"`;
}

function diagnosticsFor(directive: Directive): string[] {
  if (directive.kind === 'invalid') {
    return [
      `invalid codeguard-ignore directive: unexpected token ${quoteToken(directive.token)}; it suppresses nothing (put "--" before a free-text reason)`,
    ];
  }
  if (directive.kind === 'scoped') {
    return directive.unrecognized.map(
      id => `codeguard-ignore names unrecognized rule id ${quoteToken(id)}; it matches no rule`,
    );
  }
  return [];
}

function applies(directive: Directive | null, ruleId: string): boolean {
  if (directive === null || directive.kind === 'invalid') return false;
  return directive.kind === 'all' || directive.ids.includes(ruleId.toUpperCase());
}

const NO_DIRECTIVES: ParsedDirectives = { sameLine: null, nextLine: null };

/**
 * Splits findings into those kept and a count of those silenced by a
 * `codeguard-ignore` directive on the flagged line, or a
 * `codeguard-ignore-next-line` directive on the preceding line, covering the
 * finding's rule. Runs per file at Stage 1 so a suppressed finding never
 * reaches Stage 2 (no wasted LLM calls).
 */
export function filterSuppressed(
  nodes: SuspiciousNode[],
  source: string,
  options: SuppressionOptions = {},
): SuppressionResult {
  if (options.enabled === false) return { kept: [...nodes], suppressed: 0, diagnostics: [] };
  const lines = source.split('\n');
  const known = toKnownSet(options.knownRuleIds);
  const parsed = new Map<number, ParsedDirectives>();
  const directivesAt = (lineNo: number): ParsedDirectives => {
    if (lineNo < 1 || lineNo > lines.length) return NO_DIRECTIVES;
    let entry = parsed.get(lineNo);
    if (entry === undefined) {
      const line = lines[lineNo - 1];
      entry = {
        sameLine: parseKeyword(line, SAME_LINE_KEYWORD, known),
        nextLine: parseKeyword(line, NEXT_LINE_KEYWORD, known),
      };
      parsed.set(lineNo, entry);
    }
    return entry;
  };

  const kept: SuspiciousNode[] = [];
  const reported = new Map<string, SuppressionDiagnostic>();
  let suppressed = 0;
  for (const node of nodes) {
    const lineNo = node.location.start.line; // 1-based
    const sameLine = directivesAt(lineNo).sameLine;
    const nextLine = directivesAt(lineNo - 1).nextLine;
    for (const [directive, directiveLine] of [[sameLine, lineNo], [nextLine, lineNo - 1]] as const) {
      if (directive === null) continue;
      for (const message of diagnosticsFor(directive)) {
        reported.set(`${directiveLine}\u0000${message}`, { line: directiveLine, message });
      }
    }
    if (applies(sameLine, node.ruleId) || applies(nextLine, node.ruleId)) {
      suppressed += 1;
    } else {
      kept.push(node);
    }
  }

  const diagnostics = [...reported.values()].sort(
    (a, b) => a.line - b.line || (a.message < b.message ? -1 : a.message > b.message ? 1 : 0),
  );
  return { kept, suppressed, diagnostics };
}
