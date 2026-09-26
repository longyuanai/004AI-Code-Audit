"""Backend-neutral Finding deduplication, suppression, and baselines."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from ai_code_audit.classification import (
    CodeContext,
    DataClassification,
    DataClassifier,
    DefaultDataClassifier,
)
from ai_code_audit.fingerprint import (
    WHITESPACE_CHARS,
    canonical_fingerprint,
    normalize_snippet,
)
from ai_code_audit.risk import RiskConfig, assess_risk

BASELINE_VERSION = 1
CONTEXT_RADIUS = 3
MAX_CONTEXT_FILE_BYTES = 2 * 1024 * 1024

# Inline suppression grammar, shared with src/scanner/suppression.ts and
# pinned by contracts/suppression.json. Anything that cannot be parsed
# unambiguously makes a directive invalid: it then suppresses nothing and is
# reported, instead of degrading to "suppress everything".
_SAME_LINE_KEYWORD = re.compile(
    r"(?<![A-Za-z0-9_-])codeguard-ignore(?![A-Za-z0-9_-])"
)
_NEXT_LINE_KEYWORD = re.compile(
    r"(?<![A-Za-z0-9_-])codeguard-ignore-next-line(?![A-Za-z0-9_-])"
)
_RULE_ID = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+", re.ASCII)
# Starts like a rule id but is not one (``CG-002.``, ``CG-``): a typo, not prose.
_RULE_ID_LOOKALIKE = re.compile(r"[A-Za-z0-9]+-", re.ASCII)
_RECOGNIZED_NAMESPACE = re.compile(r"(?:CG|004)-")
_REASON_DELIMITER = re.compile("(?:--|—)")
_LEADING_WHITESPACE = re.compile(f"[{WHITESPACE_CHARS}]+")
_LEADING_SEPARATORS = re.compile(f"[{WHITESPACE_CHARS},]*")
_TOKEN = re.compile(f"[^{WHITESPACE_CHARS},]*")
_EVIDENCE_PREFIX = re.compile(r"^(?:sink|source) line \d+:\s*")


class BaselineError(ValueError):
    """Raised when a baseline path or document is invalid."""


def fingerprint_finding(finding: Mapping[str, Any]) -> str:
    metadata = _metadata(finding)
    existing = metadata.get("fingerprint")
    if isinstance(existing, str) and existing:
        return existing
    rule_id = str(metadata.get("rule_id") or finding.get("id") or "unknown")
    relative_path = str(
        metadata.get("relative_path") or finding.get("host") or "unknown"
    )
    snippet = metadata.get("snippet")
    if not isinstance(snippet, str) or not snippet.strip():
        evidence = finding.get("evidence")
        snippet = (
            str(evidence[-1])
            if isinstance(evidence, list) and evidence
            else str(finding.get("description") or finding.get("title") or "")
        )
    # Python-only snippet selection: evidence entries carry a line-number
    # prefix that would otherwise make the fingerprint move with the code.
    normalized = _EVIDENCE_PREFIX.sub("", normalize_snippet(snippet))
    return canonical_fingerprint(rule_id, relative_path, normalized)


def postprocess_envelope(
    envelope: dict[str, object],
    *,
    repo_path: Path,
    baseline_path: str | Path | None = None,
    classifier: DataClassifier | None = None,
    risk_config: RiskConfig | None = None,
    inline_suppression: bool = True,
) -> dict[str, object]:
    raw_findings = envelope.get("findings", [])
    if not isinstance(raw_findings, list):
        raise ValueError("envelope findings must be a list")
    findings = [
        finding for finding in raw_findings if isinstance(finding, dict)
    ]
    findings, duplicates = deduplicate_findings(findings)
    diagnostics: list[str] = []
    findings, suppressed = filter_suppressed(
        findings,
        repo_path=repo_path,
        inline_suppression=inline_suppression,
        warnings=diagnostics,
    )
    if diagnostics:
        existing = envelope.get("warnings")
        if isinstance(existing, list):
            existing.extend(diagnostics)
        else:
            envelope["warnings"] = diagnostics
    baselined = 0
    if baseline_path is not None:
        baseline = load_baseline(baseline_path, repo_path=repo_path)
        findings, baselined = filter_against_baseline(findings, baseline)
    findings = enrich_findings(
        findings,
        repo_path=repo_path,
        classifier=classifier or DefaultDataClassifier(),
        in_diff=_is_diff_scan(envelope),
        risk_config=risk_config,
    )
    envelope["findings"] = findings
    summary = envelope.get("summary")
    if isinstance(summary, dict):
        summary["duplicates_removed"] = duplicates
        summary["suppressed"] = suppressed
        summary["baselined"] = baselined
        summary["sensitive_findings"] = sum(
            bool(_metadata(finding).get("data_classifications"))
            for finding in findings
        )
        summary["risk_levels"] = _risk_level_counts(findings)
    return envelope


def enrich_findings(
    findings: Iterable[dict[str, Any]],
    *,
    repo_path: Path,
    classifier: DataClassifier,
    in_diff: bool,
    risk_config: RiskConfig | None = None,
) -> list[dict[str, Any]]:
    """Attach sensitive-data and risk metadata, then rank highest risk first."""

    enriched: list[dict[str, Any]] = []
    root = repo_path.resolve()
    for finding in findings:
        metadata = _metadata(finding)
        context = _classification_context(finding, metadata, root)
        classifications = classifier.classify(context) if context else []
        metadata["data_classifications"] = [
            _classification_metadata(item) for item in classifications
        ]
        finding["tags"] = _classification_tags(
            finding.get("tags"), classifications
        )
        assessment = assess_risk(
            finding,
            classifications,
            reachable=_is_reachable(metadata),
            in_diff=True if in_diff else None,
            config=risk_config,
        )
        metadata["risk"] = assessment.to_metadata()
        enriched.append(finding)
    return sorted(
        enriched,
        key=lambda finding: -float(
            _metadata(finding)["risk"]["score"]  # type: ignore[index]
        ),
    )


def deduplicate_findings(
    findings: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    kept: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, int]] = set()
    duplicates = 0
    for finding in findings:
        metadata = _metadata(finding)
        fingerprint = fingerprint_finding(finding)
        metadata["fingerprint"] = fingerprint
        key = (
            str(metadata.get("rule_id", "")),
            str(metadata.get("relative_path", finding.get("host", ""))),
            _integer(metadata.get("line"), 1),
            _integer(metadata.get("column"), 1),
        )
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        kept.append(finding)
    return kept, duplicates


@dataclass(frozen=True)
class Directive:
    """One parsed ``codeguard-ignore`` directive.

    ``kind`` is ``"all"`` (bare), ``"scoped"`` (``ids``) or ``"invalid"``
    (``token`` is the first thing that could not be parsed).
    """

    kind: str
    ids: tuple[str, ...] = ()
    unrecognized: tuple[str, ...] = ()
    token: str | None = None


@dataclass(frozen=True)
class ParsedDirectives:
    same_line: Directive | None
    next_line: Directive | None


def parse_directives(
    line: str,
    known_rule_ids: Iterable[str] | None = None,
) -> ParsedDirectives:
    known = _known_set(known_rule_ids)
    return ParsedDirectives(
        same_line=_parse_keyword(line, _SAME_LINE_KEYWORD, known),
        next_line=_parse_keyword(line, _NEXT_LINE_KEYWORD, known),
    )


def quote_token(token: str) -> str:
    """Render source text for a diagnostic without passing control characters
    through, so a crafted comment cannot inject terminal sequences into CI logs."""

    out = ['"']
    for character in token:
        code = ord(character)
        if character == "\\":
            out.append("\\\\")
        elif character == '"':
            out.append('\\"')
        elif code <= 0x1F or 0x7F <= code <= 0x9F or 0xD800 <= code <= 0xDFFF:
            out.append(f"\\u{code:04x}")
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def filter_suppressed(
    findings: Iterable[dict[str, Any]],
    *,
    repo_path: Path,
    inline_suppression: bool = True,
    known_rule_ids: Iterable[str] | None = None,
    warnings: list[str] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Drop findings covered by an inline directive.

    Invalid or unrecognized directives that target a finding's line are
    appended to ``warnings`` as ``path:line: message``.
    """

    if not inline_suppression:
        return list(findings), 0
    known = _known_set(known_rule_ids)
    cache: dict[Path, list[str]] = {}
    parsed: dict[tuple[Path, int], ParsedDirectives] = {}
    reported: set[tuple[str, int, str]] = set()
    kept: list[dict[str, Any]] = []
    suppressed = 0
    root = repo_path.resolve()

    def directives_at(path: Path, line_number: int) -> ParsedDirectives:
        lines = cache.setdefault(
            path,
            path.read_text(encoding="utf-8", errors="replace").splitlines(),
        )
        if line_number < 1 or line_number > len(lines):
            return _NO_DIRECTIVES
        key = (path, line_number)
        if key not in parsed:
            text = lines[line_number - 1]
            parsed[key] = ParsedDirectives(
                same_line=_parse_keyword(text, _SAME_LINE_KEYWORD, known),
                next_line=_parse_keyword(text, _NEXT_LINE_KEYWORD, known),
            )
        return parsed[key]

    for finding in findings:
        metadata = _metadata(finding)
        path = _finding_path(finding, metadata, root)
        line_number = _integer(metadata.get("line"), 1)
        rule_id = str(metadata.get("rule_id", ""))
        if path is None:
            kept.append(finding)
            continue
        same = directives_at(path, line_number).same_line
        previous = directives_at(path, line_number - 1).next_line
        display_path = path.relative_to(root).as_posix()
        for directive, directive_line in (
            (same, line_number),
            (previous, line_number - 1),
        ):
            if directive is not None:
                for message in _diagnostics_for(directive):
                    reported.add((display_path, directive_line, message))
        if _applies(same, rule_id) or _applies(previous, rule_id):
            suppressed += 1
        else:
            kept.append(finding)
    if warnings is not None:
        warnings.extend(
            f"{where}:{line}: {message}"
            for where, line, message in sorted(reported)
        )
    return kept, suppressed


def load_baseline(
    baseline_path: str | Path,
    *,
    repo_path: Path,
) -> dict[str, int]:
    root = repo_path.resolve()
    candidate = Path(baseline_path).expanduser()
    path = (
        candidate.resolve()
        if candidate.is_absolute()
        else (root / candidate).resolve()
    )
    try:
        path.relative_to(root)
    except ValueError as error:
        raise BaselineError("baseline_path must stay inside repo_path") from error
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise BaselineError(f"unable to read baseline: {error}") from error
    except json.JSONDecodeError as error:
        raise BaselineError("baseline is not valid JSON") from error
    if not isinstance(document, dict) or document.get("version") != BASELINE_VERSION:
        raise BaselineError("unsupported baseline format")
    fingerprints = document.get("fingerprints")
    if not isinstance(fingerprints, dict) or not all(
        isinstance(key, str)
        and isinstance(value, int)
        and value >= 0
        for key, value in fingerprints.items()
    ):
        raise BaselineError("baseline fingerprints must be non-negative counts")
    return dict(fingerprints)


def build_baseline(
    findings: Iterable[Mapping[str, Any]],
) -> dict[str, object]:
    """Create a secret-free, count-aware baseline document."""

    fingerprints: dict[str, int] = {}
    for finding in findings:
        fingerprint = fingerprint_finding(finding)
        fingerprints[fingerprint] = fingerprints.get(fingerprint, 0) + 1
    return {
        "version": BASELINE_VERSION,
        "fingerprints": dict(sorted(fingerprints.items())),
    }


def write_baseline(
    baseline_path: str | Path,
    findings: Iterable[Mapping[str, Any]],
    *,
    repo_path: Path,
) -> Path:
    """Atomically write a baseline within the scanned repository."""

    root = repo_path.resolve()
    candidate = Path(baseline_path).expanduser()
    path = (
        candidate.resolve()
        if candidate.is_absolute()
        else (root / candidate).resolve()
    )
    try:
        path.relative_to(root)
    except ValueError as error:
        raise BaselineError("baseline_path must stay inside repo_path") from error
    path.parent.mkdir(parents=True, exist_ok=True)
    document = build_baseline(findings)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            json.dump(document, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except OSError as error:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise BaselineError(f"unable to write baseline: {error}") from error
    return path


def filter_against_baseline(
    findings: Iterable[dict[str, Any]],
    baseline: Mapping[str, int],
) -> tuple[list[dict[str, Any]], int]:
    remaining = dict(baseline)
    kept: list[dict[str, Any]] = []
    baselined = 0
    for finding in findings:
        fingerprint = fingerprint_finding(finding)
        if remaining.get(fingerprint, 0) > 0:
            remaining[fingerprint] -= 1
            baselined += 1
        else:
            kept.append(finding)
    return kept, baselined


def _metadata(finding: Mapping[str, Any]) -> dict[str, Any]:
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        if isinstance(finding, dict):
            finding["metadata"] = metadata
    return metadata


def _finding_path(
    finding: Mapping[str, Any],
    metadata: Mapping[str, Any],
    root: Path,
) -> Path | None:
    raw = metadata.get("relative_path") or finding.get("host")
    if not isinstance(raw, str) or not raw:
        return None
    candidate = Path(raw)
    path = (
        candidate.resolve()
        if candidate.is_absolute()
        else (root / candidate).resolve()
    )
    try:
        path.relative_to(root)
    except ValueError:
        return None
    return path if path.is_file() else None


def _classification_context(
    finding: Mapping[str, Any],
    metadata: Mapping[str, Any],
    root: Path,
) -> CodeContext | None:
    path = _finding_path(finding, metadata, root)
    if path is None:
        return None
    try:
        if path.stat().st_size > MAX_CONTEXT_FILE_BYTES:
            return None
        lines = path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return None
    selected_lines = _context_lines(lines, metadata)
    trace_messages = _trace_messages(metadata.get("code_flows"))
    content = "\n".join([*selected_lines, *trace_messages])
    return CodeContext(
        path=str(metadata.get("relative_path") or path.name),
        language=str(metadata.get("language") or "unknown"),
        content=content,
    )


def _context_lines(
    lines: list[str],
    metadata: Mapping[str, Any],
) -> list[str]:
    line_numbers = {_integer(metadata.get("line"), 1)}
    raw_flows = metadata.get("code_flows")
    if isinstance(raw_flows, list):
        relative_path = str(metadata.get("relative_path") or "").replace(
            "\\", "/"
        )
        for step in raw_flows:
            if not isinstance(step, Mapping):
                continue
            step_path = str(step.get("path") or "").replace("\\", "/")
            if not step_path or step_path == relative_path:
                line_numbers.add(_integer(step.get("line"), 1))
    indexes: set[int] = set()
    for line_number in line_numbers:
        start = max(line_number - CONTEXT_RADIUS - 1, 0)
        end = min(line_number + CONTEXT_RADIUS, len(lines))
        indexes.update(range(start, end))
    return [lines[index] for index in sorted(indexes)]


def _trace_messages(raw_flows: Any) -> list[str]:
    if not isinstance(raw_flows, list):
        return []
    return [
        str(step["message"])
        for step in raw_flows
        if isinstance(step, Mapping)
        and isinstance(step.get("message"), str)
    ]


def _classification_metadata(
    classification: DataClassification,
) -> dict[str, object]:
    return {
        "category": classification.category,
        "confidence": classification.confidence,
        "sensitivity_weight": classification.sensitivity_weight,
        "indicators": list(classification.indicators),
    }


def _classification_tags(
    raw_tags: Any,
    classifications: Iterable[DataClassification],
) -> list[str]:
    tags = {
        str(tag)
        for tag in raw_tags
        if isinstance(tag, str)
    } if isinstance(raw_tags, list) else set()
    tags.update(f"data:{item.category}" for item in classifications)
    return sorted(tags)


def _is_reachable(metadata: Mapping[str, Any]) -> bool | None:
    flows = metadata.get("code_flows")
    if isinstance(flows, list) and flows:
        return True
    if metadata.get("rule_id") == "004-phase2-taint":
        return True
    return None


def _is_diff_scan(envelope: Mapping[str, object]) -> bool:
    summary = envelope.get("summary")
    return isinstance(summary, Mapping) and (
        summary.get("repository_source") == "git-diff"
        or isinstance(summary.get("diff"), Mapping)
    )


def _risk_level_counts(
    findings: Iterable[Mapping[str, Any]],
) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        risk = _metadata(finding).get("risk")
        level = risk.get("level") if isinstance(risk, Mapping) else None
        if isinstance(level, str) and level in counts:
            counts[level] += 1
    return counts


_NO_DIRECTIVES = ParsedDirectives(same_line=None, next_line=None)


def _known_set(known_rule_ids: Iterable[str] | None) -> frozenset[str]:
    return frozenset(rule_id.upper() for rule_id in known_rule_ids or ())


def _parse_keyword(
    line: str,
    keyword: re.Pattern[str],
    known: frozenset[str],
) -> Directive | None:
    match = keyword.search(line)
    return None if match is None else _parse_body(line[match.end():], known)


def _scoped(ids: list[str], known: frozenset[str]) -> Directive:
    return Directive(
        kind="scoped",
        ids=tuple(ids),
        unrecognized=tuple(
            rule_id
            for rule_id in ids
            if not _RECOGNIZED_NAMESPACE.match(rule_id) and rule_id not in known
        ),
    )


def _parse_body(body: str, known: frozenset[str]) -> Directive:
    leading = _LEADING_WHITESPACE.match(body)
    rest = body[leading.end():] if leading else body
    if not rest or _REASON_DELIMITER.match(rest):
        return Directive(kind="all")
    ids: list[str] = []
    after_comma = False
    while True:
        token = _TOKEN.match(rest).group()  # type: ignore[union-attr]
        if _RULE_ID.fullmatch(token):
            ids.append(token.upper())
            rest = rest[len(token):]
            separator = _LEADING_SEPARATORS.match(rest).group()  # type: ignore[union-attr]
            after_comma = "," in separator
            rest = rest[len(separator):]
            if not rest or _REASON_DELIMITER.match(rest):
                return _scoped(ids, known)
            continue
        if not ids or after_comma or _RULE_ID_LOOKALIKE.match(token):
            # An empty token means the list opened with a comma.
            return Directive(kind="invalid", token=token or rest[0])
        # Whitespace, then prose: the legacy undelimited reason ends the list.
        return _scoped(ids, known)


def _diagnostics_for(directive: Directive) -> list[str]:
    if directive.kind == "invalid":
        return [
            "invalid codeguard-ignore directive: unexpected token "
            f"{quote_token(directive.token or '')}; it suppresses nothing "
            '(put "--" before a free-text reason)'
        ]
    return [
        f"codeguard-ignore names unrecognized rule id {quote_token(rule_id)}; "
        "it matches no rule"
        for rule_id in directive.unrecognized
    ]


def _applies(directive: Directive | None, rule_id: str) -> bool:
    if directive is None or directive.kind == "invalid":
        return False
    return directive.kind == "all" or rule_id.upper() in directive.ids


def _integer(value: Any, default: int) -> int:
    return value if isinstance(value, int) else default


__all__ = [
    "BASELINE_VERSION",
    "BaselineError",
    "Directive",
    "ParsedDirectives",
    "build_baseline",
    "deduplicate_findings",
    "enrich_findings",
    "filter_against_baseline",
    "filter_suppressed",
    "fingerprint_finding",
    "load_baseline",
    "parse_directives",
    "postprocess_envelope",
    "quote_token",
    "write_baseline",
]
