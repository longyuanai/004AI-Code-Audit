"""Backend-neutral Finding deduplication, suppression, and baselines."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

BASELINE_VERSION = 1
RULE_TOKEN = r"(?:CG-[A-Za-z0-9-]+|004-[A-Za-z0-9-]+)"
RULE_LIST = rf"(?:\s+({RULE_TOKEN}(?:[\s,]+{RULE_TOKEN})*))?"
SAME_LINE = re.compile(rf"codeguard-ignore(?!-next-line){RULE_LIST}")
NEXT_LINE = re.compile(rf"codeguard-ignore-next-line{RULE_LIST}")


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
    ).replace("\\", "/")
    snippet = metadata.get("snippet")
    if not isinstance(snippet, str) or not snippet.strip():
        evidence = finding.get("evidence")
        snippet = (
            str(evidence[-1])
            if isinstance(evidence, list) and evidence
            else str(finding.get("description") or finding.get("title") or "")
        )
    normalized = re.sub(r"\s+", " ", snippet).strip()
    normalized = re.sub(r"^(?:sink|source) line \d+:\s*", "", normalized)
    return hashlib.sha256(
        f"{rule_id}\0{relative_path}\0{normalized}".encode()
    ).hexdigest()[:16]


def postprocess_envelope(
    envelope: dict[str, object],
    *,
    repo_path: Path,
    baseline_path: str | Path | None = None,
) -> dict[str, object]:
    raw_findings = envelope.get("findings", [])
    if not isinstance(raw_findings, list):
        raise ValueError("envelope findings must be a list")
    findings = [
        finding for finding in raw_findings if isinstance(finding, dict)
    ]
    findings, duplicates = deduplicate_findings(findings)
    findings, suppressed = filter_suppressed(findings, repo_path=repo_path)
    baselined = 0
    if baseline_path is not None:
        baseline = load_baseline(baseline_path, repo_path=repo_path)
        findings, baselined = filter_against_baseline(findings, baseline)
    envelope["findings"] = findings
    summary = envelope.get("summary")
    if isinstance(summary, dict):
        summary["duplicates_removed"] = duplicates
        summary["suppressed"] = suppressed
        summary["baselined"] = baselined
    return envelope


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


def filter_suppressed(
    findings: Iterable[dict[str, Any]],
    *,
    repo_path: Path,
) -> tuple[list[dict[str, Any]], int]:
    cache: dict[Path, list[str]] = {}
    kept: list[dict[str, Any]] = []
    suppressed = 0
    root = repo_path.resolve()
    for finding in findings:
        metadata = _metadata(finding)
        path = _finding_path(finding, metadata, root)
        line_number = _integer(metadata.get("line"), 1)
        rule_id = str(metadata.get("rule_id", ""))
        if path is None:
            kept.append(finding)
            continue
        lines = cache.setdefault(
            path,
            path.read_text(encoding="utf-8", errors="replace").splitlines(),
        )
        same = _suppression(lines, line_number, SAME_LINE)
        previous = _suppression(lines, line_number - 1, NEXT_LINE)
        if _matches_suppression(same, rule_id) or _matches_suppression(
            previous, rule_id
        ):
            suppressed += 1
        else:
            kept.append(finding)
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


def _suppression(
    lines: list[str],
    line_number: int,
    directive: re.Pattern[str],
) -> frozenset[str] | None:
    if line_number < 1 or line_number > len(lines):
        return None
    match = directive.search(lines[line_number - 1])
    if match is None:
        return None
    raw_rules = match.group(1)
    if not raw_rules:
        return frozenset()
    return frozenset(
        token.upper()
        for token in re.split(r"[\s,]+", raw_rules)
        if token
    )


def _matches_suppression(
    suppression: frozenset[str] | None,
    rule_id: str,
) -> bool:
    return suppression is not None and (
        not suppression or rule_id.upper() in suppression
    )


def _integer(value: Any, default: int) -> int:
    return value if isinstance(value, int) else default


__all__ = [
    "BASELINE_VERSION",
    "BaselineError",
    "deduplicate_findings",
    "filter_against_baseline",
    "filter_suppressed",
    "fingerprint_finding",
    "load_baseline",
    "postprocess_envelope",
]
