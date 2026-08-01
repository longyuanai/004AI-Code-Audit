"""Minimal, redacted context construction for LLM Finding triage."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

CONTEXT_RADIUS = 4
MAX_CONTEXT_CHARS = 6_000
MAX_CONTEXT_FILE_BYTES = 2 * 1024 * 1024

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z ]*PRIVATE KEY-----"
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(
            r"(?i)\b(api[_-]?key|client[_-]?secret|password|"
            r"access[_-]?token|refresh[_-]?token)\b"
            r"\s*[:=]\s*(['\"])[^'\"\r\n]+\2"
        ),
        r'\1 = "[REDACTED]"',
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*"),
        "Bearer [REDACTED]",
    ),
    (
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
        "[REDACTED_EMAIL]",
    ),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "[REDACTED_PAYMENT_CARD]",
    ),
)


@dataclass(frozen=True)
class TriageContext:
    """The bounded evidence that may be sent to a configured LLM provider."""

    finding_id: str
    fingerprint: str
    rule_id: str
    cwe: str | None
    severity: str
    confidence: float
    title: str
    relative_path: str
    line: int
    evidence: tuple[str, ...]
    code_flows: tuple[Mapping[str, object], ...]
    data_categories: tuple[str, ...]
    code_excerpt: str

    def to_payload(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "location": {
                "path": self.relative_path,
                "line": self.line,
            },
            "evidence": list(self.evidence),
            "code_flows": [dict(step) for step in self.code_flows],
            "data_categories": list(self.data_categories),
            "code_excerpt": self.code_excerpt,
        }


def build_triage_context(
    finding: Mapping[str, Any],
    *,
    repo_path: str | Path,
    max_chars: int = MAX_CONTEXT_CHARS,
) -> TriageContext:
    """Build bounded, redacted evidence for one already-detected Finding."""

    metadata = finding.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    relative_path = str(
        metadata.get("relative_path") or Path(str(finding.get("host") or "")).name
    ).replace("\\", "/")
    line = _positive_int(metadata.get("line"), 1)
    excerpt = _read_excerpt(
        repo_path=Path(repo_path),
        finding=finding,
        metadata=metadata,
        line=line,
    )
    evidence = finding.get("evidence")
    safe_evidence = tuple(
        redact_sensitive_text(str(item))
        for item in evidence
    ) if isinstance(evidence, (list, tuple)) else ()
    raw_flows = metadata.get("code_flows")
    safe_flows = tuple(
        _redacted_flow(step)
        for step in raw_flows
        if isinstance(step, Mapping)
    ) if isinstance(raw_flows, list) else ()
    classifications = metadata.get("data_classifications")
    categories = tuple(
        str(item["category"])
        for item in classifications
        if isinstance(item, Mapping) and isinstance(item.get("category"), str)
    ) if isinstance(classifications, list) else ()
    return TriageContext(
        finding_id=str(finding.get("id") or ""),
        fingerprint=str(metadata.get("fingerprint") or ""),
        rule_id=str(metadata.get("rule_id") or finding.get("id") or "unknown"),
        cwe=str(metadata["cwe"]) if metadata.get("cwe") else None,
        severity=str(finding.get("severity") or "medium"),
        confidence=_confidence(finding.get("confidence")),
        title=str(finding.get("title") or "Untitled finding"),
        relative_path=relative_path,
        line=line,
        evidence=tuple(item[:max_chars] for item in safe_evidence),
        code_flows=safe_flows,
        data_categories=categories,
        code_excerpt=redact_sensitive_text(excerpt)[:max_chars],
    )


def build_triage_prompt(context: TriageContext) -> str:
    """Render a deterministic JSON prompt for a cheap-tier reviewer."""

    return (
        "复核下面已经由静态分析发现的代码安全问题。不要推断未提供的"
        "文件或调用链。输出 JSON object，字段必须为：confirmed(boolean)、"
        "confidence(0到1)、explanation(简洁中文)、remediation(简洁修复建议)。\n"
        + json.dumps(context.to_payload(), ensure_ascii=False, sort_keys=True)
    )


def redact_sensitive_text(text: str) -> str:
    redacted = text
    for pattern, replacement in _REDACTIONS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _read_excerpt(
    *,
    repo_path: Path,
    finding: Mapping[str, Any],
    metadata: Mapping[str, Any],
    line: int,
) -> str:
    root = repo_path.expanduser().resolve()
    raw_path = metadata.get("relative_path") or finding.get("host")
    if not isinstance(raw_path, str) or not raw_path:
        return ""
    candidate = Path(raw_path)
    path = (
        candidate.resolve()
        if candidate.is_absolute()
        else (root / candidate).resolve()
    )
    try:
        path.relative_to(root)
        if not path.is_file() or path.stat().st_size > MAX_CONTEXT_FILE_BYTES:
            return ""
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return ""
    line_numbers = {line, *_flow_lines(metadata, relative_path=str(raw_path))}
    indexes: set[int] = set()
    for line_number in line_numbers:
        start = max(line_number - CONTEXT_RADIUS - 1, 0)
        end = min(line_number + CONTEXT_RADIUS, len(lines))
        indexes.update(range(start, end))
    return "\n".join(
        f"{index + 1}: {lines[index]}" for index in sorted(indexes)
    )


def _flow_lines(
    metadata: Mapping[str, Any],
    *,
    relative_path: str,
) -> set[int]:
    raw_flows = metadata.get("code_flows")
    if not isinstance(raw_flows, list):
        return set()
    normalized_path = relative_path.replace("\\", "/")
    return {
        _positive_int(step.get("line"), 1)
        for step in raw_flows
        if isinstance(step, Mapping)
        and str(step.get("path") or "").replace("\\", "/")
        in {"", normalized_path}
    }


def _redacted_flow(step: Mapping[str, Any]) -> Mapping[str, object]:
    return {
        key: redact_sensitive_text(str(value)) if key == "message" else value
        for key, value in step.items()
        if key in {
            "kind",
            "path",
            "line",
            "column",
            "end_line",
            "end_column",
            "message",
        }
    }


def _positive_int(value: Any, default: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return default


def _confidence(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.5
    return min(max(float(value), 0.0), 1.0)


__all__ = [
    "MAX_CONTEXT_CHARS",
    "TriageContext",
    "build_triage_context",
    "build_triage_prompt",
    "redact_sensitive_text",
]
