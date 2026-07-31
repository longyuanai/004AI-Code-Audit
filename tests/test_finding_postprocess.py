from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_code_audit.postprocess import (
    BaselineError,
    deduplicate_findings,
    fingerprint_finding,
    postprocess_envelope,
)


def test_fingerprint_is_stable_when_only_line_number_changes() -> None:
    first = _finding(line=10)
    shifted = _finding(line=200)

    assert fingerprint_finding(first) == fingerprint_finding(shifted)


def test_deduplication_removes_same_rule_and_location_only() -> None:
    first = _finding(line=10)
    duplicate = _finding(line=10)
    other_occurrence = _finding(line=20)

    kept, duplicates = deduplicate_findings(
        [first, duplicate, other_occurrence]
    )

    assert duplicates == 1
    assert [item["metadata"]["line"] for item in kept] == [10, 20]
    assert all(item["metadata"]["fingerprint"] for item in kept)


def test_inline_suppression_supports_same_and_next_line(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "eval(one)  # codeguard-ignore CG-OG-PY-001\n"
        "# codeguard-ignore-next-line CG-OG-PY-001\n"
        "eval(two)\n"
        "eval(three)\n",
        encoding="utf-8",
    )
    envelope = _envelope(
        [
            _finding(line=1),
            _finding(line=3),
            _finding(line=4),
        ]
    )

    result = postprocess_envelope(envelope, repo_path=tmp_path)

    assert [item["metadata"]["line"] for item in result["findings"]] == [4]
    assert result["summary"]["suppressed"] == 2


def test_baseline_consumes_acknowledged_occurrence_count(
    tmp_path: Path,
) -> None:
    first = _finding(line=10)
    second = _finding(line=20)
    fingerprint = fingerprint_finding(first)
    (tmp_path / "baseline.json").write_text(
        json.dumps(
            {
                "version": 1,
                "fingerprints": {fingerprint: 1},
            }
        ),
        encoding="utf-8",
    )

    result = postprocess_envelope(
        _envelope([first, second]),
        repo_path=tmp_path,
        baseline_path="baseline.json",
    )

    assert len(result["findings"]) == 1
    assert result["summary"]["baselined"] == 1


def test_baseline_path_cannot_escape_repository(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.json"
    outside.write_text(
        '{"version": 1, "fingerprints": {}}',
        encoding="utf-8",
    )

    with pytest.raises(BaselineError, match="inside repo_path"):
        postprocess_envelope(
            _envelope([]),
            repo_path=tmp_path,
            baseline_path=outside,
        )


def _finding(*, line: int) -> dict[str, object]:
    return {
        "id": f"finding-{line}",
        "source": "004",
        "severity": "high",
        "confidence": 0.9,
        "title": "Untrusted input reaches eval",
        "description": "Untrusted input reaches eval",
        "host": "app.py",
        "evidence": ["eval(value)"],
        "metadata": {
            "rule_id": "CG-OG-PY-001",
            "relative_path": "app.py",
            "line": line,
            "column": 1,
            "snippet": "eval(value)",
        },
    }


def _envelope(findings: list[dict[str, object]]) -> dict[str, object]:
    return {
        "findings": findings,
        "summary": {},
        "warnings": [],
    }
