"""Python-side conformance with contracts/suppression.json.

tests/unit/suppression-contract.test.ts reads the same file, so the directive
grammar cannot drift between stacks without failing both suites.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_code_audit.postprocess import (
    Directive,
    filter_suppressed,
    parse_directives,
    postprocess_envelope,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts" / "suppression.json").read_text(encoding="utf-8")
)
DIRECTIVE_CASES = CONTRACT["directiveCases"]
FILTER_CASES = CONTRACT["filterCases"]


def _normalize(directive: Directive | None) -> dict[str, object] | None:
    if directive is None:
        return None
    if directive.kind == "scoped":
        return {
            "kind": "scoped",
            "ids": list(directive.ids),
            "unrecognized": list(directive.unrecognized),
        }
    if directive.kind == "invalid":
        return {"kind": "invalid", "token": directive.token}
    return {"kind": "all"}


def _finding(line: int, rule_id: str) -> dict[str, object]:
    return {
        "id": f"{rule_id}@{line}",
        "severity": "high",
        "title": "t",
        "metadata": {
            "rule_id": rule_id,
            "relative_path": "contract.py",
            "line": line,
            "column": 1,
            "snippet": "x",
        },
    }


def _write_source(tmp_path: Path, case: dict[str, object]) -> None:
    line_ending = str(case.get("lineEnding", "\n"))
    text = line_ending.join(case["source"])  # type: ignore[arg-type]
    # Bytes, so CRLF cases really reach the reader as CRLF.
    (tmp_path / "contract.py").write_bytes(text.encode("utf-8"))


def test_contract_covers_required_cases() -> None:
    assert len(DIRECTIVE_CASES) >= 30


@pytest.mark.parametrize(
    "case", DIRECTIVE_CASES, ids=[case["name"] for case in DIRECTIVE_CASES]
)
def test_directive_grammar(case: dict[str, object]) -> None:
    parsed = parse_directives(case["line"], case.get("knownRuleIds"))  # type: ignore[arg-type]

    assert _normalize(parsed.same_line) == case["sameLine"]
    assert _normalize(parsed.next_line) == case["nextLine"]


@pytest.mark.parametrize(
    "case", FILTER_CASES, ids=[case["name"] for case in FILTER_CASES]
)
def test_filter_suppressed_entry_point(
    tmp_path: Path, case: dict[str, object]
) -> None:
    _write_source(tmp_path, case)
    findings = [_finding(line, rule_id) for line, rule_id in case["findings"]]  # type: ignore[union-attr]
    warnings: list[str] = []

    kept, suppressed = filter_suppressed(
        findings,
        repo_path=tmp_path,
        inline_suppression=case.get("inlineSuppression", True) is not False,
        known_rule_ids=case.get("knownRuleIds"),  # type: ignore[arg-type]
        warnings=warnings,
    )

    expect = case["expect"]
    assert [
        [item["metadata"]["line"], item["metadata"]["rule_id"]] for item in kept
    ] == expect["kept"]  # type: ignore[index]
    assert suppressed == expect["suppressed"]  # type: ignore[index]
    assert warnings == [
        f"contract.py:{diagnostic['line']}: {diagnostic['message']}"
        for diagnostic in expect["diagnostics"]  # type: ignore[index]
    ]
    assert len(kept) + suppressed == len(findings)


def test_envelope_carries_diagnostics_and_keeps_the_finding(tmp_path: Path) -> None:
    """Through postprocess_envelope, the entry point the CLI uses."""

    (tmp_path / "app.py").write_text(
        "eval(x)  # codeguard-ignore TYPO-123\n"
        "eval(y)  # codeguard-ignore CG-OG-PY-001, reviewed\n"
        "eval(z)  # codeguard-ignore CG-OG-PY-001 -- constant\n",
        encoding="utf-8",
    )
    envelope = {
        "findings": [
            {
                "id": f"f{line}",
                "severity": "high",
                "title": "eval",
                "metadata": {
                    "rule_id": "CG-OG-PY-001",
                    "relative_path": "app.py",
                    "line": line,
                    "column": 1,
                    "snippet": "eval",
                },
            }
            for line in (1, 2, 3)
        ],
        "summary": {},
        "warnings": ["pre-existing warning"],
    }

    result = postprocess_envelope(envelope, repo_path=tmp_path)

    assert sorted(item["metadata"]["line"] for item in result["findings"]) == [1, 2]
    assert result["summary"]["suppressed"] == 1
    assert result["warnings"] == [
        "pre-existing warning",
        'app.py:1: codeguard-ignore names unrecognized rule id "TYPO-123"; '
        "it matches no rule",
        'app.py:2: invalid codeguard-ignore directive: unexpected token "reviewed"; '
        'it suppresses nothing (put "--" before a free-text reason)',
    ]
    json.dumps(result)  # the envelope stays serialisable


def test_envelope_without_suppression_keeps_everything(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "eval(x)  # codeguard-ignore\n", encoding="utf-8"
    )
    envelope = {
        "findings": [
            {
                "id": "f1",
                "severity": "high",
                "title": "eval",
                "metadata": {
                    "rule_id": "CG-OG-PY-001",
                    "relative_path": "app.py",
                    "line": 1,
                    "column": 1,
                    "snippet": "eval",
                },
            }
        ],
        "summary": {},
        "warnings": [],
    }

    result = postprocess_envelope(
        envelope, repo_path=tmp_path, inline_suppression=False
    )

    assert len(result["findings"]) == 1
    assert result["summary"]["suppressed"] == 0
    assert result["warnings"] == []


def test_long_id_lists_parse_in_linear_time() -> None:
    """Scanned lines are repository content; re-slicing per token was quadratic.

    300k ids (a 2 MB line) took tens of seconds before and ~0.3 s now; the
    bound is loose enough for slow runners and still far below quadratic.
    """
    import time

    from ai_code_audit.postprocess import parse_directives

    line = "x = 1  # codeguard-ignore " + " ".join(["CG-001"] * 300_000)
    started = time.perf_counter()
    directive = parse_directives(line).same_line
    elapsed = time.perf_counter() - started

    assert directive is not None and directive.kind == "scoped"
    assert len(directive.ids) == 300_000
    assert elapsed < 5.0
