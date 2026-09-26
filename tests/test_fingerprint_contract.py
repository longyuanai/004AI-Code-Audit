"""Python-side conformance with contracts/fingerprint.json.

tests/unit/fingerprint-contract.test.ts reads the same file. The expected
values come from an independent reference, not from either implementation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ai_code_audit.backends.opengrep import _normalize_finding
from ai_code_audit.fingerprint import (
    CANONICAL_WHITESPACE_CODE_POINTS,
    canonical_fingerprint,
    normalize_snippet,
)
from ai_code_audit.postprocess import (
    BASELINE_VERSION,
    build_baseline,
    filter_against_baseline,
    fingerprint_finding,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts" / "fingerprint.json").read_text(encoding="utf-8")
)
VECTORS = {vector["name"]: vector for vector in CONTRACT["vectors"]}


def _finding(name: str) -> dict[str, object]:
    vector = VECTORS[name]
    return {
        "id": name,
        "metadata": {
            "rule_id": vector["ruleId"],
            "relative_path": vector["path"],
            "snippet": vector["snippet"],
        },
    }


def test_whitespace_set_matches_contract() -> None:
    assert [
        f"U+{code_point:04X}" for code_point in CANONICAL_WHITESPACE_CODE_POINTS
    ] == CONTRACT["canonicalWhitespace"]
    assert BASELINE_VERSION == CONTRACT["baselineVersion"]


def test_only_canonical_whitespace_is_collapsed_across_unicode() -> None:
    declared = set(CANONICAL_WHITESPACE_CODE_POINTS)
    mismatches = [
        hex(code_point)
        for code_point in range(0x110000)
        if not 0xD800 <= code_point <= 0xDFFF
        and (normalize_snippet(f"a{chr(code_point)}b") == "a b")
        != (code_point in declared)
    ]
    assert mismatches == []


@pytest.mark.parametrize("name", list(VECTORS))
def test_vector(name: str) -> None:
    vector = VECTORS[name]

    assert (
        canonical_fingerprint(vector["ruleId"], vector["path"], vector["snippet"])
        == vector["fingerprint"]
    )
    assert fingerprint_finding(_finding(name)) == vector["fingerprint"]


def test_digest_shape() -> None:
    assert all(
        re.fullmatch(r"[0-9a-f]{16}", vector["fingerprint"])
        for vector in VECTORS.values()
    )


def test_equalities_and_inequalities() -> None:
    for group in CONTRACT["equalities"]:
        assert len({VECTORS[name]["fingerprint"] for name in group}) == 1
    for first, second in CONTRACT["inequalities"]:
        assert VECTORS[first]["fingerprint"] != VECTORS[second]["fingerprint"]


@pytest.mark.parametrize(
    "case", CONTRACT["baselineCases"], ids=lambda case: case["name"]
)
def test_baseline_counts(case: dict[str, object]) -> None:
    document = build_baseline(_finding(name) for name in case["findings"])  # type: ignore[union-attr]

    assert document["version"] == CONTRACT["baselineVersion"]
    assert document["fingerprints"] == {
        VECTORS[name]["fingerprint"]: count
        for name, count in case["expect"].items()  # type: ignore[union-attr]
    }


@pytest.mark.parametrize(
    "case", CONTRACT["baselineFilterCases"], ids=lambda case: case["name"]
)
def test_baseline_filter(case: dict[str, object]) -> None:
    baseline = {
        VECTORS[name]["fingerprint"]: count
        for name, count in case["baseline"].items()  # type: ignore[union-attr]
    }

    kept, baselined = filter_against_baseline(
        (_finding(name) for name in case["findings"]), baseline  # type: ignore[union-attr]
    )

    assert len(kept) == case["expect"]["kept"]  # type: ignore[index]
    assert baselined == case["expect"]["baselined"]  # type: ignore[index]


def test_opengrep_findings_use_the_canonical_fingerprint(tmp_path: Path) -> None:
    """Through the backend's own normalisation, not a copy of the formula."""

    repo = tmp_path.resolve()
    finding = _normalize_finding(
        {
            "check_id": "rules.CG-OG-PY-001",
            "path": "pkg/app.py",
            "start": {"line": 3, "col": 5},
            "extra": {
                "message": "eval of user input",
                "severity": "ERROR",
                "lines": "    eval(  user_input )\n",
            },
        },
        repo_path=repo,
        known_rule_ids=frozenset({"CG-OG-PY-001"}),
    )

    metadata = finding["metadata"]
    expected = canonical_fingerprint("CG-OG-PY-001", "pkg/app.py", "eval( user_input )")
    assert metadata["fingerprint"] == expected  # type: ignore[index]
    # Stored and recomputed values agree, so honouring metadata.fingerprint is sound.
    assert fingerprint_finding({**finding, "metadata": {**metadata, "fingerprint": None}}) == expected  # type: ignore[dict-item]


def test_stored_fingerprint_is_honoured_verbatim() -> None:
    """Policy: a fingerprint set by an in-process backend is never recomputed."""

    finding = _finding("basic")
    finding["metadata"]["fingerprint"] = "0123456789abcdef"  # type: ignore[index]

    assert fingerprint_finding(finding) == "0123456789abcdef"


def test_python_only_evidence_prefix_is_still_removed() -> None:
    finding = {
        "id": "x",
        "evidence": ["source line 1", "sink line 12: eval(value)"],
        "metadata": {"rule_id": "004-phase2-taint", "relative_path": "app.py"},
    }

    assert fingerprint_finding(finding) == canonical_fingerprint(
        "004-phase2-taint", "app.py", "eval(value)"
    )
