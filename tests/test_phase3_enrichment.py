from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from ai_code_audit.postprocess import postprocess_envelope


def test_postprocess_adds_classification_tags_and_metadata(
    tmp_path: Path,
) -> None:
    _write_source(tmp_path, "api_key = request.query.key\neval(api_key)\n")

    result = postprocess_envelope(
        _envelope([_finding(line=2)]), repo_path=tmp_path
    )
    finding = result["findings"][0]

    assert "data:credentials" in finding["tags"]
    assert finding["metadata"]["data_classifications"][0]["category"] == (
        "credentials"
    )
    assert "request.query.key" not in repr(
        finding["metadata"]["data_classifications"]
    )


def test_postprocess_adds_explainable_risk_metadata(tmp_path: Path) -> None:
    _write_source(tmp_path, "patient_id = input()\neval(patient_id)\n")

    result = postprocess_envelope(
        _envelope([_finding(line=2, reachable=True)]), repo_path=tmp_path
    )
    risk = result["findings"][0]["metadata"]["risk"]

    assert risk["level"] == "critical"
    assert risk["factors"]["data_sensitivity_weight"] == 1.5
    assert "formula" in risk


def test_diff_scan_applies_change_scope_weight(tmp_path: Path) -> None:
    _write_source(tmp_path, "value = input()\neval(value)\n")
    envelope = _envelope([_finding(line=2)])
    envelope["summary"]["repository_source"] = "git-diff"

    result = postprocess_envelope(envelope, repo_path=tmp_path)

    assert result["findings"][0]["metadata"]["risk"]["factors"][
        "change_scope_weight"
    ] == 1.15


def test_findings_are_ranked_by_risk_without_changing_severity(
    tmp_path: Path,
) -> None:
    _write_source(
        tmp_path,
        "api_key = input()\neval(api_key)\n"
        "pass\npass\npass\npass\npass\npass\n"
        "value = input()\neval(value)\n",
    )
    ordinary = _finding(line=10, finding_id="ordinary")
    sensitive = _finding(line=2, finding_id="sensitive")

    result = postprocess_envelope(
        _envelope([ordinary, sensitive]), repo_path=tmp_path
    )

    assert [item["id"] for item in result["findings"]] == [
        "sensitive",
        "ordinary",
    ]
    assert all(item["severity"] == "high" for item in result["findings"])


def test_context_path_cannot_escape_repository(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-secret.py"
    outside.write_text("api_key = 'do-not-read'\n", encoding="utf-8")
    finding = _finding(line=1)
    finding["host"] = str(outside)
    finding["metadata"]["relative_path"] = str(outside)

    result = postprocess_envelope(
        _envelope([finding]), repo_path=tmp_path
    )

    assert result["findings"][0]["metadata"]["data_classifications"] == []


def test_enrichment_preserves_frozen_finding_fields(tmp_path: Path) -> None:
    _write_source(tmp_path, "api_key = input()\neval(api_key)\n")
    original = _finding(line=2)
    frozen_fields = {
        key: deepcopy(original[key])
        for key in (
            "id",
            "source",
            "severity",
            "confidence",
            "title",
            "host",
            "evidence",
        )
    }

    result = postprocess_envelope(
        _envelope([original]), repo_path=tmp_path
    )

    assert {
        key: result["findings"][0][key] for key in frozen_fields
    } == frozen_fields
    assert result["summary"]["sensitive_findings"] == 1
    assert result["summary"]["risk_levels"]["high"] == 1


def _write_source(root: Path, content: str) -> None:
    (root / "app.py").write_text(content, encoding="utf-8")


def _finding(
    *,
    line: int,
    finding_id: str = "finding",
    reachable: bool = False,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "language": "python",
        "line": line,
        "column": 1,
        "relative_path": "app.py",
        "rule_id": "CG-OG-PY-001",
        "snippet": "eval(value)",
    }
    if reachable:
        metadata["code_flows"] = [
            {
                "kind": "source",
                "path": "app.py",
                "line": 1,
                "message": "patient_id = input()",
            },
            {
                "kind": "sink",
                "path": "app.py",
                "line": line,
                "message": "eval(patient_id)",
            },
        ]
    return {
        "id": finding_id,
        "source": "004",
        "severity": "high",
        "confidence": 0.9,
        "title": "Untrusted input reaches eval",
        "host": str(Path("app.py")),
        "evidence": ["eval(value)"],
        "tags": ["python", "opengrep"],
        "metadata": metadata,
    }


def _envelope(findings: list[dict[str, object]]) -> dict[str, object]:
    return {"findings": findings, "summary": {}, "warnings": []}
