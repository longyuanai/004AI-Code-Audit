from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_code_audit.cli import scan_payload
from ai_code_audit.postprocess import (
    BaselineError,
    build_baseline,
    write_baseline,
)
from ai_codeguard.cli import CLIInputError


def test_build_baseline_counts_repeated_fingerprints() -> None:
    document = build_baseline(
        [_finding("aaa"), _finding("bbb"), _finding("aaa")]
    )

    assert document == {
        "version": 1,
        "fingerprints": {"aaa": 2, "bbb": 1},
    }


def test_baseline_contains_no_finding_evidence_or_secret() -> None:
    finding = _finding("aaa")
    finding["evidence"] = ['api_key = "secret-value"']

    serialized = json.dumps(build_baseline([finding]))

    assert "secret-value" not in serialized
    assert "evidence" not in serialized


def test_write_baseline_atomically_creates_valid_document(
    tmp_path: Path,
) -> None:
    path = write_baseline(
        ".codeguard-baseline.json",
        [_finding("bbb"), _finding("aaa")],
        repo_path=tmp_path,
    )

    assert path == tmp_path / ".codeguard-baseline.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "version": 1,
        "fingerprints": {"aaa": 1, "bbb": 1},
    }
    assert list(tmp_path.glob(".*.tmp")) == []


def test_write_baseline_cannot_escape_repository(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="inside repo_path"):
        write_baseline(
            tmp_path.parent / "outside-baseline.json",
            [],
            repo_path=tmp_path,
        )


def test_cli_payload_writes_baseline_and_summary(tmp_path: Path) -> None:
    _write_vulnerable_repo(tmp_path)

    envelope = scan_payload(
        {
            "repo_path": str(tmp_path),
            "write_baseline": ".codeguard-baseline.json",
        }
    )

    baseline = json.loads(
        (tmp_path / ".codeguard-baseline.json").read_text(encoding="utf-8")
    )
    assert len(baseline["fingerprints"]) == 1
    assert envelope["summary"]["baseline_written"]["findings"] == 1


def test_cli_rejects_reading_and_writing_baseline_together(
    tmp_path: Path,
) -> None:
    _write_vulnerable_repo(tmp_path)

    with pytest.raises(CLIInputError, match="mutually exclusive"):
        scan_payload(
            {
                "repo_path": str(tmp_path),
                "baseline_path": ".codeguard-baseline.json",
                "write_baseline": ".codeguard-baseline.json",
            }
        )


def _finding(fingerprint: str) -> dict[str, object]:
    return {
        "id": fingerprint,
        "source": "004",
        "severity": "high",
        "confidence": 0.9,
        "title": "Example",
        "host": "app.py",
        "evidence": ["eval(value)"],
        "metadata": {
            "fingerprint": fingerprint,
            "relative_path": "app.py",
            "line": 2,
            "rule_id": "CG-OG-PY-001",
        },
    }


def _write_vulnerable_repo(root: Path) -> None:
    (root / "app.py").write_text(
        "value = input()\neval(value)\n", encoding="utf-8"
    )
