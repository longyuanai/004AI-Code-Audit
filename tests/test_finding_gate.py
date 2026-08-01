from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ai_code_audit.cli import scan_payload
from ai_codeguard.cli import CLIInputError


ROOT = Path(__file__).resolve().parents[1]


def test_high_gate_returns_one_and_preserves_json_envelope(
    tmp_path: Path,
) -> None:
    _write_vulnerable_repo(tmp_path)

    result = _run_cli(
        {"repo_path": str(tmp_path), "fail_on": "high"}, "--json"
    )
    envelope = json.loads(result.stdout)

    assert result.returncode == 1
    assert len(envelope["findings"]) == 1
    assert envelope["summary"]["gate"] == {
        "threshold": "high",
        "triggered": True,
        "findings": 1,
    }


def test_gate_returns_zero_for_repository_without_findings(
    tmp_path: Path,
) -> None:
    (tmp_path / "safe.py").write_text("print('safe')\n", encoding="utf-8")

    result = _run_cli(
        {"repo_path": str(tmp_path), "fail_on": "any"}, "--json"
    )

    assert result.returncode == 0
    assert json.loads(result.stdout)["summary"]["gate"]["triggered"] is False


def test_baseline_filters_known_finding_before_gate(tmp_path: Path) -> None:
    _write_vulnerable_repo(tmp_path)
    scan_payload(
        {
            "repo_path": str(tmp_path),
            "write_baseline": ".codeguard-baseline.json",
        }
    )

    result = _run_cli(
        {
            "repo_path": str(tmp_path),
            "baseline_path": ".codeguard-baseline.json",
            "fail_on": "high",
        },
        "--json",
    )
    envelope = json.loads(result.stdout)

    assert result.returncode == 0
    assert envelope["findings"] == []
    assert envelope["summary"]["baselined"] == 1
    assert envelope["summary"]["gate"]["triggered"] is False


def test_critical_gate_does_not_block_high_finding(tmp_path: Path) -> None:
    _write_vulnerable_repo(tmp_path)

    envelope = scan_payload(
        {"repo_path": str(tmp_path), "fail_on": "critical"}
    )

    assert envelope["summary"]["gate"]["triggered"] is False


def test_any_gate_blocks_even_low_finding(tmp_path: Path) -> None:
    finding = {
        "id": "low",
        "source": "004",
        "severity": "low",
        "confidence": 0.9,
        "title": "Low",
    }
    from ai_code_audit.cli import _apply_gate

    envelope = {"findings": [finding], "summary": {}, "warnings": []}
    _apply_gate(envelope, "any")

    assert envelope["summary"]["gate"]["triggered"] is True


def test_sarif_is_written_even_when_gate_returns_one(tmp_path: Path) -> None:
    _write_vulnerable_repo(tmp_path)
    output = tmp_path / "report.sarif"

    result = _run_cli(
        {"repo_path": str(tmp_path), "fail_on": "high"},
        "--output",
        "sarif",
        "--output-file",
        str(output),
    )

    assert result.returncode == 1
    assert output.is_file()
    assert json.loads(output.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_fail_on_cli_flag_overrides_payload(tmp_path: Path) -> None:
    _write_vulnerable_repo(tmp_path)

    result = _run_cli(
        {"repo_path": str(tmp_path), "fail_on": "none"},
        "--json",
        "--fail-on",
        "high",
    )

    assert result.returncode == 1


def test_invalid_fail_on_value_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(CLIInputError, match="payload.fail_on"):
        scan_payload({"repo_path": str(tmp_path), "fail_on": "warning"})


def _run_cli(
    payload: dict[str, object],
    *extra: str,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        (
            str(ROOT / "src"),
            str(ROOT / ".python-deps"),
            env.get("PYTHONPATH", ""),
        )
    )
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "ai_code_audit",
            "scan",
            "--input",
            json.dumps(payload),
            *extra,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def _write_vulnerable_repo(root: Path) -> None:
    (root / "app.py").write_text(
        "value = input()\neval(value)\n", encoding="utf-8"
    )
