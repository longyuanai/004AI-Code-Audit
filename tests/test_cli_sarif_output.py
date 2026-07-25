from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from ai_code_audit.output.sarif import validate_sarif

ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ai_code_audit", *args],
        cwd=ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_cli_writes_valid_sarif_file(
    cp314_tree_sitter_binding,
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "report.sarif"
    payload = json.dumps({"repo_path": "samples/cpp"})

    result = _run_cli(
        "scan",
        "--input",
        payload,
        "--output",
        "sarif",
        "--output-file",
        str(output_file),
    )

    assert result.returncode == 0, result.stderr
    assert output_file.is_file()
    document = json.loads(output_file.read_text(encoding="utf-8"))
    validate_sarif(document)
    assert len(document["runs"][0]["results"]) == 1


def test_cli_json_preserves_v05_envelope(
    cp314_tree_sitter_binding,
) -> None:
    result = _run_cli(
        "scan",
        "--input",
        json.dumps({"repo_path": "samples/cpp"}),
        "--json",
    )

    assert result.returncode == 0, result.stderr
    envelope = json.loads(result.stdout)
    assert set(envelope) == {"findings", "summary", "warnings"}
    assert envelope["findings"][0]["source"] == "004"


def test_cli_sarif_requires_output_file(
    cp314_tree_sitter_binding,
) -> None:
    result = _run_cli(
        "scan",
        "--input",
        json.dumps({"repo_path": "samples/cpp"}),
        "--output",
        "sarif",
    )

    assert result.returncode == 2
    assert "--output-file is required" in result.stderr
