"""Real-project evidence must preserve failures instead of reporting silence."""

import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from ai_code_audit import cli
from benchmarks.c3 import realworld
from benchmarks.c3.opengrep_pin import OpengrepPin, OpengrepPinError


@pytest.fixture
def local_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "code"
    source = root / realworld.SCOPE / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text("value = 1\n", encoding="utf-8")
    rules = root / "rules/opengrep/taint.yaml"
    rules.parent.mkdir(parents=True)
    rules.write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr(realworld, "ROOT", root)

    def git(*args: str) -> bytes:
        if args[0] == "ls-tree":
            return b"src/ai_code_audit/app.py\n"
        if args[0] == "show":
            return b"value = 1\n"
        return b""

    monkeypatch.setattr(realworld, "git", git)
    return tmp_path / "output"


def test_bad_pin_never_starts_opengrep_and_keeps_builtin(
    local_run: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def bad_pin(*_args: object) -> None:
        raise OpengrepPinError("hash_mismatch", "test mismatch")

    monkeypatch.setattr(realworld, "verify_opengrep", bad_pin)
    process = Mock(side_effect=AssertionError("native process must not start"))
    monkeypatch.setattr(realworld.subprocess, "run", process)
    assert realworld.main(["--output-dir", str(local_run)]) == 4
    report = json.loads((local_run / "run.json").read_text(encoding="utf-8"))
    assert report["backends"][0]["status"] == "ok"
    assert report["backends"][1]["findings"] is None
    assert "test mismatch" in report["backends"][1]["error"]
    process.assert_not_called()


def test_second_scan_failure_preserves_first_report(
    local_run: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = Mock(side_effect=[
        {"findings": [], "summary": {"files_scanned": 1}, "warnings": []},
        RuntimeError("second scan failed"),
    ])
    monkeypatch.setattr(cli, "scan_payload", scan)
    monkeypatch.setattr(realworld, "verify_opengrep", Mock(side_effect=OSError("missing")))
    assert realworld.main(["--output-dir", str(local_run)]) == 4
    report = json.loads((local_run / "run.json").read_text(encoding="utf-8"))
    assert (local_run / "builtin-1.json").is_file()
    assert report["backends"][0]["findings"] is None
    assert report["recall"] is None


def test_existing_evidence_is_not_overwritten(local_run: Path) -> None:
    local_run.mkdir()
    prior = local_run / "run.json"
    prior.write_text("prior evidence", encoding="utf-8")
    with pytest.raises(FileExistsError):
        realworld.main(["--output-dir", str(local_run)])
    assert prior.read_text(encoding="utf-8") == "prior evidence"


def test_runtime_version_mismatch_prevents_scan(
    local_run: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(realworld, "verify_opengrep", lambda path: OpengrepPin(
        path, "0" * 64, "1.26.0", Path("test.lock"),
    ))
    process = Mock(return_value=subprocess.CompletedProcess(
        ["opengrep", "--version"], 0, "9.9.9\n", "",
    ))
    monkeypatch.setattr(realworld.subprocess, "run", process)
    assert realworld.main(["--output-dir", str(local_run)]) == 4
    report = json.loads((local_run / "run.json").read_text(encoding="utf-8"))
    assert "version mismatch" in report["backends"][1]["error"]
    assert "payload" not in report["backends"][1]
    process.assert_called_once()
