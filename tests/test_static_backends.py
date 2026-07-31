from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from ai_code_audit.backends import (
    BackendExecutionError,
    BackendOutputError,
    BackendUnavailableError,
    BuiltinTreeSitterBackend,
    OpengrepBackend,
    ScanRequest,
    StaticAnalysisBackend,
    scan_with_backend,
)
from ai_code_audit.cli import scan_payload


def test_builtin_backend_satisfies_protocol() -> None:
    assert isinstance(BuiltinTreeSitterBackend(), StaticAnalysisBackend)


def test_opengrep_backend_requires_executable_and_rules(
    tmp_path: Path,
) -> None:
    backend = OpengrepBackend(
        tmp_path / "missing.exe",
        tmp_path / "missing-rules",
    )

    assert not backend.available()
    with pytest.raises(BackendUnavailableError):
        backend.scan(ScanRequest.create(tmp_path))


def test_opengrep_maps_json_to_frozen_envelope(
    monkeypatch,
    tmp_path: Path,
) -> None:
    executable, rules, repository = _backend_fixture(tmp_path)
    source = repository / "app.py"
    source.write_text("eval(value)\n", encoding="utf-8")
    (rules / "python.yaml").write_text(
        "rules:\n  - id: CG-PY-001\n",
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "results": [
                        {
                            "check_id": "C.rules.python.CG-PY-001",
                            "path": str(source),
                            "start": {"line": 1, "col": 1},
                            "extra": {
                                "message": "Untrusted input reaches eval",
                                "severity": "ERROR",
                                "metadata": {
                                    "confidence": 0.95,
                                    "language": "python",
                                },
                                "lines": "eval(value)",
                                "dataflow_trace": {
                                    "taint_source": [
                                        "CliLoc",
                                        [
                                            {
                                                "path": str(source),
                                                "start": {"line": 1, "col": 6},
                                                "end": {"line": 1, "col": 11},
                                            },
                                            "value",
                                        ],
                                    ],
                                    "intermediate_vars": [],
                                    "taint_sink": [
                                        "CliLoc",
                                        [
                                            {
                                                "path": str(source),
                                                "start": {"line": 1, "col": 1},
                                                "end": {"line": 1, "col": 12},
                                            },
                                            "eval(value)",
                                        ],
                                    ],
                                },
                            },
                        }
                    ],
                    "errors": [],
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "ai_code_audit.backends.opengrep.subprocess.run",
        fake_run,
    )
    envelope = OpengrepBackend(executable, rules, timeout=7).scan(
        ScanRequest.create(repository, ["python"])
    )

    assert captured["command"][0] == str(executable.resolve())
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["timeout"] == 7
    assert envelope["summary"]["backend"] == "opengrep"
    assert envelope["summary"]["files_scanned"] == 1
    finding = envelope["findings"][0]
    assert finding["source"] == "004"
    assert finding["severity"] == "high"
    assert finding["confidence"] == 0.95
    assert finding["metadata"]["rule_id"] == "CG-PY-001"
    assert finding["metadata"]["relative_path"] == "app.py"
    assert len(finding["metadata"]["fingerprint"]) == 16
    assert [step["kind"] for step in finding["metadata"]["code_flows"]] == [
        "source",
        "sink",
    ]


def test_opengrep_invalid_json_is_backend_output_error(
    monkeypatch,
    tmp_path: Path,
) -> None:
    executable, rules, repository = _backend_fixture(tmp_path)
    (repository / "app.py").write_text("pass\n", encoding="utf-8")

    monkeypatch.setattr(
        "ai_code_audit.backends.opengrep.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, stdout="not-json", stderr=""
        ),
    )

    with pytest.raises(BackendOutputError, match="invalid JSON"):
        OpengrepBackend(executable, rules).scan(
            ScanRequest.create(repository)
        )


def test_opengrep_timeout_is_backend_execution_error(
    monkeypatch,
    tmp_path: Path,
) -> None:
    executable, rules, repository = _backend_fixture(tmp_path)
    (repository / "app.py").write_text("pass\n", encoding="utf-8")

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(
        "ai_code_audit.backends.opengrep.subprocess.run",
        timeout,
    )

    with pytest.raises(BackendExecutionError, match="timed out after 3s"):
        OpengrepBackend(executable, rules, timeout=3).scan(
            ScanRequest.create(repository)
        )


def test_auto_backend_falls_back_with_warning(
    cp314_tree_sitter_binding,
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "value = input('x')\neval(value)\n",
        encoding="utf-8",
    )

    envelope = scan_with_backend(
        ScanRequest.create(tmp_path, ["python"]),
        backend="auto",
    )

    assert len(envelope["findings"]) == 1
    assert envelope["summary"]["backend"] == "builtin-fallback"
    assert envelope["warnings"][0] == (
        "Opengrep unavailable; used builtin backend"
    )


def test_cli_rejects_explicit_unavailable_opengrep(tmp_path: Path) -> None:
    from ai_codeguard.cli import CLIInputError

    with pytest.raises(CLIInputError, match="CODEGUARD_OPENGREP_PATH"):
        scan_payload(
            {
                "repo_path": str(tmp_path),
                "backend": "opengrep",
            }
        )


def _backend_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    executable = tmp_path / "opengrep.exe"
    executable.write_bytes(b"stub")
    rules = tmp_path / "rules"
    rules.mkdir()
    repository = tmp_path / "repository"
    repository.mkdir()
    return executable, rules, repository
