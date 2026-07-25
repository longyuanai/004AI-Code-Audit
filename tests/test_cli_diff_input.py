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


def test_cli_diff_payload_triggers_incremental_scan(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    (repository / "app.py").write_text("value = 1\n", encoding="utf-8")
    _commit(repository, "base")
    (repository / "app.py").write_text(
        "value = input('x')\neval(value)\n",
        encoding="utf-8",
    )
    _commit(repository, "head")

    envelope = scan_payload(
        {
            "repo_path": str(repository),
            "languages": ["python"],
            "diff": {"base": "HEAD~1", "head": "HEAD"},
        }
    )

    assert envelope["summary"]["repository_source"] == "git-diff"
    assert envelope["summary"]["diff"]["base"] == "HEAD~1"
    assert len(envelope["findings"]) == 1


def test_cli_subprocess_accepts_diff_input(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    (repository / "app.py").write_text("value = 1\n", encoding="utf-8")
    _commit(repository, "base")
    (repository / "app.py").write_text(
        "value = input('x')\neval(value)\n",
        encoding="utf-8",
    )
    _commit(repository, "head")
    payload = json.dumps(
        {
            "repo_path": str(repository),
            "languages": ["python"],
            "diff": {"base": "HEAD~1", "head": "HEAD"},
        }
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ai_code_audit",
            "scan",
            "--input",
            payload,
            "--json",
        ],
        cwd=ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["summary"]["files_scanned"] == 1


def test_cli_rejects_incomplete_diff_payload(tmp_path: Path) -> None:
    with pytest.raises(CLIInputError, match="diff.head"):
        scan_payload(
            {
                "repo_path": str(tmp_path),
                "diff": {"base": "HEAD~1"},
            }
        )


def _repository(path: Path) -> Path:
    _git(path, "init")
    _git(path, "config", "user.email", "phase2@example.invalid")
    _git(path, "config", "user.name", "Phase 2 Test")
    return path


def _commit(repository: Path, message: str) -> None:
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", message)


def _git(repository: Path, *arguments: str) -> None:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        capture_output=True,
        check=False,
        shell=False,
    )
    assert result.returncode == 0, result.stderr.decode(
        "utf-8", errors="replace"
    )
