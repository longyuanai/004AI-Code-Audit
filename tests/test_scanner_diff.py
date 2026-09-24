from __future__ import annotations

import subprocess
from pathlib import Path

from ai_code_audit.scanner import scan_diff


def test_scan_diff_only_scans_changed_files(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    (repository / "unchanged.py").write_text(
        "value = input('x')\neval(value)\n",
        encoding="utf-8",
    )
    (repository / "changed.py").write_text("value = 1\n", encoding="utf-8")
    _commit(repository, "base")
    (repository / "changed.py").write_text(
        "value = input('x')\neval(value)\n",
        encoding="utf-8",
    )
    _commit(repository, "head")

    envelope = scan_diff(repository, "HEAD~1", "HEAD", ["python"])

    assert envelope["summary"]["files_scanned"] == 1
    assert envelope["summary"]["diff"]["files"] == ["changed.py"]
    assert len(envelope["findings"]) == 1
    assert envelope["findings"][0]["host"].endswith("changed.py")


def test_scan_diff_ignores_sink_outside_changed_lines(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    (repository / "app.py").write_text(
        "value = input('x')\neval(value)\n",
        encoding="utf-8",
    )
    _commit(repository, "base")
    (repository / "app.py").write_text(
        "# comment\nvalue = input('x')\neval(value)\n",
        encoding="utf-8",
    )
    _commit(repository, "head")

    envelope = scan_diff(repository, "HEAD~1", "HEAD", ["python"])

    assert envelope["summary"]["files_scanned"] == 1
    assert envelope["findings"] == []


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
