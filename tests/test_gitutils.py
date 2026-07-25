from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ai_code_audit.gitutils import GitDiffError, collect_diff


def test_collect_diff_returns_files_and_new_line_ranges(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    (repository / "app.py").write_text("value = 1\n", encoding="utf-8")
    _commit(repository, "base")
    (repository / "app.py").write_text(
        "value = 1\nexpression = input('x')\neval(expression)\n",
        encoding="utf-8",
    )
    (repository / "new.go").write_text(
        "package demo\nfunc run() {}\n",
        encoding="utf-8",
    )
    _commit(repository, "head")

    diff = collect_diff(repository, "HEAD~1", "HEAD")

    assert diff.files == ("app.py", "new.go")
    assert diff.line_ranges["app.py"] == ((2, 3),)
    assert diff.line_ranges["new.go"] == ((1, 2),)


def test_collect_diff_rejects_option_like_ref(tmp_path: Path) -> None:
    repository = _repository(tmp_path)

    with pytest.raises(GitDiffError, match="invalid git ref"):
        collect_diff(repository, "--output=/tmp/pwn", "HEAD")


def test_collect_diff_requires_git_work_tree(tmp_path: Path) -> None:
    with pytest.raises(GitDiffError):
        collect_diff(tmp_path, "HEAD~1", "HEAD")


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
