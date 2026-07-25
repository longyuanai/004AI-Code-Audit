from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ai_codeguard import cli


def test_git_url_clone_failure_falls_back(
    tree_sitter_binding,
    monkeypatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "value = input('value')\neval(value)\n",
        encoding="utf-8",
    )

    def fail_clone(git_url: str, destination: Path) -> None:
        raise cli.GitCloneError("offline")

    monkeypatch.setattr(cli, "_clone_repository", fail_clone)

    envelope = cli.scan_payload(
        {
            "git_url": "https://example.invalid/repository.git",
            "repo_path": str(tmp_path),
            "languages": ["python"],
        }
    )

    assert len(envelope["findings"]) == 1
    assert envelope["summary"]["repository_source"] == "local-fallback"
    assert envelope["warnings"] == [
        "Git clone failed; used repo_path fallback: offline"
    ]


def test_local_git_url_is_shallow_cloned_and_scanned(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    source_repo = tmp_path / "source"
    source_repo.mkdir()
    (source_repo / "app.py").write_text(
        "value = input('value')\neval(value)\n",
        encoding="utf-8",
    )
    _git(source_repo, "init")
    _git(source_repo, "config", "user.email", "codeguard@example.invalid")
    _git(source_repo, "config", "user.name", "CodeGuard Test")
    _git(source_repo, "add", "app.py")
    _git(source_repo, "commit", "-m", "fixture")

    envelope = cli.scan_payload(
        {
            "git_url": source_repo.as_uri(),
            "languages": ["python"],
        }
    )

    assert len(envelope["findings"]) == 1
    assert envelope["summary"]["repository_source"] == "git"
    assert envelope["summary"]["files_scanned"] == 1
    assert envelope["warnings"] == []


def test_git_clone_failure_without_fallback_is_error(
    tree_sitter_binding,
    monkeypatch,
) -> None:
    def fail_clone(git_url: str, destination: Path) -> None:
        raise cli.GitCloneError("network unavailable")

    monkeypatch.setattr(cli, "_clone_repository", fail_clone)

    with pytest.raises(cli.GitCloneError, match="network unavailable"):
        cli.scan_payload(
            {"git_url": "https://example.invalid/repository.git"}
        )


def _git(repository: Path, *args: str) -> None:
    result = subprocess.run(
        ["git", *args],
        cwd=repository,
        capture_output=True,
        check=False,
        shell=False,
    )
    assert result.returncode == 0, result.stderr.decode(
        "utf-8",
        errors="replace",
    )
