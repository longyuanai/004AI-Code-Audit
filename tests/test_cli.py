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
    monkeypatch,
    tmp_path: Path,
) -> None:
    # file:// is not a default-allowed scheme; this fixture opts in the same
    # way an operator with a local mirror would.
    monkeypatch.setenv(cli.GIT_URL_SCHEMES_ENV_VAR, "https,ssh,file")
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


@pytest.mark.parametrize(
    ("git_url", "scheme"),
    [
        ("file:///tmp/secret-repo", "file"),
        ("/tmp/secret-repo", "file"),
        ("./relative-repo", "file"),
        ("ext::sh -c 'id > /tmp/pwned'", "ext"),
        ("http://internal.invalid/repo.git", "http"),
        ("git://internal.invalid/repo.git", "git"),
        ("ftp://internal.invalid/repo.git", "ftp"),
    ],
)
def test_disallowed_git_url_schemes_are_rejected(
    git_url: str,
    scheme: str,
) -> None:
    with pytest.raises(cli.CLIInputError, match=f"scheme '{scheme}' is not"):
        cli.scan_payload({"git_url": git_url, "languages": ["python"]})


@pytest.mark.parametrize(
    "git_url",
    [
        "https://github.com/owner/repo.git",
        "ssh://git@github.com/owner/repo.git",
        "git+ssh://git@github.com/owner/repo.git",
        "git@github.com:owner/repo.git",
    ],
)
def test_default_allowed_git_url_schemes_pass_validation(git_url: str) -> None:
    cli._validate_git_url(git_url)


def test_disallowed_scheme_does_not_fall_back_to_repo_path(
    tmp_path: Path,
) -> None:
    """A rejected scheme must fail loudly, not silently scan repo_path.

    The fallback exists for clone *failures*; letting a refused scheme land
    there would turn the control into a no-op that still returns a scan.
    """

    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    with pytest.raises(cli.CLIInputError, match="scheme 'file' is not"):
        cli.scan_payload(
            {
                "git_url": "file:///tmp/secret-repo",
                "repo_path": str(tmp_path),
                "languages": ["python"],
            }
        )


def test_git_url_scheme_allowlist_is_configurable(monkeypatch) -> None:
    monkeypatch.setenv(cli.GIT_URL_SCHEMES_ENV_VAR, "https,file")

    cli._validate_git_url("file:///tmp/mirror")
    cli._validate_git_url("https://github.com/owner/repo.git")

    with pytest.raises(cli.CLIInputError, match="scheme 'ssh' is not"):
        cli._validate_git_url("git@github.com:owner/repo.git")


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
