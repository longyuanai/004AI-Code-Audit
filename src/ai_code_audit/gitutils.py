"""Safe git diff helpers for incremental scans."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

HUNK_HEADER = re.compile(
    r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@"
)
SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}~^:+-]*$")


class GitDiffError(RuntimeError):
    """Raised when a requested git diff cannot be produced."""


@dataclass(frozen=True)
class GitDiff:
    files: tuple[str, ...]
    line_ranges: dict[str, tuple[tuple[int, int], ...]]


def collect_diff(
    repo_path: str | Path,
    base_ref: str,
    head_ref: str,
) -> GitDiff:
    root = _repository(repo_path)
    _validate_ref(base_ref)
    _validate_ref(head_ref)
    revision_range = f"{base_ref}..{head_ref}"
    names = _run_git(
        root,
        "diff",
        "--name-only",
        "--diff-filter=ACMR",
        revision_range,
        "--",
    )
    files = tuple(
        dict.fromkeys(
            line.strip().replace("\\", "/")
            for line in names.splitlines()
            if line.strip()
        )
    )
    patch = _run_git(
        root,
        "-c",
        "core.quotepath=false",
        "diff",
        "--diff-filter=ACMR",
        "-U0",
        revision_range,
        "--",
    )
    return GitDiff(files=files, line_ranges=_parse_line_ranges(patch))


def _parse_line_ranges(
    patch: str,
) -> dict[str, tuple[tuple[int, int], ...]]:
    ranges: dict[str, list[tuple[int, int]]] = {}
    current_file: str | None = None
    for line in patch.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null":
                current_file = None
            else:
                current_file = (
                    target[2:] if target.startswith("b/") else target
                ).replace("\\", "/")
            continue
        match = HUNK_HEADER.match(line)
        if match is None or current_file is None:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        if count <= 0:
            continue
        ranges.setdefault(current_file, []).append(
            (start, start + count - 1)
        )
    return {
        path: tuple(items)
        for path, items in ranges.items()
    }


def _repository(repo_path: str | Path) -> Path:
    root = Path(repo_path).expanduser().resolve()
    if not root.is_dir():
        raise GitDiffError(f"repo_path is not a directory: {root}")
    result = _run_git(root, "rev-parse", "--is-inside-work-tree")
    if result.strip() != "true":
        raise GitDiffError(f"not a git work tree: {root}")
    return root


def _validate_ref(ref: str) -> None:
    if not isinstance(ref, str) or not SAFE_REF.fullmatch(ref):
        raise GitDiffError(f"invalid git ref: {ref!r}")


def _run_git(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            capture_output=True,
            check=False,
            shell=False,
        )
    except OSError as error:
        raise GitDiffError(f"unable to start git: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise GitDiffError(
            f"git {' '.join(arguments[:2])} exited with "
            f"{result.returncode}: {detail or 'no error output'}"
        )
    return result.stdout.decode("utf-8", errors="replace")


__all__ = ["GitDiff", "GitDiffError", "collect_diff"]
