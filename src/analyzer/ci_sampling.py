from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Iterable

SUPPORTED_EXTENSIONS = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".py",
    ".go",
    ".java",
    ".php",
}
EXCLUDED_PARTS = {
    ".git",
    ".python-deps",
    ".pytest-tmp",
    ".venv",
    "build",
    "dist",
    "node_modules",
}


def discover_source_files(root: str | Path) -> list[Path]:
    scan_root = Path(root).resolve()
    return sorted(
        (
            path
            for path in scan_root.rglob("*")
            if path.is_file()
            and path.suffix.lower() in SUPPORTED_EXTENSIONS
            and not EXCLUDED_PARTS.intersection(path.parts)
        ),
        key=lambda path: path.as_posix().lower(),
    )


def select_file_sample(
    files: Iterable[str | Path],
    *,
    rate: float = 0.2,
    seed: str = "ai-codeguard-ci-v1",
) -> list[Path]:
    if not 0 <= rate <= 1:
        raise ValueError("sample rate must be between 0 and 1")

    unique = {Path(path).resolve() for path in files}
    ordered = sorted(unique, key=lambda path: path.as_posix().lower())
    if not ordered or rate == 0:
        return []

    sample_size = min(len(ordered), max(1, math.ceil(len(ordered) * rate)))
    ranked = sorted(
        ordered,
        key=lambda path: hashlib.sha256(
            f"{seed}\0{path.as_posix().lower()}".encode()
        ).digest(),
    )
    return sorted(ranked[:sample_size], key=lambda path: path.as_posix().lower())


__all__ = [
    "EXCLUDED_PARTS",
    "SUPPORTED_EXTENSIONS",
    "discover_source_files",
    "select_file_sample",
]

