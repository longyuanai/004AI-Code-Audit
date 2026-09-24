"""Pre-execution gate: the selected Opengrep binary must match OPENGREP.lock.

Shared by ``benchmarks/c3/quality.py`` and ``scripts/c3_demo.py``. The
digest is SHA-256 over the file's raw bytes (no newline folding). Nothing is
downloaded and the lock file is never rewritten; a mismatch is a failure,
and the caller must not start the binary.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OPENGREP_LOCK = ROOT / "benchmarks" / "phase0" / "OPENGREP.lock"
_SHA256 = re.compile(r"[0-9a-f]{64}")


class OpengrepPinError(RuntimeError):
    """``reason``: missing, unreadable, lock_invalid or hash_mismatch."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class OpengrepPin:
    executable: Path
    sha256: str
    version: str
    lock: Path


def read_lock(lock: Path = OPENGREP_LOCK) -> dict[str, str]:
    try:
        text = lock.read_text(encoding="utf-8")
    except OSError as error:
        raise OpengrepPinError(
            "lock_invalid", f"cannot read Opengrep lock {lock}: {error}"
        ) from error
    entries = dict(
        line.split("=", 1) for line in text.splitlines() if "=" in line
    )
    digest = entries.get("sha256", "").strip().lower()
    if not _SHA256.fullmatch(digest) or not entries.get("version", "").strip():
        raise OpengrepPinError(
            "lock_invalid",
            f"Opengrep lock {lock} needs version= and a 64-hex sha256=",
        )
    entries["sha256"] = digest
    return entries


def raw_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_opengrep(executable: Path, lock: Path = OPENGREP_LOCK) -> OpengrepPin:
    """Return the verified pin or raise ``OpengrepPinError``; never executes."""
    entries = read_lock(lock)
    resolved = executable.expanduser().resolve()
    if not resolved.exists():
        raise OpengrepPinError(
            "missing", f"Opengrep executable not found: {resolved}"
        )
    try:
        if not resolved.is_file():
            raise OSError("not a regular file")
        actual = raw_sha256(resolved)
    except OSError as error:
        raise OpengrepPinError(
            "unreadable", f"cannot read Opengrep executable {resolved}: {error}"
        ) from error
    if actual != entries["sha256"]:
        raise OpengrepPinError(
            "hash_mismatch",
            f"Opengrep {resolved} sha256 {actual} does not match "
            f"{lock.name} {entries['sha256']} (version {entries['version']})",
        )
    return OpengrepPin(resolved, actual, entries["version"].strip(), lock)


__all__ = [
    "OPENGREP_LOCK",
    "OpengrepPin",
    "OpengrepPinError",
    "raw_sha256",
    "read_lock",
    "verify_opengrep",
]
