"""Canonical codeguardFingerprint/v1, shared with the TypeScript stack.

The byte layout is pinned by contracts/fingerprint.json and must match
src/scanner/baseline.ts. Fields are joined by U+0000, which file paths cannot
contain and rule ids do not use, so moving characters between fields changes
the digest.
"""

from __future__ import annotations

import hashlib
import re

# Spelled out instead of using ``\\s``: Python and JavaScript disagree on six
# code points (U+001C-U+001F and U+0085 vs U+FEFF), and both follow their
# engine's Unicode version. This is exactly the JavaScript set, which the
# already-released TypeScript baselines were written with.
CANONICAL_WHITESPACE_CODE_POINTS: tuple[int, ...] = (
    0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x0020, 0x00A0, 0x1680,
    0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007,
    0x2008, 0x2009, 0x200A,
    0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF,
)
WHITESPACE_CHARS = "".join(
    f"\\u{code_point:04x}" for code_point in CANONICAL_WHITESPACE_CODE_POINTS
)

_WHITESPACE_RUN = re.compile(f"[{WHITESPACE_CHARS}]+")
_SURROGATE = re.compile("[\\ud800-\\udfff]")


def normalize_path(path: str) -> str:
    return path.replace("\\", "/")


def normalize_snippet(snippet: str) -> str:
    return _WHITESPACE_RUN.sub(" ", snippet).strip(" ")


def canonical_fingerprint(rule_id: str, path: str, snippet: str) -> str:
    payload = f"{rule_id}\0{normalize_path(path)}\0{normalize_snippet(snippet)}"
    # Matches Node, which encodes an unpaired surrogate as U+FFFD; a plain
    # str.encode() would raise instead.
    payload = _SURROGATE.sub("�", payload)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


__all__ = [
    "CANONICAL_WHITESPACE_CODE_POINTS",
    "WHITESPACE_CHARS",
    "canonical_fingerprint",
    "normalize_path",
    "normalize_snippet",
]
