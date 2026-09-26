"""Source line numbering that matches tree-sitter and the TypeScript stack.

Lines are separated by ``\\n`` only (contracts/suppression.json,
``lineNumbering``). ``str.splitlines()`` and universal-newline reads also break
on a lone CR, VT, FF, FS/GS/RS, NEL, U+2028 and U+2029, so in a file containing
any of them every later line number disagreed with the findings (whose lines
come from tree-sitter or Opengrep), and suppression and context were read from
the wrong line.

For files that only use LF or CRLF the result is identical to
``text.splitlines()``.
"""

from __future__ import annotations

from pathlib import Path


def split_source_lines(text: str) -> list[str]:
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def read_source_lines(path: Path) -> list[str]:
    # Bytes, not read_text(): universal newlines would turn a lone CR into a break.
    return split_source_lines(path.read_bytes().decode("utf-8", errors="replace"))


__all__ = ["read_source_lines", "split_source_lines"]
