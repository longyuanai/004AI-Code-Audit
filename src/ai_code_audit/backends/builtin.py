"""Adapter for the existing tree-sitter heuristic scanner."""

from __future__ import annotations

from ai_code_audit.backends.base import ScanRequest
from ai_code_audit.scanner import scan_repository


class BuiltinTreeSitterBackend:
    name = "builtin"

    def available(self) -> bool:
        return True

    def scan(self, request: ScanRequest) -> dict[str, object]:
        return scan_repository(
            request.repo_path,
            request.languages,
            include_files=request.include_files,
            line_ranges=request.line_ranges,
        )


__all__ = ["BuiltinTreeSitterBackend"]
