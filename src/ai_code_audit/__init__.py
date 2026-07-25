"""Phase-2 Python entrypoints for AI-CodeGuard."""

from ai_code_audit.scanner import discover_files, scan_repository

__all__ = ["discover_files", "scan_repository"]
