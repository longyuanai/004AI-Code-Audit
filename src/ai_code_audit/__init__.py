"""Phase-2 Python entrypoints for AI-CodeGuard."""

from ai_code_audit.scanner import discover_files, scan_diff, scan_repository

__version__ = "0.6.0"

__all__ = ["__version__", "discover_files", "scan_diff", "scan_repository"]
