"""Phase-2 Python entrypoints for AI-CodeGuard."""

from ai_code_audit.scanner import discover_files, scan_diff, scan_repository

# Single source of truth for the version this stack reports (SARIF
# tool.driver.version). Mirrors the role of src/version.ts on the TypeScript
# side; tests/test_project_setup.py fails if it drifts from pyproject.toml.
__version__ = "0.6.0"

__all__ = [
    "__version__",
    "discover_files",
    "scan_diff",
    "scan_repository",
]
