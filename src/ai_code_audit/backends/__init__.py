"""Static backend selection and fallback orchestration."""

from __future__ import annotations

from pathlib import Path

from ai_code_audit.backends.base import (
    BackendError,
    BackendExecutionError,
    BackendOutputError,
    BackendUnavailableError,
    ScanRequest,
    StaticAnalysisBackend,
)
from ai_code_audit.backends.builtin import BuiltinTreeSitterBackend
from ai_code_audit.backends.opengrep import OpengrepBackend


def scan_with_backend(
    request: ScanRequest,
    *,
    backend: str,
    opengrep_path: str | Path | None = None,
    rules_path: str | Path | None = None,
    timeout: float = 120.0,
) -> dict[str, object]:
    normalized = backend.lower()
    if normalized == "builtin":
        return BuiltinTreeSitterBackend().scan(request)
    external = (
        OpengrepBackend(opengrep_path, rules_path, timeout=timeout)
        if opengrep_path is not None and rules_path is not None
        else None
    )
    if normalized == "opengrep":
        if external is None or not external.available():
            raise BackendUnavailableError(
                "backend=opengrep requires CODEGUARD_OPENGREP_PATH or an "
                "opengrep executable on PATH, plus a readable rules path"
            )
        return external.scan(request)
    if normalized != "auto":
        raise ValueError(f"Unsupported backend: {backend}")
    if external is not None and external.available():
        return external.scan(request)
    envelope = BuiltinTreeSitterBackend().scan(request)
    envelope["warnings"] = [
        "Opengrep unavailable; used builtin backend",
        *envelope["warnings"],
    ]
    envelope["summary"]["backend"] = "builtin-fallback"
    return envelope


__all__ = [
    "BackendError",
    "BackendExecutionError",
    "BackendOutputError",
    "BackendUnavailableError",
    "BuiltinTreeSitterBackend",
    "OpengrepBackend",
    "ScanRequest",
    "StaticAnalysisBackend",
    "scan_with_backend",
]
