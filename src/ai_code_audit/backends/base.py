"""Static-analysis backend contracts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Protocol, Sequence, runtime_checkable


class BackendError(RuntimeError):
    """Base error for an external or built-in static backend."""


class BackendUnavailableError(BackendError):
    """Raised when a requested backend cannot be executed."""


class BackendExecutionError(BackendError):
    """Raised when a backend process fails or times out."""


class BackendOutputError(BackendError):
    """Raised when backend output cannot be safely normalized."""


@dataclass(frozen=True)
class ScanRequest:
    """Backend-neutral repository scan request."""

    repo_path: Path
    languages: tuple[str, ...] | None = None
    include_files: tuple[str | Path, ...] | None = None
    line_ranges: Mapping[str, Sequence[tuple[int, int]]] | None = None

    @classmethod
    def create(
        cls,
        repo_path: str | Path,
        languages: Sequence[str] | None = None,
        *,
        include_files: Iterable[str | Path] | None = None,
        line_ranges: Mapping[str, Sequence[tuple[int, int]]] | None = None,
    ) -> "ScanRequest":
        return cls(
            repo_path=Path(repo_path).expanduser().resolve(),
            languages=tuple(languages) if languages is not None else None,
            include_files=(
                tuple(include_files) if include_files is not None else None
            ),
            line_ranges=line_ranges,
        )


@runtime_checkable
class StaticAnalysisBackend(Protocol):
    """A deterministic scanner that returns the frozen envelope shape."""

    name: str

    def available(self) -> bool: ...

    def scan(self, request: ScanRequest) -> dict[str, object]: ...


__all__ = [
    "BackendError",
    "BackendExecutionError",
    "BackendOutputError",
    "BackendUnavailableError",
    "ScanRequest",
    "StaticAnalysisBackend",
]
