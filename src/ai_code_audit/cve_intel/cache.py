"""Read-only adapter from the vulnerability-analysis cache to the bridge.

Only the public ``ReadOnlyEnrichmentStore`` of the single
vulnerability-analysis module is used; no enrichment client is built, so
nothing here can fall through to NVD, KEV, or EPSS on a cache miss.
Per-provider rows are read instead of the ``combined`` row because the
combined record folds an unknown KEV state into ``in_known_exploited=False``.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ai_code_audit.cve_intel.bridge import (
    PROVIDERS,
    BridgeResult,
    ProviderObservation,
    bridge_code_findings,
    cve_query_keys,
)


class CveCacheUnavailableError(RuntimeError):
    """The cache module or database cannot be used.

    ``reason`` is one of ``module_unavailable``, ``cache_not_found``,
    ``cache_unreadable`` or ``cache_schema_mismatch``.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _store_module() -> Any:
    try:
        from ai_vuln_agent.enrichment import store
    except ImportError as exc:
        raise CveCacheUnavailableError(
            "module_unavailable",
            "the vulnerability-analysis module (ai_vuln_agent) is not "
            f"importable in this environment: {exc}",
        ) from exc
    return store


def default_cache_path() -> Path:
    """The vulnerability module's default cache location (not created)."""
    location: object = _store_module().default_cache_dir()
    return Path(str(location))


def _unavailable(exc: Exception) -> CveCacheUnavailableError:
    if isinstance(exc, FileNotFoundError):
        return CveCacheUnavailableError("cache_not_found", str(exc))
    # Only EnrichmentCacheError (module after C1 commit 554c247) carries a
    # reason; older stores raise bare RuntimeError, reported as unreadable.
    reason = getattr(exc, "reason", "unreadable")
    return CveCacheUnavailableError(f"cache_{reason}", str(exc))


# Raw errors an older store may leak from queries (e.g. an undecodable row).
_STORE_ERRORS = (FileNotFoundError, RuntimeError, sqlite3.Error, ValueError)


class VulnerabilityCacheReader:
    def __init__(self, path: str | Path) -> None:
        store = _store_module()
        try:
            self._store = store.ReadOnlyEnrichmentStore(path)
        except _STORE_ERRORS as exc:
            raise _unavailable(exc) from exc

    @property
    def path(self) -> Path:
        return Path(self._store.path)

    def lookup(
        self,
        cve_ids: Iterable[str],
    ) -> dict[str, dict[str, ProviderObservation]]:
        keys = list(cve_ids)
        observations: dict[str, dict[str, ProviderObservation]] = {
            key: {} for key in keys
        }
        for provider in PROVIDERS:
            try:
                records = self._store.get_many(provider, keys)
            except _STORE_ERRORS as exc:
                raise _unavailable(exc) from exc
            for key, record in records.items():
                observations.setdefault(key, {})[provider] = (
                    ProviderObservation(
                        provider=provider,
                        status=record.status,
                        payload=record.payload,
                        fetched_at=record.fetched_at,
                        expires_at=record.expires_at,
                    )
                )
        return observations


def bridge_from_cache(
    payload: object,
    cache_path: str | Path,
    *,
    now: datetime | None = None,
) -> BridgeResult:
    """Validate, read the cache for referenced CVEs, then bridge offline."""
    keys = cve_query_keys(payload)
    reader = VulnerabilityCacheReader(cache_path)
    result = bridge_code_findings(
        payload,
        reader.lookup(keys),
        now=now or datetime.now(timezone.utc),
    )
    summary: dict[str, Any] = {**result.summary, "cache": str(reader.path)}
    return BridgeResult(envelope=result.envelope, summary=summary)


__all__ = [
    "CveCacheUnavailableError",
    "VulnerabilityCacheReader",
    "bridge_from_cache",
    "default_cache_path",
]
