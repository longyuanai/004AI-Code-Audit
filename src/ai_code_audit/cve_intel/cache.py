"""Read-only adapter from the vulnerability-analysis cache to the bridge.

Only the public ``ReadOnlyEnrichmentStore`` of the single
vulnerability-analysis module is used; no enrichment client is built, so
nothing here can fall through to NVD, KEV, or EPSS on a cache miss.
Per-provider rows are read instead of the ``combined`` row because the
combined record folds an unknown KEV state into ``in_known_exploited=False``.
"""

from __future__ import annotations

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
    """The cache module or database cannot be opened for reading."""


class VulnerabilityCacheReader:
    def __init__(self, path: str | Path) -> None:
        try:
            from ai_vuln_agent.enrichment.store import ReadOnlyEnrichmentStore
        except ImportError as exc:
            raise CveCacheUnavailableError(
                "the vulnerability-analysis module (ai_vuln_agent) is not "
                f"importable in this environment: {exc}"
            ) from exc
        try:
            self._store = ReadOnlyEnrichmentStore(path)
        except (FileNotFoundError, RuntimeError) as exc:
            raise CveCacheUnavailableError(str(exc)) from exc

    @property
    def path(self) -> Path:
        return self._store.path

    def lookup(
        self,
        cve_ids: Iterable[str],
    ) -> dict[str, dict[str, ProviderObservation]]:
        keys = list(cve_ids)
        observations: dict[str, dict[str, ProviderObservation]] = {
            key: {} for key in keys
        }
        for provider in PROVIDERS:
            for key, record in self._store.get_many(provider, keys).items():
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
]
