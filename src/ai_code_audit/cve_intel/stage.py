"""C2 stage: offline CVE enrichment of a saved source ``004`` envelope.

Reuses the C1 bridge and read-only cache adapter; performs no network
refresh and no LLM call. The returned document is the input envelope with
per-Finding ``metadata.code_audit_enrichment`` plus a top-level
``code_audit_enrichment`` stage record. When the cache cannot be used the
original Findings are returned unchanged and the stage is ``failed``.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from ai_code_audit.cve_intel.bridge import (
    METADATA_KEY,
    PROVIDERS,
    SCHEMA_VERSION,
    CodeIntelBridgeError,
    ProviderObservation,
    bridge_code_findings,
    cve_query_keys,
)
from ai_code_audit.cve_intel.cache import (
    CveCacheUnavailableError,
    VulnerabilityCacheReader,
    default_cache_path,
)

STAGE_KEY = METADATA_KEY
PROVIDER_SOURCES = {
    "nvd": "NVD CVE API 2.0 (local cache)",
    "kev": "CISA Known Exploited Vulnerabilities catalog (local cache)",
    "epss": "FIRST EPSS (local cache)",
}
_COMPLETE_FINDING = frozenset({"enriched", "not_applicable"})


@dataclass(frozen=True)
class StageOutcome:
    document: dict[str, Any]
    stage: dict[str, Any]

    @property
    def status(self) -> str:
        return str(self.stage["status"])


def run_offline_enrichment(
    payload: object,
    *,
    cache_path: str | Path | None = None,
    now: datetime | None = None,
    reader_factory: Callable[[Path], Any] = VulnerabilityCacheReader,
) -> StageOutcome:
    """Enrich ``payload`` from the local cache only.

    Raises ``CodeIntelBridgeError`` for envelopes that cannot be processed
    without guessing (wrong source, malformed Findings, prior enrichment).
    Cache problems never raise: they produce a ``failed`` stage.
    """
    moment = now or datetime.now(timezone.utc)
    if isinstance(payload, Mapping) and STAGE_KEY in payload:
        raise CodeIntelBridgeError(
            f"envelope already has a top-level {STAGE_KEY}; "
            "refusing to overwrite it"
        )
    keys = cve_query_keys(payload)
    stage: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "",
        "reason": None,
        "error": None,
        "cache": None,
        "evaluated_at": moment.isoformat(),
        "network_refresh": False,
        "sources": dict(PROVIDER_SOURCES),
        "providers": list(PROVIDERS),
        "cves": len(keys),
    }
    if not keys:
        # Nothing to look up: the cache is deliberately never opened.
        result = bridge_code_findings(payload, {}, now=moment)
        return _finish(result.envelope, result.summary, stage, skipped=True)

    try:
        path = Path(cache_path) if cache_path is not None else default_cache_path()
        stage["cache"] = str(path)
        reader = reader_factory(path)
        stage["cache"] = str(getattr(reader, "path", path))
        observations: Mapping[str, Mapping[str, ProviderObservation]] = (
            reader.lookup(keys)
        )
    except CveCacheUnavailableError as exc:
        # cve_query_keys has already proven payload is a Mapping.
        document = copy.deepcopy(dict(cast(Mapping[str, Any], payload)))
        stage.update(
            status="failed",
            reason=exc.reason,
            error=str(exc),
            findings=len(document["findings"]),
            status_counts={},
        )
        document[STAGE_KEY] = stage
        return StageOutcome(document=document, stage=stage)
    result = bridge_code_findings(payload, observations, now=moment)
    return _finish(result.envelope, result.summary, stage, skipped=False)


def _finish(
    document: dict[str, Any],
    summary: Mapping[str, Any],
    stage: dict[str, Any],
    *,
    skipped: bool,
) -> StageOutcome:
    counts: dict[str, int] = dict(summary["status_counts"])
    complete = all(status in _COMPLETE_FINDING for status in counts)
    if skipped and complete:
        status, reason = "skipped", "no_queryable_cve"
    elif complete:
        status, reason = "complete", None
    else:
        status = "partial"
        reason = "no_queryable_cve" if skipped else "intel_incomplete"
    stage.update(
        status=status,
        reason=reason,
        findings=summary["findings"],
        status_counts=counts,
    )
    document[STAGE_KEY] = stage
    return StageOutcome(document=document, stage=stage)


__all__ = [
    "PROVIDER_SOURCES",
    "STAGE_KEY",
    "StageOutcome",
    "run_offline_enrichment",
]
