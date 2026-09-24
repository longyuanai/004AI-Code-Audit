"""Offline CVE intelligence for source ``004`` code Findings (C1).

Not wired into the scan CLI; see docs/tech-spec.md §5.
"""

from ai_code_audit.cve_intel.bridge import (
    METADATA_KEY,
    BridgeResult,
    CodeIntelBridgeError,
    ProviderObservation,
    bridge_code_findings,
    cve_query_keys,
)
from ai_code_audit.cve_intel.cache import (
    CveCacheUnavailableError,
    VulnerabilityCacheReader,
    bridge_from_cache,
    default_cache_path,
)
from ai_code_audit.cve_intel.stage import (
    PROVIDER_SOURCES,
    STAGE_KEY,
    StageOutcome,
    run_offline_enrichment,
)

__all__ = [
    "METADATA_KEY",
    "PROVIDER_SOURCES",
    "STAGE_KEY",
    "BridgeResult",
    "CodeIntelBridgeError",
    "CveCacheUnavailableError",
    "ProviderObservation",
    "StageOutcome",
    "VulnerabilityCacheReader",
    "bridge_code_findings",
    "bridge_from_cache",
    "cve_query_keys",
    "default_cache_path",
    "run_offline_enrichment",
]
