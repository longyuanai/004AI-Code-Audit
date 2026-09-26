"""Pure offline bridge from source ``004`` code Findings to CVE intelligence.

The bridge performs no I/O: callers pass cached provider observations and
an explicit evaluation time. Original Finding fields are never rewritten;
intelligence is attached under ``metadata.code_audit_enrichment`` on deep
copies. Missing, expired, or malformed intelligence is reported as such and
never collapsed into "not exploited" or zero scores.
"""

from __future__ import annotations

import copy
import math
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from shared_llm_core.finding import Finding

CODE_SOURCE = "004"
METADATA_KEY = "code_audit_enrichment"
SCHEMA_VERSION = 1
PROVIDERS = ("nvd", "kev", "epss")

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
_USABLE = frozenset({"ok", "not_found"})


class CodeIntelBridgeError(ValueError):
    """Raised when an envelope cannot be bridged without guessing."""


@dataclass(frozen=True)
class ProviderObservation:
    """One cached provider row, as read from the vulnerability cache."""

    provider: str
    status: str
    payload: Mapping[str, Any]
    fetched_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class BridgeResult:
    envelope: dict[str, Any]
    summary: dict[str, Any]


Observations = Mapping[str, Mapping[str, ProviderObservation]]


def cve_query_keys(payload: object) -> list[str]:
    """Validate ``payload`` and return unique normalized CVE ids in order.

    Findings without a CVE or with an invalid one contribute no key, so a
    cache adapter never queries anything derived from malformed input.
    """
    return _unique_keys(_validated_findings(payload))


def _unique_keys(validated: list[tuple[int, Mapping[str, Any]]]) -> list[str]:
    keys: list[str] = []
    for _, finding in validated:
        try:
            key = _cve_key(finding.get("cve"))
        except _InvalidCve:
            continue
        if key is not None and key not in keys:
            keys.append(key)
    return keys


def bridge_code_findings(
    payload: object,
    observations: Observations,
    *,
    now: datetime,
) -> BridgeResult:
    """Attach cached CVE intelligence to every source ``004`` Finding.

    ``observations`` maps an upper-case CVE id to provider name to its
    cached row. ``payload`` is not modified; Finding count and order are
    preserved even when several Findings share a CVE.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    validated = _validated_findings(payload)
    # _validated_findings has already proven payload is a Mapping.
    envelope = copy.deepcopy(dict(cast(Mapping[str, Any], payload)))
    findings = envelope["findings"]
    statuses: Counter[str] = Counter()
    for index, original in validated:
        enrichment = _finding_enrichment(original, observations, now)
        statuses[enrichment["status"]] += 1
        item = findings[index] = dict(findings[index])
        metadata = dict(item.get("metadata") or {})
        metadata[METADATA_KEY] = enrichment
        item["metadata"] = metadata
    summary = {
        "schema_version": SCHEMA_VERSION,
        "evaluated_at": now.isoformat(),
        "findings": len(validated),
        "cves": len(_unique_keys(validated)),
        "status_counts": dict(sorted(statuses.items())),
    }
    return BridgeResult(envelope=envelope, summary=summary)


def _validated_findings(payload: object) -> list[tuple[int, Mapping[str, Any]]]:
    if not isinstance(payload, Mapping):
        raise CodeIntelBridgeError("envelope must be a JSON object")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise CodeIntelBridgeError("envelope requires a 'findings' array")
    validated: list[tuple[int, Mapping[str, Any]]] = []
    for index, item in enumerate(findings):
        if not isinstance(item, Mapping):
            raise CodeIntelBridgeError(
                f"finding at index {index} must be an object"
            )
        try:
            finding = Finding.from_dict(item)
        except (TypeError, ValueError) as exc:
            raise CodeIntelBridgeError(
                f"invalid finding at index {index}: {exc}"
            ) from exc
        if finding.source.value != CODE_SOURCE:
            raise CodeIntelBridgeError(
                f"finding at index {index} has source "
                f"{finding.source.value!r}; the code CVE bridge only "
                f"accepts source {CODE_SOURCE!r}"
            )
        metadata = item.get("metadata")
        if metadata is not None and not isinstance(metadata, Mapping):
            raise CodeIntelBridgeError(
                f"finding at index {index} metadata must be an object"
            )
        if isinstance(metadata, Mapping) and METADATA_KEY in metadata:
            raise CodeIntelBridgeError(
                f"finding at index {index} already has metadata."
                f"{METADATA_KEY}; refusing to overwrite it"
            )
        validated.append((index, item))
    return validated


def _cve_key(value: object) -> str | None:
    """Return the query key, None when absent; raise on unusable input."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, str):
        raise _InvalidCve(f"cve must be a string, got {type(value).__name__}")
    key = value.strip().upper()
    if not _CVE_PATTERN.fullmatch(key):
        raise _InvalidCve(f"cve {value!r} is not a CVE identifier")
    return key


class _InvalidCve(ValueError):
    pass


def _finding_enrichment(
    finding: Mapping[str, Any],
    observations: Observations,
    now: datetime,
) -> dict[str, Any]:
    try:
        key = _cve_key(finding.get("cve"))
    except _InvalidCve as exc:
        return _empty("invalid_input", None, [str(exc)])
    if key is None:
        return _empty("not_applicable", None, [])

    cached = observations.get(key) or {}
    warnings: list[str] = []
    providers: dict[str, dict[str, Any]] = {}
    values: dict[str, Any] = _empty_values()
    for provider in PROVIDERS:
        state, provider_values, warning = _provider_state(
            provider, key, cached.get(provider), now
        )
        providers[provider] = state
        values.update(provider_values)
        if warning:
            warnings.append(warning)

    usable = [p for p in PROVIDERS if providers[p]["status"] in _USABLE]
    if len(usable) == len(PROVIDERS):
        status = "enriched"
    elif usable:
        status = "partial"
    elif any(providers[p]["status"] == "stale" for p in PROVIDERS):
        status = "stale"
    else:
        status = "unknown"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "cve": key,
        "providers": providers,
        "values": values,
        "warnings": warnings,
    }


def _empty(status: str, key: str | None, warnings: list[str]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "cve": key,
        "providers": {},
        "values": _empty_values(),
        "warnings": warnings,
    }


def _empty_values() -> dict[str, Any]:
    return {
        "cvss_v3": None,
        "cvss_vector": None,
        "cwe": None,
        "epss": None,
        "epss_percentile": None,
        "kev": None,
    }


def _provider_state(
    provider: str,
    key: str,
    observation: ProviderObservation | None,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    if observation is None:
        return (
            {"status": "missing", "fetched_at": None, "expires_at": None},
            {},
            f"{provider}: no cached record for {key}",
        )
    state = {
        "status": observation.status,
        "fetched_at": observation.fetched_at.isoformat(),
        "expires_at": observation.expires_at.isoformat(),
    }
    if observation.expires_at <= now:
        state["status"] = "stale"
        return (
            state,
            {},
            (
                f"{provider}: cached record for {key} expired at "
                f"{state['expires_at']}"
            ),
        )
    if observation.status == "not_found":
        # KEV is a complete catalog, so a fresh miss is a real "not listed".
        return state, ({"kev": False} if provider == "kev" else {}), None
    if observation.status != "ok":
        state["status"] = "unsupported_status"
        state["cache_status"] = observation.status
        return (
            state,
            {},
            f"{provider}: unsupported cache status {observation.status!r}",
        )
    try:
        values = _payload_values(provider, key, observation.payload)
    except (TypeError, ValueError) as exc:
        state["status"] = "invalid_cache"
        return state, {}, f"{provider}: {exc}"
    return state, values, None


def _payload_values(
    provider: str,
    key: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise TypeError("cached payload is not an object")
    cached_id = payload.get("cve_id")
    if not isinstance(cached_id, str) or cached_id.strip().upper() != key:
        raise ValueError(f"cached payload does not describe {key}")
    if provider == "nvd":
        return {
            "cvss_v3": _number(payload.get("cvss_v3"), "cvss_v3", 0.0, 10.0),
            "cvss_vector": _text(payload.get("cvss_vector"), "cvss_vector"),
            "cwe": _text(payload.get("cwe"), "cwe"),
        }
    if provider == "epss":
        score = _number(payload.get("score"), "score", 0.0, 1.0)
        if score is None:
            raise ValueError("cached EPSS record has no score")
        return {
            "epss": score,
            "epss_percentile": _number(
                payload.get("percentile"), "percentile", 0.0, 1.0
            ),
        }
    return {"kev": True}


def _number(
    value: object,
    name: str,
    low: float,
    high: float,
) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"cached {name} is not a number")
    number = float(value)
    if not math.isfinite(number) or not low <= number <= high:
        raise ValueError(f"cached {name} {number!r} is out of range")
    return number


def _text(value: object, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"cached {name} is not a string")
    return value.strip() or None


__all__ = [
    "CODE_SOURCE",
    "METADATA_KEY",
    "PROVIDERS",
    "SCHEMA_VERSION",
    "BridgeResult",
    "CodeIntelBridgeError",
    "ProviderObservation",
    "bridge_code_findings",
    "cve_query_keys",
]
