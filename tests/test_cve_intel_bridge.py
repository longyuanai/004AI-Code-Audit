"""C1: pure offline bridge from source 004 Findings to cached CVE intel."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from ai_code_audit.cve_intel import (
    METADATA_KEY,
    CodeIntelBridgeError,
    ProviderObservation,
    bridge_code_findings,
    cve_query_keys,
)

FIXTURES = Path(__file__).parent / "fixtures" / "cve_intel"
NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)
CVE = "CVE-2024-1234"


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _obs(
    provider: str,
    payload: dict[str, Any],
    *,
    status: str = "ok",
    age: timedelta = timedelta(hours=1),
    ttl: timedelta = timedelta(days=1),
) -> ProviderObservation:
    fetched = NOW - age
    return ProviderObservation(
        provider=provider,
        status=status,
        payload=payload,
        fetched_at=fetched,
        expires_at=fetched + ttl,
    )


def _nvd(cve: str = CVE, **overrides: Any) -> ProviderObservation:
    payload = {
        "cve_id": cve,
        "cvss_v3": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-94",
        "description": "NVD text is not copied into the finding description",
    }
    payload.update(overrides)
    return _obs("nvd", payload)


def _kev(cve: str = CVE) -> ProviderObservation:
    return _obs(
        "kev",
        {
            "cve_id": cve,
            "vulnerability_name": "Example",
            "date_added": "2024-01-01",
            "due_date": "2024-01-22",
            "required_action": "Patch",
        },
    )


def _epss(cve: str = CVE, score: Any = 0.42) -> ProviderObservation:
    return _obs("epss", {"cve_id": cve, "score": score, "percentile": 0.9})


def _fresh(cve: str = CVE) -> dict[str, ProviderObservation]:
    return {"nvd": _nvd(cve), "kev": _kev(cve), "epss": _epss(cve)}


def _finding(**overrides: Any) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": "f1",
        "source": "004",
        "severity": "high",
        "confidence": 0.8,
        "title": "t",
        "description": "original",
        "cve": CVE,
    }
    finding.update(overrides)
    return finding


def _one(finding: dict[str, Any], observations: Any) -> dict[str, Any]:
    result = bridge_code_findings(
        {"findings": [finding]}, observations, now=NOW
    )
    return result.envelope["findings"][0]["metadata"][METADATA_KEY]


def test_golden_fixture_preserves_original_fields_and_order() -> None:
    payload = _load("code-envelope.json")
    pristine = copy.deepcopy(payload)

    result = bridge_code_findings(payload, {CVE: _fresh()}, now=NOW)
    encoded = json.loads(json.dumps(result.envelope, ensure_ascii=False))

    assert payload == pristine
    assert encoded == _load("expected-enriched.json")
    assert result.summary == {
        "schema_version": 1,
        "evaluated_at": NOW.isoformat(),
        "findings": 4,
        "cves": 2,
        "status_counts": {
            "enriched": 1,
            "invalid_input": 1,
            "not_applicable": 1,
            "unknown": 1,
        },
    }
    for before, after in zip(pristine["findings"], encoded["findings"]):
        extra = dict(after["metadata"])
        extra.pop(METADATA_KEY)
        assert extra == before.get("metadata", {})
        assert {k: v for k, v in after.items() if k != "metadata"} == {
            k: v for k, v in before.items() if k != "metadata"
        }
    assert {k: v for k, v in encoded.items() if k != "findings"} == {
        k: v for k, v in pristine.items() if k != "findings"
    }


def test_fresh_cache_hit_attaches_facts_without_rewriting() -> None:
    finding = _finding()
    result = bridge_code_findings({"findings": [finding]}, {CVE: _fresh()}, now=NOW)
    item = result.envelope["findings"][0]
    enrichment = item["metadata"][METADATA_KEY]

    assert item["description"] == "original"
    assert item["severity"] == "high"
    assert item["source"] == "004"
    assert enrichment["status"] == "enriched"
    assert enrichment["values"] == {
        "cvss_v3": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-94",
        "epss": 0.42,
        "epss_percentile": 0.9,
        "kev": True,
    }
    assert enrichment["warnings"] == []
    assert enrichment["providers"]["nvd"]["fetched_at"] == (
        NOW - timedelta(hours=1)
    ).isoformat()
    assert "narrative" not in item
    assert "prisk" not in json.dumps(enrichment)


@pytest.mark.parametrize("cve", [None, "", "   "])
def test_missing_cve_is_not_applicable(cve: Any) -> None:
    finding = _finding(cve=cve)

    enrichment = _one(finding, {CVE: _fresh()})

    assert enrichment["status"] == "not_applicable"
    assert enrichment["cve"] is None
    assert enrichment["providers"] == {}
    assert set(enrichment["values"].values()) == {None}


def test_absent_cve_key_is_not_added() -> None:
    finding = _finding()
    del finding["cve"]

    result = bridge_code_findings({"findings": [finding]}, {}, now=NOW)

    assert "cve" not in result.envelope["findings"][0]
    assert result.envelope["findings"][0]["metadata"][METADATA_KEY][
        "status"
    ] == "not_applicable"


@pytest.mark.parametrize("cve", ["CVE-24-1", "not-a-cve", "CVE-2024-12a4", 123])
def test_invalid_cve_is_reported_and_never_queried(cve: Any) -> None:
    finding = _finding(cve=cve)
    observations = {CVE: _fresh()}

    assert cve_query_keys({"findings": [finding]}) == []
    result = bridge_code_findings({"findings": [finding]}, observations, now=NOW)
    item = result.envelope["findings"][0]
    enrichment = item["metadata"][METADATA_KEY]

    assert item["cve"] == cve
    assert enrichment["status"] == "invalid_input"
    assert enrichment["warnings"]
    assert enrichment["values"]["kev"] is None


def test_cache_miss_is_unknown_not_zero_or_false() -> None:
    enrichment = _one(_finding(), {})

    assert enrichment["status"] == "unknown"
    assert enrichment["values"] == {
        "cvss_v3": None,
        "cvss_vector": None,
        "cwe": None,
        "epss": None,
        "epss_percentile": None,
        "kev": None,
    }
    assert {p["status"] for p in enrichment["providers"].values()} == {
        "missing"
    }
    assert len(enrichment["warnings"]) == 3


def test_expired_cache_is_stale_and_values_are_withheld() -> None:
    old = {
        provider: _obs(
            provider,
            observation.payload,
            age=timedelta(days=3),
        )
        for provider, observation in _fresh().items()
    }

    enrichment = _one(_finding(), {CVE: old})

    assert enrichment["status"] == "stale"
    assert set(enrichment["values"].values()) == {None}
    assert enrichment["providers"]["kev"]["status"] == "stale"
    assert enrichment["providers"]["kev"]["fetched_at"] is not None


def test_expiry_boundary_counts_as_stale() -> None:
    edge = _obs("epss", _epss().payload, age=timedelta(days=1))

    enrichment = _one(_finding(), {CVE: {**_fresh(), "epss": edge}})

    assert enrichment["providers"]["epss"]["status"] == "stale"
    assert enrichment["status"] == "partial"


def test_partial_providers_keep_known_values_and_mark_gaps() -> None:
    observations = {
        CVE: {
            "nvd": _nvd(),
            "epss": _obs("epss", _epss().payload, age=timedelta(days=2)),
        }
    }

    enrichment = _one(_finding(), observations)

    assert enrichment["status"] == "partial"
    assert enrichment["values"]["cvss_v3"] == 9.8
    assert enrichment["values"]["kev"] is None
    assert enrichment["values"]["epss"] is None
    assert enrichment["providers"]["kev"]["status"] == "missing"
    assert enrichment["providers"]["epss"]["status"] == "stale"
    assert len(enrichment["warnings"]) == 2


def test_fresh_not_found_is_a_definite_answer() -> None:
    observations = {
        CVE: {
            "nvd": _obs("nvd", {}, status="not_found"),
            "kev": _obs("kev", {}, status="not_found"),
            "epss": _obs("epss", {}, status="not_found"),
        }
    }

    enrichment = _one(_finding(), observations)

    assert enrichment["status"] == "enriched"
    assert enrichment["values"]["kev"] is False
    assert enrichment["values"]["cvss_v3"] is None
    assert enrichment["values"]["epss"] is None


def test_unsupported_provider_status_is_unknown_not_negative() -> None:
    observations = {
        CVE: {**_fresh(), "kev": _obs("kev", {}, status="temporary_error")}
    }

    enrichment = _one(_finding(), observations)

    assert enrichment["status"] == "partial"
    assert enrichment["providers"]["kev"] == {
        "status": "unsupported_status",
        "cache_status": "temporary_error",
        "fetched_at": (NOW - timedelta(hours=1)).isoformat(),
        "expires_at": (NOW + timedelta(hours=23)).isoformat(),
    }
    assert enrichment["values"]["kev"] is None


@pytest.mark.parametrize(
    ("provider", "observation"),
    [
        ("nvd", _nvd(cve="CVE-2020-0001")),
        ("nvd", _nvd(cvss_v3=11.0)),
        ("nvd", _nvd(cvss_v3=True)),
        ("nvd", _nvd(cvss_v3="9.8")),
        ("nvd", _nvd(cwe=["CWE-79"])),
        ("epss", _epss(score=None)),
        ("epss", _epss(score=float("nan"))),
        ("kev", _obs("kev", {"vulnerability_name": "no id"})),
    ],
)
def test_malformed_cache_payload_is_invalid_cache(
    provider: str,
    observation: ProviderObservation,
) -> None:
    enrichment = _one(_finding(), {CVE: {**_fresh(), provider: observation}})

    assert enrichment["providers"][provider]["status"] == "invalid_cache"
    assert enrichment["status"] == "partial"
    assert enrichment["warnings"]


def test_duplicate_cves_keep_every_finding_in_order() -> None:
    findings = [
        _finding(id="a", cve="cve-2024-1234"),
        _finding(id="b", cve=None),
        _finding(id="c", cve=" CVE-2024-1234 "),
        _finding(id="d", cve="CVE-2024-1234"),
    ]
    payload = {"findings": findings}

    assert cve_query_keys(payload) == [CVE]
    result = bridge_code_findings(payload, {CVE: _fresh()}, now=NOW)
    items = result.envelope["findings"]

    assert [item["id"] for item in items] == ["a", "b", "c", "d"]
    assert [item["cve"] for item in items] == [
        "cve-2024-1234",
        None,
        " CVE-2024-1234 ",
        "CVE-2024-1234",
    ]
    assert [item["metadata"][METADATA_KEY]["status"] for item in items] == [
        "enriched",
        "not_applicable",
        "enriched",
        "enriched",
    ]
    assert result.summary["cves"] == 1
    assert result.summary["findings"] == 4


def test_outputs_do_not_share_mutable_state() -> None:
    payload = {"findings": [_finding(id="a"), _finding(id="b")]}

    result = bridge_code_findings(payload, {CVE: _fresh()}, now=NOW)
    first, second = result.envelope["findings"]
    first["metadata"][METADATA_KEY]["warnings"].append("mutated")
    first["metadata"][METADATA_KEY]["values"]["kev"] = "mutated"

    assert second["metadata"][METADATA_KEY]["warnings"] == []
    assert second["metadata"][METADATA_KEY]["values"]["kev"] is True
    assert "metadata" not in payload["findings"][0]


@pytest.mark.parametrize("source", ["002", "001", "006", "external"])
def test_non_code_source_is_rejected_not_rewritten(source: str) -> None:
    payload = {"findings": [_finding(), _finding(id="x", source=source)]}
    pristine = copy.deepcopy(payload)

    with pytest.raises(CodeIntelBridgeError, match="index 1 has source"):
        bridge_code_findings(payload, {CVE: _fresh()}, now=NOW)
    with pytest.raises(CodeIntelBridgeError):
        cve_query_keys(payload)
    assert payload == pristine


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ([_finding()], "must be a JSON object"),
        ("findings", "must be a JSON object"),
        ({}, "'findings' array"),
        ({"findings": {"0": _finding()}}, "'findings' array"),
        ({"findings": [_finding(), "x"]}, "index 1 must be an object"),
        ({"findings": [{"id": "a", "source": "004"}]}, "invalid finding at index 0"),
        ({"findings": [_finding(confidence=2.0)]}, "invalid finding at index 0"),
        ({"findings": [_finding(source="999")]}, "invalid finding at index 0"),
        ({"findings": [_finding(severity="urgent")]}, "invalid finding at index 0"),
        ({"findings": [_finding(metadata=[])]}, "metadata must be an object"),
        (
            {"findings": [_finding(metadata={METADATA_KEY: {}})]},
            "refusing to overwrite",
        ),
    ],
)
def test_malformed_envelopes_fail_with_location(payload: Any, message: str) -> None:
    with pytest.raises(CodeIntelBridgeError, match=message):
        bridge_code_findings(payload, {}, now=NOW)


def test_empty_findings_is_a_valid_empty_result() -> None:
    result = bridge_code_findings({"findings": [], "summary": {}}, {}, now=NOW)

    assert result.envelope == {"findings": [], "summary": {}}
    assert result.summary["findings"] == 0
    assert result.summary["status_counts"] == {}


def test_naive_evaluation_time_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        bridge_code_findings(
            {"findings": []},
            {},
            now=datetime(2026, 9, 23, 12, 0),  # noqa: DTZ001 - deliberately naive
        )
