"""C1: read-only cache adapter against the real vulnerability-analysis store.

The cache is populated through the module's own CVEEnricher with in-memory
provider fakes, so the rows have exactly the shape production writes. The
bridge then runs with every socket operation blocked (loopback included).
Integration scope only: a missing module fails the run instead of skipping.
"""

from __future__ import annotations

import copy
import hashlib
import socket
from datetime import timedelta
from pathlib import Path

import pytest
from _cve_intel_support import (
    DEAD_PROXY,
    WRITTEN_AT,
    install_network_guard,
    mixed_envelope,
    populate_cache,
)

from ai_code_audit.cve_intel import (
    METADATA_KEY,
    CveCacheUnavailableError,
    bridge_from_cache,
)

pytestmark = pytest.mark.vuln_integration


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    target = tmp_path / "漏洞 情报"
    populate_cache(target)
    return target


@pytest.fixture
def blocked_network(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    return install_network_guard(monkeypatch)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_network_guard_is_effective(blocked_network: list[str]) -> None:
    import httpx

    with pytest.raises(OSError, match="network blocked"):
        socket.create_connection(("127.0.0.1", 9))
    with pytest.raises(OSError, match="network blocked"):
        socket.socket().connect(("127.0.0.1", 9))
    # The client honours the (dead, loopback) proxy variables; the patched
    # send stops it. The raw transport bypasses send and must still be
    # stopped at the socket layer.
    with pytest.raises(OSError, match="network blocked"):
        httpx.Client().get("https://services.nvd.nist.gov/")
    with pytest.raises(Exception, match="network blocked"):
        httpx.HTTPTransport(proxy=DEAD_PROXY).handle_request(
            httpx.Request("GET", "https://services.nvd.nist.gov/")
        )
    assert blocked_network[:3] == [
        "create_connection(('127.0.0.1', 9),)",
        "socket.connect(('127.0.0.1', 9),)",
        "httpx.Client.send(<Request('GET', 'https://services.nvd.nist.gov/')>,)",
    ]
    assert any(
        entry.startswith(("create_connection", "getaddrinfo"))
        for entry in blocked_network[3:]
    )


def test_hit_stale_and_miss_make_zero_network_requests(
    cache_dir: Path,
    blocked_network: list[str],
) -> None:
    from ai_vuln_agent.enrichment.store import DATABASE_FILENAME

    payload = mixed_envelope()
    pristine = copy.deepcopy(payload)
    database = cache_dir / DATABASE_FILENAME
    before = _digest(database)

    result = bridge_from_cache(
        payload,
        cache_dir,
        now=WRITTEN_AT + timedelta(hours=1),
    )

    assert blocked_network == []
    assert payload == pristine
    assert _digest(database) == before
    assert sorted(p.name for p in cache_dir.iterdir()) == [DATABASE_FILENAME]
    items = result.envelope["findings"]
    statuses = [item["metadata"][METADATA_KEY]["status"] for item in items]
    assert statuses == [
        "enriched",
        "stale",
        "enriched",
        "unknown",
        "not_applicable",
        "invalid_input",
        "enriched",
    ]
    fresh = items[0]["metadata"][METADATA_KEY]
    assert fresh["values"] == {
        "cvss_v3": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N",
        "cwe": "CWE-89",
        "epss": 0.25,
        "epss_percentile": 0.8,
        "kev": True,
    }
    assert fresh["providers"]["nvd"]["fetched_at"] == WRITTEN_AT.isoformat()
    not_listed = items[2]["metadata"][METADATA_KEY]
    assert not_listed["values"]["kev"] is False
    assert not_listed["values"]["cvss_v3"] is None
    assert not_listed["providers"]["nvd"]["status"] == "not_found"
    assert items[3]["metadata"][METADATA_KEY]["values"]["kev"] is None
    assert [item["description"] for item in items] == ["static evidence"] * 7
    assert [item["cve"] for item in items] == [f["cve"] for f in pristine["findings"]]
    assert result.summary["cves"] == 4
    assert result.summary["cache"] == str(database.resolve())


def test_everything_expired_reports_stale_without_refresh(
    cache_dir: Path,
    blocked_network: list[str],
) -> None:
    result = bridge_from_cache(
        mixed_envelope(),
        cache_dir,
        now=WRITTEN_AT + timedelta(days=5),
    )

    assert blocked_network == []
    assert result.summary["status_counts"] == {
        "invalid_input": 1,
        "not_applicable": 1,
        "stale": 4,
        "unknown": 1,
    }


def test_missing_cache_is_an_explicit_error(
    tmp_path: Path,
    blocked_network: list[str],
) -> None:
    target = tmp_path / "no-cache"

    with pytest.raises(CveCacheUnavailableError, match="does not exist") as caught:
        bridge_from_cache(mixed_envelope(), target)

    assert caught.value.reason == "cache_not_found"
    assert not target.exists()
    assert blocked_network == []


def test_invalid_envelope_is_rejected_before_opening_cache(
    tmp_path: Path,
) -> None:
    payload = mixed_envelope()
    payload["findings"][1]["source"] = "002"

    with pytest.raises(ValueError, match="index 1 has source '002'"):
        bridge_from_cache(payload, tmp_path / "never-opened")
