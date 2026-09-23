"""C1: read-only cache adapter against the real vulnerability-analysis store.

The cache is populated through the module's own CVEEnricher with in-memory
provider fakes, so the rows have exactly the shape production writes. The
bridge then runs with every socket operation blocked (loopback included).
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import socket
from collections import Counter
from collections.abc import Iterator, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip(
    "ai_vuln_agent.enrichment.store",
    reason="vulnerability-analysis src must be on PYTHONPATH for C1 cache tests",
)

from ai_vuln_agent.enrichment.client import CVEEnricher
from ai_vuln_agent.enrichment.epss import EPSSRecord
from ai_vuln_agent.enrichment.kev import KEVRecord
from ai_vuln_agent.enrichment.nvd import NVDRecord
from ai_vuln_agent.enrichment.store import (
    DATABASE_FILENAME,
    SQLiteEnrichmentStore,
)

from ai_code_audit.cve_intel import (
    METADATA_KEY,
    CveCacheUnavailableError,
    bridge_from_cache,
)

FRESH = "CVE-2024-1111"
STALE = "CVE-2024-2222"
NOT_LISTED = "CVE-2024-3333"
MISSING = "CVE-2024-4444"
WRITTEN_AT = datetime(2026, 9, 23, 8, 0, tzinfo=timezone.utc)


class _Clock:
    def __init__(self) -> None:
        self.now = WRITTEN_AT

    def __call__(self) -> datetime:
        return self.now


class _Source:
    def __init__(
        self, records: Mapping[str, object], calls: Counter[str], name: str
    ) -> None:
        self.records = records
        self.calls = calls
        self.name = name

    async def lookup(self, cve_id: str) -> object:
        self.calls[self.name] += 1
        return self.records.get(cve_id)

    async def close(self) -> None:
        pass


def _populate(cache_dir: Path) -> None:
    calls: Counter[str] = Counter()
    clock = _Clock()
    store = SQLiteEnrichmentStore(cache_dir, clock=clock)
    nvd = {
        cve: NVDRecord(cve, 7.5, "CVSS:3.1/AV:N", "CWE-89", "nvd text")
        for cve in (FRESH, STALE)
    }
    kev = {FRESH: KEVRecord(FRESH, "name", "2024-01-01", "2024-02-01", "patch")}
    epss = {
        FRESH: EPSSRecord(FRESH, 0.25, 0.8),
        NOT_LISTED: EPSSRecord(NOT_LISTED, 0.01, 0.1),
    }
    enricher = CVEEnricher(
        cache_dir=None,
        store=store,
        nvd=_Source(nvd, calls, "nvd"),
        kev=_Source(kev, calls, "kev"),
        epss=_Source(epss, calls, "epss"),
    )
    asyncio.run(enricher.enrich_many([FRESH, STALE, NOT_LISTED]))
    assert sum(calls.values()) == 9
    # Age STALE's rows past their 24h TTL by rewriting them in the past.
    clock.now = WRITTEN_AT - timedelta(days=3)
    for provider in ("nvd", "kev", "epss"):
        record = store.get(provider, STALE)
        assert record is not None
        store.put(provider, STALE, record.payload, status=record.status)


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    target = tmp_path / "漏洞 情报"
    _populate(target)
    return target


@pytest.fixture
def blocked_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    attempts: list[str] = []

    def deny(name: str):
        def _deny(*args: Any, **kwargs: Any) -> Any:
            attempts.append(f"{name}{args[1:2] or args[:1]}")
            raise OSError(f"network blocked in test: {name}")

        return _deny

    for name in ("connect", "connect_ex", "sendto", "sendall", "send"):
        monkeypatch.setattr(socket.socket, name, deny(f"socket.{name}"))
    for name in ("create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, deny(name))
    import httpx  # a hard dependency of the vulnerability module

    monkeypatch.setattr(httpx.Client, "send", deny("httpx.Client.send"))
    monkeypatch.setattr(httpx.AsyncClient, "send", deny("httpx.AsyncClient.send"))
    yield attempts


def _payload() -> dict[str, Any]:
    def finding(index: int, cve: object) -> dict[str, Any]:
        return {
            "id": f"code-{index}",
            "source": "004",
            "severity": "medium",
            "confidence": 0.6,
            "title": f"finding {index}",
            "description": "static evidence",
            "cve": cve,
            "metadata": {"rule_id": "004-test"},
        }

    return {
        "findings": [
            finding(0, FRESH.lower()),
            finding(1, STALE),
            finding(2, NOT_LISTED),
            finding(3, MISSING),
            finding(4, None),
            finding(5, "CVE-bad"),
            finding(6, FRESH),
        ],
        "summary": {"files_scanned": 3},
    }


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_network_guard_is_effective(blocked_network: list[str]) -> None:
    with pytest.raises(OSError, match="network blocked"):
        socket.create_connection(("127.0.0.1", 9))
    with pytest.raises(OSError, match="network blocked"):
        socket.socket().connect(("127.0.0.1", 9))
    import httpx

    # A local HTTP(S)_PROXY is reached over loopback, so loopback is blocked
    # too. The transport bypasses the patched Client.send and must still be
    # stopped at the socket layer.
    with pytest.raises(OSError, match="network blocked"):
        httpx.Client().get("https://services.nvd.nist.gov/")
    with pytest.raises(Exception, match="network blocked"):
        httpx.HTTPTransport().handle_request(
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
    payload = _payload()
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
        _payload(),
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

    with pytest.raises(CveCacheUnavailableError, match="does not exist"):
        bridge_from_cache(_payload(), target)

    assert not target.exists()
    assert blocked_network == []


def test_invalid_envelope_is_rejected_before_opening_cache(
    tmp_path: Path,
) -> None:
    payload = _payload()
    payload["findings"][1]["source"] = "002"

    with pytest.raises(ValueError, match="index 1 has source '002'"):
        bridge_from_cache(payload, tmp_path / "never-opened")
