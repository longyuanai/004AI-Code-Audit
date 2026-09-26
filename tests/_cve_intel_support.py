"""Shared helpers for the C1/C2 offline CVE enrichment tests.

Imports of ``ai_vuln_agent`` are lazy so this module can be imported in the
unit scope, where the tests that need it are deselected.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sqlite3
import subprocess
import sys
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

PROJECT = Path(__file__).resolve().parents[1]
FRESH = "CVE-2024-1111"
STALE = "CVE-2024-2222"
NOT_LISTED = "CVE-2024-3333"
MISSING = "CVE-2024-4444"
WRITTEN_AT = datetime(2026, 9, 23, 8, 0, tzinfo=timezone.utc)
# A dead loopback port: if a guard ever failed, traffic would hit this local
# address instead of the real internet (never use real external probes).
DEAD_PROXY = "http://127.0.0.1:9"


def install_network_guard(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Block every socket path in-process, loopback included."""
    attempts: list[str] = []

    def deny(name: str) -> Callable[..., Any]:
        def _deny(*args: Any, **_kwargs: Any) -> Any:
            attempts.append(f"{name}{args[1:2] or args[:1]}")
            raise OSError(f"network blocked in test: {name}")

        return _deny

    for name in ("connect", "connect_ex", "sendto", "sendall", "send"):
        monkeypatch.setattr(socket.socket, name, deny(f"socket.{name}"))
    for name in ("create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, deny(name))
    import httpx

    monkeypatch.setattr(httpx.Client, "send", deny("httpx.Client.send"))
    monkeypatch.setattr(httpx.AsyncClient, "send", deny("httpx.AsyncClient.send"))
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(variable, DEAD_PROXY)
    monkeypatch.delenv("NO_PROXY", raising=False)
    return attempts


_SITECUSTOMIZE = '''
import os, socket
_LOG = os.environ["CODE_AUDIT_NET_GUARD_LOG"]
def _deny(name):
    def _blocked(*args, **kwargs):
        with open(_LOG, "a", encoding="utf-8") as handle:
            handle.write(name + "\\n")
        raise OSError("network blocked in test: " + name)
    return _blocked
for _name in ("connect", "connect_ex", "sendto", "sendall", "send"):
    setattr(socket.socket, _name, _deny("socket." + _name))
for _name in ("create_connection", "getaddrinfo", "gethostbyname"):
    setattr(socket, _name, _deny(_name))
try:
    import httpx
except ImportError:
    pass
else:
    httpx.Client.send = _deny("httpx.Client.send")
    httpx.AsyncClient.send = _deny("httpx.AsyncClient.send")
with open(_LOG, "a", encoding="utf-8") as _handle:
    _handle.write("")
'''


class ChildGuard:
    """Environment for CLI child processes with all networking blocked."""

    def __init__(self, root: Path, *, with_vuln_module: bool = True) -> None:
        guard_dir = root / "net-guard"
        guard_dir.mkdir(parents=True, exist_ok=True)
        (guard_dir / "sitecustomize.py").write_text(_SITECUSTOMIZE, encoding="utf-8")
        self.log = root / "net-guard.log"
        self.log.write_text("", encoding="utf-8")
        parts = [str(guard_dir)]
        for part in os.environ.get("PYTHONPATH", "").split(os.pathsep):
            if not part:
                continue
            if not with_vuln_module and "vulnerability-analysis" in part:
                continue
            parts.append(part)
        self.env = dict(os.environ)
        self.env["PYTHONPATH"] = os.pathsep.join(parts)
        self.env["CODE_AUDIT_NET_GUARD_LOG"] = str(self.log)
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.env["PYTHONIOENCODING"] = "utf-8"
        for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            self.env[variable] = DEAD_PROXY
        self.env.pop("NO_PROXY", None)
        if not with_vuln_module:
            # Keep the default cache lookup away from the real profile.
            self.env["LOCALAPPDATA"] = str(root / "no-profile")

    def attempts(self) -> list[str]:
        return [line for line in self.log.read_text("utf-8").splitlines() if line]

    def run(
        self, *args: str, stdin: str | None = None, cwd: Path = PROJECT
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "ai_code_audit", *args],
            cwd=cwd,
            env=self.env,
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            timeout=120,
        )


class _Clock:
    def __init__(self, start: datetime) -> None:
        self.now = start

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


def populate_cache(cache_dir: Path, *, written_at: datetime = WRITTEN_AT) -> Path:
    """Write FRESH/STALE/NOT_LISTED through the module's own enricher.

    Rows written at ``written_at`` stay fresh for 24h; STALE is rewritten
    three days earlier. Must run before any in-process network guard: the
    enricher is async and Windows asyncio needs a loopback socket pair.
    The fake providers never touch the network.
    """
    from ai_vuln_agent.enrichment.client import CVEEnricher
    from ai_vuln_agent.enrichment.epss import EPSSRecord
    from ai_vuln_agent.enrichment.kev import KEVRecord
    from ai_vuln_agent.enrichment.nvd import NVDRecord
    from ai_vuln_agent.enrichment.store import (
        DATABASE_FILENAME,
        SQLiteEnrichmentStore,
    )

    calls: Counter[str] = Counter()
    clock = _Clock(written_at)
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
        nvd=_Source(nvd, calls, "nvd"),  # type: ignore[arg-type]
        kev=_Source(kev, calls, "kev"),  # type: ignore[arg-type]
        epss=_Source(epss, calls, "epss"),  # type: ignore[arg-type]
    )
    asyncio.run(enricher.enrich_many([FRESH, STALE, NOT_LISTED]))
    assert sum(calls.values()) == 9
    # Age STALE's rows past their 24h TTL by rewriting them in the past.
    clock.now = written_at - timedelta(days=3)
    for provider in ("nvd", "kev", "epss"):
        record = store.get(provider, STALE)
        assert record is not None
        store.put(provider, STALE, record.payload, status=record.status)
    return cache_dir / DATABASE_FILENAME


def set_schema_version(database: Path, version: int) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE database_metadata SET schema_version = ?", (version,)
        )


def finding(index: int, cve: object, **extra: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": f"code-{index}",
        "source": "004",
        "severity": "medium",
        "confidence": 0.6,
        "title": f"finding {index}",
        "description": "static evidence",
        "evidence": [f"sink line {index}: eval(value)"],
        "cve": cve,
        "metadata": {"rule_id": "004-test", "relative_path": "app.py", "line": 2},
    }
    item.update(extra)
    return item


def mixed_envelope() -> dict[str, Any]:
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
        "summary": {"files_scanned": 3, "repository_source": "local"},
        "warnings": [],
        "x_unknown_top_level": {"kept": True},
    }


def write_json(path: Path, document: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    return path
