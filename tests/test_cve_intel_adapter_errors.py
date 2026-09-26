"""Adapter error mapping, including stores older than EnrichmentCacheError.

The C1 store (commit 554c247) raised bare RuntimeError and could leak raw
sqlite3/JSON errors from queries; none of these may crash the enrich stage.
"""

from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace
from typing import Any

import pytest

from ai_code_audit.cve_intel import cache as cache_module
from ai_code_audit.cve_intel import run_offline_enrichment

ENVELOPE = {
    "findings": [
        {
            "id": "a",
            "source": "004",
            "severity": "low",
            "confidence": 0.5,
            "title": "t",
            "cve": "CVE-2024-1111",
        }
    ]
}


class _Reasoned(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _fake_store(*, init: Exception | None = None, query: Exception | None = None) -> Any:
    class Store:
        path = "fake.sqlite3"

        def __init__(self, _path: object) -> None:
            if init is not None:
                raise init

        def get_many(self, _provider: str, _keys: list[str]) -> dict[str, Any]:
            if query is not None:
                raise query
            return {}

    return SimpleNamespace(ReadOnlyEnrichmentStore=Store, default_cache_dir=lambda: "d")


@pytest.mark.parametrize(
    ("init", "query", "reason"),
    [
        (FileNotFoundError("absent"), None, "cache_not_found"),
        (RuntimeError("unsupported schema version 2"), None, "cache_unreadable"),
        (_Reasoned("schema_mismatch"), None, "cache_schema_mismatch"),
        (_Reasoned("unreadable"), None, "cache_unreadable"),
        (sqlite3.DatabaseError("file is not a database"), None, "cache_unreadable"),
        (None, json.JSONDecodeError("bad", "{", 1), "cache_unreadable"),
        (None, sqlite3.OperationalError("no such table"), "cache_unreadable"),
        (None, _Reasoned("unreadable"), "cache_unreadable"),
    ],
)
def test_store_errors_become_failed_stage(
    monkeypatch: pytest.MonkeyPatch,
    init: Exception | None,
    query: Exception | None,
    reason: str,
) -> None:
    monkeypatch.setattr(
        cache_module, "_store_module", lambda: _fake_store(init=init, query=query)
    )

    outcome = run_offline_enrichment(ENVELOPE, cache_path="fake")

    assert (outcome.stage["status"], outcome.stage["reason"]) == ("failed", reason)
    assert outcome.document["findings"] == ENVELOPE["findings"]


def test_unexpected_errors_are_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cache_module, "_store_module", lambda: _fake_store(query=KeyError("bug"))
    )

    with pytest.raises(KeyError):
        run_offline_enrichment(ENVELOPE, cache_path="fake")
