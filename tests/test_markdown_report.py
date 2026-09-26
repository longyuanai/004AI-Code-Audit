"""C2: Markdown rendering of an enriched envelope (pure, no I/O)."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any

from _cve_intel_support import finding

from ai_code_audit.cve_intel import ProviderObservation, run_offline_enrichment
from ai_code_audit.output.markdown import render_enrichment_markdown

NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)
CVE = "CVE-2024-1234"


class _Reader:
    def __init__(self, observations: dict[str, Any]) -> None:
        self.observations = observations
        self.path = "C:/缓存/enrichment-v1.sqlite3"

    def lookup(self, keys: list[str]) -> dict[str, Any]:
        return {key: self.observations.get(key, {}) for key in keys}


def _obs(provider: str, payload: dict[str, Any], age_hours: int = 1) -> ProviderObservation:
    fetched = NOW - timedelta(hours=age_hours)
    return ProviderObservation(
        provider=provider,
        status="ok",
        payload=payload,
        fetched_at=fetched,
        expires_at=fetched + timedelta(days=1),
    )


def _enrich(envelope: dict[str, Any], observations: dict[str, Any]) -> dict[str, Any]:
    return run_offline_enrichment(
        envelope,
        cache_path="unused",
        now=NOW,
        reader_factory=lambda _path: _Reader(observations),
    ).document


def test_report_shows_stage_sources_times_and_unknowns() -> None:
    observations = {
        CVE: {
            "nvd": _obs("nvd", {"cve_id": CVE, "cvss_v3": 9.8, "cvss_vector": None, "cwe": "CWE-94"}),
            "epss": _obs("epss", {"cve_id": CVE, "score": 0.4, "percentile": None}, age_hours=30),
        }
    }
    envelope = {
        "findings": [finding(0, CVE), finding(1, None)],
        "summary": {"gate": {"threshold": "high", "triggered": False, "findings": 0}},
        "warnings": ["backend fallback: builtin"],
    }

    report = render_enrichment_markdown(_enrich(envelope, observations))

    assert "| 阶段状态 | `partial` |" in report
    assert "**情报不完整**" in report
    assert "NVD CVE API 2.0 (local cache)" in report
    assert "| 联网刷新 | 否（仅读取本地缓存） |" in report
    assert "`C:/缓存/enrichment-v1.sqlite3`" in report
    assert "| `nvd` | ok | 2026-09-23T11:00:00+00:00 | 2026-09-24T11:00:00+00:00 |" in report
    assert "| `kev` | 缓存无记录（missing） | — | — |" in report
    assert "已过期，值未采用（stale）" in report
    assert "| CISA KEV | 未知（null） |" in report
    assert "| EPSS | 未知（null） |" in report
    assert "| CVSS v3 | 9.8 |" in report
    assert "**CVE 情报**：`not_applicable`" in report
    assert "| 阈值 | `high` |" in report
    assert "backend fallback: builtin" in report
    # Evidence is verbatim inside a fence (not escaped).
    assert "```text\nsink line 0: eval(value)\n```" in report
    assert "| 位置 | `app.py:2` |" in report


def test_failed_stage_keeps_findings_and_says_so() -> None:
    envelope = {"findings": [finding(0, CVE)], "summary": {}}
    document = copy.deepcopy(envelope)
    document["code_audit_enrichment"] = {
        "status": "failed",
        "reason": "cache_not_found",
        "error": "enrichment cache does not exist: C:\\none",
        "cache": "C:\\none",
        "network_refresh": False,
        "findings": 1,
        "cves": 1,
        "status_counts": {},
    }

    report = render_enrichment_markdown(document)

    assert "**情报阶段失败**" in report
    assert "| 原因 | `cache_not_found` |" in report
    assert "**CVE 情报**：未附加（阶段 `cache_not_found`）" in report
    assert "static evidence" in report
    assert "sink line 0: eval(value)" in report


def test_empty_findings_render() -> None:
    document = _enrich({"findings": [], "summary": {}}, {})

    report = render_enrichment_markdown(document)

    assert "| 阶段状态 | `skipped` |" in report
    assert "| 缓存 | 未打开 |" in report
    assert "（无发现）" in report


def test_untrusted_text_cannot_inject_markup() -> None:
    hostile = finding(
        0,
        "CVE-2024-1234 | x",
        title="<script>alert(1)</script> | ## [link](http://x) `tick`",
        description="**bold** <img src=x onerror=1>\nsecond line",
        evidence=["```", "code with ``` fence and `ticks`"],
        metadata={"relative_path": "a|b`c.py", "line": 3, "rule_id": "r`1"},
    )

    report = render_enrichment_markdown(_enrich({"findings": [hostile]}, {}))

    assert "<script>" not in report
    assert "<img" not in report
    assert "&lt;script&gt;" in report
    assert "\\*\\*bold\\*\\*" in report
    assert "\\[link\\](http://x)" in report
    assert "### 1. &lt;script&gt;alert(1)&lt;/script&gt; \\| \\#\\# " in report
    # The evidence fence is longer than any backtick run inside it.
    assert "````text\n```\ncode with ``` fence and `ticks`\n````" in report
    # Inline code spans survive backticks and table pipes.
    assert "``a\\|b`c.py:3``" in report
    assert "| CVE（原值） | `CVE-2024-1234 \\| x` |" in report
    for line in report.splitlines():
        if line.startswith("| 位置"):
            assert line.count(" | ") == 1


def test_unicode_is_preserved() -> None:
    item = finding(0, None, title="路径 注入", metadata={"relative_path": "源码/样本.py", "line": 1})

    report = render_enrichment_markdown(_enrich({"findings": [item]}, {}))

    assert "### 1. 路径 注入" in report
    assert "`源码/样本.py:1`" in report
