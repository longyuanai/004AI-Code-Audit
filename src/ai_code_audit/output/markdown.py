"""Markdown report for an offline CVE-enriched envelope (C2).

Renders exactly what the enrichment stage produced: original Findings and
source evidence, the stage record, provider sources, fetch/expiry times and
unknown or stale intelligence. Nothing is recomputed or fetched. Scan data is
untrusted, so all text is escaped and evidence goes into code fences that are
longer than any backtick run inside them.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping, Sequence
from typing import Any

STAGE_KEY = "code_audit_enrichment"
# Escaped text never starts a line (always after a prefix), and brackets are
# escaped, so ( ) + ! need no escape and timestamps stay readable.
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]#|~])")
_PROVIDER_STATUS = {
    "ok": "ok",
    "not_found": "未收录（not_found）",
    "missing": "缓存无记录（missing）",
    "stale": "已过期，值未采用（stale）",
    "invalid_cache": "缓存数据无效（invalid_cache）",
    "unsupported_status": "不支持的缓存状态（unsupported_status）",
}
_VALUE_LABELS = (
    ("cvss_v3", "CVSS v3"),
    ("cvss_vector", "CVSS 向量"),
    ("cwe", "CWE"),
    ("epss", "EPSS"),
    ("epss_percentile", "EPSS 百分位"),
    ("kev", "CISA KEV"),
)


def render_enrichment_markdown(document: Mapping[str, Any]) -> str:
    stage = document.get(STAGE_KEY)
    stage = stage if isinstance(stage, Mapping) else {}
    findings = document.get("findings")
    findings = findings if isinstance(findings, list) else []
    lines = ["# Code Audit 离线 CVE 情报报告", ""]
    lines += _stage_section(stage)
    lines += _sources_section(stage)
    lines += _counts_section(stage)
    lines += _gate_section(document.get("summary"))
    lines += _warnings_section(document.get("warnings"))
    lines += ["## 发现", ""]
    if not findings:
        lines += ["（无发现）", ""]
    for index, finding in enumerate(findings, start=1):
        if isinstance(finding, Mapping):
            lines += _finding_section(index, finding, stage)
    lines += [
        "---",
        "",
        (
            "CVE 情报仅为附加参考：不修改严重性，不证明缺陷可利用；"
            "未知值显示为“未知（null）”，不按 0 或“未收录”处理。"
        ),
        "",
    ]
    return "\n".join(lines)


def _stage_section(stage: Mapping[str, Any]) -> list[str]:
    status = stage.get("status") or "unknown"
    rows = [
        ("阶段状态", _code(status)),
        ("原因", _code(stage.get("reason")) if stage.get("reason") else "—"),
        ("错误", _text(stage.get("error")) if stage.get("error") else "—"),
        ("评估时间", _text(stage.get("evaluated_at"))),
        ("缓存", _code(stage.get("cache")) if stage.get("cache") else "未打开"),
        (
            "联网刷新",
            "否（仅读取本地缓存）"
            if stage.get("network_refresh") is False
            else _text(stage.get("network_refresh")),
        ),
        ("Finding 数", _text(stage.get("findings"))),
        ("可查询 CVE 数", _text(stage.get("cves"))),
    ]
    lines = ["## 增强阶段", ""]
    if status == "failed":
        lines += [
            (
                "> **情报阶段失败**：原始扫描发现已完整保留，未附加任何情报；"
                "请勿将本报告理解为“无已知漏洞”。"
            ),
            "",
        ]
    elif status == "partial":
        lines += [
            "> **情报不完整**：部分 CVE 缓存缺失、过期或输入无效，见各发现。",
            "",
        ]
    return lines + _table(("项目", "值"), rows) + [""]


def _sources_section(stage: Mapping[str, Any]) -> list[str]:
    sources = stage.get("sources")
    if not isinstance(sources, Mapping) or not sources:
        return []
    lines = ["## 情报来源", ""]
    lines += [f"- {_code(name)}：{_text(label)}" for name, label in sources.items()]
    return lines + [""]


def _counts_section(stage: Mapping[str, Any]) -> list[str]:
    counts = stage.get("status_counts")
    if not isinstance(counts, Mapping) or not counts:
        return []
    rows = [(_code(name), _text(count)) for name, count in counts.items()]
    return ["## 状态统计", "", *_table(("Finding 情报状态", "数量"), rows), ""]


def _gate_section(summary: object) -> list[str]:
    gate = summary.get("gate") if isinstance(summary, Mapping) else None
    if not isinstance(gate, Mapping):
        return []
    rows = [
        ("阈值", _code(gate.get("threshold"))),
        ("触发", "是" if gate.get("triggered") is True else "否"),
        ("阻断发现数", _text(gate.get("findings"))),
    ]
    return ["## 扫描门禁", "", *_table(("项目", "值"), rows), ""]


def _warnings_section(warnings: object) -> list[str]:
    if not isinstance(warnings, list) or not warnings:
        return []
    return ["## 扫描警告", "", *(f"- {_text(item)}" for item in warnings), ""]


def _finding_section(
    index: int,
    finding: Mapping[str, Any],
    stage: Mapping[str, Any],
) -> list[str]:
    metadata = finding.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    lines = [f"### {index}. {_text(finding.get('title'))}", ""]
    facts = [
        ("ID", _code(finding.get("id"))),
        ("来源", _code(finding.get("source"))),
        ("严重性", _code(finding.get("severity"))),
        ("置信度", _text(finding.get("confidence"))),
        ("规则", _code(metadata.get("rule_id")) if metadata.get("rule_id") else "—"),
        ("位置", _location(finding, metadata)),
        (
            "CVE（原值）",
            _code(finding.get("cve")) if "cve" in finding else "（无字段）",
        ),
    ]
    lines += _table(("字段", "值"), facts) + [""]
    if finding.get("description"):
        lines += [f"**描述**：{_text(finding.get('description'))}", ""]
    evidence = finding.get("evidence")
    if isinstance(evidence, list) and evidence:
        lines += ["**源码证据**：", "", *_fence("\n".join(map(str, evidence))), ""]
    intel = metadata.get(STAGE_KEY)
    if not isinstance(intel, Mapping):
        reason = stage.get("reason") or stage.get("status") or "unknown"
        lines += [f"**CVE 情报**：未附加（阶段 {_code(reason)}）", ""]
        return lines
    lines += [
        f"**CVE 情报**：{_code(intel.get('status'))}"
        + (f"，查询键 {_code(intel.get('cve'))}" if intel.get("cve") else ""),
        "",
    ]
    providers = intel.get("providers")
    if isinstance(providers, Mapping) and providers:
        rows = [
            (
                _code(name),
                _text(_PROVIDER_STATUS.get(str(state.get("status")), state.get("status"))),
                _text(state.get("fetched_at")) if state.get("fetched_at") else "—",
                _text(state.get("expires_at")) if state.get("expires_at") else "—",
            )
            for name, state in providers.items()
            if isinstance(state, Mapping)
        ]
        lines += _table(("来源", "状态", "采集时间", "过期时间"), rows) + [""]
    values = intel.get("values")
    if isinstance(values, Mapping):
        value_rows = [(label, _value(values.get(key))) for key, label in _VALUE_LABELS]
        lines += _table(("情报字段", "值"), value_rows) + [""]
    warnings = intel.get("warnings")
    if isinstance(warnings, list) and warnings:
        lines += ["情报提示：", "", *(f"- {_text(item)}" for item in warnings), ""]
    return lines


def _location(finding: Mapping[str, Any], metadata: Mapping[str, Any]) -> str:
    path = metadata.get("relative_path") or finding.get("host")
    if not path:
        return "—"
    line = metadata.get("line")
    return _code(f"{path}:{line}" if line is not None else path)


def _value(value: object) -> str:
    if value is None:
        return "未知（null）"
    if isinstance(value, bool):
        return "是" if value else "否"
    return _text(value)


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    return [
        "| " + " | ".join(headers) + " |",
        "|" + "---|" * len(headers),
        *("| " + " | ".join(row) + " |" for row in rows),
    ]


def _text(value: object) -> str:
    """Escape untrusted text for inline Markdown (one line, no raw HTML)."""
    flat = " ".join(str(value).split())
    return _MD_SPECIAL.sub(r"\\\1", html.escape(flat, quote=False))


def _code(value: object) -> str:
    """Inline code span that cannot be broken out of.

    Code spans are literal (no HTML), so only GFM's table pipe needs ``\\|``.
    """
    flat = " ".join(str(value).split()).replace("|", "\\|")
    longest = max((len(run) for run in re.findall(r"`+", flat)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if flat.startswith("`") or flat.endswith("`") else ""
    return f"{ticks}{pad}{flat}{pad}{ticks}"


def _fence(body: str) -> list[str]:
    longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}text", body, fence]


__all__ = ["render_enrichment_markdown"]
