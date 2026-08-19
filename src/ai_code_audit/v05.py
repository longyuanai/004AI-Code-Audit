"""Additive v0.5 contract adapter.

The frozen shared-core checkout used by this repository is still v0.1.0.
Prefer its public v0.5 exports as soon as they exist; until then these local
definitions implement the exact §8/§9 surface needed by CodeGuard without
modifying or monkey-patching shared_llm_core.
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Mapping, Sequence

try:
    from shared_llm_core import (  # type: ignore[attr-defined]
        Finding,
        FindingSeverity,
        FindingSource,
        Rule,
        RuleContext,
        RuleEngine,
        RuleRegistry,
    )

    USING_SHARED_V05 = True
except ImportError:
    USING_SHARED_V05 = False

    class FindingSource(str, Enum):
        SOC = "001"
        VULN = "002"
        LAB = "003"
        CODE = "004"
        REVERSE = "005"
        FIRMWARE = "006"
        EXTERNAL = "external"

    class FindingSeverity(str, Enum):
        INFO = "info"
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    @dataclass(frozen=True)
    class Finding:
        id: str
        source: FindingSource
        severity: FindingSeverity
        confidence: float
        title: str
        description: str = ""
        host: str | None = None
        cve: str | None = None
        ts: datetime | None = None
        evidence: tuple[str, ...] = ()
        related: tuple[str, ...] = ()
        tags: frozenset[str] = frozenset()
        metadata: Mapping[str, Any] = field(default_factory=dict)

        def __post_init__(self) -> None:
            if not 0.0 <= self.confidence <= 1.0:
                raise ValueError("confidence must be between 0.0 and 1.0")

        def to_dict(self) -> dict[str, Any]:
            return {
                "id": self.id,
                "source": self.source.value,
                "severity": self.severity.value,
                "confidence": self.confidence,
                "title": self.title,
                "description": self.description,
                "host": self.host,
                "cve": self.cve,
                "ts": self.ts.isoformat() if self.ts is not None else None,
                "evidence": list(self.evidence),
                "related": list(self.related),
                "tags": sorted(self.tags),
                "metadata": dict(self.metadata),
            }

        @classmethod
        def from_dict(cls, data: dict[str, Any]) -> "Finding":
            timestamp = data.get("ts")
            return cls(
                id=str(data["id"]),
                source=FindingSource(data["source"]),
                severity=FindingSeverity(data["severity"]),
                confidence=float(data["confidence"]),
                title=str(data["title"]),
                description=str(data.get("description", "")),
                host=data.get("host"),
                cve=data.get("cve"),
                ts=datetime.fromisoformat(timestamp) if timestamp else None,
                evidence=tuple(data.get("evidence", ())),
                related=tuple(data.get("related", ())),
                tags=frozenset(data.get("tags", ())),
                metadata=dict(data.get("metadata", {})),
            )

    @dataclass(frozen=True)
    class RuleContext:
        subject: str
        facts: Mapping[str, Any]
        window: tuple[datetime, datetime] | None = None
        related: tuple[Finding, ...] = ()

    class Rule(ABC):
        id: str
        severity_hint: Literal[
            "low", "medium", "high", "critical"
        ] = "medium"

        @abstractmethod
        def evaluate(self, ctx: RuleContext) -> list[Finding]:
            raise NotImplementedError

        def __repr__(self) -> str:
            return f"Rule({self.id})"

    class RuleRegistry:
        def __init__(self) -> None:
            self._rules: dict[str, Rule] = {}

        def register(self, rule: Rule) -> None:
            self._rules[rule.id] = rule

        def get(self, rule_id: str) -> Rule:
            return self._rules[rule_id]

        def all(self) -> list[Rule]:
            return list(self._rules.values())

        @classmethod
        def default(cls) -> "RuleRegistry":
            return cls()

    class RuleEngine:
        def __init__(self, registry: RuleRegistry | None = None) -> None:
            self.registry = registry or RuleRegistry.default()

        def evaluate(
            self,
            ctx: RuleContext,
            *,
            rule_ids: Sequence[str] | None = None,
        ) -> list[Finding]:
            rules = (
                self.registry.all()
                if rule_ids is None
                else [self.registry.get(rule_id) for rule_id in rule_ids]
            )
            findings: list[Finding] = []
            for rule in rules:
                try:
                    findings.extend(rule.evaluate(ctx))
                except Exception as error:
                    print(
                        f"Rule {rule.id} failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
            return findings


__all__ = [
    "Finding",
    "FindingSeverity",
    "FindingSource",
    "Rule",
    "RuleContext",
    "RuleEngine",
    "RuleRegistry",
    "USING_SHARED_V05",
]
