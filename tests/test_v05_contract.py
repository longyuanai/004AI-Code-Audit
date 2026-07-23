from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from uuid import UUID

import pytest

from codeguard.taint import TaintRule
from codeguard.v05 import (
    Finding,
    FindingSeverity,
    FindingSource,
    Rule,
    RuleContext,
    RuleEngine,
    RuleRegistry,
)


def _finding(*, title: str = "finding", confidence: float = 0.8) -> Finding:
    return Finding(
        id="12345678-1234-4234-9234-123456789abc",
        source=FindingSource.CODE,
        severity=FindingSeverity.HIGH,
        confidence=confidence,
        title=title,
    )


class _GoodRule(Rule):
    id = "004-test-good"
    severity_hint = "high"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        return [_finding(title=ctx.subject)]


class _SecondRule(Rule):
    id = "004-test-second"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        return [_finding(title=f"second:{ctx.subject}")]


class _FailingRule(Rule):
    id = "004-test-failing"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        raise RuntimeError("expected failure")


def test_rule_registry_registers_and_gets_by_id() -> None:
    registry = RuleRegistry()
    rule = _GoodRule()

    registry.register(rule)

    assert registry.get(rule.id) is rule


def test_rule_registry_preserves_registration_order() -> None:
    registry = RuleRegistry()
    registry.register(_GoodRule())
    registry.register(_SecondRule())

    assert [rule.id for rule in registry.all()] == [
        "004-test-good",
        "004-test-second",
    ]


def test_rule_repr_uses_frozen_contract_shape() -> None:
    assert repr(_GoodRule()) == "Rule(004-test-good)"


def test_rule_engine_executes_registered_rules_in_order() -> None:
    registry = RuleRegistry()
    registry.register(_GoodRule())
    registry.register(_SecondRule())
    context = RuleContext(subject="subject", facts={})

    findings = RuleEngine(registry).evaluate(context)

    assert [finding.title for finding in findings] == [
        "subject",
        "second:subject",
    ]


def test_rule_engine_can_select_rule_ids() -> None:
    registry = RuleRegistry()
    registry.register(_GoodRule())
    registry.register(_SecondRule())

    findings = RuleEngine(registry).evaluate(
        RuleContext(subject="selected", facts={}),
        rule_ids=["004-test-second"],
    )

    assert [finding.title for finding in findings] == ["second:selected"]


def test_rule_engine_skips_failure_and_runs_remaining_rule(
    capsys,
) -> None:
    registry = RuleRegistry()
    registry.register(_FailingRule())
    registry.register(_GoodRule())

    findings = RuleEngine(registry).evaluate(
        RuleContext(subject="survived", facts={})
    )

    assert [finding.title for finding in findings] == ["survived"]
    assert "004-test-failing" in capsys.readouterr().err


def test_rule_context_is_frozen() -> None:
    context = RuleContext(subject="subject", facts={"value": 1})

    with pytest.raises(FrozenInstanceError):
        context.subject = "changed"  # type: ignore[misc]


def test_rule_evaluation_does_not_mutate_context_facts() -> None:
    facts = {"source": "constant", "language": "python"}
    context = RuleContext(subject="subject", facts=facts)

    _GoodRule().evaluate(context)

    assert facts == {"source": "constant", "language": "python"}


def test_finding_source_and_severity_values_match_contract() -> None:
    assert FindingSource.CODE.value == "004"
    assert FindingSeverity.CRITICAL.value == "critical"


def test_finding_rejects_confidence_below_zero() -> None:
    with pytest.raises(ValueError, match="confidence"):
        _finding(confidence=-0.01)


def test_finding_rejects_confidence_above_one() -> None:
    with pytest.raises(ValueError, match="confidence"):
        _finding(confidence=1.01)


def test_finding_to_dict_has_stable_dataclass_field_order() -> None:
    finding = _finding()

    assert list(finding.to_dict()) == [
        "id",
        "source",
        "severity",
        "confidence",
        "title",
        "description",
        "host",
        "cve",
        "ts",
        "evidence",
        "related",
        "tags",
        "metadata",
    ]


def test_finding_round_trip_preserves_contract_fields() -> None:
    finding = Finding(
        id="12345678-1234-4234-9234-123456789abc",
        source=FindingSource.CODE,
        severity=FindingSeverity.CRITICAL,
        confidence=0.95,
        title="SQL injection",
        description="tainted query",
        ts=datetime(2026, 7, 24, tzinfo=timezone.utc),
        evidence=("source", "sink"),
        related=("related-id",),
        tags=frozenset({"taint", "sql"}),
        metadata={"language": "python"},
    )

    restored = Finding.from_dict(finding.to_dict())

    assert restored == finding


def test_finding_from_dict_ignores_unknown_fields() -> None:
    data = _finding().to_dict()
    data["future_v06_field"] = "ignored"

    restored = Finding.from_dict(data)

    assert restored.title == "finding"


def test_taint_rule_generates_unique_uuid4_finding_ids() -> None:
    context = RuleContext(
        subject="demo.py",
        facts={
            "language": "python",
            "source": "value = input('value')\neval(value)\n",
        },
    )

    first = TaintRule().evaluate(context)[0]
    second = TaintRule().evaluate(context)[0]

    assert first.id != second.id
    assert UUID(first.id).version == 4
    assert UUID(second.id).version == 4


def test_finding_serializes_tags_deterministically() -> None:
    finding = Finding(
        id="12345678-1234-4234-9234-123456789abc",
        source=FindingSource.CODE,
        severity=FindingSeverity.HIGH,
        confidence=0.8,
        title="finding",
        tags=frozenset({"zeta", "alpha"}),
    )

    assert finding.to_dict()["tags"] == ["alpha", "zeta"]
