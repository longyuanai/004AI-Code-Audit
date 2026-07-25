from __future__ import annotations

from pathlib import Path

import pytest

from ai_codeguard.cli import scan_payload
from codeguard.rules import default
from codeguard.rules.taint import TaintSourceToSinkRule
from codeguard.v05 import (
    USING_SHARED_V05,
    Finding,
    FindingSource,
    Rule,
    RuleContext,
    RuleEngine,
    RuleRegistry,
)

TAINT_FLOW = {
    "language": "python",
    "variable": "value",
    "steps": [
        {"kind": "source", "name": "input", "line": 1},
        {"kind": "sink", "name": "eval", "line": 2},
    ],
}


class _FailingRule(Rule):
    id = "004-test-failing-rule"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        del ctx
        raise RuntimeError("expected rule failure")


def test_taint_rule_id_is_unique_in_default_registry() -> None:
    rule_ids = [rule.id for rule in default().all()]

    assert TaintSourceToSinkRule.id in rule_ids
    assert len(rule_ids) == len(set(rule_ids))


@pytest.mark.skipif(
    not USING_SHARED_V05,
    reason="core-* built-ins ship with shared_llm_core, not with the "
    "local v0.5 fallback contract",
)
def test_default_registry_includes_shared_core_builtins() -> None:
    rule_ids = [rule.id for rule in default().all()]

    assert {"core-brute-force", "core-known-cve"}.issubset(rule_ids)


def test_rule_registry_duplicate_id_raises_value_error() -> None:
    registry = default()

    with pytest.raises(ValueError, match="already registered"):
        registry.register(TaintSourceToSinkRule())


def test_rule_registry_missing_id_raises_key_error() -> None:
    with pytest.raises(KeyError, match="not found"):
        default().get("004-does-not-exist")


def test_rule_engine_empty_facts_returns_no_findings() -> None:
    findings = RuleEngine(default()).evaluate(
        RuleContext(subject="empty.py", facts={})
    )

    assert findings == []


def test_rule_engine_taint_flow_returns_one_finding() -> None:
    findings = RuleEngine(default()).evaluate(
        RuleContext(
            subject="unsafe.py",
            facts={"taint_flow": TAINT_FLOW},
        )
    )

    assert len(findings) == 1
    assert findings[0].host == "unsafe.py"
    assert findings[0].confidence == 0.85


def test_rule_engine_rule_ids_runs_only_taint_rule() -> None:
    context = RuleContext(
        subject="selected.py",
        facts={
            "taint_flow": TAINT_FLOW,
            "failed_logins": 100,
        },
    )

    findings = RuleEngine(default()).evaluate(
        context,
        rule_ids=[TaintSourceToSinkRule.id],
    )

    assert len(findings) == 1
    assert findings[0].source is FindingSource.CODE


def test_rule_engine_failure_logs_to_stderr_without_raising(
    capsys: pytest.CaptureFixture[str],
) -> None:
    registry = RuleRegistry()
    registry.register(_FailingRule())

    findings = RuleEngine(registry).evaluate(
        RuleContext(subject="failure.py", facts={})
    )

    assert findings == []
    stderr = capsys.readouterr().err
    assert _FailingRule.id in stderr
    assert "expected rule failure" in stderr


def test_cli_scan_python_repo_returns_finding(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    (tmp_path / "unsafe.py").write_text(
        "value = input('value')\neval(value)\n",
        encoding="utf-8",
    )

    envelope = scan_payload(
        {
            "repo_path": str(tmp_path),
            "languages": ["python"],
            "rules": [TaintSourceToSinkRule.id],
        }
    )

    assert len(envelope["findings"]) == 1
    assert envelope["findings"][0]["metadata"]["rule_id"] == (
        TaintSourceToSinkRule.id
    )


def test_cli_scan_empty_repo_returns_no_findings(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    envelope = scan_payload(
        {
            "repo_path": str(tmp_path),
            "languages": ["python"],
        }
    )

    assert envelope["findings"] == []
    assert envelope["summary"]["files_scanned"] == 0


def test_taint_finding_source_is_code() -> None:
    findings = TaintSourceToSinkRule().evaluate(
        RuleContext(
            subject="source.py",
            facts={"taint_flow": TAINT_FLOW},
        )
    )

    assert findings[0].source is FindingSource.CODE
