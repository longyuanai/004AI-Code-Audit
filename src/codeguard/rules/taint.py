"""004 taint source-to-sink Rule for v0.5 RuleEngine."""

from __future__ import annotations

from codeguard.v05 import (
    Finding,
    FindingSeverity,
    FindingSource,
    Rule,
    RuleContext,
)


class TaintSourceToSinkRule(Rule):
    """Convert one precomputed source-to-sink flow into a Finding."""

    id = "004-taint-source-to-sink"
    severity_hint = "high"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        if not ctx.facts.get("taint_flow"):
            return []
        return [
            Finding(
                id="",
                source=FindingSource.CODE,
                severity=FindingSeverity.HIGH,
                confidence=0.85,
                title=f"taint flow in {ctx.subject}",
                host=ctx.subject,
                evidence=(str(ctx.facts["taint_flow"]),),
                metadata={
                    "rule_id": self.id,
                    "path": ctx.facts["taint_flow"],
                },
            )
        ]


__all__ = ["TaintSourceToSinkRule"]
