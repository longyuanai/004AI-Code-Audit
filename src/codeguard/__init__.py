"""AI-CodeGuard v0.5 Python analysis components."""

from codeguard.dataflow import (
    CallEdge,
    DataflowAnalyzer,
    DataflowPath,
    DataflowReport,
    DataflowRule,
    register_dataflow_rule,
)
from codeguard.taint import (
    TaintAnalyzer,
    TaintPath,
    TaintRule,
    TaintStep,
    register_taint_rule,
)

# `codeguard.explain` needs the LLM types from shared_llm_core, which the
# offline taint/dataflow engine does not. Importing it eagerly here made the
# whole static-analysis path unusable whenever shared_llm_core was missing,
# so it is resolved on first attribute access instead (PEP 562). The public
# surface in __all__ is unchanged.
_EXPLAIN_EXPORTS = frozenset(
    {
        "DataflowExplainer",
        "DataflowExplanation",
        "build_explanation_prompt",
    }
)


def __getattr__(name: str) -> object:
    if name in _EXPLAIN_EXPORTS:
        from codeguard import explain

        return getattr(explain, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)


__all__ = [
    "CallEdge",
    "DataflowAnalyzer",
    "DataflowExplainer",
    "DataflowExplanation",
    "DataflowPath",
    "DataflowReport",
    "DataflowRule",
    "TaintAnalyzer",
    "TaintPath",
    "TaintRule",
    "TaintStep",
    "build_explanation_prompt",
    "register_dataflow_rule",
    "register_taint_rule",
]
