"""AI-CodeGuard v0.5 Python analysis components."""

from codeguard.dataflow import (
    CallEdge,
    DataflowAnalyzer,
    DataflowPath,
    DataflowReport,
    DataflowRule,
    register_dataflow_rule,
)
from codeguard.explain import (
    DataflowExplainer,
    DataflowExplanation,
    build_explanation_prompt,
)
from codeguard.taint import (
    TaintAnalyzer,
    TaintPath,
    TaintRule,
    TaintStep,
    register_taint_rule,
)

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
