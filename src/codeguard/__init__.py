"""AI-CodeGuard v0.5 Python analysis components."""

from codeguard.taint import (
    TaintAnalyzer,
    TaintPath,
    TaintRule,
    TaintStep,
    register_taint_rule,
)

__all__ = [
    "TaintAnalyzer",
    "TaintPath",
    "TaintRule",
    "TaintStep",
    "register_taint_rule",
]
