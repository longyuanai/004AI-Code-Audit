"""004 product rules registered with shared-llm-core v0.5."""

from codeguard.v05 import RuleRegistry

from .taint import TaintSourceToSinkRule


def default() -> RuleRegistry:
    """Return shared built-ins plus the 004 taint flow rule."""

    registry = RuleRegistry.default()
    registry.register(TaintSourceToSinkRule())
    return registry


__all__ = ["TaintSourceToSinkRule", "default"]
