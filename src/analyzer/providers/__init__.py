"""LLM provider adapters.

The existing TypeScript providers remain available for v0.4 callers. Python
v2 adapters route requests through shared_llm_core.LLMRouter.
"""

from analyzer.providers.claude_v2 import (
    ClaudeV2Provider,
    analyze_with_claude_v2,
)
from analyzer.providers.openai_v2 import (
    OpenAIV2Provider,
    analyze_with_openai_v2,
)

__all__ = [
    "ClaudeV2Provider",
    "OpenAIV2Provider",
    "analyze_with_claude_v2",
    "analyze_with_openai_v2",
]
