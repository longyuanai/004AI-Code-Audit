from __future__ import annotations

from shared_llm_core import TaskTier

from analyzer.providers._router_v2 import (
    ProviderV2Response,
    RouterLike,
    RouterV2Provider,
)


class ClaudeV2Provider(RouterV2Provider):
    """Claude-compatible import surface routed by shared_llm_core."""


def analyze_with_claude_v2(
    router: RouterLike,
    *,
    system_prompt: str,
    user_prompt: str,
    tier: TaskTier = TaskTier.STANDARD,
    max_tokens: int = 600,
) -> ProviderV2Response:
    return ClaudeV2Provider(router, tier=tier).analyze(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        max_tokens=max_tokens,
    )


__all__ = ["ClaudeV2Provider", "analyze_with_claude_v2"]

