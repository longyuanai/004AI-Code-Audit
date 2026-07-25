from pathlib import Path

import pytest

pytest.importorskip(
    "shared_llm_core",
    reason="v2 provider adapters route through shared_llm_core.LLMRouter",
)

from analyzer.providers.claude_v2 import (  # noqa: E402
    ClaudeV2Provider,
    analyze_with_claude_v2,
)
from analyzer.providers.openai_v2 import (
    OpenAIV2Provider,
    analyze_with_openai_v2,
)
from shared_llm_core import TaskTier


def test_claude_v2_uses_router_contract(stub_router) -> None:
    result = analyze_with_claude_v2(
        stub_router,
        system_prompt="system",
        user_prompt="user",
    )

    assert result.text.startswith('{"confirmed": true')
    assert result.input_tokens == 10
    tier, request = stub_router.calls[0]
    assert tier is TaskTier.STANDARD
    assert request.model is None
    assert [message.role for message in request.messages] == ["system", "user"]


def test_openai_v2_respects_selected_tier_and_token_limit(stub_router) -> None:
    result = analyze_with_openai_v2(
        stub_router,
        system_prompt="system",
        user_prompt="user",
        tier=TaskTier.CHEAP,
        max_tokens=123,
    )

    assert isinstance(OpenAIV2Provider(stub_router), OpenAIV2Provider)
    assert result.output_tokens == 5
    tier, request = stub_router.calls[0]
    assert tier is TaskTier.CHEAP
    assert request.max_tokens == 123


def test_v2_provider_propagates_router_errors(stub_router) -> None:
    stub_router.error = RuntimeError("router unavailable")

    with pytest.raises(RuntimeError, match="router unavailable"):
        ClaudeV2Provider(stub_router).analyze(
            system_prompt="system",
            user_prompt="user",
        )


def test_legacy_typescript_providers_are_retained() -> None:
    providers = Path(__file__).resolve().parents[1] / "src" / "analyzer" / "providers"
    assert (providers / "claude.ts").is_file()
    assert (providers / "openai.ts").is_file()

