from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

SHARED_SRC = Path(__file__).resolve().parents[3] / "000shared-llm-core" / "src"
PROJECT_SRC = Path(__file__).resolve().parents[1] / "src"
LOCAL_DEPS = Path(__file__).resolve().parents[1] / ".python-deps"
for source_root in (LOCAL_DEPS, SHARED_SRC, PROJECT_SRC):
    source = str(source_root)
    if source not in sys.path:
        sys.path.insert(0, source)

from shared_llm_core import (  # noqa: E402
    ChatChoice,
    ChatMessage,
    ChatResponse,
    ChatUsage,
)


class StubRouter:
    def __init__(
        self,
        *,
        content: str = (
            '{"confirmed": true, "confidence": 0.9, '
            '"reasoning": "stub router verdict"}'
        ),
        model: str = "stub-model",
    ) -> None:
        self.content = content
        self.model = model
        self.calls: list[tuple[Any, Any]] = []
        self.error: Exception | None = None

    def chat(self, tier: Any, request: Any) -> ChatResponse:
        self.calls.append((tier, request))
        if self.error is not None:
            raise self.error
        return ChatResponse(
            id="stub-response",
            model=self.model,
            created=0,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content=self.content),
                    finish_reason="stop",
                )
            ],
            usage=ChatUsage(
                prompt_tokens=10,
                completion_tokens=5,
                total_tokens=15,
            ),
        )


@pytest.fixture
def stub_router() -> StubRouter:
    return StubRouter()


@pytest.fixture
def stub_router_with():
    def factory(
        *,
        content: str,
        model: str = "stub-model",
    ) -> StubRouter:
        return StubRouter(content=content, model=model)

    return factory
