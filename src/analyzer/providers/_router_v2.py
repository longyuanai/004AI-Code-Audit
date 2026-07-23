from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from shared_llm_core import ChatMessage, ChatRequest, ChatResponse, TaskTier


class RouterLike(Protocol):
    def chat(self, tier: TaskTier, req: ChatRequest) -> ChatResponse: ...


@dataclass(frozen=True)
class ProviderV2Response:
    text: str
    input_tokens: int
    output_tokens: int
    model: str


class RouterV2Provider:
    """Provider-shaped compatibility adapter backed only by LLMRouter."""

    def __init__(
        self,
        router: RouterLike,
        *,
        tier: TaskTier = TaskTier.STANDARD,
    ) -> None:
        self.router = router
        self.tier = tier

    def analyze(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 600,
    ) -> ProviderV2Response:
        request = ChatRequest(
            messages=[
                ChatMessage(role="system", content=system_prompt),
                ChatMessage(role="user", content=user_prompt),
            ],
            temperature=0,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )
        response = self.router.chat(self.tier, request)
        text = response.choices[0].message.content.strip() if response.choices else ""
        return ProviderV2Response(
            text=text,
            input_tokens=response.usage.prompt_tokens,
            output_tokens=response.usage.completion_tokens,
            model=response.model,
        )

