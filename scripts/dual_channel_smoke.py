from __future__ import annotations

import json

from analyzer.dual_channel import DualChannelScheduler, RuleMatch
from analyzer.providers.claude_v2 import ClaudeV2Provider
from shared_llm_core import (
    ChatChoice,
    ChatMessage,
    ChatResponse,
    ChatUsage,
)


class SmokeRouter:
    def chat(self, _tier, _request) -> ChatResponse:
        return ChatResponse(
            id="smoke",
            model="stub-model",
            created=0,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(
                        role="assistant",
                        content=json.dumps(
                            {
                                "confirmed": True,
                                "confidence": 0.95,
                                "reasoning": "stub review confirmed the rule match",
                            }
                        ),
                    ),
                    finish_reason="stop",
                )
            ],
            usage=ChatUsage(
                prompt_tokens=10,
                completion_tokens=5,
                total_tokens=15,
            ),
        )


report = DualChannelScheduler(ClaudeV2Provider(SmokeRouter())).schedule(
    [
        RuleMatch(
            rule_id="CG-001",
            file="samples/demo.py",
            line=5,
            severity="critical",
            snippet='query = f"SELECT ... {user_name}"',
            language="python",
        )
    ]
)
print(json.dumps(report.stats.__dict__, ensure_ascii=False))

