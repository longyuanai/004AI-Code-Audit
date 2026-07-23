"""LLM explanations for cross-function dataflow paths."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Protocol

from shared_llm_core import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    TaskTier,
)

from codeguard.dataflow import DataflowPath


class RouterLike(Protocol):
    def chat(self, tier: TaskTier, req: ChatRequest) -> ChatResponse: ...


@dataclass(frozen=True)
class DataflowExplanation:
    text: str
    model: str
    prompt_tokens: int
    completion_tokens: int


class DataflowExplainer:
    """Turn one verified dataflow path into a concise Chinese explanation."""

    def __init__(self, router: RouterLike) -> None:
        self.router = router

    def explain(self, path: DataflowPath) -> DataflowExplanation:
        request = ChatRequest(
            messages=[
                ChatMessage(
                    role="system",
                    content=(
                        "你是 AI-CodeGuard 数据流解释器。只解释输入中已经"
                        "验证的 source、调用链和 sink，不补充不存在的步骤。"
                        "输出 JSON：{\"explanation\":\"一条中文句子\"}。"
                    ),
                ),
                ChatMessage(
                    role="user",
                    content=build_explanation_prompt(path),
                ),
            ],
            temperature=0,
            max_tokens=300,
            response_format={"type": "json_object"},
        )
        response = self.router.chat(TaskTier.CHEAP, request)
        if not response.choices:
            raise ValueError("LLM explanation response has no choices")

        try:
            payload = json.loads(response.choices[0].message.content)
        except json.JSONDecodeError as error:
            raise ValueError(
                "LLM explanation response is not valid JSON"
            ) from error
        explanation = payload.get("explanation")
        if not isinstance(explanation, str) or not explanation.strip():
            raise ValueError(
                "LLM explanation response is missing explanation"
            )
        return DataflowExplanation(
            text=explanation.strip(),
            model=response.model,
            prompt_tokens=response.usage.prompt_tokens,
            completion_tokens=response.usage.completion_tokens,
        )

    def explain_all(
        self,
        paths: Iterable[DataflowPath],
    ) -> list[DataflowExplanation]:
        return [self.explain(path) for path in paths]


def build_explanation_prompt(path: DataflowPath) -> str:
    payload = {
        "language": path.language,
        "variable": path.variable,
        "source": {
            "name": path.source.name,
            "function": path.source.function,
            "line": path.source.line,
            "detail": path.source.detail,
        },
        "calls": [
            {
                "caller": edge.caller,
                "callee": edge.callee,
                "line": edge.line,
            }
            for edge in path.calls
        ],
        "propagations": [
            {
                "variable": step.name,
                "function": step.function,
                "line": step.line,
            }
            for step in path.propagations
        ],
        "sink": {
            "name": path.sink.name,
            "function": path.sink.function,
            "line": path.sink.line,
            "detail": path.sink.detail,
        },
    }
    return (
        "请把下面经过静态分析验证的数据流写成一条中文安全解释，"
        "格式类似“变量 x 在 func_a:23 接收 HTTP body，在 "
        "func_b:45 流入 SQL，触发 SQLi”。\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )


__all__ = [
    "DataflowExplainer",
    "DataflowExplanation",
    "RouterLike",
    "build_explanation_prompt",
]
