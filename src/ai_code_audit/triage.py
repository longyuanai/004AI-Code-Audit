"""Cheap-tier LLM review for deterministic static-analysis Findings."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Protocol

from shared_llm_core import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    TaskTier,
)

from ai_code_audit.triage_context import (
    build_triage_context,
    build_triage_prompt,
    redact_sensitive_text,
)


class RouterLike(Protocol):
    def chat(self, tier: TaskTier, req: ChatRequest) -> ChatResponse: ...


@dataclass(frozen=True)
class TriageResult:
    status: str
    confirmed: bool | None
    confidence: float | None
    explanation: str
    remediation: str
    model: str | None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached: bool = False
    error: str | None = None

    def to_metadata(self) -> dict[str, object]:
        return {
            "status": self.status,
            "confirmed": self.confirmed,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cached": self.cached,
            "error": self.error,
        }


class TriageCache:
    """Small process-local cache keyed by Finding fingerprint and model version."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], TriageResult] = {}

    def get(self, fingerprint: str, model_version: str) -> TriageResult | None:
        result = self._entries.get((fingerprint, model_version))
        return replace(result, cached=True) if result is not None else None

    def put(
        self,
        fingerprint: str,
        model_version: str,
        result: TriageResult,
    ) -> None:
        if result.status == "reviewed":
            self._entries[(fingerprint, model_version)] = replace(
                result, cached=False
            )


class FindingTriageReviewer:
    """Review one static Finding while preserving failure-safe behavior."""

    def __init__(
        self,
        router: RouterLike,
        *,
        model_version: str = "cheap-default",
        cache: TriageCache | None = None,
        max_tokens: int = 500,
    ) -> None:
        self.router = router
        self.model_version = model_version
        self.cache = cache or TriageCache()
        self.max_tokens = max_tokens

    def review(
        self,
        finding: Mapping[str, Any],
        *,
        repo_path: str | Path,
    ) -> TriageResult:
        context = build_triage_context(finding, repo_path=repo_path)
        cache_key = context.fingerprint or context.finding_id
        cached = self.cache.get(cache_key, self.model_version)
        if cached is not None:
            return cached
        request = ChatRequest(
            messages=[
                ChatMessage(
                    role="system",
                    content=(
                        "你是 AI-CodeGuard 静态分析复核器。只判断提供的"
                        "证据，不假设其他代码；不得输出或还原已脱敏值。"
                    ),
                ),
                ChatMessage(
                    role="user",
                    content=build_triage_prompt(context),
                ),
            ],
            temperature=0,
            max_tokens=self.max_tokens,
            response_format={"type": "json_object"},
        )
        try:
            response = self.router.chat(TaskTier.CHEAP, request)
            result = _parse_response(response)
        except Exception as error:  # router/provider errors must not drop Finding
            return _error_result(error)
        self.cache.put(cache_key, self.model_version, result)
        return result


def _parse_response(response: ChatResponse) -> TriageResult:
    if not response.choices:
        raise ValueError("LLM triage response has no choices")
    try:
        payload = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError as error:
        raise ValueError("LLM triage response is not valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("LLM triage response must be a JSON object")
    confirmed = payload.get("confirmed")
    confidence = payload.get("confidence")
    explanation = payload.get("explanation")
    remediation = payload.get("remediation")
    if not isinstance(confirmed, bool):
        raise ValueError("LLM triage confirmed must be boolean")
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= float(confidence) <= 1
    ):
        raise ValueError("LLM triage confidence must be between 0 and 1")
    if not isinstance(explanation, str) or not explanation.strip():
        raise ValueError("LLM triage explanation must be non-empty")
    if not isinstance(remediation, str) or not remediation.strip():
        raise ValueError("LLM triage remediation must be non-empty")
    return TriageResult(
        status="reviewed",
        confirmed=confirmed,
        confidence=float(confidence),
        explanation=explanation.strip(),
        remediation=remediation.strip(),
        model=response.model,
        prompt_tokens=response.usage.prompt_tokens,
        completion_tokens=response.usage.completion_tokens,
    )


def _error_result(error: Exception) -> TriageResult:
    message = redact_sensitive_text(
        f"{type(error).__name__}: {error}"
    )[:240]
    return TriageResult(
        status="error",
        confirmed=None,
        confidence=None,
        explanation="",
        remediation="",
        model=None,
        error=message,
    )


__all__ = [
    "FindingTriageReviewer",
    "RouterLike",
    "TriageCache",
    "TriageResult",
]
