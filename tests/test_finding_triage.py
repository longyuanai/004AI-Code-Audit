from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from shared_llm_core import TaskTier

from ai_code_audit.triage import FindingTriageReviewer, TriageCache


VALID_RESPONSE = (
    '{"confirmed":true,"confidence":0.94,'
    '"explanation":"用户输入可达动态执行函数。",'
    '"remediation":"使用允许列表并移除 eval。"}'
)


def test_reviewer_uses_frozen_chat_signature_and_cheap_tier(
    tmp_path: Path,
    stub_router_with,
) -> None:
    router = stub_router_with(content=VALID_RESPONSE)

    result = FindingTriageReviewer(router).review(
        _finding(tmp_path), repo_path=tmp_path
    )

    assert result.status == "reviewed"
    assert result.confirmed is True
    assert result.model == "stub-model"
    tier, request = router.calls[0]
    assert tier is TaskTier.CHEAP
    assert request.temperature == 0
    assert request.max_tokens == 500
    assert request.response_format == {"type": "json_object"}
    assert request.request_id


def test_reviewer_returns_structured_usage_and_remediation(
    tmp_path: Path,
    stub_router_with,
) -> None:
    result = FindingTriageReviewer(
        stub_router_with(content=VALID_RESPONSE)
    ).review(_finding(tmp_path), repo_path=tmp_path)

    metadata = result.to_metadata()
    assert metadata["confidence"] == 0.94
    assert metadata["prompt_tokens"] == 10
    assert metadata["completion_tokens"] == 5
    assert metadata["remediation"].endswith("eval。")


def test_cache_uses_fingerprint_and_model_version(
    tmp_path: Path,
    stub_router_with,
) -> None:
    router = stub_router_with(content=VALID_RESPONSE)
    cache = TriageCache()
    reviewer = FindingTriageReviewer(
        router, cache=cache, model_version="stub-v1"
    )

    first = reviewer.review(_finding(tmp_path), repo_path=tmp_path)
    second = reviewer.review(_finding(tmp_path), repo_path=tmp_path)

    assert first.cached is False
    assert second.cached is True
    assert len(router.calls) == 1


def test_different_model_version_does_not_reuse_cache(
    tmp_path: Path,
    stub_router_with,
) -> None:
    router = stub_router_with(content=VALID_RESPONSE)
    cache = TriageCache()
    FindingTriageReviewer(router, cache=cache, model_version="v1").review(
        _finding(tmp_path), repo_path=tmp_path
    )
    FindingTriageReviewer(router, cache=cache, model_version="v2").review(
        _finding(tmp_path), repo_path=tmp_path
    )

    assert len(router.calls) == 2


def test_router_failure_returns_error_without_raising(
    tmp_path: Path,
    stub_router,
) -> None:
    stub_router.error = TimeoutError("provider timed out")

    result = FindingTriageReviewer(stub_router).review(
        _finding(tmp_path), repo_path=tmp_path
    )

    assert result.status == "error"
    assert result.confirmed is None
    assert "TimeoutError" in result.error


def test_router_error_message_is_redacted(
    tmp_path: Path,
    stub_router,
) -> None:
    stub_router.error = RuntimeError('api_key = "secret-value"')

    result = FindingTriageReviewer(stub_router).review(
        _finding(tmp_path), repo_path=tmp_path
    )

    assert "secret-value" not in result.error
    assert "[REDACTED]" in result.error


def test_invalid_json_returns_error_without_raising(
    tmp_path: Path,
    stub_router_with,
) -> None:
    result = FindingTriageReviewer(
        stub_router_with(content="not-json")
    ).review(_finding(tmp_path), repo_path=tmp_path)

    assert result.status == "error"
    assert "not valid JSON" in result.error


def test_invalid_schema_returns_error_without_raising(
    tmp_path: Path,
    stub_router_with,
) -> None:
    result = FindingTriageReviewer(
        stub_router_with(
            content=(
                '{"confirmed":"yes","confidence":2,'
                '"explanation":"x","remediation":"y"}'
            )
        )
    ).review(_finding(tmp_path), repo_path=tmp_path)

    assert result.status == "error"
    assert "confirmed must be boolean" in result.error


def test_review_does_not_mutate_static_finding(
    tmp_path: Path,
    stub_router_with,
) -> None:
    finding = _finding(tmp_path)
    original = deepcopy(finding)

    FindingTriageReviewer(stub_router_with(content=VALID_RESPONSE)).review(
        finding, repo_path=tmp_path
    )

    assert finding == original


def _finding(root: Path) -> dict[str, object]:
    (root / "app.py").write_text(
        "value = input()\neval(value)\n", encoding="utf-8"
    )
    return {
        "id": "code-og-abc",
        "source": "004",
        "severity": "high",
        "confidence": 0.85,
        "title": "Potential code execution",
        "host": str(root / "app.py"),
        "evidence": ["input()", "eval(value)"],
        "metadata": {
            "fingerprint": "abc123",
            "relative_path": "app.py",
            "line": 2,
            "rule_id": "CG-OG-PY-001",
        },
    }
