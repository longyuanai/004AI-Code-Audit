from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from ai_code_audit.cli import scan_payload, triage_envelope
from ai_codeguard.cli import CLIInputError


CONFIRMED = (
    '{"confirmed":true,"confidence":0.93,'
    '"explanation":"静态路径证据完整。",'
    '"remediation":"移除动态执行并使用允许列表。"}'
)
DISMISSED = (
    '{"confirmed":false,"confidence":0.81,'
    '"explanation":"输入已受严格约束。",'
    '"remediation":"保留验证并增加回归测试。"}'
)


def test_fast_mode_is_default_and_does_not_call_router(
    tmp_path: Path,
    stub_router,
) -> None:
    _write_repo(tmp_path)

    envelope = scan_payload({"repo_path": str(tmp_path)}, router=stub_router)

    assert envelope["summary"]["mode"] == "fast"
    assert "llm_triage" not in envelope["summary"]
    assert stub_router.calls == []


def test_hybrid_mode_reviews_finding_with_stub_router(
    tmp_path: Path,
    stub_router_with,
) -> None:
    _write_repo(tmp_path)

    envelope = scan_payload(
        {"repo_path": str(tmp_path), "mode": "hybrid"},
        router=stub_router_with(content=CONFIRMED),
    )

    triage = envelope["findings"][0]["metadata"]["llm_triage"]
    assert triage["status"] == "reviewed"
    assert triage["confirmed"] is True
    assert envelope["summary"]["llm_triage"]["confirmed"] == 1


def test_dismissed_verdict_preserves_static_finding_fields(
    tmp_path: Path,
    stub_router_with,
) -> None:
    _write_repo(tmp_path)
    fast = scan_payload({"repo_path": str(tmp_path)})
    expected = {
        key: deepcopy(fast["findings"][0][key])
        for key in (
            "id",
            "source",
            "severity",
            "confidence",
            "title",
            "host",
            "evidence",
        )
    }

    hybrid = scan_payload(
        {"repo_path": str(tmp_path), "mode": "hybrid"},
        router=stub_router_with(content=DISMISSED),
    )

    assert len(hybrid["findings"]) == 1
    assert {key: hybrid["findings"][0][key] for key in expected} == expected
    assert hybrid["summary"]["llm_triage"]["dismissed"] == 1


def test_router_failure_preserves_finding_and_records_error(
    tmp_path: Path,
    stub_router,
) -> None:
    _write_repo(tmp_path)
    stub_router.error = TimeoutError("offline")

    envelope = scan_payload(
        {"repo_path": str(tmp_path), "mode": "hybrid"},
        router=stub_router,
    )

    assert len(envelope["findings"]) == 1
    assert envelope["findings"][0]["metadata"]["llm_triage"][
        "status"
    ] == "error"
    assert envelope["summary"]["llm_triage"]["errors"] == 1


def test_router_initialization_failure_preserves_static_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_repo(tmp_path)

    def fail_from_env():
        raise RuntimeError("provider is not configured")

    monkeypatch.setattr(
        "ai_code_audit.cli.LLMRouter.from_env", fail_from_env
    )

    envelope = scan_payload(
        {"repo_path": str(tmp_path), "mode": "hybrid"}
    )

    assert len(envelope["findings"]) == 1
    assert envelope["summary"]["llm_triage"]["errors"] == 1
    assert envelope["summary"]["llm_triage"]["skipped"] == 1
    assert "static findings preserved" in envelope["warnings"][-1]


def test_hybrid_policy_skips_non_high_confidence_finding(
    tmp_path: Path,
    stub_router_with,
) -> None:
    finding = _finding(tmp_path, severity="medium", confidence=0.9)
    envelope = {"findings": [finding], "summary": {}, "warnings": []}

    triage_envelope(
        envelope,
        repo_path=tmp_path,
        router=stub_router_with(content=CONFIRMED),
    )

    assert "llm_triage" not in finding["metadata"]
    assert envelope["summary"]["llm_triage"]["skipped"] == 1


def test_hybrid_policy_reviews_low_confidence_medium_finding(
    tmp_path: Path,
    stub_router_with,
) -> None:
    finding = _finding(tmp_path, severity="medium", confidence=0.5)
    envelope = {"findings": [finding], "summary": {}, "warnings": []}

    triage_envelope(
        envelope,
        repo_path=tmp_path,
        router=stub_router_with(content=CONFIRMED),
    )

    assert finding["metadata"]["llm_triage"]["status"] == "reviewed"


def test_hybrid_limit_caps_cost_by_risk_order(
    tmp_path: Path,
    stub_router_with,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CODEGUARD_TRIAGE_MAX_FINDINGS", "1")
    first = _finding(tmp_path, finding_id="first")
    second = _finding(tmp_path, finding_id="second")
    envelope = {
        "findings": [first, second],
        "summary": {},
        "warnings": [],
    }
    router = stub_router_with(content=CONFIRMED)

    triage_envelope(envelope, repo_path=tmp_path, router=router)

    assert len(router.calls) == 1
    assert "llm_triage" in first["metadata"]
    assert "llm_triage" not in second["metadata"]
    assert envelope["summary"]["llm_triage"]["skipped"] == 1


def test_invalid_mode_is_rejected(tmp_path: Path) -> None:
    _write_repo(tmp_path)

    with pytest.raises(CLIInputError, match="fast or hybrid"):
        scan_payload({"repo_path": str(tmp_path), "mode": "deep"})


def _write_repo(root: Path) -> None:
    (root / "app.py").write_text(
        "value = input()\neval(value)\n", encoding="utf-8"
    )


def _finding(
    root: Path,
    *,
    finding_id: str = "finding",
    severity: str = "high",
    confidence: float = 0.9,
) -> dict[str, object]:
    _write_repo(root)
    return {
        "id": finding_id,
        "source": "004",
        "severity": severity,
        "confidence": confidence,
        "title": "Potential code execution",
        "host": str(root / "app.py"),
        "evidence": ["eval(value)"],
        "metadata": {
            "fingerprint": finding_id,
            "relative_path": "app.py",
            "line": 2,
            "rule_id": "CG-OG-PY-001",
        },
    }
