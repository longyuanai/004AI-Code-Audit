from __future__ import annotations

import json
from pathlib import Path

from ai_code_audit.triage_context import (
    build_triage_context,
    build_triage_prompt,
    redact_sensitive_text,
)


def test_context_contains_only_bounded_lines(tmp_path: Path) -> None:
    lines = [f"line_{number}" for number in range(1, 30)]
    (tmp_path / "app.py").write_text("\n".join(lines), encoding="utf-8")

    context = build_triage_context(_finding(line=15), repo_path=tmp_path)

    assert "11: line_11" in context.code_excerpt
    assert "19: line_19" in context.code_excerpt
    assert "1: line_1\n" not in context.code_excerpt
    assert "29: line_29" not in context.code_excerpt


def test_context_includes_taint_source_and_sink_windows(tmp_path: Path) -> None:
    lines = [f"line_{number}" for number in range(1, 40)]
    (tmp_path / "app.py").write_text("\n".join(lines), encoding="utf-8")
    finding = _finding(line=30)
    finding["metadata"]["code_flows"] = [
        {"kind": "source", "path": "app.py", "line": 5, "message": "input"},
        {"kind": "sink", "path": "app.py", "line": 30, "message": "eval"},
    ]

    context = build_triage_context(finding, repo_path=tmp_path)

    assert "5: line_5" in context.code_excerpt
    assert "30: line_30" in context.code_excerpt
    assert [step["kind"] for step in context.code_flows] == ["source", "sink"]


def test_sensitive_values_are_redacted_from_all_prompt_inputs(
    tmp_path: Path,
) -> None:
    secret = "sk-example-do-not-send"
    email = "person@example.com"
    (tmp_path / "app.py").write_text(
        f'api_key = "{secret}"\nowner = "{email}"\neval(api_key)\n',
        encoding="utf-8",
    )
    finding = _finding(line=3)
    finding["evidence"] = [f'api_key = "{secret}"', email]

    prompt = build_triage_prompt(
        build_triage_context(finding, repo_path=tmp_path)
    )

    assert secret not in prompt
    assert email not in prompt
    assert "[REDACTED]" in prompt
    assert "[REDACTED_EMAIL]" in prompt


def test_context_does_not_read_path_outside_repository(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.py"
    outside.write_text('password = "outside-secret"', encoding="utf-8")
    finding = _finding(line=1)
    finding["metadata"]["relative_path"] = str(outside)

    context = build_triage_context(finding, repo_path=tmp_path)

    assert context.code_excerpt == ""


def test_prompt_is_deterministic_and_requests_structured_verdict(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("eval(value)\n", encoding="utf-8")
    context = build_triage_context(_finding(line=1), repo_path=tmp_path)

    first = build_triage_prompt(context)
    second = build_triage_prompt(context)
    payload = json.loads(first.split("\n", 1)[1])

    assert first == second
    assert "confirmed(boolean)" in first
    assert payload["rule_id"] == "CG-OG-PY-001"
    assert payload["location"] == {"line": 1, "path": "app.py"}


def test_context_length_is_capped(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x" * 10_000, encoding="utf-8")

    context = build_triage_context(
        _finding(line=1), repo_path=tmp_path, max_chars=120
    )

    assert len(context.code_excerpt) == 120


def test_redaction_handles_tokens_ssn_and_payment_cards() -> None:
    redacted = redact_sensitive_text(
        "Bearer abc.def.ghi 123-45-6789 4111 1111 1111 1111"
    )

    assert "abc.def.ghi" not in redacted
    assert "123-45-6789" not in redacted
    assert "4111" not in redacted


def _finding(*, line: int) -> dict[str, object]:
    return {
        "id": "code-og-example",
        "source": "004",
        "severity": "high",
        "confidence": 0.9,
        "title": "Potential code execution",
        "host": "app.py",
        "evidence": ["eval(value)"],
        "metadata": {
            "fingerprint": "abc123",
            "rule_id": "CG-OG-PY-001",
            "cwe": "CWE-95",
            "relative_path": "app.py",
            "line": line,
            "data_classifications": [
                {"category": "credentials"},
            ],
        },
    }
