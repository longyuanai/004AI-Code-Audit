from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ai_code_audit.cli import main, scan_payload
from ai_code_audit.hybrid_cli import CLIInputError


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("summary", [], "summary must be an object"),
        ("summary", {"files_scanned": True}, "nonnegative integer"),
        ("summary", {"files_scanned": -1}, "nonnegative integer"),
        ("summary", {"files_scanned": "1"}, "nonnegative integer"),
        ("findings", None, "findings must be a list of objects"),
        ("findings", ["lost finding"], "findings must be a list of objects"),
        ("warnings", None, "warnings must be a list of strings"),
        ("warnings", [42], "warnings must be a list of strings"),
    ],
)
def test_malformed_backend_result_is_rejected_before_postprocessing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    field: str, value: object, message: str,
) -> None:
    result = {"summary": {"files_scanned": 1}, "findings": [], "warnings": []}
    result[field] = value
    monkeypatch.setattr("ai_code_audit.cli.scan_repository", lambda *_: result)

    def must_not_postprocess(*_: Any, **__: Any) -> None:
        pytest.fail("Malformed backend result reached postprocessing")

    monkeypatch.setattr("ai_code_audit.cli.postprocess_envelope", must_not_postprocess)
    with pytest.raises(CLIInputError, match=message):
        scan_payload({"repo_path": str(tmp_path)})


def test_invalid_postprocessed_result_does_not_export_a_success_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    report = tmp_path / "scan.json"
    report.write_text("previous report", encoding="utf-8")
    monkeypatch.setattr(
        "ai_code_audit.cli.postprocess_envelope",
        lambda *_args, **_kwargs: {"summary": {"files_scanned": 0}, "findings": None, "warnings": []},
    )
    code = main(["scan", "--repo-path", str(tmp_path), "--json", "--output-file", str(report)])
    assert code == 2
    assert "findings must be a list of objects" in capsys.readouterr().out
    assert report.read_text(encoding="utf-8") == "previous report"


def test_router_cleanup_failure_preserves_finding_and_completed_triage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_router_with: Any,
) -> None:
    (tmp_path / "app.py").write_text("value = input()\neval(value)\n", encoding="utf-8")
    router = stub_router_with(content=(
        '{"confirmed":true,"confidence":0.9,"explanation":"confirmed",'
        '"remediation":"remove eval"}'
    ))
    closes = []

    def fail_close() -> None:
        closes.append(True)
        raise RuntimeError("provider cleanup failed")

    router.close = fail_close
    monkeypatch.setattr("ai_code_audit.cli.LLMRouter.from_env", lambda: router)
    envelope = scan_payload({"repo_path": str(tmp_path), "mode": "hybrid"})
    assert closes == [True]
    assert len(envelope["findings"]) == 1
    assert envelope["summary"]["llm_triage"]["confirmed"] == 1
    assert "LLM triage close failed; static findings preserved" in envelope["warnings"][-1]
