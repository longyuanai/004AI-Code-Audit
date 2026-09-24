"""C3 quality baseline: label integrity, scoring rules and measured ratchet.

The expected numbers below were measured on 2026-09-24 against the
hand-labeled corpus in benchmarks/c3; they are a regression ratchet for
synthetic samples, not an accuracy claim.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from ai_code_audit.backends import BackendExecutionError
from benchmarks.c3 import quality
from benchmarks.c3.opengrep_pin import OpengrepPinError, verify_opengrep
from benchmarks.c3.quality import Label, evaluate, load_labels, score_rule
from benchmarks.phase0.benchmark import Location

PROJECT = Path(__file__).resolve().parents[1]
OPENGREP = quality.DEFAULT_OPENGREP


def _rule(document: dict, backend: str, rule_id: str) -> dict:
    entry = next(b for b in document["result"]["backends"] if b["backend"] == backend)
    return next(r for r in entry["rules"] if r["rule_id"] == rule_id)


def test_every_label_has_a_rationale_and_fixes_point_at_vulnerable_cases() -> None:
    manifest, labels = load_labels()

    assert sum(label.kind == "vuln" for label in labels) == 7
    assert sum(label.kind == "safe" for label in labels) == 9
    vulnerable = {label.case for label in labels if label.kind == "vuln"}
    for case, spec in manifest["cases"].items():
        assert spec["rationale"].strip(), case
        if spec["category"] == "fixed":
            assert spec["fixes"] in vulnerable, case


def test_label_without_rationale_is_rejected(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.py").write_text("x = 1  # c3-expect safe PY-FP-99\n", encoding="utf-8")
    manifest = tmp_path / "labels.json"
    manifest.write_text(json.dumps({"cases": {}}), encoding="utf-8")

    with pytest.raises(ValueError, match="no rationale"):
        load_labels(corpus, manifest)


def test_scoring_separates_out_of_scope_unlabeled_and_na() -> None:
    labels = [
        Label("V1", "vuln", "CWE-95", "vulnerable", Location("a.py", 1)),
        Label("V2", "vuln", "CWE-78", "vulnerable", Location("a.py", 2)),
        Label("S1", "safe", None, "fp_prone", Location("a.py", 3)),
    ]
    reported = {Location("a.py", 2), Location("a.py", 3), Location("a.py", 9)}

    scored = score_rule("R", ["CWE-95"], labels, reported)

    assert (scored["tp"], scored["fp"], scored["fn"], scored["tn"]) == (0, 2, 1, 0)
    assert scored["out_of_scope"] == 1
    assert scored["precision"] == 0.0 and scored["recall"] == 0.0
    assert [item["category"] for item in scored["false_positives"]] == [
        "fp_prone",
        "unlabeled",
    ]
    silent = score_rule("R", ["CWE-89"], labels, set())
    assert silent["precision"] is None and silent["recall"] is None
    assert silent["claimed_cwes_without_cases"] == ["CWE-89"]


def test_builtin_ratchet_and_known_errors_are_stable() -> None:
    first = evaluate(backends_to_run=("builtin",))
    second = evaluate(backends_to_run=("builtin",))

    assert first["result"] == second["result"]
    rule = _rule(first, "builtin", "004-phase2-taint")
    assert (rule["tp"], rule["fp"], rule["fn"], rule["tn"]) == (6, 4, 1, 5)
    assert {item["case"] for item in rule["false_positives"]} == {
        "PY-FP-01",  # constant eval after an unrelated input()
        "PY-FP-03",  # eval( inside a comment
        "PY-FP-04",  # system( inside a string literal
        "PY-FP-06",  # constant exec after sys.argv is read
    }
    assert [item["case"] for item in rule["false_negatives"]] == ["PY-CI-05"]


def test_unavailable_opengrep_is_an_error_not_zero_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CODEGUARD_OPENGREP_PATH", raising=False)
    document = evaluate(tmp_path / "missing-opengrep.exe", ("opengrep",))

    entry = document["result"]["backends"][0]
    assert entry["status"] == "error"
    assert entry["reason"] == "opengrep_pin_missing"
    assert entry["rules"] == [
        {"rule_id": "CG-OG-PY-001", "status": "not_run", "precision": None, "recall": None}
    ]


@pytest.mark.skipif(
    not OPENGREP.is_file(),
    reason=f"pinned Opengrep 1.26.0 not installed at {OPENGREP} (see OPENGREP.lock)",
)
def test_opengrep_rule_covers_argv_and_exec_without_constant_false_positive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CODEGUARD_OPENGREP_PATH", raising=False)
    document = evaluate(OPENGREP, ("opengrep",))

    assert document["run"]["opengrep_pin"]["status"] == "verified"
    rule = _rule(document, "opengrep", "CG-OG-PY-001")
    assert (rule["tp"], rule["fp"], rule["fn"], rule["tn"]) == (5, 0, 0, 9)
    entry = document["result"]["backends"][0]
    assert [item["case"] for item in entry["unsupported_cases"]] == [
        "PY-CMD-01",
        "PY-CMD-02",
    ]


# -- CLI exit contract (quality.main) -----------------------------------


@pytest.fixture
def no_process(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Record (and refuse) any child process start in this interpreter."""
    started: list[object] = []

    def refuse(*args: object, **_kwargs: object) -> None:
        started.append(args[0] if args else None)
        raise AssertionError(f"unexpected process start: {args[:1]}")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.delenv("CODEGUARD_OPENGREP_PATH", raising=False)
    return started


def _report(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "q.json").read_text(encoding="utf-8"))


def _args(tmp_path: Path, *extra: str) -> list[str]:
    return [
        "--json-output", str(tmp_path / "q.json"),
        "--markdown-output", str(tmp_path / "q.md"),
        *extra,
    ]


def test_cli_success_exits_zero(tmp_path: Path) -> None:
    code = quality.main(_args(tmp_path, "--backend", "builtin", "--repeat", "2"))

    assert code == quality.EXIT_OK == 0
    run = _report(tmp_path)["run"]
    assert (run["exit_code"], run["execution_ok"], run["repeat_identical"]) == (0, True, True)
    assert run["opengrep_pin"] is None


@pytest.mark.skipif(not OPENGREP.is_file(), reason=f"pinned Opengrep not at {OPENGREP}")
def test_cli_both_backends_succeed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODEGUARD_OPENGREP_PATH", raising=False)
    code = quality.main(_args(tmp_path, "--repeat", "2"))

    assert code == 0
    assert _report(tmp_path)["run"]["opengrep_pin"]["status"] == "verified"


def test_cli_missing_opengrep_exits_four_without_starting_it(
    tmp_path: Path, no_process: list[object]
) -> None:
    code = quality.main(
        _args(tmp_path, "--backend", "opengrep", "--repeat", "3",
              "--opengrep", str(tmp_path / "absent" / "opengrep.exe"))
    )

    assert code == quality.EXIT_BACKEND_FAILED == 4
    assert no_process == []
    document = _report(tmp_path)
    assert document["run"]["failed_backends"] == ["opengrep:opengrep_pin_missing"]
    assert document["run"]["repeat_identical"] is True  # judged separately
    assert document["run"]["opengrep_pin"]["started"] is False
    rule = document["result"]["backends"][0]["rules"][0]
    assert rule["precision"] is None and rule["recall"] is None and "tp" not in rule
    assert "Opengrep was not started" in (tmp_path / "q.md").read_text(encoding="utf-8")


def test_cli_hash_mismatch_exits_four_without_starting_placeholder(
    tmp_path: Path, no_process: list[object]
) -> None:
    placeholder = tmp_path / "opengrep.exe"
    placeholder.write_bytes(b"placeholder, never executed\r\n")

    code = quality.main(_args(tmp_path, "--backend", "opengrep", "--opengrep", str(placeholder)))

    assert code == 4
    assert no_process == []
    pin = _report(tmp_path)["run"]["opengrep_pin"]
    assert (pin["status"], pin["reason"], pin["started"]) == ("failed", "hash_mismatch", False)


def test_cli_invalid_lock_exits_four(
    tmp_path: Path, no_process: list[object], monkeypatch: pytest.MonkeyPatch
) -> None:
    bad_lock = tmp_path / "OPENGREP.lock"
    bad_lock.write_text("version=1.26.0\nsha256=not-a-digest\n", encoding="utf-8")
    monkeypatch.setattr(quality, "OPENGREP_LOCK", bad_lock)

    code = quality.main(_args(tmp_path, "--backend", "opengrep", "--opengrep", str(OPENGREP)))

    assert code == 4
    assert no_process == []
    assert _report(tmp_path)["run"]["failed_backends"] == ["opengrep:opengrep_pin_lock_invalid"]


def test_cli_execution_error_exits_four_with_metrics_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(_payload: object) -> dict[str, object]:
        raise BackendExecutionError("simulated backend crash")

    monkeypatch.setattr(quality, "scan_payload", broken)

    code = quality.main(_args(tmp_path, "--backend", "builtin"))

    assert code == 4
    entry = _report(tmp_path)["result"]["backends"][0]
    assert (entry["status"], entry["reason"]) == ("error", "execution_error")
    assert entry["rules"][0]["precision"] is None


def test_cli_repeat_mismatch_exits_three_and_backend_failure_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = quality.evaluate
    calls = {"n": 0}

    def drifting(*args: object, **kwargs: object) -> dict:
        document = real(*args, **kwargs)  # type: ignore[arg-type]
        calls["n"] += 1
        document["result"]["corpus_version"] += f"-drift{calls['n']}"
        return document

    monkeypatch.setattr(quality, "evaluate", drifting)
    code = quality.main(_args(tmp_path, "--backend", "builtin", "--repeat", "2"))

    assert code == quality.EXIT_REPEAT_MISMATCH == 3
    run = _report(tmp_path)["run"]
    assert (run["execution_ok"], run["repeat_identical"]) == (True, False)

    monkeypatch.setattr(
        quality, "scan_payload",
        lambda _payload: (_ for _ in ()).throw(BackendExecutionError("crash")),
    )
    assert quality.main(_args(tmp_path, "--backend", "builtin", "--repeat", "2")) == 4


def test_pin_uses_raw_bytes_and_reports_unreadable(tmp_path: Path) -> None:
    lock = tmp_path / "OPENGREP.lock"
    crlf = b"binary\r\ncontent"
    lock.write_text(
        f"version=1.26.0\nsha256={hashlib.sha256(crlf).hexdigest()}\n", encoding="utf-8"
    )
    exact = tmp_path / "exact.bin"
    exact.write_bytes(crlf)
    folded = tmp_path / "folded.bin"
    folded.write_bytes(crlf.replace(b"\r\n", b"\n"))

    assert verify_opengrep(exact, lock).sha256 == hashlib.sha256(crlf).hexdigest()
    with pytest.raises(OpengrepPinError) as mismatch:
        verify_opengrep(folded, lock)
    assert mismatch.value.reason == "hash_mismatch"
    with pytest.raises(OpengrepPinError) as unreadable:
        verify_opengrep(tmp_path, lock)  # a directory cannot be read as a binary
    assert unreadable.value.reason == "unreadable"


# -- delivery demo ------------------------------------------------------


def _load_demo() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "c3_demo_under_test", PROJECT / "scripts" / "c3_demo.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_pin_failure_exits_four_without_any_process(
    tmp_path: Path, no_process: list[object]
) -> None:
    placeholder = tmp_path / "opengrep.exe"
    placeholder.write_bytes(b"placeholder, never executed")
    out = tmp_path / "demo"

    code = _load_demo().main(
        ["--output-dir", str(out), "--backend", "opengrep", "--opengrep", str(placeholder)]
    )

    assert code == 4
    assert no_process == []
    summary = json.loads((out / "demo-summary.json").read_text(encoding="utf-8"))
    assert summary["result"]["opengrep_pin"] == {"status": "failed", "reason": "hash_mismatch"}
    assert summary["run"]["opengrep_started"] is False
    assert not (out / "project").exists()


@pytest.mark.vuln_integration
def test_builtin_demo_passes_with_python_guard_and_needs_no_opengrep(
    tmp_path: Path,
) -> None:
    out = tmp_path / "演示 output"
    completed = subprocess.run(
        [sys.executable, str(PROJECT / "scripts" / "c3_demo.py"), "--output-dir", str(out),
         "--opengrep", str(tmp_path / "no-opengrep-here.exe")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=600,
        check=False,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads((out / "demo-summary.json").read_text(encoding="utf-8"))
    assert summary["result"]["passed"] is True
    assert (out / "network-guard.log").read_text(encoding="utf-8") == ""
    network = summary["result"]["network_verification"]
    assert network["python_layer"]["attempts_logged"] == 0
    assert network["native_subprocesses"]["status"] == "not_verified"
    assert network["whole_process_tree_zero_network"] == "not_verified"
    for name in ("before.json", "before.sarif", "before.md", "synthetic-enriched.md"):
        assert (out / "reports" / name).is_file()
