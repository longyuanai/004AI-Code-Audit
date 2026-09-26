"""C2: ``ai-code-audit enrich`` and scan ``--output-file`` in real subprocesses.

Every child runs with a sitecustomize network guard (sockets, DNS and httpx
blocked, loopback included) and proxy variables pointing at a dead loopback
port; each test asserts the guard log stayed empty. Unit-scope tests strip
the vulnerability module from the child's PYTHONPATH; ``vuln_integration``
tests use a real cache written by the module itself.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from _cve_intel_support import (
    FRESH,
    NOT_LISTED,
    STALE,
    ChildGuard,
    finding,
    mixed_envelope,
    populate_cache,
    set_schema_version,
    write_json,
)

from ai_code_audit.output.sarif import validate_sarif

STAGE = "code_audit_enrichment"
integration = pytest.mark.vuln_integration


@pytest.fixture
def guard(tmp_path: Path) -> ChildGuard:
    return ChildGuard(tmp_path / "guard-unit", with_vuln_module=False)


@pytest.fixture
def vuln_guard(tmp_path: Path) -> ChildGuard:
    return ChildGuard(tmp_path / "guard-int", with_vuln_module=True)


@pytest.fixture
def cache(tmp_path: Path) -> Path:
    folder = tmp_path / "情报 缓存"
    populate_cache(folder, written_at=datetime.now(timezone.utc))
    return folder


def _without_stage(document: dict[str, Any]) -> dict[str, Any]:
    stripped = copy.deepcopy(document)
    stripped.pop(STAGE, None)
    for item in stripped["findings"]:
        item.get("metadata", {}).pop(STAGE, None)
    return stripped


def _statuses(document: dict[str, Any]) -> list[str]:
    return [item["metadata"][STAGE]["status"] for item in document["findings"]]


def _sample_repo(root: Path) -> Path:
    repo = root / "授权 样本"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text(
        "value = input('value')\neval(value)\n", encoding="utf-8"
    )
    return repo


# --- default scan behaviour and --output-file --------------------------------


def test_scan_json_stdout_is_unchanged_and_has_no_enrichment(
    guard: ChildGuard, tmp_path: Path
) -> None:
    repo = _sample_repo(tmp_path)

    result = guard.run("scan", "--json", "--repo-path", str(repo))

    assert result.returncode == 0, result.stderr
    envelope = json.loads(result.stdout)
    assert set(envelope) == {"findings", "summary", "warnings"}
    assert [item["source"] for item in envelope["findings"]] == ["004"]
    assert STAGE not in json.dumps(envelope)
    assert guard.attempts() == []


def test_scan_output_file_writes_envelope_and_prints_path(
    guard: ChildGuard, tmp_path: Path
) -> None:
    repo = _sample_repo(tmp_path)
    target = tmp_path / "输出 目录" / "scan.json"
    target.parent.mkdir()
    target.write_text("old content", encoding="utf-8")

    stdout_run = guard.run("scan", "--json", "--repo-path", str(repo))
    file_run = guard.run(
        "scan",
        "--json",
        "--repo-path",
        str(repo),
        "--fail-on",
        "any",
        "--output-file",
        str(target),
    )

    assert file_run.returncode == 1, file_run.stderr  # gate still applies
    assert file_run.stdout.strip() == str(target.resolve())
    written = json.loads(target.read_text(encoding="utf-8"))
    expected = json.loads(stdout_run.stdout)
    assert written["findings"] == expected["findings"]
    assert written["summary"]["gate"] == {
        "threshold": "any",
        "triggered": True,
        "findings": 1,
    }
    assert not list(target.parent.glob(".*.tmp"))
    assert guard.attempts() == []


def test_scan_output_file_without_json_flag_also_writes_file(
    guard: ChildGuard, tmp_path: Path
) -> None:
    repo = _sample_repo(tmp_path)
    target = tmp_path / "plain.json"

    result = guard.run("scan", "--repo-path", str(repo), "--output-file", str(target))

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(target.resolve())
    assert len(json.loads(target.read_text(encoding="utf-8"))["findings"]) == 1


def test_scan_output_file_that_is_a_directory_is_an_error(
    guard: ChildGuard, tmp_path: Path
) -> None:
    repo = _sample_repo(tmp_path)

    result = guard.run(
        "scan", "--json", "--repo-path", str(repo), "--output-file", str(tmp_path)
    )

    assert result.returncode == 2
    assert "cannot write --output-file" in result.stdout


def test_enrich_only_flags_are_rejected_for_scan(
    guard: ChildGuard, tmp_path: Path
) -> None:
    repo = _sample_repo(tmp_path)

    result = guard.run("scan", "--repo-path", str(repo), "--require-intel")

    assert result.returncode == 2
    assert "--require-intel is only valid with enrich" in result.stderr


# --- enrich: paths that never need the vulnerability module -------------------


def test_no_cve_skips_stage_without_opening_cache(
    guard: ChildGuard, tmp_path: Path
) -> None:
    envelope = {
        "findings": [finding(0, None), finding(1, None)],
        "summary": {"files_scanned": 1},
        "x_custom": [1],
    }
    source = write_json(tmp_path / "in.json", envelope)
    absent_cache = tmp_path / "must-not-exist"

    result = guard.run(
        "enrich", "--envelope", str(source), "--cache", str(absent_cache),
        "--require-intel",
    )

    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document[STAGE]["status"] == "skipped"
    assert document[STAGE]["reason"] == "no_queryable_cve"
    assert document[STAGE]["cache"] is None
    assert _statuses(document) == ["not_applicable", "not_applicable"]
    assert _without_stage(document) == envelope
    assert not absent_cache.exists()
    assert "CVE enrichment skipped" in result.stderr
    assert guard.attempts() == []


def test_invalid_cves_only_is_partial_and_strict_exits_3(
    guard: ChildGuard, tmp_path: Path
) -> None:
    source = write_json(
        tmp_path / "in.json",
        {"findings": [finding(0, "CVE-24-1"), finding(1, 7)], "summary": {}},
    )

    lenient = guard.run("enrich", "--envelope", str(source))
    strict = guard.run("enrich", "--envelope", str(source), "--require-intel")

    assert lenient.returncode == 0
    assert strict.returncode == 3
    document = json.loads(lenient.stdout)
    assert document[STAGE]["status"] == "partial"
    assert document[STAGE]["cves"] == 0
    assert _statuses(document) == ["invalid_input", "invalid_input"]
    assert [item["cve"] for item in document["findings"]] == ["CVE-24-1", 7]


def test_module_unavailable_fails_stage_but_keeps_findings(
    guard: ChildGuard, tmp_path: Path
) -> None:
    envelope = mixed_envelope()
    source = write_json(tmp_path / "in.json", envelope)

    lenient = guard.run("enrich", "--envelope", str(source))
    strict = guard.run("enrich", "--envelope", str(source), "--require-intel")

    assert lenient.returncode == 0, lenient.stderr
    assert strict.returncode == 3
    document = json.loads(lenient.stdout)
    stage = document.pop(STAGE)
    assert stage["status"] == "failed"
    assert stage["reason"] == "module_unavailable"
    assert stage["findings"] == 7
    assert document == envelope  # original scan result, byte-for-byte data
    assert "CVE enrichment failed (module_unavailable)" in lenient.stderr
    assert guard.attempts() == []


def test_gate_takes_precedence_over_strict_intel(
    guard: ChildGuard, tmp_path: Path
) -> None:
    envelope = mixed_envelope()
    envelope["findings"][0]["severity"] = "high"
    source = write_json(tmp_path / "in.json", envelope)

    gated = guard.run(
        "enrich", "--envelope", str(source), "--fail-on", "high", "--require-intel"
    )
    ungated = guard.run(
        "enrich", "--envelope", str(source), "--fail-on", "critical",
        "--require-intel",
    )

    assert gated.returncode == 1
    assert json.loads(gated.stdout)["summary"]["gate"] == {
        "threshold": "high",
        "triggered": True,
        "findings": 1,
    }
    assert ungated.returncode == 3


def test_recorded_scan_gate_is_preserved(guard: ChildGuard, tmp_path: Path) -> None:
    envelope = {
        "findings": [finding(0, None, severity="high")],
        "summary": {"gate": {"threshold": "any", "triggered": True, "findings": 1}},
    }
    source = write_json(tmp_path / "in.json", envelope)

    kept = guard.run("enrich", "--envelope", str(source))
    overridden = guard.run("enrich", "--envelope", str(source), "--fail-on", "none")

    assert kept.returncode == 1
    assert json.loads(kept.stdout)["summary"]["gate"]["triggered"] is True
    assert overridden.returncode == 0


def test_stdin_envelope(guard: ChildGuard) -> None:
    envelope = {"findings": [finding(0, None)], "summary": {}}

    result = guard.run("enrich", "--envelope", "-", stdin=json.dumps(envelope))

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)[STAGE]["status"] == "skipped"


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"findings": [finding(0, None, source="002")]}, "has source '002'"),
        ({"findings": [{"id": "x", "source": "004"}]}, "invalid finding"),
        ({"findings": "nope"}, "'findings' array"),
        ([finding(0, None)], "must be a JSON object"),
        ({"findings": [], STAGE: {}}, "refusing to overwrite"),
    ],
)
def test_invalid_envelopes_exit_2_with_no_output(
    guard: ChildGuard, tmp_path: Path, document: object, message: str
) -> None:
    source = write_json(tmp_path / "in.json", document)
    target = tmp_path / "out.json"

    result = guard.run(
        "enrich", "--envelope", str(source), "--output-file", str(target)
    )

    assert result.returncode == 2
    assert message in result.stderr
    assert result.stdout == ""
    assert not target.exists()


def test_argument_and_file_errors_exit_2(guard: ChildGuard, tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    source = write_json(tmp_path / "in.json", {"findings": []})
    before = source.read_bytes()

    cases = [
        (("enrich",), "requires --envelope"),
        (("enrich", "--envelope", str(tmp_path / "absent.json")), "not found"),
        (("enrich", "--envelope", str(broken)), "not UTF-8 JSON"),
        (("enrich", "--envelope", str(source), "--repo-path", "."), "not valid"),
        (
            ("enrich", "--envelope", str(source), "--output-file", str(source)),
            "must differ from --envelope",
        ),
        (("enrich", "--envelope", str(source), "--output", "sarif"), "required"),
    ]
    for args, message in cases:
        result = guard.run(*args)
        assert result.returncode == 2, (args, result.stderr)
        assert message in result.stderr, (args, result.stderr)
        assert result.stdout == ""
    assert source.read_bytes() == before


def test_child_network_guard_is_effective(guard: ChildGuard) -> None:
    import subprocess
    import sys

    script = (
        "import socket, httpx\n"
        "for call in (lambda: socket.create_connection(('127.0.0.1', 9)),\n"
        "             lambda: httpx.get('https://services.nvd.nist.gov/')):\n"
        "    try:\n"
        "        call()\n"
        "    except OSError:\n"
        "        pass\n"
    )
    probe = subprocess.run(
        [sys.executable, "-c", script],
        env=guard.env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert probe.returncode == 0, probe.stderr
    assert guard.attempts() == ["create_connection", "httpx.Client.send"]


# --- enrich against a real cache (integration scope) --------------------------


@integration
def test_mixed_cache_states_report_partial(
    vuln_guard: ChildGuard, cache: Path, tmp_path: Path
) -> None:
    envelope = mixed_envelope()
    source = write_json(tmp_path / "输入" / "scan.json", envelope)
    target = tmp_path / "输出" / "enriched.json"

    result = vuln_guard.run(
        "enrich", "--envelope", str(source), "--cache", str(cache),
        "--output-file", str(target),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(target.resolve())
    document = json.loads(target.read_text(encoding="utf-8"))
    stage = document[STAGE]
    assert stage["status"] == "partial"
    assert stage["reason"] == "intel_incomplete"
    assert stage["network_refresh"] is False
    assert set(stage["sources"]) == {"nvd", "kev", "epss"}
    assert stage["cache"].endswith("enrichment-v1.sqlite3")
    assert stage["cves"] == 4
    assert _statuses(document) == [
        "enriched", "stale", "enriched", "unknown",
        "not_applicable", "invalid_input", "enriched",
    ]
    missing = document["findings"][3]["metadata"][STAGE]
    assert set(missing["values"].values()) == {None}
    assert missing["providers"]["kev"] == {
        "status": "missing", "fetched_at": None, "expires_at": None,
    }
    fresh = document["findings"][0]["metadata"][STAGE]
    assert fresh["values"]["kev"] is True
    assert fresh["providers"]["nvd"]["fetched_at"] is not None
    assert _without_stage(document) == envelope
    assert vuln_guard.attempts() == []


@integration
def test_all_fresh_is_complete_and_strict_passes(
    vuln_guard: ChildGuard, cache: Path, tmp_path: Path
) -> None:
    envelope = {
        "findings": [
            finding(0, FRESH), finding(1, None), finding(2, NOT_LISTED),
            finding(3, FRESH.lower()),
        ],
        "summary": {},
    }
    source = write_json(tmp_path / "in.json", envelope)

    result = vuln_guard.run(
        "enrich", "--envelope", str(source), "--cache", str(cache),
        "--require-intel",
    )

    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document[STAGE]["status"] == "complete"
    assert document[STAGE]["cves"] == 2
    assert [item["id"] for item in document["findings"]] == [
        "code-0", "code-1", "code-2", "code-3",
    ]
    assert document["findings"][2]["metadata"][STAGE]["values"]["kev"] is False
    assert vuln_guard.attempts() == []


@integration
def test_stale_only_is_partial_under_strict(
    vuln_guard: ChildGuard, cache: Path, tmp_path: Path
) -> None:
    source = write_json(tmp_path / "in.json", {"findings": [finding(0, STALE)]})

    result = vuln_guard.run(
        "enrich", "--envelope", str(source), "--cache", str(cache),
        "--require-intel",
    )

    assert result.returncode == 3
    document = json.loads(result.stdout)
    assert _statuses(document) == ["stale"]
    assert document["findings"][0]["metadata"][STAGE]["values"]["cvss_v3"] is None


@integration
@pytest.mark.parametrize(
    ("damage", "reason"),
    [
        ("garbage", "cache_unreadable"),
        ("schema", "cache_schema_mismatch"),
        ("absent", "cache_not_found"),
    ],
)
def test_unusable_cache_fails_stage_and_keeps_findings(
    vuln_guard: ChildGuard, cache: Path, tmp_path: Path, damage: str, reason: str
) -> None:
    database = cache / "enrichment-v1.sqlite3"
    target: Path = cache
    if damage == "garbage":
        database.write_bytes(b"not a database" * 64)
    elif damage == "schema":
        set_schema_version(database, 2)
    else:
        target = tmp_path / "nowhere"
    envelope = mixed_envelope()
    source = write_json(tmp_path / "in.json", envelope)
    before = database.read_bytes() if database.exists() else b""

    lenient = vuln_guard.run(
        "enrich", "--envelope", str(source), "--cache", str(target)
    )
    strict = vuln_guard.run(
        "enrich", "--envelope", str(source), "--cache", str(target),
        "--require-intel",
    )

    assert lenient.returncode == 0, lenient.stderr
    assert strict.returncode == 3
    document = json.loads(lenient.stdout)
    stage = document.pop(STAGE)
    assert stage["status"] == "failed"
    assert stage["reason"] == reason
    assert stage["error"]
    assert document == envelope
    assert (database.read_bytes() if database.exists() else b"") == before
    assert not (tmp_path / "nowhere").exists()
    assert vuln_guard.attempts() == []


@integration
def test_default_cache_location_is_used_when_not_given(
    vuln_guard: ChildGuard, tmp_path: Path
) -> None:
    profile = tmp_path / "profile"
    vuln_guard.env["LOCALAPPDATA"] = str(profile)
    vuln_guard.env["HOME"] = str(profile)
    source = write_json(tmp_path / "in.json", {"findings": [finding(0, FRESH)]})

    result = vuln_guard.run("enrich", "--envelope", str(source))

    assert result.returncode == 0, result.stderr
    stage = json.loads(result.stdout)[STAGE]
    assert stage["reason"] == "cache_not_found"
    assert str(profile) in stage["cache"]
    assert not profile.exists()


@integration
def test_enrich_sarif_carries_intel_with_null_unknowns(
    vuln_guard: ChildGuard, cache: Path, tmp_path: Path
) -> None:
    source = write_json(tmp_path / "in.json", mixed_envelope())
    target = tmp_path / "报告.sarif"

    result = vuln_guard.run(
        "enrich", "--envelope", str(source), "--cache", str(cache),
        "--output", "sarif", "--output-file", str(target),
    )

    assert result.returncode == 0, result.stderr
    sarif = json.loads(target.read_text(encoding="utf-8"))
    validate_sarif(sarif)
    results = sarif["runs"][0]["results"]
    assert len(results) == 7
    intel = [r["properties"]["longyuanai:cve-intel"] for r in results]
    assert intel[0]["values"]["kev"] is True
    assert intel[3]["status"] == "unknown"
    assert intel[3]["values"]["kev"] is None
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 2


# --- report formats: SARIF run-level stage, Markdown, exit priority ----------


def _run_stage(sarif: dict[str, Any]) -> dict[str, Any]:
    return sarif["runs"][0]["properties"]["longyuanai:cve-intel-stage"]


def test_plain_scan_sarif_is_unchanged(guard: ChildGuard, tmp_path: Path) -> None:
    repo = _sample_repo(tmp_path)
    target = tmp_path / "scan.sarif"

    result = guard.run(
        "scan", "--repo-path", str(repo), "--output", "sarif",
        "--output-file", str(target),
    )

    assert result.returncode == 0, result.stderr
    sarif = json.loads(target.read_text(encoding="utf-8"))
    validate_sarif(sarif)
    assert "properties" not in sarif["runs"][0]
    assert "cve-intel" not in target.read_text(encoding="utf-8")


def test_markdown_is_rejected_for_scan(guard: ChildGuard, tmp_path: Path) -> None:
    repo = _sample_repo(tmp_path)

    result = guard.run("scan", "--repo-path", str(repo), "--output", "markdown")

    assert result.returncode == 2
    assert "--output markdown is only valid with enrich" in result.stderr


@pytest.mark.parametrize(
    ("findings", "status"),
    [([finding(0, None)], "skipped"), ([], "skipped"), ([finding(0, "bad")], "partial")],
    ids=["no-cve", "empty-findings", "invalid-cve"],
)
def test_sarif_run_stage_without_cache(
    guard: ChildGuard, tmp_path: Path, findings: list[Any], status: str
) -> None:
    source = write_json(tmp_path / "in.json", {"findings": findings, "summary": {}})
    target = tmp_path / "out.sarif"

    result = guard.run(
        "enrich", "--envelope", str(source), "--output", "sarif",
        "--output-file", str(target),
    )

    assert result.returncode == 0, result.stderr
    sarif = json.loads(target.read_text(encoding="utf-8"))
    validate_sarif(sarif)
    stage = _run_stage(sarif)
    assert stage["status"] == status
    assert stage["findings"] == len(findings)
    assert len(sarif["runs"][0]["results"]) == len(findings)
    assert guard.attempts() == []


def test_sarif_run_stage_when_module_unavailable(
    guard: ChildGuard, tmp_path: Path
) -> None:
    source = write_json(tmp_path / "in.json", mixed_envelope())
    target = tmp_path / "out.sarif"

    result = guard.run(
        "enrich", "--envelope", str(source), "--output", "sarif",
        "--output-file", str(target), "--require-intel",
    )

    assert result.returncode == 3  # strict, but the full report is written
    sarif = json.loads(target.read_text(encoding="utf-8"))
    validate_sarif(sarif)
    assert _run_stage(sarif)["status"] == "failed"
    assert _run_stage(sarif)["reason"] == "module_unavailable"
    assert len(sarif["runs"][0]["results"]) == 7
    assert all(
        "longyuanai:cve-intel" not in r["properties"]
        for r in sarif["runs"][0]["results"]
    )


def test_markdown_file_output_with_unicode_path(
    guard: ChildGuard, tmp_path: Path
) -> None:
    source = write_json(
        tmp_path / "输入" / "scan.json",
        {"findings": [finding(0, "CVE-24-1"), finding(1, None)], "summary": {}},
    )
    target = tmp_path / "报告 目录" / "增强.md"

    result = guard.run(
        "enrich", "--envelope", str(source), "--output", "markdown",
        "--output-file", str(target), "--require-intel",
    )

    assert result.returncode == 3, result.stderr
    assert result.stdout.strip() == str(target.resolve())
    report = target.read_text(encoding="utf-8")
    assert report.startswith("# Code Audit 离线 CVE 情报报告")
    assert "| 阶段状态 | `partial` |" in report
    assert "**CVE 情报**：`invalid_input`" in report
    assert "sink line 0: eval(value)" in report
    assert guard.attempts() == []


def test_markdown_to_stdout(guard: ChildGuard) -> None:
    envelope = {"findings": [finding(0, None)], "summary": {}}

    result = guard.run(
        "enrich", "--envelope", "-", "--output", "markdown", stdin=json.dumps(envelope)
    )

    assert result.returncode == 0, result.stderr
    assert "| 阶段状态 | `skipped` |" in result.stdout


@pytest.mark.parametrize("output", ["envelope", "sarif", "markdown"])
@pytest.mark.parametrize(
    ("fail_on", "strict", "expected"),
    [("high", True, 1), ("critical", True, 3), ("critical", False, 0), ("high", False, 1)],
)
def test_exit_code_priority_is_format_independent(
    guard: ChildGuard,
    tmp_path: Path,
    output: str,
    fail_on: str,
    strict: bool,
    expected: int,
) -> None:
    envelope = mixed_envelope()  # module stripped -> stage failed
    envelope["findings"][0]["severity"] = "high"
    source = write_json(tmp_path / "in.json", envelope)
    target = tmp_path / f"out.{output}"
    args = [
        "enrich", "--envelope", str(source), "--output", output,
        "--output-file", str(target), "--fail-on", fail_on,
    ]
    if strict:
        args.append("--require-intel")

    result = guard.run(*args)

    assert result.returncode == expected, result.stderr
    assert target.stat().st_size > 0  # report written whatever the exit code
    assert guard.attempts() == []


@integration
def test_sarif_run_stage_cache_not_found_differs_from_plain_export(
    vuln_guard: ChildGuard, tmp_path: Path
) -> None:
    from ai_code_audit.output.sarif import export_sarif

    envelope = mixed_envelope()
    source = write_json(tmp_path / "in.json", envelope)
    target = tmp_path / "out.sarif"
    absent = tmp_path / "no-cache"

    result = vuln_guard.run(
        "enrich", "--envelope", str(source), "--cache", str(absent),
        "--output", "sarif", "--output-file", str(target), "--require-intel",
    )

    assert result.returncode == 3
    sarif = json.loads(target.read_text(encoding="utf-8"))
    validate_sarif(sarif)
    stage = _run_stage(sarif)
    assert (stage["status"], stage["reason"]) == ("failed", "cache_not_found")
    assert stage["cache"] == str(absent)
    plain = json.loads(json.dumps(export_sarif(envelope["findings"])))
    assert sarif["runs"][0]["results"] == plain["runs"][0]["results"]
    assert sarif != plain
    assert not absent.exists()
    assert vuln_guard.attempts() == []


@integration
@pytest.mark.parametrize(
    ("cves", "status"),
    [((FRESH, NOT_LISTED), "complete"), ((FRESH, STALE), "partial")],
)
def test_sarif_run_stage_with_real_cache(
    vuln_guard: ChildGuard,
    cache: Path,
    tmp_path: Path,
    cves: tuple[str, str],
    status: str,
) -> None:
    envelope = {"findings": [finding(i, cve) for i, cve in enumerate(cves)]}
    source = write_json(tmp_path / "in.json", envelope)
    target = tmp_path / "out.sarif"

    result = vuln_guard.run(
        "enrich", "--envelope", str(source), "--cache", str(cache),
        "--output", "sarif", "--output-file", str(target),
    )

    assert result.returncode == 0, result.stderr
    sarif = json.loads(target.read_text(encoding="utf-8"))
    validate_sarif(sarif)
    assert _run_stage(sarif)["status"] == status
    assert _run_stage(sarif)["network_refresh"] is False
    assert vuln_guard.attempts() == []


@integration
def test_markdown_with_real_cache_shows_times_and_gaps(
    vuln_guard: ChildGuard, cache: Path, tmp_path: Path
) -> None:
    source = write_json(tmp_path / "in.json", mixed_envelope())
    target = tmp_path / "报告.md"

    result = vuln_guard.run(
        "enrich", "--envelope", str(source), "--cache", str(cache),
        "--output", "markdown", "--output-file", str(target),
    )

    assert result.returncode == 0, result.stderr
    report = target.read_text(encoding="utf-8")
    assert "| 阶段状态 | `partial` |" in report
    assert "已过期，值未采用（stale）" in report
    assert "缓存无记录（missing）" in report
    assert "| CISA KEV | 是 |" in report
    assert "| CISA KEV | 否 |" in report
    assert "| CISA KEV | 未知（null） |" in report
    assert "enrichment-v1.sqlite3" in report
    assert report.count("\n### ") == 7
    assert vuln_guard.attempts() == []
