"""Report writes must not share temporary files across concurrent requests."""
from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from ai_code_audit import cli


def test_existing_predictable_temp_file_is_never_touched(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    planted = tmp_path / f".report.json.{os.getpid()}.tmp"
    planted.write_text("unrelated file", encoding="utf-8")
    cli._write_output(str(target), "new report\n")
    assert planted.read_text(encoding="utf-8") == "unrelated file"
    assert target.read_text(encoding="utf-8") == "new report\n"


def test_concurrent_writers_use_distinct_temps_and_publish_whole_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "report.json"
    barrier = threading.Barrier(2)
    original = os.replace
    temps: list[Path] = []
    local = threading.local()

    def synchronized_replace(source: Path, destination: Path) -> None:
        if not getattr(local, "ready", False):
            temps.append(Path(source))
            barrier.wait(timeout=10)
            local.ready = True
        original(source, destination)

    monkeypatch.setattr(os, "replace", synchronized_replace)
    bodies = ["first" * 10000, "second" * 10000]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(cli._write_output, str(target), body) for body in bodies]
        assert [f.result(timeout=15) for f in futures] == [target, target]
    assert len(set(temps)) == 2
    assert target.read_text(encoding="utf-8") in bodies
    assert not list(tmp_path.glob("*.tmp"))


def test_replace_failure_preserves_report_and_cleans_own_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "report.json"
    target.write_text("old", encoding="utf-8")

    def fail_replace(source: Path, destination: Path) -> None:
        raise PermissionError("destination locked")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(PermissionError, match="locked"):
        cli._write_output(str(target), "new")
    assert target.read_text(encoding="utf-8") == "old"
    assert not list(tmp_path.glob("*.tmp"))


def test_encoding_failure_does_not_publish_partial_report(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("old", encoding="utf-8")
    with pytest.raises(UnicodeEncodeError):
        cli._write_output(str(target), "bad surrogate: \ud800")
    assert target.read_text(encoding="utf-8") == "old"
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("failures", [2, 5])
def test_windows_sharing_retry_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failures: int
) -> None:
    target = tmp_path / "report.json"
    target.write_text("old", encoding="utf-8")
    original = os.replace
    calls = 0

    class SharingViolation(PermissionError):
        winerror = 32

    def sometimes_locked(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls <= failures:
            raise SharingViolation("file busy")
        original(source, destination)

    monkeypatch.setattr(os, "replace", sometimes_locked)
    if failures == 5:
        with pytest.raises(SharingViolation):
            cli._write_output(str(target), "new")
        assert target.read_text(encoding="utf-8") == "old"
        assert calls == 5
    else:
        cli._write_output(str(target), "new")
        assert target.read_text(encoding="utf-8") == "new"
        assert calls == 3
    assert not list(tmp_path.glob("*.tmp"))
