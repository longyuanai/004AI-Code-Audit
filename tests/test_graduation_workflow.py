"""Real worker/SQLite/HTTP workflow and recoverability regression tests."""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from ai_code_audit.web.server import AuditServer
from ai_code_audit.web.service import BusyError, Service
from ai_code_audit.web.worker import analyze


def source_payload(source="eval(input())\n", name="可控测试"):
    return {
        "name": name,
        "files": [
            {
                "path": "app.py",
                "content_base64": base64.b64encode(source.encode()).decode(),
            }
        ],
    }


def wait_task(service, task_id, *, ai=False):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        task = service.store.task(task_id)
        state = task["ai_status"] if ai else task["status"]
        if state not in {"queued", "running"}:
            return task
        time.sleep(0.02)
    raise AssertionError("Task did not finish")


@pytest.fixture
def service(tmp_path):
    instance = Service(tmp_path / "storage", scan_timeout=10, ai_timeout=10)
    yield instance
    instance.close()


def test_complete_pipeline_with_real_process_and_db(service, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDERS", "")
    project = service.import_project(source_payload())
    task = wait_task(service, service.create_task(project["id"])["id"])
    assert task["status"] == "completed", task
    assert task["envelope"]["summary"]["files_scanned"] == 1
    assert len(task["envelope"]["findings"]) == 1
    evidence = task["envelope"]["findings"][0]["evidence"]
    for format_name in ("html", "json", "sarif"):
        body, _ = service.report(task["id"], format_name)
        assert body
    service.request_ai(task["id"])
    degraded = wait_task(service, task["id"], ai=True)
    assert degraded["ai_status"] == "unavailable"
    assert degraded["envelope"]["findings"][0]["evidence"] == evidence


def test_no_uploaded_code_executes(service, tmp_path):
    marker = tmp_path / "executed-marker"
    source = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\neval(input())\n"
    project = service.import_project(source_payload(source))
    task = wait_task(service, service.create_task(project["id"])["id"])
    assert task["status"] == "completed"
    assert not marker.exists()


def test_failed_database_insert_rolls_back_new_snapshot(service, monkeypatch):
    def fail_insert(*args):
        raise sqlite3.OperationalError("simulated database write failure")

    monkeypatch.setattr(service.store, "add_project", fail_insert)
    with pytest.raises(sqlite3.OperationalError):
        service.import_project(source_payload())
    assert service.store.projects() == []
    assert list((service.root / "projects").iterdir()) == []
    assert list(service.root.glob("import-*")) == []


def test_real_worker_timeout_is_failed_and_not_zero_findings(tmp_path):
    instance = Service(tmp_path / "timeout", scan_timeout=0.001)
    try:
        project = instance.import_project(source_payload())
        task = wait_task(instance, instance.create_task(project["id"])["id"])
        assert task["status"] == "failed"
        assert "超时" in task["error"]
        with pytest.raises(BusyError):
            instance.report(task["id"], "html")
    finally:
        instance.close()


def test_syntax_errors_and_tampered_snapshots_fail(service):
    project = service.import_project(source_payload("def invalid(\n"))
    task = wait_task(service, service.create_task(project["id"])["id"])
    assert task["status"] == "failed"
    project = service.import_project(source_payload())
    (service.root / "projects" / project["id"] / "app.py").write_text(
        "pass", encoding="utf-8"
    )
    assert (
        wait_task(service, service.create_task(project["id"])["id"])["status"]
        == "failed"
    )


def test_report_escapes_untrusted_name_and_evidence(service):
    project = service.import_project(
        source_payload(
            'eval("<script>alert(1)</script>")\n', name='<img src=x onerror="alert(1)">'
        )
    )
    task = wait_task(service, service.create_task(project["id"])["id"])
    body, _ = service.report(task["id"], "html")
    report = body.decode()
    assert "<script>" not in report and "<img src=x" not in report
    assert "&lt;script&gt;" in report and "&lt;img" in report


def test_restart_recovers_only_incomplete_jobs_and_keeps_history(tmp_path):
    first = Service(tmp_path / "restart")
    project = first.import_project(source_payload())
    task = wait_task(first, first.create_task(project["id"])["id"])
    first.store.add_task("pending", project["id"])
    first.store.update(task["id"], ai_status="running")
    first.close()
    second = Service(tmp_path / "restart")
    try:
        assert second.store.task(task["id"])["status"] == "completed"
        assert second.store.task(task["id"])["ai_status"] == "unavailable"
        assert second.store.task("pending")["status"] == "interrupted"
        assert len(second.store.task(task["id"])["envelope"]["findings"]) == 1
    finally:
        second.close()


def test_single_instance_and_queue_limits(service):
    with pytest.raises(BusyError):
        Service(service.root)
    project = service.import_project(source_payload())
    service.pending = 4
    with pytest.raises(BusyError):
        service.create_task(project["id"])
    assert service.store.tasks() == []
    service.pending = 0


def test_ai_valid_response_is_separate_from_evidence(
    service, monkeypatch, stub_router_with
):
    router = stub_router_with(
        content=json.dumps(
            {
                "confirmed": True,
                "confidence": 0.9,
                "explanation": "静态证据表明 eval 解释用户输入",
                "remediation": "使用 ast.literal_eval",
            }
        )
    )
    from shared_llm_core.config import CoreConfig, ProviderConfig

    monkeypatch.setattr(
        "shared_llm_core.config.load_config",
        lambda: CoreConfig(
            providers={
                "test": ProviderConfig(
                    "test", "http://127.0.0.1", "unused", "stub-model"
                )
            }
        ),
    )
    monkeypatch.setattr("shared_llm_core.LLMRouter", lambda *args, **kwargs: router)
    router.close = lambda: None
    project = service.import_project(source_payload())
    task = wait_task(service, service.create_task(project["id"])["id"])
    before = task["envelope"]["findings"][0]["evidence"]
    result = analyze(task["envelope"], service.root / "projects" / project["id"])
    assert result["status"] == "completed"
    service.store.save_ai(task["id"], result["analyses"])
    after = service.store.task(task["id"])["envelope"]["findings"][0]
    assert after["evidence"] == before
    assert after["metadata"]["verification"] == "unverified"
    assert after["metadata"]["llm_triage"]["confirmed"] is True


def test_live_http_business_flow_and_security(service):
    server = AuditServer(service, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"

    def request(path, body=None, headers=None):
        request_headers = (
            {"Content-Type": "application/json"} if body is not None else {}
        )
        request_headers.update(headers or {})
        req = Request(
            url + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers=request_headers,
        )
        with urlopen(req, timeout=15) as response:
            return response.status, response.headers, response.read()

    try:
        _, headers, home = request("/")
        assert (
            b"app.js" in home
            and "frame-ancestors 'none'" in headers["Content-Security-Policy"]
        )
        session = json.loads(request("/api/session")[2])
        for bad_headers in (
            {},
            {"X-Audit-Token": session["token"], "Origin": "https://attacker.invalid"},
            {"Host": "attacker.invalid"},
            {"X-Audit-Token": "é"},
        ):
            with pytest.raises(HTTPError) as caught:
                request("/api/projects", source_payload(), bad_headers)
            assert caught.value.code == 403
        good_headers = {"X-Audit-Token": session["token"]}
        project = json.loads(
            request("/api/projects", source_payload(), good_headers)[2]
        )
        task = json.loads(
            request("/api/tasks", {"project_id": project["id"]}, good_headers)[2]
        )
        assert wait_task(service, task["id"])["status"] == "completed"
        body = request(f"/api/tasks/{task['id']}/report.html")[2]
        assert "潜在风险" in body.decode()
        assert len(json.loads(request("/api/tasks")[2])) == 1
        with pytest.raises(HTTPError) as caught:
            request(f"/api/tasks/{task['id']}/ai", {"consent": False}, good_headers)
        assert caught.value.code == 400
        with pytest.raises(HTTPError) as caught:
            request(
                "/api/projects",
                source_payload(),
                {**good_headers, "Content-Length": str(13 * 1024 * 1024)},
            )
        assert caught.value.code == 413
        with pytest.raises(HTTPError) as caught:
            request("/api/tasks/missing")
        assert caught.value.code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
