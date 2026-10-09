"""Verify an installed distribution using real HTTP, processes and SQLite.

Run with the clean environment's absolute Python: python -I this-script.py.
This script deliberately never adds a source checkout to sys.path.
"""

from __future__ import annotations

import argparse
import base64
import json
import threading
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

import shared_llm_core

import ai_code_audit
from ai_code_audit.web.server import AuditServer
from ai_code_audit.web.service import Service


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument(
        "--ai-mode", choices=("degraded", "success"), default="degraded"
    )
    args = parser.parse_args()
    service = Service(args.data_dir)
    server = AuditServer(service, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    evidence: dict[str, object] = {
        "product_module": ai_code_audit.__file__,
        "shared_module": shared_llm_core.__file__,
    }
    checks: dict[str, bool] = {}

    def request(path: str, data: object = None, token: str = "") -> bytes:
        req = Request(
            base + path,
            data=None if data is None else json.dumps(data).encode(),
            headers={"Content-Type": "application/json", "X-Audit-Token": token},
        )
        with urlopen(req, timeout=10) as response:
            return bytes(response.read())

    def wait(task_id: str, *, ai: bool = False) -> dict[str, Any]:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            task = service.store.task(task_id)
            if task["ai_status" if ai else "status"] not in {"queued", "running"}:
                return task
            time.sleep(0.05)
        raise RuntimeError("Task did not finish")

    try:
        token = json.loads(request("/api/session"))["token"]
        checks["static_assets"] = all(
            request(path) for path in ("/", "/app.js", "/style.css")
        )
        for name, source, expected in (
            ("before", "value = input()\neval(value)\n", 1),
            ("after", "import ast\nvalue = input()\nast.literal_eval(value)\n", 0),
        ):
            payload = {
                "name": name,
                "files": [
                    {
                        "path": "app.py",
                        "content_base64": base64.b64encode(source.encode()).decode(),
                    }
                ],
            }
            project = json.loads(request("/api/projects", payload, token))
            task_id = json.loads(
                request("/api/tasks", {"project_id": project["id"]}, token)
            )["id"]
            task = wait(task_id)
            evidence[f"{name}_scan_duration_seconds"] = task["duration_seconds"]
            checks[name] = (
                task["status"] == "completed"
                and len(task["envelope"]["findings"]) == expected
            )
            for format_name in ("html", "json", "sarif"):
                output = request(f"/api/tasks/{task_id}/report.{format_name}")
                (args.data_dir / f"{name}.{format_name}").write_bytes(output)
                checks[f"{name}_{format_name}"] = len(output) > 0
            if name == "before":
                request(f"/api/tasks/{task_id}/ai", {"consent": True}, token)
                ai_task = wait(task_id, ai=True)
                checks[f"ai_{args.ai_mode}"] = (
                    ai_task["ai_status"]
                    == ("completed" if args.ai_mode == "success" else "unavailable")
                    and ai_task["envelope"]["findings"][0]["evidence"]
                    == task["envelope"]["findings"][0]["evidence"]
                )
                evidence["ai_result"] = ai_task["envelope"]["findings"][0][
                    "metadata"
                ].get("llm_triage")
        checks["history"] = len(json.loads(request("/api/tasks"))) == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        service.close()
    restarted = Service(args.data_dir)
    try:
        checks["restart"] = len(restarted.store.tasks()) == 2
    finally:
        restarted.close()
    checks["installed_modules"] = all(
        "site-packages" in str(path)
        for path in (ai_code_audit.__file__, shared_llm_core.__file__)
    )
    evidence["checks"] = checks
    evidence["passed"] = all(checks.values())
    (args.data_dir / "smoke-result.json").write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(checks))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
