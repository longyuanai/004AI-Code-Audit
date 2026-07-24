from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Iterator

import httpx
import pytest
import uvicorn

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SUITE_ROOT = PROJECT_ROOT.parents[1]
INTEGRATION_SRC = SUITE_ROOT / "000shared-integration" / "src"
if str(INTEGRATION_SRC) not in sys.path:
    sys.path.insert(0, str(INTEGRATION_SRC))

from shared_integration.gateway import build_gateway


@pytest.fixture(scope="module")
def gateway_18080() -> Iterator[str]:
    app = build_gateway(SUITE_ROOT).app
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=18080,
            log_level="error",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        raise RuntimeError("gateway did not start on port 18080")
    try:
        yield "http://127.0.0.1:18080"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_post_scan_returns_findings(
    cp314_tree_sitter_binding,
    gateway_18080: str,
) -> None:
    response = httpx.post(
        f"{gateway_18080}/v0.5/004/scan",
        json={
            "repo_path": str(PROJECT_ROOT / "samples" / "mini_repo"),
            "languages": ["python"],
        },
        timeout=20,
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["source"] == "004"
    assert payload["count"] == 1
    assert payload["findings"][0]["source"] == "004"


def test_health_endpoint_reports_code_ok(
    cp314_tree_sitter_binding,
    gateway_18080: str,
) -> None:
    response = httpx.get(
        f"{gateway_18080}/v0.5/health",
        timeout=10,
    )

    assert response.status_code == 200
    code_health = response.json()["products"]["004"]
    assert code_health["status"] == "ok"
    assert code_health["available"] is True
