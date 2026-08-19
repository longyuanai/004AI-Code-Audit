from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from ai_code_audit import hybrid_cli


def test_scan_entrypoint_creates_span(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, dict[str, object]]] = []

    @contextmanager
    def recording_span(
        name: str,
        *,
        attributes: dict[str, object],
    ) -> Iterator[None]:
        captured.append((name, attributes))
        yield

    expected = {"findings": [], "summary": {}, "warnings": []}
    monkeypatch.setattr(hybrid_cli, "span", recording_span)
    monkeypatch.setattr(hybrid_cli, "_scan_payload", lambda _payload: expected)

    assert hybrid_cli.scan_payload({"repo_path": "C:/private/customer"}) is expected
    assert captured == [
        (
            "product.scan",
            {"product.id": "004", "scan.target_type": "repository"},
        )
    ]
