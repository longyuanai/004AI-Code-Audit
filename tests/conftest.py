from __future__ import annotations

import os
import sys
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest

SHARED_SRC = Path(__file__).resolve().parents[3] / "000shared-llm-core" / "src"
PROJECT_SRC = Path(__file__).resolve().parents[1] / "src"
LOCAL_DEPS = Path(__file__).resolve().parents[1] / ".python-deps"
for source_root in (LOCAL_DEPS, SHARED_SRC, PROJECT_SRC):
    source = str(source_root)
    if source not in sys.path:
        sys.path.insert(0, source)


def _ensure_pythonpath() -> None:
    """Expose product sources and bundled wheels to every child process."""

    current = os.environ.get("PYTHONPATH", "")
    existing = current.split(os.pathsep) if current else []
    required = (str(PROJECT_SRC), str(LOCAL_DEPS))
    parts = [*required, *(part for part in existing if part not in required)]
    os.environ["PYTHONPATH"] = os.pathsep.join(parts)


_ensure_pythonpath()


# JSONSubprocessAdapter.scan() only injects <repo>/src into the child
# env's PYTHONPATH, not .python-deps/. Without this autouse fixture the
# tree-sitter language bindings (tree_sitter_python / _go / _java) are
# unimportable in the adapter subprocess and the taint/dataflow rules
# emit zero findings.
@pytest.fixture(scope="session", autouse=True)
def _ensure_python_deps_in_pythonpath() -> None:
    deps = str(LOCAL_DEPS)
    current = os.environ.get("PYTHONPATH", "")
    parts = current.split(os.pathsep) if current else []
    if deps in parts:
        return
    os.environ["PYTHONPATH"] = (
        os.pathsep.join((deps, *parts)) if parts else deps
    )

from shared_llm_core import (  # noqa: E402
    ChatChoice,
    ChatMessage,
    ChatResponse,
    ChatUsage,
)


class StubRouter:
    def __init__(
        self,
        *,
        content: str = (
            '{"confirmed": true, "confidence": 0.9, '
            '"reasoning": "stub router verdict"}'
        ),
        model: str = "stub-model",
    ) -> None:
        self.content = content
        self.model = model
        self.calls: list[tuple[Any, Any]] = []
        self.error: Exception | None = None

    def chat(self, tier: Any, request: Any) -> ChatResponse:
        self.calls.append((tier, request))
        if self.error is not None:
            raise self.error
        return ChatResponse(
            id="stub-response",
            model=self.model,
            created=0,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content=self.content),
                    finish_reason="stop",
                )
            ],
            usage=ChatUsage(
                prompt_tokens=10,
                completion_tokens=5,
                total_tokens=15,
            ),
        )


@pytest.fixture
def stub_router() -> StubRouter:
    return StubRouter()


@pytest.fixture
def stub_router_with():
    def factory(
        *,
        content: str,
        model: str = "stub-model",
    ) -> StubRouter:
        return StubRouter(content=content, model=model)

    return factory


@pytest.fixture
def cp314_tree_sitter_binding():
    binding = import_module("tree_sitter._binding")
    assert "cp314" in str(binding.__file__)
    return binding
