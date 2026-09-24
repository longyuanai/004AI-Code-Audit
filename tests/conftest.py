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

VULN_MODULE_SRC = (
    Path(__file__).resolve().parents[1]
    / "modules"
    / "vulnerability-analysis"
    / "src"
)
VULN_MARKER = "vuln_integration"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--vuln-integration",
        action="store_true",
        default=False,
        help=(
            "Run tests that need the single vulnerability-analysis module; "
            "a missing module is then an error, not a skip. Use "
            "scripts/run_python_tests.py --scope integration."
        ),
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        f"{VULN_MARKER}: needs modules/vulnerability-analysis "
        "(run with --vuln-integration)",
    )
    if config.getoption("--vuln-integration"):
        _require_unique_vuln_module()


def _require_unique_vuln_module() -> None:
    try:
        store = import_module("ai_vuln_agent.enrichment.store")
    except ImportError as exc:
        raise pytest.UsageError(
            "--vuln-integration requires ai_vuln_agent from "
            f"{VULN_MODULE_SRC} on PYTHONPATH: {exc}"
        ) from exc
    location = Path(str(store.__file__)).resolve()
    if not location.is_relative_to(VULN_MODULE_SRC.resolve()):
        raise pytest.UsageError(
            f"ai_vuln_agent was imported from {location}, not the single "
            f"module source {VULN_MODULE_SRC}"
        )


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    if config.getoption("--vuln-integration"):
        return
    deselected = [item for item in items if item.get_closest_marker(VULN_MARKER)]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = [item for item in items if item not in deselected]
        config.stash[_DESELECTED] = len(deselected)


_DESELECTED = pytest.StashKey[int]()


def pytest_terminal_summary(terminalreporter: Any, config: pytest.Config) -> None:
    count = config.stash.get(_DESELECTED, 0)
    if count:
        terminalreporter.write_line(
            f"{count} {VULN_MARKER} test(s) deselected (unit scope); run "
            "scripts/run_python_tests.py --scope integration to execute them"
        )


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

from shared_llm_core import (
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
    """Return a tree-sitter binding built for the active CPython ABI.

    The fixture name is retained for compatibility with the existing test
    suite, which originally needed a local CPython 3.14 wheel workaround.
    """

    binding = import_module("tree_sitter._binding")
    abi_version = f"{sys.version_info.major}{sys.version_info.minor}"
    binding_path = str(binding.__file__)
    assert any(
        marker in binding_path
        for marker in (f"cp{abi_version}", f"cpython-{abi_version}")
    )
    return binding
