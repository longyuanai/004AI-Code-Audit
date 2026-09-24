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

# shared_llm_core is an unpublished path dependency, so it is absent on any
# checkout that has not been set up alongside it (including CI). Importing it
# at module scope aborted collection for the entire suite -- including the
# ~2/3 of it that never touches an LLM. Tests that genuinely need the router
# skip via the stub_router fixtures below; everything else now runs.
try:  # noqa: E402
    from shared_llm_core import (
        ChatChoice,
        ChatMessage,
        ChatResponse,
        ChatUsage,
    )

    HAS_SHARED_LLM_CORE = True
except ImportError:  # pragma: no cover - depends on local checkout layout
    HAS_SHARED_LLM_CORE = False

SHARED_LLM_CORE_REQUIRED = (
    "requires shared_llm_core (unpublished path dependency); "
    "set it up next to this repo or install it to run this test"
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
    if not HAS_SHARED_LLM_CORE:
        pytest.skip(SHARED_LLM_CORE_REQUIRED)
    return StubRouter()


@pytest.fixture
def stub_router_with():
    if not HAS_SHARED_LLM_CORE:
        pytest.skip(SHARED_LLM_CORE_REQUIRED)

    def factory(
        *,
        content: str,
        model: str = "stub-model",
    ) -> StubRouter:
        return StubRouter(content=content, model=model)

    return factory


@pytest.fixture
def tree_sitter_binding():
    """Guarantee the native tree-sitter binding is importable.

    This previously asserted `"cp314" in binding.__file__`, pinning the whole
    suite to a CPython 3.14 wheel even though pyproject declares ^3.11 and CI
    provisions 3.11 -- so all 29 tests using it errored on the supported
    interpreter. The parsing behaviour under test does not depend on the ABI
    tag, only on the binding being present.
    """

    try:
        return import_module("tree_sitter._binding")
    except ImportError as error:  # pragma: no cover - env without the wheel
        pytest.skip(f"native tree-sitter binding unavailable: {error}")
