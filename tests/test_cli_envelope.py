from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUITE_ROOT = PROJECT_ROOT.parents[1]
INTEGRATION_SRC = SUITE_ROOT / "000shared-integration" / "src"
if str(INTEGRATION_SRC) not in sys.path:
    sys.path.insert(0, str(INTEGRATION_SRC))

import pytest

# shared_integration lives in the sibling 000shared-integration checkout and
# is not declared as a dependency at all, so it is absent in CI.
pytest.importorskip(
    "shared_integration",
    reason="requires the sibling 000shared-integration checkout",
)

from shared_integration.adapters.code import CodeAdapter  # noqa: E402


def _run_cli(payload: dict[str, object]) -> dict[str, object]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        (
            str(PROJECT_ROOT / "src"),
            str(PROJECT_ROOT / ".python-deps"),
            str(SUITE_ROOT / "000shared-llm-core" / "src"),
            env.get("PYTHONPATH", ""),
        )
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ai_codeguard.cli",
            "scan",
            "--input",
            json.dumps(payload),
            "--json",
        ],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_scan_local_repo(tree_sitter_binding) -> None:
    envelope = _run_cli(
        {
            "repo_path": str(PROJECT_ROOT / "samples" / "mini_repo"),
            "languages": ["python", "go", "java"],
        }
    )

    assert envelope["summary"]["files_scanned"] == 3
    assert len(envelope["findings"]) == 3
    assert {finding["metadata"]["language"] for finding in envelope["findings"]} == {
        "python",
        "go",
        "java",
    }
    assert all(Path(finding["host"]).is_absolute() for finding in envelope["findings"])


def test_scan_with_rules_filter(tree_sitter_binding) -> None:
    envelope = _run_cli(
        {
            "repo_path": str(PROJECT_ROOT / "samples" / "mini_repo"),
            "rules": ["004-taint-source-to-sink"],
        }
    )

    assert envelope["findings"]
    assert {
        finding["metadata"]["rule_id"] for finding in envelope["findings"]
    } == {"004-taint-source-to-sink"}
    assert envelope["summary"]["rules"] == ["004-taint-source-to-sink"]


def test_scan_unsupported_language_graceful(
    tree_sitter_binding,
) -> None:
    envelope = _run_cli(
        {
            "repo_path": str(PROJECT_ROOT / "samples" / "mini_repo"),
            "languages": ["rust"],
        }
    )

    assert envelope["findings"] == []
    assert envelope["summary"]["files_scanned"] == 0
    assert envelope["warnings"] == ["Unsupported languages ignored: rust"]


def test_json_subprocess_code_adapter_end_to_end(
    tree_sitter_binding,
) -> None:
    async def collect():
        return [
            finding
            async for finding in CodeAdapter(PROJECT_ROOT).scan(
                {
                    "repo_path": str(PROJECT_ROOT / "samples" / "mini_repo"),
                    "languages": ["python"],
                }
            )
        ]

    findings = asyncio.run(collect())

    assert len(findings) == 1
    assert findings[0].source.value == "004"
    assert findings[0].host is not None
    assert findings[0].description
