from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_declares_upgrade_package() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["tool"]["poetry"]["name"] == "ai-codeguard-upgrade"
    assert config["tool"]["poetry"]["version"] == "0.6.0"


def test_pyproject_uses_shared_core_path_dependency() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependency = config["tool"]["poetry"]["dependencies"]["shared-llm-core"]
    assert dependency == {
        "path": "../000shared-llm-core",
        "develop": True,
    }


def test_upstream_stage1_sources_are_present_in_upgrade() -> None:
    assert (ROOT / "src" / "scanner" / "orchestrator.ts").is_file()
    assert (ROOT / "src" / "rules" / "engine.ts").is_file()
    assert (ROOT / "src" / "parser" / "tree-sitter" / "runtime.ts").is_file()

