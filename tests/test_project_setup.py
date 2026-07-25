from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_declares_upgrade_package() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["tool"]["poetry"]["name"] == "ai-codeguard-upgrade"
    assert config["tool"]["poetry"]["version"] == "0.6.0"


def test_pyproject_declares_shared_core_dependency() -> None:
    """The shared core must be declared -- but not pinned to one layout.

    This previously asserted the dependency equalled exactly
    `{"path": "../../000shared-llm-core", "develop": True}`, which froze a
    machine-specific sibling-directory layout into the test suite: publishing
    the package, vendoring it, or making it optional would all have failed
    here. Assert that it is declared and resolvable instead.
    """

    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = config["tool"]["poetry"]["dependencies"]

    assert "shared-llm-core" in dependencies
    dependency = dependencies["shared-llm-core"]
    if isinstance(dependency, str):
        assert dependency.strip(), "version constraint must not be empty"
    else:
        assert dependency.get("path") or dependency.get("git") or dependency.get(
            "version"
        ), "shared-llm-core needs a path, git, or version source"


def test_upstream_stage1_sources_are_present_in_upgrade() -> None:
    assert (ROOT / "src" / "scanner" / "orchestrator.ts").is_file()
    assert (ROOT / "src" / "rules" / "engine.ts").is_file()
    assert (ROOT / "src" / "parser" / "tree-sitter" / "runtime.ts").is_file()

