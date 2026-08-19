from pathlib import Path


SRC = Path(__file__).resolve().parents[1] / "src"


def test_no_legacy_package_trees() -> None:
    assert not (SRC / "ai_codeguard").exists()

    codeguard = SRC / "codeguard"
    source_files = {
        path.relative_to(codeguard).as_posix()
        for path in codeguard.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    assert source_files == {"__init__.py", "cli.py"}
