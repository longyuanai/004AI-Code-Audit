from pathlib import Path

from ai_code_audit.languages import (
    LanguageAdapter,
    adapter_for_path,
    get_adapter,
)
from ai_code_audit.scanner import discover_files, scan_repository

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_language_registry_satisfies_protocol() -> None:
    for name in ("python", "cpp", "java", "go", "typescript"):
        assert isinstance(get_adapter(name), LanguageAdapter)


def test_extension_dispatch_covers_phase2_languages() -> None:
    expected = {
        "demo.py": "python",
        "demo.cpp": "cpp",
        "Demo.java": "java",
        "main.go": "go",
        "app.ts": "typescript",
        "app.tsx": "typescript",
    }

    assert {
        filename: adapter_for_path(filename).name
        for filename in expected
    } == expected


def test_mixed_repository_dispatches_each_adapter(
    cp314_tree_sitter_binding,
) -> None:
    selected = ("cpp", "java", "go", "typescript")
    files = discover_files(SAMPLES, selected)
    result = scan_repository(SAMPLES, selected)

    assert {adapter.name for _, adapter in files} == set(selected)
    assert set(result["summary"]["languages"]) == set(selected)
    assert result["summary"]["files_scanned"] == len(files)
    assert len(files) >= 8
