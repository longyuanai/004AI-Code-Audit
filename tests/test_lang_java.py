from pathlib import Path

from ai_code_audit.languages.java_lang import JavaLanguageAdapter
from ai_code_audit.scanner import scan_repository

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples" / "java"


def test_java_adapter_extracts_methods_and_classes(
    tree_sitter_binding,
) -> None:
    adapter = JavaLanguageAdapter()
    tree = adapter.parser().parse((SAMPLES / "Demo.java").read_bytes())

    assert tree.root_node.has_error is False
    assert [span.name for span in adapter.extract_functions(tree)] == ["find"]
    assert [span.name for span in adapter.extract_classes(tree)] == ["Demo"]


def test_java_samples_include_safe_and_unsafe_files(
    tree_sitter_binding,
) -> None:
    result = scan_repository(SAMPLES, ["java"])

    assert result["summary"]["files_scanned"] == 2
    assert len(result["findings"]) == 1
    assert result["findings"][0]["host"].endswith("Demo.java")
