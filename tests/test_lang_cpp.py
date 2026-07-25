from pathlib import Path

from ai_code_audit.languages.cpp_lang import CppLanguageAdapter
from ai_code_audit.scanner import scan_repository

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples" / "cpp"


def test_cpp_adapter_extracts_function_and_class(
    cp314_tree_sitter_binding,
) -> None:
    adapter = CppLanguageAdapter()
    tree = adapter.parser().parse((SAMPLES / "demo.cpp").read_bytes())

    assert tree.root_node.has_error is False
    assert {span.name for span in adapter.extract_functions(tree)} >= {
        "add",
        "greet",
    }
    assert [span.name for span in adapter.extract_classes(tree)] == ["Greeter"]


def test_cpp_buggy_fixture_produces_taint_finding(
    cp314_tree_sitter_binding,
) -> None:
    result = scan_repository(SAMPLES, ["cpp"])

    assert result["summary"]["files_scanned"] == 2
    assert len(result["findings"]) == 1
    assert result["findings"][0]["metadata"]["language"] == "cpp"
