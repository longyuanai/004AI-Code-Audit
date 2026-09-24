from pathlib import Path

from ai_code_audit.languages.typescript_lang import (
    TypeScriptLanguageAdapter,
)
from ai_code_audit.scanner import scan_repository

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples" / "typescript"


def test_typescript_adapter_extracts_function_and_class(
    tree_sitter_binding,
) -> None:
    adapter = TypeScriptLanguageAdapter()
    tree = adapter.parser().parse((SAMPLES / "app.ts").read_bytes())

    assert tree.root_node.has_error is False
    assert [span.name for span in adapter.extract_functions(tree)] == ["render"]
    assert [span.name for span in adapter.extract_classes(tree)] == ["Controller"]


def test_tsx_grammar_parses_component(
    tree_sitter_binding,
) -> None:
    adapter = TypeScriptLanguageAdapter()
    tree = adapter.parser_for_extension(".tsx").parse(
        (SAMPLES / "app.tsx").read_bytes()
    )

    assert tree.root_node.has_error is False
    assert [span.name for span in adapter.extract_functions(tree)] == ["Greeting"]


def test_typescript_samples_find_only_unsafe_ts(
    tree_sitter_binding,
) -> None:
    result = scan_repository(SAMPLES, ["typescript"])

    assert result["summary"]["files_scanned"] == 2
    assert len(result["findings"]) == 1
    assert result["findings"][0]["host"].endswith("app.ts")
