from pathlib import Path

from ai_code_audit.languages.go_lang import GoLanguageAdapter
from ai_code_audit.scanner import scan_repository

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples" / "go"


def test_go_adapter_extracts_functions(
    tree_sitter_binding,
) -> None:
    adapter = GoLanguageAdapter()
    tree = adapter.parser().parse((SAMPLES / "main.go").read_bytes())

    assert tree.root_node.has_error is False
    assert [span.name for span in adapter.extract_functions(tree)] == ["run"]


def test_go_samples_dispatch_and_find_command_flow(
    tree_sitter_binding,
) -> None:
    result = scan_repository(SAMPLES, ["go"])

    assert result["summary"]["files_scanned"] == 2
    assert len(result["findings"]) == 1
    assert result["findings"][0]["metadata"]["language"] == "go"
