from pathlib import Path

import pytest

from parser.tree_sitter_bindings import (
    detect_language,
    parse_file,
    parse_source,
    walk_nodes,
)


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("filename", "language"),
    [
        ("demo.py", "python"),
        ("demo.go", "go"),
        ("Demo.java", "java"),
    ],
)
def test_detects_supported_language(filename: str, language: str) -> None:
    assert detect_language(filename) == language


@pytest.mark.parametrize(
    ("filename", "root_type", "call_type"),
    [
        ("demo.py", "module", "call"),
        ("demo.go", "source_file", "call_expression"),
        ("Demo.java", "program", "method_invocation"),
    ],
)
def test_parses_multilanguage_sample(
    filename: str,
    root_type: str,
    call_type: str,
) -> None:
    tree = parse_file(ROOT / "samples" / filename)
    node_types = {node.type for node in walk_nodes(tree.root_node)}

    assert tree.root_node.type == root_type
    assert call_type in node_types
    assert not tree.root_node.has_error


def test_rejects_unsupported_file_extension() -> None:
    with pytest.raises(ValueError, match="Unsupported source extension"):
        parse_file(ROOT / "samples" / "demo.rs")


def test_parses_crlf_source_on_windows() -> None:
    tree = parse_source("def scan():\r\n    return run()\r\n", "python")
    assert tree.root_node.end_point.row == 2
    assert not tree.root_node.has_error

