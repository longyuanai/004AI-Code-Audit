"""Language adapter protocol and shared tree-sitter helpers."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Protocol, TypeVar, runtime_checkable

from tree_sitter import Language, Node, Parser, Tree


@dataclass(frozen=True)
class FunctionSpan:
    name: str
    start_line: int
    end_line: int
    start_column: int = 1
    end_column: int = 1


@dataclass(frozen=True)
class ClassSpan:
    name: str
    start_line: int
    end_line: int
    start_column: int = 1
    end_column: int = 1


@runtime_checkable
class LanguageAdapter(Protocol):
    name: str
    extensions: tuple[str, ...]

    def parser(self) -> Parser: ...

    def extract_functions(self, tree: Tree) -> list[FunctionSpan]: ...

    def extract_classes(self, tree: Tree) -> list[ClassSpan]: ...


SpanT = TypeVar("SpanT", FunctionSpan, ClassSpan)


class TreeSitterLanguageAdapter:
    """Reusable implementation for grammar packages exposing language()."""

    name = ""
    extensions: tuple[str, ...] = ()
    grammar_module = ""
    function_types: frozenset[str] = frozenset()
    class_types: frozenset[str] = frozenset()

    def parser(self) -> Parser:
        grammar = import_module(self.grammar_module)
        return Parser(Language(grammar.language()))

    def extract_functions(self, tree: Tree) -> list[FunctionSpan]:
        return _extract_spans(tree.root_node, self.function_types, FunctionSpan)

    def extract_classes(self, tree: Tree) -> list[ClassSpan]:
        return _extract_spans(tree.root_node, self.class_types, ClassSpan)


def _extract_spans(
    root: Node,
    node_types: frozenset[str],
    span_type: type[SpanT],
) -> list[SpanT]:
    spans: list[SpanT] = []
    for node in walk_nodes(root):
        if node.type not in node_types:
            continue
        start_row, start_column = node.start_point
        end_row, end_column = node.end_point
        spans.append(
            span_type(
                name=_node_name(node),
                start_line=start_row + 1,
                end_line=end_row + 1,
                start_column=start_column + 1,
                end_column=end_column + 1,
            )
        )
    return spans


def _node_name(node: Node) -> str:
    name = node.child_by_field_name("name")
    if name is None:
        declarator = node.child_by_field_name("declarator")
        if declarator is not None:
            name = _first_named_identifier(declarator)
    if name is None and node.type == "arrow_function":
        parent = node.parent
        if parent is not None:
            name = parent.child_by_field_name("name")
    if name is None:
        name = _first_named_identifier(node)
    if name is None or name.text is None:
        return "<anonymous>"
    return name.text.decode("utf-8", errors="replace")


def _first_named_identifier(node: Node) -> Node | None:
    identifiers = {
        "field_identifier",
        "identifier",
        "property_identifier",
        "type_identifier",
    }
    for candidate in walk_nodes(node):
        if candidate.type in identifiers:
            return candidate
    return None


def walk_nodes(root: Node):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


__all__ = [
    "ClassSpan",
    "FunctionSpan",
    "LanguageAdapter",
    "TreeSitterLanguageAdapter",
    "walk_nodes",
]
