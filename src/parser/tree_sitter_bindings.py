from __future__ import annotations

from functools import lru_cache
from importlib import import_module
from pathlib import Path
from typing import Iterator, Literal

from tree_sitter import Language, Node, Parser, Tree

SupportedLanguage = Literal["python", "go", "java"]

_GRAMMAR_MODULES: dict[SupportedLanguage, str] = {
    "python": "tree_sitter_python",
    "go": "tree_sitter_go",
    "java": "tree_sitter_java",
}
_EXTENSIONS: dict[str, SupportedLanguage] = {
    ".py": "python",
    ".go": "go",
    ".java": "java",
}


def detect_language(path: str | Path) -> SupportedLanguage | None:
    return _EXTENSIONS.get(Path(path).suffix.lower())


@lru_cache(maxsize=len(_GRAMMAR_MODULES))
def get_language(language: SupportedLanguage) -> Language:
    module = import_module(_GRAMMAR_MODULES[language])
    return Language(module.language())


def create_parser(language: SupportedLanguage) -> Parser:
    return Parser(get_language(language))


def parse_source(source: str | bytes, language: SupportedLanguage) -> Tree:
    encoded = source.encode("utf-8") if isinstance(source, str) else source
    return create_parser(language).parse(encoded)


def parse_file(path: str | Path) -> Tree:
    source_path = Path(path)
    language = detect_language(source_path)
    if language is None:
        raise ValueError(f"Unsupported source extension: {source_path.suffix}")
    return parse_source(source_path.read_bytes(), language)


def walk_nodes(root: Node) -> Iterator[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


__all__ = [
    "SupportedLanguage",
    "create_parser",
    "detect_language",
    "get_language",
    "parse_file",
    "parse_source",
    "walk_nodes",
]

