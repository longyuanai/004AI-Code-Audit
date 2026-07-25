"""Go tree-sitter adapter."""

from ai_code_audit.languages.base import TreeSitterLanguageAdapter


class GoLanguageAdapter(TreeSitterLanguageAdapter):
    name = "go"
    extensions = (".go",)
    grammar_module = "tree_sitter_go"
    function_types = frozenset(
        {"function_declaration", "method_declaration"}
    )
    class_types = frozenset({"type_spec"})


__all__ = ["GoLanguageAdapter"]
