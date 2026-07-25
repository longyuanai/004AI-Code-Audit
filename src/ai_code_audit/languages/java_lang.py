"""Java tree-sitter adapter."""

from ai_code_audit.languages.base import TreeSitterLanguageAdapter


class JavaLanguageAdapter(TreeSitterLanguageAdapter):
    name = "java"
    extensions = (".java",)
    grammar_module = "tree_sitter_java"
    function_types = frozenset(
        {"constructor_declaration", "method_declaration"}
    )
    class_types = frozenset(
        {
            "class_declaration",
            "enum_declaration",
            "interface_declaration",
            "record_declaration",
        }
    )


__all__ = ["JavaLanguageAdapter"]
