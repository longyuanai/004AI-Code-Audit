"""Python tree-sitter adapter."""

from ai_code_audit.languages.base import TreeSitterLanguageAdapter


class PythonLanguageAdapter(TreeSitterLanguageAdapter):
    name = "python"
    extensions = (".py",)
    grammar_module = "tree_sitter_python"
    function_types = frozenset({"function_definition"})
    class_types = frozenset({"class_definition"})


__all__ = ["PythonLanguageAdapter"]
