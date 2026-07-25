"""C++ tree-sitter adapter."""

from ai_code_audit.languages.base import TreeSitterLanguageAdapter


class CppLanguageAdapter(TreeSitterLanguageAdapter):
    name = "cpp"
    extensions = (".cpp", ".hpp", ".cc", ".cxx", ".hxx")
    grammar_module = "tree_sitter_cpp"
    function_types = frozenset({"function_definition"})
    class_types = frozenset({"class_specifier", "struct_specifier"})


__all__ = ["CppLanguageAdapter"]
