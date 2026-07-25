"""TypeScript and TSX tree-sitter adapter."""

from tree_sitter import Language, Parser
import tree_sitter_typescript

from ai_code_audit.languages.base import TreeSitterLanguageAdapter


class TypeScriptLanguageAdapter(TreeSitterLanguageAdapter):
    name = "typescript"
    extensions = (".ts", ".tsx")
    grammar_module = "tree_sitter_typescript"
    function_types = frozenset(
        {
            "arrow_function",
            "function_declaration",
            "generator_function_declaration",
            "method_definition",
        }
    )
    class_types = frozenset(
        {"abstract_class_declaration", "class_declaration", "interface_declaration"}
    )

    def parser(self) -> Parser:
        return Parser(Language(tree_sitter_typescript.language_typescript()))

    def parser_for_extension(self, extension: str) -> Parser:
        grammar = (
            tree_sitter_typescript.language_tsx
            if extension.lower() == ".tsx"
            else tree_sitter_typescript.language_typescript
        )
        return Parser(Language(grammar()))


__all__ = ["TypeScriptLanguageAdapter"]
