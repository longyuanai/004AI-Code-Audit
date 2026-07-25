"""Language adapter registry."""

from __future__ import annotations

from pathlib import Path

from ai_code_audit.languages.base import (
    ClassSpan,
    FunctionSpan,
    LanguageAdapter,
)
from ai_code_audit.languages.cpp_lang import CppLanguageAdapter
from ai_code_audit.languages.go_lang import GoLanguageAdapter
from ai_code_audit.languages.java_lang import JavaLanguageAdapter
from ai_code_audit.languages.python_lang import PythonLanguageAdapter
from ai_code_audit.languages.typescript_lang import (
    TypeScriptLanguageAdapter,
)

ADAPTERS: tuple[LanguageAdapter, ...] = (
    PythonLanguageAdapter(),
    CppLanguageAdapter(),
    JavaLanguageAdapter(),
    GoLanguageAdapter(),
    TypeScriptLanguageAdapter(),
)
_BY_NAME = {adapter.name: adapter for adapter in ADAPTERS}
_BY_NAME["c++"] = _BY_NAME["cpp"]
_BY_NAME["ts"] = _BY_NAME["typescript"]
_BY_EXTENSION = {
    extension: adapter
    for adapter in ADAPTERS
    for extension in adapter.extensions
}


def get_adapter(name: str) -> LanguageAdapter:
    try:
        return _BY_NAME[name.lower()]
    except KeyError as error:
        raise KeyError(f"Unsupported language: {name}") from error


def adapter_for_path(path: str | Path) -> LanguageAdapter | None:
    return _BY_EXTENSION.get(Path(path).suffix.lower())


def supported_languages() -> tuple[str, ...]:
    return tuple(adapter.name for adapter in ADAPTERS)


__all__ = [
    "ADAPTERS",
    "ClassSpan",
    "CppLanguageAdapter",
    "FunctionSpan",
    "GoLanguageAdapter",
    "JavaLanguageAdapter",
    "LanguageAdapter",
    "PythonLanguageAdapter",
    "TypeScriptLanguageAdapter",
    "adapter_for_path",
    "get_adapter",
    "supported_languages",
]
