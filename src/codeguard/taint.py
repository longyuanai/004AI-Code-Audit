"""Tree-sitter based intra-procedural taint analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from uuid import uuid4

from tree_sitter import Node

from codeguard.v05 import (
    Finding,
    FindingSeverity,
    FindingSource,
    Rule,
    RuleContext,
    RuleRegistry,
)
from parser.tree_sitter_bindings import (
    SupportedLanguage,
    parse_source,
    walk_nodes,
)

_FUNCTION_TYPES = {
    "function_definition",
    "function_declaration",
    "method_declaration",
    "constructor_declaration",
}
_ASSIGNMENT_TYPES = {
    "assignment",
    "assignment_expression",
    "short_var_declaration",
    "variable_declarator",
}
_CALL_TYPES = {"call", "call_expression", "method_invocation"}
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


@dataclass(frozen=True)
class TaintStep:
    kind: str
    name: str
    file: str
    function: str
    line: int
    column: int
    detail: str

    def render(self) -> str:
        return (
            f"{self.kind}:{self.name} at "
            f"{self.function}:{self.line}:{self.column} ({self.detail})"
        )


@dataclass(frozen=True)
class TaintPath:
    language: SupportedLanguage
    variable: str
    source: TaintStep
    sink: TaintStep
    propagations: tuple[TaintStep, ...] = ()

    @property
    def steps(self) -> tuple[TaintStep, ...]:
        return (self.source, *self.propagations, self.sink)

    def to_dict(self) -> dict[str, object]:
        return {
            "language": self.language,
            "variable": self.variable,
            "steps": [
                {
                    "kind": step.kind,
                    "name": step.name,
                    "file": step.file,
                    "function": step.function,
                    "line": step.line,
                    "column": step.column,
                    "detail": step.detail,
                }
                for step in self.steps
            ],
        }


@dataclass(frozen=True)
class _Origin:
    source: TaintStep
    propagations: tuple[TaintStep, ...]
    variable: str


@dataclass(frozen=True)
class _FunctionRegion:
    name: str
    node: Node


class TaintAnalyzer:
    """Track user-controlled values through assignments to dangerous calls."""

    def analyze(
        self,
        source: str | bytes,
        language: SupportedLanguage,
        *,
        file: str = "<memory>",
    ) -> list[TaintPath]:
        encoded = source.encode("utf-8") if isinstance(source, str) else source
        tree = parse_source(encoded, language)
        paths: list[TaintPath] = []
        for region in _function_regions(tree.root_node, encoded):
            paths.extend(
                self._analyze_region(region, encoded, language, file)
            )
        return paths

    def analyze_file(self, path: str | Path) -> list[TaintPath]:
        source_path = Path(path)
        extension = source_path.suffix.lower()
        languages: dict[str, SupportedLanguage] = {
            ".py": "python",
            ".go": "go",
            ".java": "java",
        }
        try:
            language = languages[extension]
        except KeyError as error:
            raise ValueError(
                f"Unsupported source extension: {extension}"
            ) from error
        return self.analyze(
            source_path.read_bytes(),
            language,
            file=str(source_path),
        )

    def _analyze_region(
        self,
        region: _FunctionRegion,
        source: bytes,
        language: SupportedLanguage,
        file: str,
    ) -> list[TaintPath]:
        tainted: dict[str, _Origin] = {}
        paths: list[TaintPath] = []
        events = [
            node
            for node in _walk_region(region.node)
            if node.type in _ASSIGNMENT_TYPES | _CALL_TYPES
        ]
        events.sort(key=lambda node: (node.start_byte, _event_priority(node)))

        for node in events:
            if node.type in _ASSIGNMENT_TYPES:
                assignment = _assignment_parts(node, source)
                if assignment is None:
                    continue
                names, value = assignment
                origin = _origin_from_expression(
                    value,
                    tainted,
                    source,
                    file=file,
                    function=region.name,
                )
                if origin is None:
                    continue
                for name in names:
                    propagation = _step(
                        "propagation",
                        name,
                        node,
                        source,
                        file,
                        region.name,
                    )
                    tainted[name] = _Origin(
                        source=origin.source,
                        propagations=(
                            *origin.propagations,
                            propagation,
                        ),
                        variable=name,
                    )
                continue

            sink_name = _sink_name(node, source)
            if sink_name is None:
                continue
            arguments = node.child_by_field_name("arguments") or node
            origins = _origins_in_expression(
                arguments,
                tainted,
                source,
                file=file,
                function=region.name,
            )
            for origin in origins:
                paths.append(
                    TaintPath(
                        language=language,
                        variable=origin.variable,
                        source=origin.source,
                        propagations=origin.propagations,
                        sink=_step(
                            "sink",
                            sink_name,
                            node,
                            source,
                            file,
                            region.name,
                        ),
                    )
                )
        return _deduplicate_paths(paths)


class TaintRule(Rule):
    id = "004-taint-source-to-sink"
    severity_hint = "high"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        source = ctx.facts.get("source")
        language = ctx.facts.get("language")
        file = str(ctx.facts.get("file", ctx.subject))
        if not isinstance(source, (str, bytes)):
            raise TypeError("RuleContext.facts['source'] must be str or bytes")
        if language not in {"python", "go", "java"}:
            raise ValueError(
                "RuleContext.facts['language'] must be python, go, or java"
            )

        findings: list[Finding] = []
        for path in TaintAnalyzer().analyze(
            source,
            language,
            file=file,
        ):
            severity = (
                FindingSeverity.CRITICAL
                if _is_rce_sink(path.sink.name)
                else FindingSeverity.HIGH
            )
            findings.append(
                Finding(
                    id=str(uuid4()),
                    source=FindingSource.CODE,
                    severity=severity,
                    confidence=0.9,
                    title=f"Tainted data reaches {path.sink.name}",
                    description=(
                        f"User-controlled value {path.variable} flows from "
                        f"{path.source.name} to {path.sink.name}."
                    ),
                    evidence=tuple(step.render() for step in path.steps),
                    tags=frozenset({"taint", language}),
                    metadata={
                        "rule_id": self.id,
                        "file": file,
                        "path": path.to_dict(),
                    },
                )
            )
        return findings


def register_taint_rule(
    registry: RuleRegistry | None = None,
) -> RuleRegistry:
    target = registry or RuleRegistry()
    target.register(TaintRule())
    return target


def _function_regions(root: Node, source: bytes) -> list[_FunctionRegion]:
    functions = [
        node for node in walk_nodes(root) if node.type in _FUNCTION_TYPES
    ]
    if not functions:
        return [_FunctionRegion("<module>", root)]
    return [
        _FunctionRegion(_function_name(node, source), node)
        for node in functions
    ]


def _function_name(node: Node, source: bytes) -> str:
    name = node.child_by_field_name("name")
    return _text(name, source) if name is not None else "<anonymous>"


def _walk_region(root: Node) -> Iterable[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        for child in reversed(node.children):
            if child is not root and child.type in _FUNCTION_TYPES:
                continue
            stack.append(child)


def _assignment_parts(
    node: Node,
    source: bytes,
) -> tuple[tuple[str, ...], Node] | None:
    if node.type == "variable_declarator":
        left = node.child_by_field_name("name")
        right = node.child_by_field_name("value")
    else:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
    if left is None or right is None:
        return None
    return (_assigned_names(left, source), right)


def _assigned_names(node: Node, source: bytes) -> tuple[str, ...]:
    names = [
        child
        for child in walk_nodes(node)
        if child.type in {"identifier", "variable_name"}
    ]
    if not names and node.type in {"identifier", "variable_name"}:
        names = [node]
    return tuple(_text(child, source) for child in names)


def _origin_from_expression(
    node: Node,
    tainted: dict[str, _Origin],
    source: bytes,
    *,
    file: str,
    function: str,
) -> _Origin | None:
    origins = _origins_in_expression(
        node,
        tainted,
        source,
        file=file,
        function=function,
    )
    return origins[0] if origins else None


def _origins_in_expression(
    node: Node,
    tainted: dict[str, _Origin],
    source: bytes,
    *,
    file: str,
    function: str,
) -> list[_Origin]:
    source_node = _find_source(node, source)
    origins: list[_Origin] = []
    if source_node is not None:
        source_name = _source_name(source_node, source) or "user-input"
        origins.append(
            _Origin(
                source=_step(
                    "source",
                    source_name,
                    source_node,
                    source,
                    file,
                    function,
                ),
                propagations=(),
                variable=source_name,
            )
        )

    expression = _text(node, source)
    for variable, origin in tainted.items():
        if re.search(rf"(?<![\w$]){re.escape(variable)}(?![\w$])", expression):
            origins.append(origin)
    return list(
        {
            (
                origin.source.file,
                origin.source.line,
                origin.variable,
            ): origin
            for origin in origins
        }.values()
    )


def _find_source(node: Node, source: bytes) -> Node | None:
    for child in walk_nodes(node):
        if _source_name(child, source) is not None:
            return child
    return None


def _source_name(node: Node, source: bytes) -> str | None:
    text = _text(node, source)
    lowered = text.lower().replace(" ", "")
    if node.type in _CALL_TYPES:
        original_target = _call_target(node, source)
        target = original_target.lower().replace(" ", "")
        if target == "input" or target.endswith(".input"):
            return original_target
        if any(
            marker in target
            for marker in (
                ".formvalue",
                ".getparameter",
                ".args.get",
                ".form.get",
                ".json.get",
                ".get_json",
                ".query().get",
            )
        ):
            return original_target
        if target.endswith((".nextline", ".next", ".readline")):
            return original_target
    if "sys.argv" in lowered or "os.args" in lowered:
        return "argv"
    if re.search(r"(?<![\w$])args\s*\[", text, re.IGNORECASE):
        return "argv"
    return None


def _sink_name(node: Node, source: bytes) -> str | None:
    target = _call_target(node, source)
    lowered = target.lower().replace(" ", "")
    exact = {"eval", "exec"}
    suffixes = (
        ".system",
        ".popen",
        ".execute",
        ".executemany",
        ".query",
        ".queryrow",
        ".executequery",
        ".executeupdate",
        ".executescript",
    )
    if lowered in exact or lowered.startswith("subprocess."):
        return target
    if lowered == "exec.command" or lowered.endswith(suffixes):
        return target
    if "getruntime().exec" in lowered:
        return target
    return None


def _call_target(node: Node, source: bytes) -> str:
    function = node.child_by_field_name("function")
    if function is not None:
        return _text(function, source)
    name = node.child_by_field_name("name")
    object_node = node.child_by_field_name("object")
    if name is None:
        return _text(node, source).split("(", 1)[0]
    if object_node is None:
        return _text(name, source)
    return f"{_text(object_node, source)}.{_text(name, source)}"


def _step(
    kind: str,
    name: str,
    node: Node,
    source: bytes,
    file: str,
    function: str,
) -> TaintStep:
    row, column = node.start_point
    return TaintStep(
        kind=kind,
        name=name,
        file=file,
        function=function,
        line=row + 1,
        column=column + 1,
        detail=_text(node, source).strip(),
    )


def _text(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode(
        "utf-8",
        errors="replace",
    )


def _event_priority(node: Node) -> int:
    return 0 if node.type in _ASSIGNMENT_TYPES else 1


def _deduplicate_paths(paths: Iterable[TaintPath]) -> list[TaintPath]:
    unique: dict[tuple[object, ...], TaintPath] = {}
    for path in paths:
        key = (
            path.source.file,
            path.source.line,
            path.sink.line,
            path.sink.name,
            path.variable,
        )
        unique[key] = path
    return list(unique.values())


def _is_rce_sink(name: str) -> bool:
    lowered = name.lower()
    return any(
        marker in lowered
        for marker in ("eval", "exec", "system", "popen", "command")
    )


__all__ = [
    "TaintAnalyzer",
    "TaintPath",
    "TaintRule",
    "TaintStep",
    "register_taint_rule",
]
