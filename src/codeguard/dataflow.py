"""Cross-function taint propagation and call-graph construction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from uuid import uuid4

from tree_sitter import Node

from codeguard.taint import (
    TaintStep,
    _ASSIGNMENT_TYPES,
    _CALL_TYPES,
    _assignment_parts,
    _call_target,
    _function_regions,
    _sink_name,
    _source_name,
    _step,
    _text,
    _walk_region,
)
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

_RETURN_TYPES = {"return_statement"}
_PARAMETER_TYPES = {
    "default_parameter",
    "formal_parameter",
    "parameter_declaration",
    "typed_default_parameter",
    "typed_parameter",
}


@dataclass(frozen=True)
class CallEdge:
    caller: str
    callee: str
    file: str
    line: int
    arguments: tuple[str, ...] = ()

    def render(self) -> str:
        return f"call:{self.caller}->{self.callee} at {self.file}:{self.line}"


@dataclass(frozen=True)
class DataflowPath:
    language: SupportedLanguage
    variable: str
    source: TaintStep
    sink: TaintStep
    calls: tuple[CallEdge, ...] = ()
    propagations: tuple[TaintStep, ...] = ()

    @property
    def evidence(self) -> tuple[str, ...]:
        return (
            self.source.render(),
            *(edge.render() for edge in self.calls),
            *(step.render() for step in self.propagations),
            self.sink.render(),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "language": self.language,
            "variable": self.variable,
            "source": _step_dict(self.source),
            "calls": [
                {
                    "caller": edge.caller,
                    "callee": edge.callee,
                    "file": edge.file,
                    "line": edge.line,
                    "arguments": list(edge.arguments),
                }
                for edge in self.calls
            ],
            "propagations": [
                _step_dict(step) for step in self.propagations
            ],
            "sink": _step_dict(self.sink),
        }


@dataclass(frozen=True)
class DataflowReport:
    call_graph: tuple[CallEdge, ...]
    paths: tuple[DataflowPath, ...]


@dataclass(frozen=True)
class _FunctionModel:
    name: str
    node: Node
    parameters: tuple[str, ...]


@dataclass(frozen=True)
class _Flow:
    source: TaintStep
    variable: str
    calls: tuple[CallEdge, ...] = ()
    propagations: tuple[TaintStep, ...] = ()


@dataclass
class _Execution:
    returned: list[_Flow]
    paths: list[DataflowPath]


class DataflowAnalyzer:
    """Follow tainted arguments and return values across local functions."""

    def analyze(
        self,
        source: str | bytes,
        language: SupportedLanguage,
        *,
        file: str = "<memory>",
    ) -> DataflowReport:
        encoded = source.encode("utf-8") if isinstance(source, str) else source
        tree = parse_source(encoded, language)
        models = {
            region.name: _FunctionModel(
                name=region.name,
                node=region.node,
                parameters=_parameters(region.node, encoded),
            )
            for region in _function_regions(tree.root_node, encoded)
        }
        graph = _build_call_graph(models, encoded, file)
        paths: list[DataflowPath] = []
        for model in models.values():
            execution = self._execute(
                model,
                {},
                models,
                encoded,
                language,
                file,
                active=(),
            )
            paths.extend(execution.paths)
        return DataflowReport(
            call_graph=tuple(graph),
            paths=tuple(_deduplicate_paths(paths)),
        )

    def analyze_file(self, path: str | Path) -> DataflowReport:
        source_path = Path(path)
        language_by_extension: dict[str, SupportedLanguage] = {
            ".py": "python",
            ".go": "go",
            ".java": "java",
        }
        try:
            language = language_by_extension[source_path.suffix.lower()]
        except KeyError as error:
            raise ValueError(
                f"Unsupported source extension: {source_path.suffix}"
            ) from error
        return self.analyze(
            source_path.read_bytes(),
            language,
            file=str(source_path),
        )

    def _execute(
        self,
        model: _FunctionModel,
        inputs: dict[str, list[_Flow]],
        models: dict[str, _FunctionModel],
        source: bytes,
        language: SupportedLanguage,
        file: str,
        *,
        active: tuple[str, ...],
    ) -> _Execution:
        if model.name in active:
            return _Execution(returned=[], paths=[])

        tainted = {name: list(flows) for name, flows in inputs.items()}
        returned: list[_Flow] = []
        paths: list[DataflowPath] = []
        events = [
            node
            for node in _walk_region(model.node)
            if node.type
            in _ASSIGNMENT_TYPES | _CALL_TYPES | _RETURN_TYPES
        ]
        events.sort(key=lambda node: (node.start_byte, _event_priority(node)))

        for node in events:
            if node.type in _ASSIGNMENT_TYPES:
                assignment = _assignment_parts(node, source)
                if assignment is None:
                    continue
                names, value = assignment
                flows, nested_paths = self._evaluate_expression(
                    value,
                    tainted,
                    model,
                    models,
                    source,
                    language,
                    file,
                    active=(*active, model.name),
                )
                paths.extend(nested_paths)
                for name in names:
                    propagation = _step(
                        "propagation",
                        name,
                        node,
                        source,
                        file,
                        model.name,
                    )
                    tainted[name] = [
                        _Flow(
                            source=flow.source,
                            variable=name,
                            calls=flow.calls,
                            propagations=(
                                *flow.propagations,
                                propagation,
                            ),
                        )
                        for flow in flows
                    ]
                continue

            if node.type in _RETURN_TYPES:
                expression = (
                    node.named_children[0]
                    if node.named_children
                    else node
                )
                flows, nested_paths = self._evaluate_expression(
                    expression,
                    tainted,
                    model,
                    models,
                    source,
                    language,
                    file,
                    active=(*active, model.name),
                )
                paths.extend(nested_paths)
                returned.extend(flows)
                continue

            if _inside_assignment_or_return(node, model.node):
                continue
            call_flows, call_paths = self._evaluate_call(
                node,
                tainted,
                model,
                models,
                source,
                language,
                file,
                active=(*active, model.name),
            )
            del call_flows
            paths.extend(call_paths)

        return _Execution(returned=returned, paths=paths)

    def _evaluate_expression(
        self,
        node: Node,
        tainted: dict[str, list[_Flow]],
        model: _FunctionModel,
        models: dict[str, _FunctionModel],
        source: bytes,
        language: SupportedLanguage,
        file: str,
        *,
        active: tuple[str, ...],
    ) -> tuple[list[_Flow], list[DataflowPath]]:
        local_calls = [
            child
            for child in walk_nodes(node)
            if child.type in _CALL_TYPES
            and _callee_name(child, source) in models
        ]
        if local_calls:
            return self._evaluate_call(
                local_calls[0],
                tainted,
                model,
                models,
                source,
                language,
                file,
                active=active,
            )
        return (
            _flows_in_expression(
                node,
                tainted,
                source,
                file=file,
                function=model.name,
            ),
            [],
        )

    def _evaluate_call(
        self,
        node: Node,
        tainted: dict[str, list[_Flow]],
        model: _FunctionModel,
        models: dict[str, _FunctionModel],
        source: bytes,
        language: SupportedLanguage,
        file: str,
        *,
        active: tuple[str, ...],
    ) -> tuple[list[_Flow], list[DataflowPath]]:
        callee_name = _callee_name(node, source)
        arguments_node = node.child_by_field_name("arguments")
        argument_nodes = (
            list(arguments_node.named_children)
            if arguments_node is not None
            else []
        )
        sink = _sink_name(node, source)
        if sink is not None:
            sink_flows = _flows_in_expression(
                arguments_node or node,
                tainted,
                source,
                file=file,
                function=model.name,
            )
            return (
                [],
                [
                    DataflowPath(
                        language=language,
                        variable=flow.variable,
                        source=flow.source,
                        calls=flow.calls,
                        propagations=flow.propagations,
                        sink=_step(
                            "sink",
                            sink,
                            node,
                            source,
                            file,
                            model.name,
                        ),
                    )
                    for flow in sink_flows
                ],
            )

        callee = models.get(callee_name)
        if callee is None:
            return ([], [])
        edge = _edge(model.name, callee.name, node, source, file)
        inputs: dict[str, list[_Flow]] = {}
        for index, parameter in enumerate(callee.parameters):
            if index >= len(argument_nodes):
                break
            flows = _flows_in_expression(
                argument_nodes[index],
                tainted,
                source,
                file=file,
                function=model.name,
            )
            inputs[parameter] = [
                _append_call(flow, edge) for flow in flows
            ]

        execution = self._execute(
            callee,
            inputs,
            models,
            source,
            language,
            file,
            active=active,
        )
        returned = [
            _append_call(flow, edge) for flow in execution.returned
        ]
        return returned, execution.paths


class DataflowRule(Rule):
    id = "004-cross-function-dataflow"
    severity_hint = "critical"

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

        report = DataflowAnalyzer().analyze(
            source,
            language,
            file=file,
        )
        return [
            Finding(
                id=str(uuid4()),
                source=FindingSource.CODE,
                severity=FindingSeverity.CRITICAL,
                confidence=0.92,
                title=(
                    f"Cross-function taint reaches {path.sink.name}"
                ),
                description=(
                    f"{path.variable} crosses {len(path.calls)} call "
                    f"boundary(s) before reaching {path.sink.name}."
                ),
                evidence=path.evidence,
                tags=frozenset({"dataflow", "taint", language}),
                metadata={
                    "rule_id": self.id,
                    "file": file,
                    "call_graph": [
                        {
                            "caller": edge.caller,
                            "callee": edge.callee,
                            "line": edge.line,
                        }
                        for edge in report.call_graph
                    ],
                    "path": path.to_dict(),
                },
            )
            for path in report.paths
            if path.calls
        ]


def register_dataflow_rule(
    registry: RuleRegistry | None = None,
) -> RuleRegistry:
    target = registry or RuleRegistry()
    target.register(DataflowRule())
    return target


def _parameters(node: Node, source: bytes) -> tuple[str, ...]:
    parameters = node.child_by_field_name("parameters")
    if parameters is None:
        return ()
    names: list[str] = []
    for child in parameters.named_children:
        if child.type in {"identifier", "variable_name"}:
            names.append(_text(child, source))
            continue
        if child.type not in _PARAMETER_TYPES:
            continue
        name = child.child_by_field_name("name")
        if name is not None:
            names.append(_text(name, source))
    return tuple(names)


def _build_call_graph(
    models: dict[str, _FunctionModel],
    source: bytes,
    file: str,
) -> list[CallEdge]:
    edges: dict[tuple[str, str, int], CallEdge] = {}
    for model in models.values():
        for node in _walk_region(model.node):
            if node.type not in _CALL_TYPES:
                continue
            callee = _callee_name(node, source)
            if callee not in models:
                continue
            edge = _edge(model.name, callee, node, source, file)
            edges[(edge.caller, edge.callee, edge.line)] = edge
    return sorted(
        edges.values(),
        key=lambda edge: (edge.file, edge.line, edge.caller, edge.callee),
    )


def _edge(
    caller: str,
    callee: str,
    node: Node,
    source: bytes,
    file: str,
) -> CallEdge:
    arguments = node.child_by_field_name("arguments")
    row, _ = node.start_point
    return CallEdge(
        caller=caller,
        callee=callee,
        file=file,
        line=row + 1,
        arguments=tuple(
            _text(child, source)
            for child in (
                arguments.named_children if arguments is not None else []
            )
        ),
    )


def _callee_name(node: Node, source: bytes) -> str:
    target = _call_target(node, source)
    return target.rsplit(".", 1)[-1]


def _flows_in_expression(
    node: Node,
    tainted: dict[str, list[_Flow]],
    source: bytes,
    *,
    file: str,
    function: str,
) -> list[_Flow]:
    flows: list[_Flow] = []
    for child in walk_nodes(node):
        source_name = _source_name(child, source)
        if source_name is None:
            continue
        flows.append(
            _Flow(
                source=_step(
                    "source",
                    source_name,
                    child,
                    source,
                    file,
                    function,
                ),
                variable=source_name,
            )
        )
        break

    expression = _text(node, source)
    for variable, variable_flows in tainted.items():
        if re.search(
            rf"(?<![\w$]){re.escape(variable)}(?![\w$])",
            expression,
        ):
            flows.extend(variable_flows)
    return _deduplicate_flows(flows)


def _append_call(flow: _Flow, edge: CallEdge) -> _Flow:
    calls = (
        flow.calls
        if edge in flow.calls
        else (*flow.calls, edge)
    )
    return _Flow(
        source=flow.source,
        variable=flow.variable,
        calls=calls,
        propagations=flow.propagations,
    )


def _inside_assignment_or_return(node: Node, root: Node) -> bool:
    current = node.parent
    while current is not None and current != root:
        if current.type in _ASSIGNMENT_TYPES | _RETURN_TYPES:
            return True
        current = current.parent
    return False


def _event_priority(node: Node) -> int:
    if node.type in _ASSIGNMENT_TYPES:
        return 0
    if node.type in _RETURN_TYPES:
        return 2
    return 1


def _deduplicate_flows(flows: Iterable[_Flow]) -> list[_Flow]:
    unique: dict[tuple[object, ...], _Flow] = {}
    for flow in flows:
        key = (
            flow.source.file,
            flow.source.line,
            flow.variable,
            tuple((edge.caller, edge.callee, edge.line) for edge in flow.calls),
        )
        unique[key] = flow
    return list(unique.values())


def _deduplicate_paths(
    paths: Iterable[DataflowPath],
) -> list[DataflowPath]:
    unique: dict[tuple[object, ...], DataflowPath] = {}
    for path in paths:
        key = (
            path.source.file,
            path.source.line,
            path.sink.function,
            path.sink.line,
            tuple(
                (edge.caller, edge.callee, edge.line)
                for edge in path.calls
            ),
        )
        unique[key] = path
    return list(unique.values())


def _step_dict(step: TaintStep) -> dict[str, object]:
    return {
        "kind": step.kind,
        "name": step.name,
        "file": step.file,
        "function": step.function,
        "line": step.line,
        "column": step.column,
        "detail": step.detail,
    }


__all__ = [
    "CallEdge",
    "DataflowAnalyzer",
    "DataflowPath",
    "DataflowReport",
    "DataflowRule",
    "register_dataflow_rule",
]
