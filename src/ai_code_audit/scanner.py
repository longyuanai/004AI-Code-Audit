"""Tree-sitter dispatch and Phase-2 repository scanning."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ai_code_audit.gitutils import collect_diff
from ai_code_audit.languages import (
    FunctionSpan,
    LanguageAdapter,
    adapter_for_path,
    get_adapter,
)
from ai_code_audit.languages.base import walk_nodes
from ai_code_audit.languages.typescript_lang import TypeScriptLanguageAdapter

EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".python-deps",
        ".pytest-tmp",
        ".venv",
        "build",
        "dist",
        "node_modules",
    }
)
SOURCE_PATTERN = re.compile(
    r"\b(?:argv|cin|FormValue|getParameter|getline|input)\b"
    r"|(?:req|request)\.(?:body|params|query)",
    re.IGNORECASE,
)
SINK_PATTERN = re.compile(
    r"\b(?:Command|eval|exec|execute|executeQuery|popen|query|system)\s*\(",
    re.IGNORECASE,
)


def discover_files(
    repo_path: str | Path,
    languages: Sequence[str] | None = None,
    *,
    include_files: Iterable[str | Path] | None = None,
) -> list[tuple[Path, LanguageAdapter]]:
    root = Path(repo_path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"repo_path is not a directory: {root}")
    selected = (
        {get_adapter(name).name for name in languages}
        if languages is not None
        else None
    )
    allowed = (
        {_relative_key(root, path) for path in include_files}
        if include_files is not None
        else None
    )
    discovered: list[tuple[Path, LanguageAdapter]] = []
    for path in root.rglob("*"):
        if not path.is_file() or EXCLUDED_PARTS.intersection(path.parts):
            continue
        adapter = adapter_for_path(path)
        if adapter is None or (selected is not None and adapter.name not in selected):
            continue
        if allowed is not None and _relative_key(root, path) not in allowed:
            continue
        discovered.append((path.resolve(), adapter))
    return sorted(discovered, key=lambda item: item[0].as_posix().lower())


def scan_repository(
    repo_path: str | Path,
    languages: Sequence[str] | None = None,
    *,
    include_files: Iterable[str | Path] | None = None,
    line_ranges: Mapping[str, Sequence[tuple[int, int]]] | None = None,
) -> dict[str, object]:
    root = Path(repo_path).expanduser().resolve()
    files = discover_files(root, languages, include_files=include_files)
    findings: list[dict[str, object]] = []
    function_count = 0
    class_count = 0
    actual_languages: list[str] = []

    for source_file, adapter in files:
        source = source_file.read_bytes()
        parser = _parser_for_file(adapter, source_file)
        tree = parser.parse(source)
        function_spans = adapter.extract_functions(tree)
        function_count += len(function_spans)
        class_count += len(adapter.extract_classes(tree))
        if adapter.name not in actual_languages:
            actual_languages.append(adapter.name)
        relative_path = source_file.relative_to(root).as_posix()
        findings.extend(
            _security_findings(
                source,
                tree=tree,
                function_spans=function_spans,
                source_file=source_file,
                relative_path=relative_path,
                language=adapter.name,
                changed_ranges=(
                    line_ranges.get(relative_path)
                    if line_ranges is not None
                    else None
                ),
            )
        )

    findings.sort(
        key=lambda finding: (
            str(finding["host"]),
            int(finding["metadata"]["line"]),  # type: ignore[index]
        )
    )
    return {
        "findings": findings,
        "summary": {
            "repo_path": str(root),
            "repository_source": "local",
            "files_scanned": len(files),
            "languages": actual_languages,
            "functions": function_count,
            "classes": class_count,
        },
        "warnings": [],
    }


def scan_diff(
    repo_path: str | Path,
    base_ref: str,
    head_ref: str,
    languages: Sequence[str] | None = None,
) -> dict[str, object]:
    diff = collect_diff(repo_path, base_ref, head_ref)
    envelope = scan_repository(
        repo_path,
        languages,
        include_files=diff.files,
        line_ranges=diff.line_ranges,
    )
    envelope["summary"]["repository_source"] = "git-diff"
    envelope["summary"]["diff"] = {
        "base": base_ref,
        "head": head_ref,
        "files": list(diff.files),
    }
    return envelope


def _parser_for_file(adapter: LanguageAdapter, path: Path):
    if isinstance(adapter, TypeScriptLanguageAdapter):
        return adapter.parser_for_extension(path.suffix)
    return adapter.parser()


def _mask_literals(tree, source: bytes) -> bytes:
    """Blank out comment and string bytes, preserving offsets and newlines.

    The source/sink patterns are matched against raw text, so without this a
    docstring mentioning "input" counted as a taint source and any prose
    containing "query(" counted as a sink. Replacing those spans with spaces
    keeps every line number and column intact while removing them from
    consideration. Only the literal's own bytes are cleared, so the call that
    *takes* a string argument -- `execute("SELECT ...")` -- still matches.
    """

    masked = bytearray(source)
    limit = len(masked)
    for node in walk_nodes(tree.root_node):
        node_type = node.type
        if not (
            "comment" in node_type
            or "string" in node_type
            or node_type in {"char_literal", "character_literal"}
        ):
            continue
        for index in range(node.start_byte, min(node.end_byte, limit)):
            if masked[index] not in (0x0A, 0x0D):
                masked[index] = 0x20
    return bytes(masked)


def _enclosing_span(
    line: int,
    spans: Sequence[FunctionSpan],
) -> FunctionSpan | None:
    """Return the innermost function containing `line`, or None at module level."""

    enclosing: FunctionSpan | None = None
    for span in spans:
        if span.start_line <= line <= span.end_line and (
            enclosing is None or span.start_line > enclosing.start_line
        ):
            enclosing = span
    return enclosing


def _security_findings(
    source: bytes,
    *,
    tree,
    function_spans: Sequence[FunctionSpan],
    source_file: Path,
    relative_path: str,
    language: str,
    changed_ranges: Sequence[tuple[int, int]] | None,
) -> list[dict[str, object]]:
    raw_lines = source.decode("utf-8", errors="replace").splitlines()
    code_lines = _mask_literals(tree, source).decode(
        "utf-8", errors="replace"
    ).splitlines()

    source_lines = [
        number
        for number, line in enumerate(code_lines, start=1)
        if SOURCE_PATTERN.search(line)
    ]
    if not source_lines:
        return []

    findings: list[dict[str, object]] = []
    for line_number, line in enumerate(code_lines, start=1):
        sink = SINK_PATTERN.search(line)
        if sink is None:
            continue
        if changed_ranges is not None and not _line_in_ranges(
            line_number, changed_ranges
        ):
            continue

        # A source anywhere in the file used to justify every later sink, so a
        # read in one function was reported as reaching a call in an unrelated
        # one. Require the source to be in the same function as the sink, or
        # at module level where it is genuinely in scope for it.
        sink_scope = _enclosing_span(line_number, function_spans)
        reaching = [
            candidate
            for candidate in source_lines
            if candidate <= line_number
            and (
                _enclosing_span(candidate, function_spans)
                in (sink_scope, None)
            )
        ]
        if not reaching:
            continue
        nearest_source = max(reaching)

        digest = hashlib.sha256(
            f"{relative_path}\0{language}\0{line_number}\0{sink.group(0)}".encode()
        ).hexdigest()[:12]
        sink_name = sink.group(0).rstrip("(").strip()
        scope_label = (
            f"function {sink_scope.name}"
            if sink_scope is not None
            else "module level"
        )
        # Deliberately not "reaches": this is a co-occurrence heuristic with
        # no variable tracking, so it cannot show the value read at the source
        # is the one passed to the sink. Severity and confidence say so --
        # codeguard.taint is the AST dataflow engine that can prove it.
        narrative = (
            f"Input read at line {nearest_source} may reach {sink_name} "
            f"at line {line_number} ({scope_label}); no dataflow proof."
        )
        findings.append(
            {
                "id": f"code-{language[:2]}-{digest}",
                "source": "004",
                "severity": "medium",
                "confidence": 0.5,
                "title": (
                    f"Possible taint flow in {relative_path}:{line_number}"
                ),
                "description": narrative,
                "host": str(source_file),
                "narrative": narrative,
                "evidence": [
                    f"source line {nearest_source}: "
                    f"{raw_lines[nearest_source - 1].strip()}",
                    f"sink line {line_number}: "
                    f"{raw_lines[line_number - 1].strip()}",
                ],
                "tags": [language, "taint", "heuristic"],
                "metadata": {
                    "language": language,
                    "line": line_number,
                    "column": sink.start() + 1,
                    "relative_path": relative_path,
                    "rule_id": "004-phase2-taint",
                    "analysis": "heuristic-cooccurrence",
                    "scope": scope_label,
                },
            }
        )
    return findings


def _line_in_ranges(
    line: int,
    ranges: Sequence[tuple[int, int]],
) -> bool:
    return any(start <= line <= end for start, end in ranges)


def _relative_key(root: Path, path: str | Path) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        candidate = candidate.resolve().relative_to(root)
    return candidate.as_posix()


__all__ = ["discover_files", "scan_diff", "scan_repository"]
