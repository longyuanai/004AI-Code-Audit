"""Tree-sitter dispatch and Phase-2 repository scanning."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ai_code_audit.gitutils import collect_diff
from ai_code_audit.languages import (
    LanguageAdapter,
    adapter_for_path,
    get_adapter,
)
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
        function_count += len(adapter.extract_functions(tree))
        class_count += len(adapter.extract_classes(tree))
        if adapter.name not in actual_languages:
            actual_languages.append(adapter.name)
        relative_path = source_file.relative_to(root).as_posix()
        findings.extend(
            _security_findings(
                source,
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


def _security_findings(
    source: bytes,
    *,
    source_file: Path,
    relative_path: str,
    language: str,
    changed_ranges: Sequence[tuple[int, int]] | None,
) -> list[dict[str, object]]:
    text = source.decode("utf-8", errors="replace")
    source_lines = [
        number
        for number, line in enumerate(text.splitlines(), start=1)
        if SOURCE_PATTERN.search(line)
    ]
    if not source_lines:
        return []
    first_source = min(source_lines)
    findings: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        sink = SINK_PATTERN.search(line)
        if sink is None or line_number < first_source:
            continue
        if changed_ranges is not None and not _line_in_ranges(
            line_number, changed_ranges
        ):
            continue
        digest = hashlib.sha256(
            f"{relative_path}\0{language}\0{line_number}\0{sink.group(0)}".encode()
        ).hexdigest()[:12]
        narrative = (
            f"User-controlled input reaches {sink.group(0).rstrip('(')}."
        )
        findings.append(
            {
                "id": f"code-{language[:2]}-{digest}",
                "source": "004",
                "severity": "high",
                "confidence": 0.85,
                "title": f"Potential taint flow in {relative_path}:{line_number}",
                "description": narrative,
                "host": str(source_file),
                "narrative": narrative,
                "evidence": [
                    f"source line {first_source}",
                    f"sink line {line_number}: {line.strip()}",
                ],
                "tags": [language, "taint"],
                "metadata": {
                    "language": language,
                    "line": line_number,
                    "column": sink.start() + 1,
                    "relative_path": relative_path,
                    "rule_id": "004-phase2-taint",
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
