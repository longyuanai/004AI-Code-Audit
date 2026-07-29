"""Opengrep subprocess adapter with frozen-envelope normalization."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from ai_code_audit.backends.base import (
    BackendExecutionError,
    BackendOutputError,
    BackendUnavailableError,
    ScanRequest,
)
from ai_code_audit.scanner import discover_files

SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "INVENTORY": "info",
    "EXPERIMENT": "info",
}


class OpengrepBackend:
    name = "opengrep"

    def __init__(
        self,
        executable: str | Path,
        rules_path: str | Path,
        *,
        timeout: float = 120.0,
    ) -> None:
        self.executable = Path(executable).expanduser().resolve()
        self.rules_path = Path(rules_path).expanduser().resolve()
        self.timeout = timeout
        self.rule_ids = _load_rule_ids(self.rules_path)

    def available(self) -> bool:
        return self.executable.is_file() and self.rules_path.exists()

    def scan(self, request: ScanRequest) -> dict[str, object]:
        if not self.available():
            raise BackendUnavailableError(
                "Opengrep requires an executable and rules directory"
            )
        files = discover_files(
            request.repo_path,
            request.languages,
            include_files=request.include_files,
        )
        if not files:
            return _empty_envelope(request.repo_path)

        command = [
            str(self.executable),
            "scan",
            "--json",
            "--quiet",
            "--taint-intrafile",
            "--config",
            str(self.rules_path),
            *(str(path) for path, _ in files),
        ]
        environment = os.environ.copy()
        environment["SEMGREP_SEND_METRICS"] = "off"
        environment["OPENGREP_SEND_METRICS"] = "off"
        try:
            completed = subprocess.run(
                command,
                cwd=request.repo_path,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as error:
            raise BackendExecutionError(
                f"Opengrep timed out after {self.timeout:g}s"
            ) from error
        except OSError as error:
            raise BackendExecutionError(
                f"Unable to start Opengrep: {error}"
            ) from error
        if completed.returncode != 0:
            detail = completed.stderr.strip() or "no error output"
            raise BackendExecutionError(
                f"Opengrep exited with {completed.returncode}: {detail}"
            )
        try:
            document = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise BackendOutputError("Opengrep emitted invalid JSON") from error
        if not isinstance(document, dict):
            raise BackendOutputError("Opengrep JSON must be an object")
        findings = _normalize_findings(
            document,
            repo_path=request.repo_path,
            line_ranges=request.line_ranges,
            known_rule_ids=self.rule_ids,
        )
        languages = list(
            dict.fromkeys(adapter.name for _, adapter in files)
        )
        return {
            "findings": findings,
            "summary": {
                "repo_path": str(request.repo_path),
                "repository_source": "local",
                "files_scanned": len(files),
                "languages": languages,
                "backend": self.name,
            },
            "warnings": _document_warnings(document),
        }


def _normalize_findings(
    document: Mapping[str, Any],
    *,
    repo_path: Path,
    line_ranges: Mapping[str, Sequence[tuple[int, int]]] | None,
    known_rule_ids: frozenset[str],
) -> list[dict[str, object]]:
    raw_results = document.get("results", [])
    if not isinstance(raw_results, list):
        raise BackendOutputError("Opengrep results must be a list")
    findings: list[dict[str, object]] = []
    for result in raw_results:
        if not isinstance(result, dict):
            raise BackendOutputError("Opengrep result must be an object")
        findings.append(
            _normalize_finding(
                result,
                repo_path=repo_path,
                known_rule_ids=known_rule_ids,
            )
        )
    if line_ranges is not None:
        findings = [
            finding
            for finding in findings
            if _line_is_selected(finding, line_ranges)
        ]
    findings.sort(
        key=lambda item: (
            str(item["metadata"]["relative_path"]),  # type: ignore[index]
            int(item["metadata"]["line"]),  # type: ignore[index]
            str(item["metadata"]["rule_id"]),  # type: ignore[index]
        )
    )
    return findings


def _normalize_finding(
    result: Mapping[str, Any],
    *,
    repo_path: Path,
    known_rule_ids: frozenset[str],
) -> dict[str, object]:
    try:
        raw_path = str(result["path"])
        start = result["start"]
        line = int(start["line"])
        column = int(start.get("col", 1))
    except (KeyError, TypeError, ValueError) as error:
        raise BackendOutputError(
            "Opengrep result is missing path/start location"
        ) from error
    source_file = _source_path(raw_path, repo_path)
    relative_path = source_file.relative_to(repo_path).as_posix()
    extra = result.get("extra", {})
    if not isinstance(extra, dict):
        raise BackendOutputError("Opengrep result extra must be an object")
    rule_id = _stable_rule_id(
        str(result.get("check_id") or "opengrep-unknown"),
        known_rule_ids,
    )
    message = str(extra.get("message") or f"Opengrep rule {rule_id} matched")
    raw_severity = str(extra.get("severity") or "WARNING").upper()
    severity = SEVERITY_MAP.get(raw_severity, "medium")
    confidence = _confidence(extra)
    language = _language(extra, source_file)
    digest = hashlib.sha256(
        f"{relative_path}\0{rule_id}\0{line}\0{message}".encode()
    ).hexdigest()[:12]
    evidence = [message]
    matched_lines = extra.get("lines")
    if isinstance(matched_lines, str) and matched_lines.strip():
        evidence.append(matched_lines.strip())
    return {
        "id": f"code-og-{digest}",
        "source": "004",
        "severity": severity,
        "confidence": confidence,
        "title": f"{message} in {relative_path}:{line}",
        "description": message,
        "host": str(source_file),
        "narrative": message,
        "evidence": evidence,
        "tags": sorted({"opengrep", language}),
        "metadata": {
            "backend": "opengrep",
            "language": language,
            "line": line,
            "column": column,
            "relative_path": relative_path,
            "rule_id": rule_id,
        },
    }


def _source_path(raw_path: str, repo_path: Path) -> Path:
    candidate = Path(raw_path)
    source_file = (
        candidate.resolve()
        if candidate.is_absolute()
        else (repo_path / candidate).resolve()
    )
    try:
        source_file.relative_to(repo_path)
    except ValueError as error:
        raise BackendOutputError(
            f"Opengrep result escaped repository: {raw_path}"
        ) from error
    return source_file


def _confidence(extra: Mapping[str, Any]) -> float:
    metadata = extra.get("metadata")
    raw = metadata.get("confidence") if isinstance(metadata, dict) else None
    try:
        confidence = float(raw) if raw is not None else 0.9
    except (TypeError, ValueError):
        confidence = 0.9
    return min(1.0, max(0.0, confidence))


def _language(extra: Mapping[str, Any], source_file: Path) -> str:
    metadata = extra.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("language"), str):
        return metadata["language"].lower()
    suffixes = {
        ".c": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".cxx": "cpp",
        ".go": "go",
        ".java": "java",
        ".py": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
    }
    return suffixes.get(source_file.suffix.lower(), "unknown")


def _line_is_selected(
    finding: Mapping[str, object],
    line_ranges: Mapping[str, Sequence[tuple[int, int]]],
) -> bool:
    metadata = finding["metadata"]
    assert isinstance(metadata, dict)
    relative_path = str(metadata["relative_path"])
    line = int(metadata["line"])
    ranges = line_ranges.get(relative_path)
    return ranges is not None and any(
        start <= line <= end for start, end in ranges
    )


def _document_warnings(document: Mapping[str, Any]) -> list[str]:
    errors = document.get("errors", [])
    if not isinstance(errors, list):
        return []
    return [f"Opengrep warning: {error}" for error in errors if error]


def _load_rule_ids(rules_path: Path) -> frozenset[str]:
    files = (
        [rules_path]
        if rules_path.is_file()
        else sorted(
            (
                *rules_path.rglob("*.yaml"),
                *rules_path.rglob("*.yml"),
            )
        )
        if rules_path.is_dir()
        else []
    )
    rule_ids: set[str] = set()
    pattern = re.compile(r"^\s*-\s+id:\s*['\"]?([^'\"\s]+)")
    for path in files:
        for line in path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines():
            match = pattern.match(line)
            if match:
                rule_ids.add(match.group(1))
    return frozenset(rule_ids)


def _stable_rule_id(
    raw_rule_id: str,
    known_rule_ids: frozenset[str],
) -> str:
    matches = [
        rule_id
        for rule_id in known_rule_ids
        if raw_rule_id == rule_id
        or raw_rule_id.endswith(f".{rule_id}")
    ]
    return max(matches, key=len) if matches else raw_rule_id


def _empty_envelope(repo_path: Path) -> dict[str, object]:
    return {
        "findings": [],
        "summary": {
            "repo_path": str(repo_path),
            "repository_source": "local",
            "files_scanned": 0,
            "languages": [],
            "backend": "opengrep",
        },
        "warnings": [],
    }


__all__ = ["OpengrepBackend", "SEVERITY_MAP"]
