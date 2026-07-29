"""Phase-2 multi-language and SARIF command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from ai_code_audit.output import (
    export_sarif,
    render_envelope,
    render_sarif,
)
from ai_code_audit.backends import BackendError, ScanRequest, scan_with_backend
from ai_code_audit.gitutils import GitDiffError, collect_diff
from ai_code_audit.scanner import scan_diff, scan_repository
from ai_codeguard.cli import (
    CLIInputError,
    _materialize_repo,
    _payload_from_args,
)


def scan_payload(payload: dict[str, Any]) -> dict[str, object]:
    languages = payload.get("languages")
    if languages is not None and (
        not isinstance(languages, list)
        or not all(isinstance(item, str) for item in languages)
    ):
        raise CLIInputError("payload.languages must be a list of strings")
    backend = _backend_input(payload)
    diff = _diff_input(payload)
    with _materialize_repo(payload) as (
        repo_path,
        repository_source,
        acquisition_warnings,
    ):
        try:
            if backend == "builtin":
                envelope = (
                    scan_diff(
                        repo_path,
                        diff["base"],
                        diff["head"],
                        languages,
                    )
                    if diff is not None
                    else scan_repository(repo_path, languages)
                )
            else:
                diff_scope = (
                    collect_diff(repo_path, diff["base"], diff["head"])
                    if diff is not None
                    else None
                )
                request = ScanRequest.create(
                    repo_path,
                    languages,
                    include_files=(
                        diff_scope.files if diff_scope is not None else None
                    ),
                    line_ranges=(
                        diff_scope.line_ranges
                        if diff_scope is not None
                        else None
                    ),
                )
                envelope = scan_with_backend(
                    request,
                    backend=backend,
                    opengrep_path=os.environ.get("CODEGUARD_OPENGREP_PATH"),
                    rules_path=os.environ.get("CODEGUARD_OPENGREP_RULES"),
                    timeout=_backend_timeout(),
                )
                if diff is not None and diff_scope is not None:
                    envelope["summary"]["repository_source"] = "git-diff"
                    envelope["summary"]["diff"] = {
                        "base": diff["base"],
                        "head": diff["head"],
                        "files": list(diff_scope.files),
                    }
        except (BackendError, GitDiffError, KeyError, ValueError) as error:
            raise CLIInputError(str(error)) from error
        if diff is None:
            envelope["summary"]["repository_source"] = repository_source
        envelope["warnings"] = [
            *acquisition_warnings,
            *envelope["warnings"],
        ]
        return envelope


def _backend_input(payload: dict[str, Any]) -> str:
    raw = payload.get("backend", "builtin")
    if not isinstance(raw, str):
        raise CLIInputError("payload.backend must be a string")
    backend = raw.lower()
    if backend not in {"auto", "builtin", "opengrep"}:
        raise CLIInputError(
            "payload.backend must be auto, builtin, or opengrep"
        )
    return backend


def _backend_timeout() -> float:
    raw = os.environ.get("CODEGUARD_BACKEND_TIMEOUT", "120")
    try:
        timeout = float(raw)
    except ValueError as error:
        raise CLIInputError(
            "CODEGUARD_BACKEND_TIMEOUT must be a number"
        ) from error
    if timeout <= 0:
        raise CLIInputError(
            "CODEGUARD_BACKEND_TIMEOUT must be greater than zero"
        )
    return timeout


def _diff_input(payload: dict[str, Any]) -> dict[str, str] | None:
    raw_diff = payload.get("diff")
    if raw_diff is None:
        return None
    if not isinstance(raw_diff, dict):
        raise CLIInputError("payload.diff must be an object")
    base = raw_diff.get("base")
    head = raw_diff.get("head")
    if not isinstance(base, str) or not base:
        raise CLIInputError("payload.diff.base must be a non-empty string")
    if not isinstance(head, str) or not head:
        raise CLIInputError("payload.diff.head must be a non-empty string")
    return {"base": base, "head": head}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-code-audit",
        description="Multi-language code audit with JSON or SARIF output.",
    )
    parser.add_argument("command", nargs="?", choices=("scan",))
    parser.add_argument("--input", help="One JSON payload object.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", choices=("envelope", "sarif"), default="envelope")
    parser.add_argument("--output-file")
    parser.add_argument("--repo-path")
    parser.add_argument("--git-url")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _configure_utf8_streams()
    args = build_parser().parse_args(argv)
    if args.output == "sarif" and args.json:
        return _input_error("--json cannot be combined with --output sarif", False)
    if args.output == "sarif" and not args.output_file:
        return _input_error("--output-file is required for SARIF output", False)
    try:
        payload = _payload_from_args(
            raw_input=args.input,
            repo_path=args.repo_path,
            git_url=args.git_url,
        )
        envelope = scan_payload(payload)
    except (CLIInputError, json.JSONDecodeError) as error:
        return _input_error(str(error), args.json)

    if args.output == "sarif":
        document = export_sarif(envelope["findings"])
        output_path = Path(args.output_file).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render_sarif(document), encoding="utf-8")
        print(str(output_path))
        return 0
    if args.json:
        print(render_envelope(envelope))
    else:
        summary = envelope["summary"]
        print(
            f"Scanned {summary['files_scanned']} files; "
            f"found {len(envelope['findings'])} issue(s)."
        )
    return 0


def _input_error(message: str, json_output: bool) -> int:
    if json_output:
        print(
            json.dumps(
                {"findings": [], "error": message, "warnings": []},
                ensure_ascii=False,
            )
        )
    else:
        print(f"AI-CodeGuard input error: {message}", file=sys.stderr)
    return 2


def _configure_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")


__all__ = ["build_parser", "main", "scan_payload"]
