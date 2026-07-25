"""Phase-2 multi-language and SARIF command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from ai_code_audit.output import (
    export_sarif,
    render_envelope,
    render_sarif,
)
from ai_code_audit.scanner import scan_repository
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
    with _materialize_repo(payload) as (
        repo_path,
        repository_source,
        acquisition_warnings,
    ):
        try:
            envelope = scan_repository(repo_path, languages)
        except (KeyError, ValueError) as error:
            raise CLIInputError(str(error)) from error
        envelope["summary"]["repository_source"] = repository_source
        envelope["warnings"] = [
            *acquisition_warnings,
            *envelope["warnings"],
        ]
        return envelope


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
