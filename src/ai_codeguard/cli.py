"""JSON CLI consumed by shared-integration's CodeAdapter."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from codeguard import rules
from codeguard.dataflow import DataflowRule, register_dataflow_rule
from codeguard.rules.taint import TaintSourceToSinkRule
from codeguard.taint import TaintAnalyzer
from codeguard.v05 import Finding, RuleContext, RuleEngine

SUPPORTED_LANGUAGES = ("python", "go", "java")
LANGUAGE_EXTENSIONS = {
    "python": ".py",
    "go": ".go",
    "java": ".java",
}
RULE_ALIASES = {
    TaintSourceToSinkRule.id: TaintSourceToSinkRule.id,
    DataflowRule.id: DataflowRule.id,
    "taint": TaintSourceToSinkRule.id,
    "dataflow": DataflowRule.id,
}
EXCLUDED_PARTS = {
    ".git",
    ".python-deps",
    ".pytest-tmp",
    ".venv",
    "build",
    "dist",
    "node_modules",
}

# `git_url` reaches this process from adapter callers, and `git clone` accepts
# far more than remote URLs: a bare path or `file://` clones any repository on
# the scanner host, and findings echo matched source lines back to the caller,
# so an unrestricted value turns a scan request into a local-source read (and
# an internal URL into an SSRF). `ext::<command>` is a command-execution
# transport -- current Git refuses it by default, but an environment with
# `protocol.ext.allow=always` would not.
#
# Default to the two transports that address a genuine remote with transport
# security. Operators who need more (a `file://` mirror, a plaintext internal
# host) opt in explicitly via CODEGUARD_GIT_ALLOWED_SCHEMES.
DEFAULT_GIT_URL_SCHEMES = frozenset({"https", "ssh", "git+ssh"})
GIT_URL_SCHEMES_ENV_VAR = "CODEGUARD_GIT_ALLOWED_SCHEMES"
_URL_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
# Git's transport-helper form, e.g. `ext::sh -c ...` or `transport::address`.
_TRANSPORT_HELPER = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)::")
# scp-like shorthand, e.g. `git@github.com:owner/repo.git`. Rejects anything
# containing a path separator before the colon so Windows paths do not match.
_SCP_LIKE = re.compile(r"^[^/\\:]+@[^/\\:]+:")


class CLIInputError(ValueError):
    """Raised for malformed adapter input."""


class GitCloneError(CLIInputError):
    """Raised when a shallow clone cannot be completed."""


def scan_payload(payload: dict[str, Any]) -> dict[str, Any]:
    with _materialize_repo(payload) as (
        repo_path,
        repository_source,
        acquisition_warnings,
    ):
        return _scan_local_payload(
            payload,
            repo_path=repo_path,
            repository_source=repository_source,
            acquisition_warnings=acquisition_warnings,
        )


def _scan_local_payload(
    payload: dict[str, Any],
    *,
    repo_path: Path,
    repository_source: str,
    acquisition_warnings: list[str],
) -> dict[str, Any]:
    languages, language_warnings = _languages(payload)
    rule_ids, rule_warnings = _rule_ids(payload)
    files = _discover_files(repo_path, languages)
    registry = rules.default()
    register_dataflow_rule(registry)
    engine = RuleEngine(registry)
    core_rule_ids = tuple(
        rule.id
        for rule in registry.all()
        if rule.id
        not in {TaintSourceToSinkRule.id, DataflowRule.id}
    )
    findings: list[dict[str, Any]] = []

    for source_file, language in files:
        source = source_file.read_bytes()
        facts = {
            "source": source,
            "language": language,
            "file": str(source_file),
        }
        context = RuleContext(
            subject=str(source_file),
            facts=facts,
        )
        file_rule_ids = tuple(
            rule_id
            for rule_id in rule_ids
            if rule_id != TaintSourceToSinkRule.id
        )
        if "rules" not in payload:
            file_rule_ids = (*core_rule_ids, *file_rule_ids)
        for finding in engine.evaluate(
            context,
            rule_ids=file_rule_ids,
        ):
            findings.append(
                _finding_envelope(
                    finding,
                    source_file=source_file,
                    repo_path=repo_path,
                    language=language,
                )
            )
        if TaintSourceToSinkRule.id not in rule_ids:
            continue
        for path in TaintAnalyzer().analyze(
            source,
            language,
            file=str(source_file),
        ):
            flow_context = RuleContext(
                subject=str(source_file),
                facts={**facts, "taint_flow": path.to_dict()},
            )
            for finding in engine.evaluate(
                flow_context,
                rule_ids=[TaintSourceToSinkRule.id],
            ):
                findings.append(
                    _finding_envelope(
                        finding,
                        source_file=source_file,
                        repo_path=repo_path,
                        language=language,
                    )
                )

    findings.sort(
        key=lambda finding: (
            finding["host"],
            finding["metadata"]["line"],
            finding["metadata"]["rule_id"],
        )
    )
    return {
        "findings": findings,
        "summary": {
            "repo_path": str(repo_path),
            "repository_source": repository_source,
            "files_scanned": len(files),
            "languages": list(languages),
            "rules": list(rule_ids),
        },
        "warnings": [
            *acquisition_warnings,
            *language_warnings,
            *rule_warnings,
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m ai_codeguard.cli",
        description="Scan a repository and emit a Finding JSON envelope.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("scan",),
        help="Optional compatibility command; defaults to scan.",
    )
    parser.add_argument(
        "--input",
        help="JSON payload; if omitted, read one JSON object from stdin.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the integration JSON envelope.",
    )
    parser.add_argument(
        "--repo-path",
        help="Local repository path; also used as git clone fallback.",
    )
    parser.add_argument(
        "--git-url",
        help="Git URL to shallow-clone before scanning.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _configure_utf8_streams()
    args = build_parser().parse_args(argv)
    del args.command
    try:
        payload = _payload_from_args(
            raw_input=args.input,
            repo_path=args.repo_path,
            git_url=args.git_url,
        )
        envelope = scan_payload(payload)
    except (CLIInputError, json.JSONDecodeError) as error:
        if args.json:
            print(
                json.dumps(
                    {
                        "findings": [],
                        "error": str(error),
                        "warnings": [],
                    },
                    ensure_ascii=False,
                )
            )
        else:
            print(f"AI-CodeGuard input error: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(envelope, ensure_ascii=False))
    else:
        print(
            f"Scanned {envelope['summary']['files_scanned']} files; "
            f"found {len(envelope['findings'])} issue(s)."
        )
    return 0


def _configure_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")


def _load_payload(raw_input: str | None) -> dict[str, Any]:
    raw = raw_input if raw_input is not None else sys.stdin.read()
    if not raw.strip():
        raise CLIInputError("expected JSON via --input or stdin")
    decoded = json.loads(raw)
    if not isinstance(decoded, dict):
        raise CLIInputError("input payload must be a JSON object")
    return decoded


def _payload_from_args(
    *,
    raw_input: str | None,
    repo_path: str | None,
    git_url: str | None,
) -> dict[str, Any]:
    if raw_input is None and (repo_path is not None or git_url is not None):
        payload: dict[str, Any] = {}
    else:
        payload = _load_payload(raw_input)
    if repo_path is not None:
        payload["repo_path"] = repo_path
    if git_url is not None:
        payload["git_url"] = git_url
    return payload


def _local_repo_path(payload: dict[str, Any]) -> Path:
    raw_path = payload.get("repo_path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise CLIInputError("payload.repo_path must be a non-empty path")
    repo_path = Path(raw_path).expanduser().resolve()
    if not repo_path.is_dir():
        raise CLIInputError(f"repo_path is not a directory: {repo_path}")
    return repo_path


@contextmanager
def _materialize_repo(
    payload: dict[str, Any],
) -> Iterator[tuple[Path, str, list[str]]]:
    raw_git_url = payload.get("git_url")
    if raw_git_url is None:
        yield _local_repo_path(payload), "local", []
        return
    if not isinstance(raw_git_url, str) or not raw_git_url.strip():
        raise CLIInputError("payload.git_url must be a non-empty string")
    # Deliberately outside the try below: a disallowed scheme is a rejected
    # request, not a clone failure, so it must not degrade into the silent
    # repo_path fallback.
    _validate_git_url(raw_git_url)

    with tempfile.TemporaryDirectory(prefix="ai-codeguard-git-") as temp:
        destination = Path(temp) / "repository"
        try:
            _clone_repository(raw_git_url, destination)
        except GitCloneError as error:
            raw_fallback = payload.get("repo_path")
            if not isinstance(raw_fallback, str) or not raw_fallback.strip():
                raise
            fallback = _local_repo_path(payload)
            yield (
                fallback,
                "local-fallback",
                [f"Git clone failed; used repo_path fallback: {error}"],
            )
            return
        yield destination.resolve(), "git", []


def _git_url_scheme(git_url: str) -> str:
    """Classify a git URL into the token used for allowlist checks.

    Bare and relative filesystem paths report ``file`` so they are governed by
    the same opt-in as explicit ``file://`` URLs.
    """

    candidate = git_url.strip()
    match = _URL_SCHEME.match(candidate)
    if match is not None:
        return match.group(1).lower()
    match = _TRANSPORT_HELPER.match(candidate)
    if match is not None:
        return match.group(1).lower()
    if _SCP_LIKE.match(candidate):
        return "ssh"
    return "file"


def _allowed_git_url_schemes() -> frozenset[str]:
    configured = os.environ.get(GIT_URL_SCHEMES_ENV_VAR)
    if configured is None or not configured.strip():
        return DEFAULT_GIT_URL_SCHEMES
    return frozenset(
        token.strip().lower()
        for token in configured.split(",")
        if token.strip()
    )


def _validate_git_url(git_url: str) -> None:
    scheme = _git_url_scheme(git_url)
    allowed = _allowed_git_url_schemes()
    if scheme in allowed:
        return
    raise CLIInputError(
        f"git_url scheme {scheme!r} is not allowed; permitted schemes are "
        f"{', '.join(sorted(allowed))}. Set {GIT_URL_SCHEMES_ENV_VAR} to a "
        "comma-separated list to override."
    )


def _clone_repository(git_url: str, destination: Path) -> None:
    try:
        result = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--",
                git_url,
                str(destination),
            ],
            capture_output=True,
            check=False,
            shell=False,
        )
    except OSError as error:
        raise GitCloneError(f"unable to start git: {error}") from error
    if result.returncode == 0:
        return
    detail = result.stderr.decode("utf-8", errors="replace").strip()
    raise GitCloneError(
        f"git clone exited with {result.returncode}: "
        f"{detail or 'no error output'}"
    )


def _languages(
    payload: dict[str, Any],
) -> tuple[tuple[str, ...], list[str]]:
    raw_languages = payload.get("languages", list(SUPPORTED_LANGUAGES))
    if not isinstance(raw_languages, list) or not all(
        isinstance(language, str) for language in raw_languages
    ):
        raise CLIInputError("payload.languages must be a list of strings")
    normalized = tuple(
        dict.fromkeys(language.lower() for language in raw_languages)
    )
    supported = tuple(
        language
        for language in normalized
        if language in SUPPORTED_LANGUAGES
    )
    unsupported = [
        language
        for language in normalized
        if language not in SUPPORTED_LANGUAGES
    ]
    warnings = (
        [f"Unsupported languages ignored: {', '.join(unsupported)}"]
        if unsupported
        else []
    )
    return supported, warnings


def _rule_ids(
    payload: dict[str, Any],
) -> tuple[tuple[str, ...], list[str]]:
    raw_rules = payload.get(
        "rules",
        [TaintSourceToSinkRule.id, DataflowRule.id],
    )
    if not isinstance(raw_rules, list) or not all(
        isinstance(rule, str) for rule in raw_rules
    ):
        raise CLIInputError("payload.rules must be a list of strings")
    normalized = tuple(dict.fromkeys(rule.lower() for rule in raw_rules))
    selected = tuple(
        dict.fromkeys(
            RULE_ALIASES[rule]
            for rule in normalized
            if rule in RULE_ALIASES
        )
    )
    unknown = [rule for rule in normalized if rule not in RULE_ALIASES]
    warnings = (
        [f"Unknown rules ignored: {', '.join(unknown)}"]
        if unknown
        else []
    )
    return selected, warnings


def _discover_files(
    repo_path: Path,
    languages: tuple[str, ...],
) -> list[tuple[Path, str]]:
    by_extension = {
        LANGUAGE_EXTENSIONS[language]: language for language in languages
    }
    return sorted(
        (
            (path.resolve(), by_extension[path.suffix.lower()])
            for path in repo_path.rglob("*")
            if path.is_file()
            and path.suffix.lower() in by_extension
            and not EXCLUDED_PARTS.intersection(path.parts)
        ),
        key=lambda item: item[0].as_posix().lower(),
    )


def _finding_envelope(
    finding: Finding,
    *,
    source_file: Path,
    repo_path: Path,
    language: str,
) -> dict[str, Any]:
    metadata = dict(finding.metadata)
    rule_id = str(metadata.get("rule_id", "004-codeguard"))
    line = _finding_line(metadata)
    relative_path = source_file.relative_to(repo_path).as_posix()
    digest = hashlib.sha256(
        f"{relative_path}\0{rule_id}\0{line}\0{finding.title}".encode()
    ).hexdigest()[:12]
    narrative = finding.description or "Static analysis detected a code risk."
    return {
        "id": f"code-{language[:2]}-{digest}",
        "source": "004",
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "title": f"{finding.title} in {relative_path}:{line}",
        "description": narrative,
        "host": str(source_file),
        "narrative": narrative,
        "evidence": list(finding.evidence),
        "tags": sorted(finding.tags),
        "metadata": {
            **metadata,
            "language": language,
            "line": line,
            "relative_path": relative_path,
            "rule_id": rule_id,
        },
    }


def _finding_line(metadata: dict[str, Any]) -> int:
    path = metadata.get("path")
    if not isinstance(path, dict):
        return 1
    sink = path.get("sink")
    if isinstance(sink, dict) and isinstance(sink.get("line"), int):
        return sink["line"]
    steps = path.get("steps")
    if isinstance(steps, list):
        for step in reversed(steps):
            if isinstance(step, dict) and isinstance(step.get("line"), int):
                return step["line"]
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
