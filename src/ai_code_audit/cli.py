"""Phase-2 multi-language and SARIF command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from shared_llm_core import LLMRouter

from ai_code_audit.output import (
    export_sarif,
    render_envelope,
    render_sarif,
)
from ai_code_audit.postprocess import (
    BaselineError,
    postprocess_envelope,
    write_baseline,
)
from ai_code_audit.backends import BackendError, ScanRequest, scan_with_backend
from ai_code_audit.gitutils import GitDiffError, collect_diff
from ai_code_audit.scanner import scan_diff, scan_repository
from ai_code_audit.triage import FindingTriageReviewer, RouterLike
from ai_code_audit.triage_context import redact_sensitive_text
from ai_codeguard.cli import (
    CLIInputError,
    _materialize_repo,
    _payload_from_args,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OPENGREP_RULES = PROJECT_ROOT / "rules" / "opengrep"
SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def scan_payload(
    payload: dict[str, Any],
    *,
    router: RouterLike | None = None,
) -> dict[str, object]:
    languages = payload.get("languages")
    if languages is not None and (
        not isinstance(languages, list)
        or not all(isinstance(item, str) for item in languages)
    ):
        raise CLIInputError("payload.languages must be a list of strings")
    backend = _backend_input(payload)
    mode = _mode_input(payload)
    fail_on = _fail_on_input(payload)
    diff = _diff_input(payload)
    baseline_input = _baseline_input(payload)
    baseline_output = _baseline_output(payload)
    if baseline_input is not None and baseline_output is not None:
        raise CLIInputError(
            "payload.baseline_path and payload.write_baseline are mutually exclusive"
        )
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
                    opengrep_path=_opengrep_path(),
                    rules_path=os.environ.get(
                        "CODEGUARD_OPENGREP_RULES",
                        str(DEFAULT_OPENGREP_RULES),
                    ),
                    timeout=_backend_timeout(),
                )
                if diff is not None and diff_scope is not None:
                    envelope["summary"]["repository_source"] = "git-diff"
                    envelope["summary"]["diff"] = {
                        "base": diff["base"],
                        "head": diff["head"],
                        "files": list(diff_scope.files),
                    }
        except (
            BackendError,
            BaselineError,
            GitDiffError,
            KeyError,
            ValueError,
        ) as error:
            raise CLIInputError(str(error)) from error
        if diff is None:
            envelope["summary"]["repository_source"] = repository_source
        envelope["warnings"] = [
            *acquisition_warnings,
            *envelope["warnings"],
        ]
        try:
            envelope = postprocess_envelope(
                envelope,
                repo_path=repo_path,
                baseline_path=baseline_input,
            )
        except BaselineError as error:
            raise CLIInputError(str(error)) from error
        envelope["summary"]["mode"] = mode
        if baseline_output is not None:
            try:
                written = write_baseline(
                    baseline_output,
                    envelope["findings"],
                    repo_path=repo_path,
                )
            except BaselineError as error:
                raise CLIInputError(str(error)) from error
            envelope["summary"]["baseline_written"] = {
                "path": str(written),
                "findings": len(envelope["findings"]),
            }
        if mode == "hybrid":
            triage_envelope(envelope, repo_path=repo_path, router=router)
        _apply_gate(envelope, fail_on)
        return envelope


def triage_envelope(
    envelope: dict[str, object],
    *,
    repo_path: Path,
    router: RouterLike | None = None,
) -> dict[str, object]:
    """Attach LLM verdict metadata without removing static Findings."""

    findings = envelope.get("findings")
    findings = findings if isinstance(findings, list) else []
    limit = _triage_limit()
    active_router = router
    owns_router = False
    if active_router is None:
        try:
            active_router = LLMRouter.from_env()
            owns_router = True
        except Exception as error:
            _append_warning(envelope, _triage_unavailable_warning(error))
            _set_triage_summary(
                envelope,
                total=0,
                errors=1,
                skipped=len(findings),
            )
            return envelope
    eligible = [
        finding
        for finding in findings
        if isinstance(finding, dict) and _should_triage(finding)
    ]
    selected = eligible[:limit]
    reviewer = FindingTriageReviewer(
        active_router,
        model_version=os.environ.get(
            "CODEGUARD_TRIAGE_MODEL_VERSION", "cheap-route"
        ),
    )
    reviewed = confirmed = dismissed = errors = cached = 0
    try:
        for finding in selected:
            result = reviewer.review(finding, repo_path=repo_path)
            metadata = finding.get("metadata")
            if not isinstance(metadata, dict):
                metadata = {}
                finding["metadata"] = metadata
            metadata["llm_triage"] = result.to_metadata()
            if result.status == "error":
                errors += 1
                continue
            reviewed += 1
            cached += int(result.cached)
            confirmed += int(result.confirmed is True)
            dismissed += int(result.confirmed is False)
    finally:
        if owns_router:
            close = getattr(active_router, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as error:
                    _append_warning(
                        envelope,
                        _triage_unavailable_warning(error).replace(
                            "unavailable", "close failed", 1
                        ),
                    )
    _set_triage_summary(
        envelope,
        total=len(selected),
        reviewed=reviewed,
        confirmed=confirmed,
        dismissed=dismissed,
        errors=errors,
        cached=cached,
        skipped=len(findings) - len(selected),
    )
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


def _mode_input(payload: dict[str, Any]) -> str:
    raw = payload.get("mode", "fast")
    if not isinstance(raw, str):
        raise CLIInputError("payload.mode must be a string")
    mode = raw.lower()
    if mode not in {"fast", "hybrid"}:
        raise CLIInputError("payload.mode must be fast or hybrid")
    return mode


def _fail_on_input(payload: dict[str, Any]) -> str:
    raw = payload.get("fail_on", "none")
    if not isinstance(raw, str):
        raise CLIInputError("payload.fail_on must be a string")
    threshold = raw.lower()
    if threshold not in {"none", "any", *SEVERITY_RANK}:
        raise CLIInputError(
            "payload.fail_on must be none, any, info, low, medium, high, or critical"
        )
    return threshold


def _apply_gate(envelope: dict[str, object], threshold: str) -> None:
    if threshold == "none":
        return
    findings = envelope.get("findings")
    findings = findings if isinstance(findings, list) else []
    blocking = [
        finding
        for finding in findings
        if isinstance(finding, dict) and _blocks_gate(finding, threshold)
    ]
    summary = envelope.get("summary")
    if not isinstance(summary, dict):
        summary = {}
        envelope["summary"] = summary
    summary["gate"] = {
        "threshold": threshold,
        "triggered": bool(blocking),
        "findings": len(blocking),
    }


def _blocks_gate(finding: Mapping[str, Any], threshold: str) -> bool:
    if threshold == "any":
        return True
    severity = str(finding.get("severity") or "medium").lower()
    return SEVERITY_RANK.get(severity, SEVERITY_RANK["medium"]) >= (
        SEVERITY_RANK[threshold]
    )


def _should_triage(finding: dict[str, Any]) -> bool:
    severity = str(finding.get("severity") or "medium").lower()
    confidence = finding.get("confidence")
    low_confidence = (
        isinstance(confidence, (int, float))
        and not isinstance(confidence, bool)
        and float(confidence) < 0.75
    )
    return severity in {"high", "critical"} or low_confidence


def _triage_limit() -> int:
    raw = os.environ.get("CODEGUARD_TRIAGE_MAX_FINDINGS", "20")
    try:
        limit = int(raw)
    except ValueError as error:
        raise CLIInputError(
            "CODEGUARD_TRIAGE_MAX_FINDINGS must be an integer"
        ) from error
    if limit <= 0:
        raise CLIInputError(
            "CODEGUARD_TRIAGE_MAX_FINDINGS must be greater than zero"
        )
    return limit


def _append_warning(envelope: dict[str, object], warning: str) -> None:
    warnings = envelope.get("warnings")
    if not isinstance(warnings, list):
        warnings = []
        envelope["warnings"] = warnings
    warnings.append(warning)


def _triage_unavailable_warning(error: Exception) -> str:
    detail = redact_sensitive_text(f"{type(error).__name__}: {error}")[:240]
    return f"LLM triage unavailable; static findings preserved ({detail})"


def _set_triage_summary(
    envelope: dict[str, object],
    *,
    total: int,
    reviewed: int = 0,
    confirmed: int = 0,
    dismissed: int = 0,
    errors: int = 0,
    cached: int = 0,
    skipped: int = 0,
) -> None:
    summary = envelope.get("summary")
    if not isinstance(summary, dict):
        summary = {}
        envelope["summary"] = summary
    summary["llm_triage"] = {
        "selected": total,
        "reviewed": reviewed,
        "confirmed": confirmed,
        "dismissed": dismissed,
        "errors": errors,
        "cached": cached,
        "skipped": skipped,
    }


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


def _opengrep_path() -> str | None:
    return os.environ.get("CODEGUARD_OPENGREP_PATH") or shutil.which("opengrep")


def _baseline_input(payload: dict[str, Any]) -> str | None:
    raw = payload.get("baseline_path")
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw:
        raise CLIInputError("payload.baseline_path must be a non-empty string")
    return raw


def _baseline_output(payload: dict[str, Any]) -> str | None:
    raw = payload.get("write_baseline")
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw:
        raise CLIInputError("payload.write_baseline must be a non-empty string")
    return raw


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
    parser.add_argument(
        "--fail-on",
        choices=("none", "any", "info", "low", "medium", "high", "critical"),
    )
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
        if args.fail_on is not None:
            payload["fail_on"] = args.fail_on
        envelope = scan_payload(payload)
    except (CLIInputError, json.JSONDecodeError) as error:
        return _input_error(str(error), args.json)

    if args.output == "sarif":
        document = export_sarif(envelope["findings"])
        output_path = Path(args.output_file).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render_sarif(document), encoding="utf-8")
        print(str(output_path))
        return _gate_exit_code(envelope)
    if args.json:
        print(render_envelope(envelope))
    else:
        summary = envelope["summary"]
        print(
            f"Scanned {summary['files_scanned']} files; "
            f"found {len(envelope['findings'])} issue(s)."
        )
    return _gate_exit_code(envelope)


def _gate_exit_code(envelope: Mapping[str, object]) -> int:
    summary = envelope.get("summary")
    gate = summary.get("gate") if isinstance(summary, Mapping) else None
    return 1 if isinstance(gate, Mapping) and gate.get("triggered") is True else 0


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


__all__ = ["build_parser", "main", "scan_payload", "triage_envelope"]
