"""C3 per-rule quality baseline on the hand-labeled synthetic Python corpus.

Scans ``benchmarks/c3/corpus`` through the product entry point
(``ai_code_audit.cli.scan_payload``) once per backend and scores each rule
against the inline ``c3-expect`` labels and ``labels.json``. Reuses the
Phase 0 line-level method; labels are written from the code facts, never
from scanner output.

Scoring for a rule R with claimed CWEs S (``labels.json``):

- TP: reported on a ``vuln`` line whose CWE is in S.
- FN: ``vuln`` line with CWE in S that R did not report.
- FP: reported on a ``safe`` line or on an unlabeled line.
- out_of_scope: reported on a ``vuln`` line whose CWE is outside S (neither
  TP nor FP; the rule does not claim that class).
- precision/recall are ``null`` (N/A) when the denominator is zero.

``result`` is deterministic; ``run`` holds timing, environment, the Opengrep
pin record and the exit decision, and is excluded from the repeat check.
Exit codes: see ``main`` (0 ok, 4 backend failed, 3 repeat mismatch, 2
usage). The opengrep backend starts only after the binary's raw-byte
SHA-256 matched ``benchmarks/phase0/OPENGREP.lock``. These are synthetic
samples: the numbers
are a regression baseline, not an accuracy claim for real projects.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
import time
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ai_code_audit.backends import BackendError
from ai_code_audit.cli import CLIInputError, scan_payload
from benchmarks.c3.opengrep_pin import (
    OPENGREP_LOCK,
    OpengrepPinError,
    verify_opengrep,
)
from benchmarks.phase0.benchmark import Location

ROOT = Path(__file__).resolve().parents[2]
C3 = Path(__file__).resolve().parent
CORPUS = C3 / "corpus"
LABELS = C3 / "labels.json"
DEFAULT_OPENGREP = ROOT / "tools" / "opengrep" / "v1.26.0" / "opengrep.exe"
OPENGREP_RULES = ROOT / "rules" / "opengrep" / "taint.yaml"
BUILTIN_RULE_SOURCE = ROOT / "src" / "ai_code_audit" / "scanner.py"
MARKER = re.compile(
    r"c3-expect\s+(?P<kind>vuln|safe)"
    r"(?:\s+(?P<cwe>CWE-\d+))?\s+(?P<case>PY-[A-Z]+-\d+)"
)
BACKENDS = ("builtin", "opengrep")
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_REPEAT_MISMATCH = 3
EXIT_BACKEND_FAILED = 4


@dataclass(frozen=True)
class Label:
    case: str
    kind: str
    cwe: str | None
    category: str
    location: Location


def load_labels(
    corpus: Path = CORPUS,
    manifest_path: Path = LABELS,
) -> tuple[dict[str, Any], list[Label]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases: dict[str, Any] = manifest["cases"]
    labels: list[Label] = []
    for path in sorted(item for item in corpus.rglob("*.py") if item.is_file()):
        relative = path.relative_to(corpus).as_posix()
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, start=1):
            match = MARKER.search(line)
            if match is None:
                continue
            case = match["case"]
            if case not in cases:
                raise ValueError(f"{relative}:{number}: {case} has no rationale")
            kind = match["kind"]
            if (kind == "vuln") != (match["cwe"] is not None):
                raise ValueError(f"{relative}:{number}: vuln labels need a CWE")
            category = cases[case]["category"]
            if (kind == "vuln") != (category == "vulnerable"):
                raise ValueError(f"{relative}:{number}: {case} kind/category mismatch")
            labels.append(
                Label(case, kind, match["cwe"], category, Location(relative, number))
            )
    seen = [label.case for label in labels]
    duplicates = sorted({case for case in seen if seen.count(case) > 1})
    missing = sorted(set(cases) - set(seen))
    if duplicates or missing:
        raise ValueError(f"label mismatch: duplicates={duplicates} missing={missing}")
    return manifest, labels


def scan_backend(backend: str, corpus: Path = CORPUS) -> dict[str, Any]:
    """Run the product scan; return findings or a recorded error."""
    try:
        envelope: dict[str, Any] = dict(
            scan_payload({"repo_path": str(corpus), "backend": backend})
        )
    # Recorded as an error, never scored as zero findings.
    except (BackendError, CLIInputError, OSError, RuntimeError, ValueError) as error:
        return {"status": "error", "error": f"{type(error).__name__}: {error}"}
    findings = []
    for finding in envelope["findings"]:
        metadata = finding["metadata"]
        findings.append(
            {
                "rule_id": str(metadata["rule_id"]),
                "location": Location(
                    str(metadata["relative_path"]).replace("\\", "/"),
                    int(metadata["line"]),
                ),
                "id": str(finding["id"]),
                "fingerprint": str(metadata.get("fingerprint", "")),
            }
        )
    return {
        "status": "ok",
        "backend": str(envelope["summary"].get("backend", backend)),
        "warnings": list(envelope.get("warnings", [])),
        "findings": findings,
    }


def score_rule(
    rule_id: str,
    claimed: Sequence[str],
    labels: Sequence[Label],
    reported: set[Location],
) -> dict[str, Any]:
    in_scope = {
        label.location: label
        for label in labels
        if label.kind == "vuln" and label.cwe in claimed
    }
    vulnerable = {label.location: label for label in labels if label.kind == "vuln"}
    by_location = {label.location: label for label in labels}
    tp = sorted(set(in_scope) & reported)
    fn = sorted(set(in_scope) - reported)
    out_of_scope = sorted((set(vulnerable) - set(in_scope)) & reported)
    fp = sorted(reported - set(vulnerable))
    safe = [label for label in labels if label.kind == "safe"]
    tn = [label for label in safe if label.location not in reported]
    covered_cwes = {label.cwe for label in in_scope.values()}

    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None

    def describe(location: Location) -> dict[str, Any]:
        label = by_location.get(location)
        return {
            "path": location.path,
            "line": location.line,
            "case": label.case if label else None,
            "category": label.category if label else "unlabeled",
        }

    return {
        "rule_id": rule_id,
        "claimed_cwes": list(claimed),
        "claimed_cwes_without_cases": sorted(set(claimed) - covered_cwes),
        "tp": len(tp),
        "fp": len(fp),
        "fn": len(fn),
        "tn": len(tn),
        "out_of_scope": len(out_of_scope),
        "precision": ratio(len(tp), len(tp) + len(fp)),
        "recall": ratio(len(tp), len(tp) + len(fn)),
        "true_positives": [describe(item) for item in tp],
        "false_positives": [describe(item) for item in fp],
        "false_negatives": [describe(item) for item in fn],
        "out_of_scope_hits": [describe(item) for item in out_of_scope],
    }


def evaluate(
    opengrep: Path | None = None,
    backends_to_run: Sequence[str] = BACKENDS,
) -> dict[str, Any]:
    """Score each selected backend once; failures are recorded, not raised.

    The opengrep backend runs only after ``verify_opengrep`` accepted the
    exact binary (raw-byte SHA-256 against OPENGREP.lock); otherwise no
    Opengrep process is started and the backend is recorded as failed.
    """
    manifest, labels = load_labels()
    rules: dict[str, Any] = manifest["rules"]
    executable = opengrep if opengrep is not None else DEFAULT_OPENGREP
    backends: list[dict[str, Any]] = []
    timings: dict[str, float] = {}
    pin_record: dict[str, Any] | None = None
    for backend in backends_to_run:
        backend_rules = {
            rule_id: spec for rule_id, spec in rules.items()
            if spec["backend"] == backend
        }
        started = time.perf_counter()
        if backend == "opengrep":
            try:
                pin = verify_opengrep(executable, OPENGREP_LOCK)
            except OpengrepPinError as error:
                pin_record = {
                    "status": "failed",
                    "reason": error.reason,
                    "error": str(error),
                    "executable": str(executable),
                    "started": False,
                }
                backends.append(
                    _failed_entry(
                        backend, backend_rules, f"opengrep_pin_{error.reason}", str(error)
                    )
                )
                continue
            pin_record = {
                "status": "verified",
                "executable": str(pin.executable),
                "sha256": pin.sha256,
                "version": pin.version,
            }
            with _pinned_opengrep_env(pin.executable):
                scanned = scan_backend(backend)
        else:
            scanned = scan_backend(backend)
        timings[backend] = round(time.perf_counter() - started, 3)
        if scanned["status"] != "ok":
            backends.append(
                _failed_entry(backend, backend_rules, "execution_error", scanned["error"])
            )
            continue
        findings = scanned["findings"]
        entry: dict[str, Any] = {"backend": backend, "status": "ok"}
        entry["effective_backend"] = scanned["backend"]
        entry["warnings"] = scanned["warnings"]
        entry["rules"] = [
            score_rule(
                rule_id,
                spec["claimed_cwes"],
                labels,
                {f["location"] for f in findings if f["rule_id"] == rule_id},
            )
            for rule_id, spec in sorted(backend_rules.items())
        ]
        entry["unscored_rule_ids"] = sorted(
            {f["rule_id"] for f in findings} - set(backend_rules)
        )
        claimed = {cwe for spec in backend_rules.values() for cwe in spec["claimed_cwes"]}
        entry["unsupported_cases"] = [
            {"case": label.case, "cwe": label.cwe, "path": label.location.path,
             "line": label.location.line}
            for label in labels
            if label.kind == "vuln" and label.cwe not in claimed
        ]
        ids = [f["id"] for f in findings]
        entry["findings"] = len(findings)
        entry["duplicate_finding_ids"] = sorted({i for i in ids if ids.count(i) > 1})
        backends.append(entry)
    result = {
        "schema_version": 1,
        "corpus_version": manifest["corpus_version"],
        "language": manifest["language"],
        "corpus_files": {
            path.relative_to(CORPUS).as_posix(): _text_sha256(path)
            for path in sorted(CORPUS.rglob("*.py"))
        },
        "labels": {
            "vulnerable": sum(label.kind == "vuln" for label in labels),
            "safe": sum(label.kind == "safe" for label in labels),
            "by_category": _count(label.category for label in labels),
        },
        "rule_sources": {
            "004-phase2-taint": _text_sha256(BUILTIN_RULE_SOURCE),
            "CG-OG-PY-001": _text_sha256(OPENGREP_RULES),
        },
        "backends_run": list(backends_to_run),
        "backends": backends,
    }
    return {
        "result": result,
        "run": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "opengrep_pin": pin_record,
            "seconds": timings,
        },
    }


def _failed_entry(
    backend: str, backend_rules: dict[str, Any], reason: str, error: str
) -> dict[str, Any]:
    """A failed backend keeps metrics unavailable (null), never zero."""
    return {
        "backend": backend,
        "status": "error",
        "reason": reason,
        "error": error,
        "rules": [
            {"rule_id": rule_id, "status": "not_run", "precision": None, "recall": None}
            for rule_id in sorted(backend_rules)
        ],
    }


@contextmanager
def _pinned_opengrep_env(executable: Path) -> Generator[None]:
    """Point the product at the verified binary and the scored rule pack."""
    keys = ("CODEGUARD_OPENGREP_PATH", "CODEGUARD_OPENGREP_RULES")
    saved = {key: os.environ.get(key) for key in keys}
    os.environ["CODEGUARD_OPENGREP_PATH"] = str(executable)
    os.environ["CODEGUARD_OPENGREP_RULES"] = str(OPENGREP_RULES.parent)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def render_markdown(document: dict[str, Any]) -> str:
    result = document["result"]
    lines = [
        "# C3 Python rule quality baseline (synthetic corpus)",
        "",
        (
            f"Corpus {result['corpus_version']}: {result['labels']['vulnerable']} "
            f"vulnerable and {result['labels']['safe']} safe labeled lines "
            f"{result['labels']['by_category']}. Synthetic samples only; not a "
            "real-project accuracy figure."
        ),
        "",
        _status_line(document["run"]),
        _pin_line(document["run"].get("opengrep_pin")),
        "",
        "| Backend | Rule | TP | FP | FN | TN | Out of scope | Precision | Recall |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for backend in result["backends"]:
        for rule in backend["rules"]:
            if backend["status"] != "ok":
                lines.append(
                    f"| {backend['backend']} | {rule['rule_id']} | - | - | - | - | - "
                    f"| N/A | N/A |"
                )
                continue
            lines.append(
                "| {b} | {r} | {tp} | {fp} | {fn} | {tn} | {oos} | {p} | {rc} |".format(
                    b=backend["backend"], r=rule["rule_id"], tp=rule["tp"],
                    fp=rule["fp"], fn=rule["fn"], tn=rule["tn"],
                    oos=rule["out_of_scope"], p=_pct(rule["precision"]),
                    rc=_pct(rule["recall"]),
                )
            )
    lines.append("")
    for backend in result["backends"]:
        if backend["status"] != "ok":
            lines.append(
                f"- {backend['backend']}: ERROR {backend['reason']}: {backend['error']}"
            )
            continue
        for rule in backend["rules"]:
            for key in ("false_positives", "false_negatives", "out_of_scope_hits"):
                for item in rule[key]:
                    lines.append(
                        f"- {backend['backend']} {rule['rule_id']} {key}: "
                        f"{item['path']}:{item['line']} {item['case'] or ''} "
                        f"({item['category']})"
                    )
        for item in backend["unsupported_cases"]:
            lines.append(
                f"- {backend['backend']} unsupported (no rule claims {item['cwe']}): "
                f"{item['path']}:{item['line']} {item['case']}"
            )
        if backend["duplicate_finding_ids"]:
            lines.append(
                f"- {backend['backend']} duplicate finding ids: "
                f"{', '.join(backend['duplicate_finding_ids'])}"
            )
    return "\n".join(lines) + "\n"


def decide_exit(documents: Sequence[dict[str, Any]]) -> tuple[int, str, list[str]]:
    """Execution success and repeat consistency are judged separately.

    Priority: EXIT_BACKEND_FAILED (4) over EXIT_REPEAT_MISMATCH (3) over
    EXIT_OK (0); usage/label/report-writing errors (2) are decided in main.
    Every selected backend is required.
    """
    failed = sorted(
        {
            f"{entry['backend']}:{entry['reason']}"
            for document in documents
            for entry in document["result"]["backends"]
            if entry["status"] != "ok"
        }
    )
    if failed:
        return EXIT_BACKEND_FAILED, "backend_failed", failed
    first = documents[0]["result"]
    if any(document["result"] != first for document in documents[1:]):
        return EXIT_REPEAT_MISMATCH, "repeat_mismatch", []
    return EXIT_OK, "ok", []


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="C3 per-rule quality baseline (synthetic Python corpus).",
        epilog=(
            "Exit codes: 0 all selected backends ran and repeats are identical; "
            "4 a selected backend failed (Opengrep pin check, unavailable or "
            "execution error); 3 repeats differ; 2 usage, label or report-write "
            "error. Priority 2 > 4 > 3 > 0. Reports are still written for 3/4."
        ),
    )
    parser.add_argument("--opengrep", type=Path, default=DEFAULT_OPENGREP)
    parser.add_argument(
        "--backend", action="append", choices=BACKENDS, dest="backends",
        help="Backend to evaluate (repeatable; default: all). Each one is required.",
    )
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    parser.add_argument(
        "--repeat", type=int, default=1,
        help="Run N times; any differing result section exits 3.",
    )
    args = parser.parse_args(argv)
    if args.repeat < 1:
        parser.error("--repeat must be >= 1")
    selected = tuple(dict.fromkeys(args.backends or BACKENDS))
    try:
        documents = [evaluate(args.opengrep, selected) for _ in range(args.repeat)]
    except (OSError, ValueError) as error:
        print(f"c3 quality error: {error}", file=sys.stderr)
        return EXIT_USAGE
    code, reason, failed = decide_exit(documents)
    first = documents[0]["result"]
    document = documents[0]
    document["run"].update(
        repeat=args.repeat,
        backends_required=list(selected),
        execution_ok=not failed,
        failed_backends=failed,
        repeat_identical=all(item["result"] == first for item in documents),
        exit_code=code,
        exit_reason=reason,
    )
    rendered = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    markdown = render_markdown(document)
    try:
        for target, text in (
            (args.json_output, rendered),
            (args.markdown_output, markdown),
        ):
            if target:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
    except OSError as error:
        print(f"c3 quality error: cannot write report: {error}", file=sys.stderr)
        return EXIT_USAGE
    print(markdown, end="")
    if code != EXIT_OK:
        print(f"c3 quality: exit {code} ({reason}) {failed}", file=sys.stderr)
    return code


def _text_sha256(path: Path) -> str:
    """Digest of a text file, CRLF folded to LF so checkouts agree.

    Only for corpus/rule text; binaries go through opengrep_pin.raw_sha256.
    """
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _status_line(run: dict[str, Any]) -> str:
    if "exit_code" not in run:
        return "Status: not decided (single evaluate() call)."
    state = "PASSED" if run["exit_code"] == EXIT_OK else "FAILED"
    return (
        f"Status: {state} (exit {run['exit_code']}, {run['exit_reason']}); "
        f"execution_ok={run['execution_ok']}, "
        f"repeat_identical={run['repeat_identical']} over {run['repeat']} run(s); "
        f"failed={run['failed_backends'] or 'none'}."
    )


def _pin_line(pin: dict[str, Any] | None) -> str:
    if pin is None:
        return "Opengrep pin: not checked (opengrep backend not selected)."
    if pin["status"] == "verified":
        return (
            f"Opengrep pin: verified {pin['version']} sha256 {pin['sha256']} "
            "(raw bytes, matched OPENGREP.lock before execution)."
        )
    return (
        f"Opengrep pin: FAILED {pin['reason']}; Opengrep was not started. "
        f"{pin['error']}"
    )


def _count(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _pct(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.1%}"


if __name__ == "__main__":
    raise SystemExit(main())
