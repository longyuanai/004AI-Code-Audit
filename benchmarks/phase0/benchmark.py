"""Measure static backends against the labeled Phase 0 corpus."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from ai_code_audit.scanner import scan_repository

ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path(__file__).resolve().parent / "corpus"
RULES = Path(__file__).resolve().parent / "rules"
EXPECTATION_MARKER = "phase0-expect"


@dataclass(frozen=True, order=True)
class Location:
    path: str
    line: int


@dataclass(frozen=True)
class CorpusExpectations:
    vulnerable: frozenset[Location]
    safe: frozenset[Location]


@dataclass(frozen=True)
class Metrics:
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float


def load_expectations(corpus: Path = CORPUS) -> CorpusExpectations:
    vulnerable: set[Location] = set()
    safe: set[Location] = set()
    for path in sorted(item for item in corpus.rglob("*") if item.is_file()):
        relative = path.relative_to(corpus).as_posix()
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            if f"{EXPECTATION_MARKER} vuln" in line:
                vulnerable.add(Location(relative, line_number))
            elif f"{EXPECTATION_MARKER} safe" in line:
                safe.add(Location(relative, line_number))
    if not vulnerable or not safe:
        raise ValueError("Phase 0 corpus must contain vuln and safe labels")
    overlap = vulnerable.intersection(safe)
    if overlap:
        raise ValueError(f"Conflicting Phase 0 labels: {sorted(overlap)}")
    return CorpusExpectations(frozenset(vulnerable), frozenset(safe))


def calculate_metrics(
    expected: CorpusExpectations,
    reported: Iterable[Location],
) -> Metrics:
    reported_set = set(reported)
    true_positives = len(expected.vulnerable.intersection(reported_set))
    false_negatives = len(expected.vulnerable.difference(reported_set))
    false_positives = len(reported_set.difference(expected.vulnerable))
    true_negatives = len(expected.safe.difference(reported_set))
    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives
    return Metrics(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        true_negatives=true_negatives,
        precision=(
            true_positives / precision_denominator
            if precision_denominator
            else 0.0
        ),
        recall=(
            true_positives / recall_denominator
            if recall_denominator
            else 0.0
        ),
    )


def run_builtin(corpus: Path = CORPUS) -> tuple[set[Location], float, str]:
    started = time.perf_counter()
    envelope = scan_repository(corpus)
    elapsed = time.perf_counter() - started
    reported = {
        Location(
            str(finding["metadata"]["relative_path"]).replace("\\", "/"),
            int(finding["metadata"]["line"]),
        )
        for finding in envelope["findings"]
    }
    return reported, elapsed, "builtin-tree-sitter-heuristic"


def parse_opengrep_results(
    document: dict[str, Any],
    *,
    corpus: Path = CORPUS,
) -> set[Location]:
    locations: set[Location] = set()
    corpus_resolved = corpus.resolve()
    for result in document.get("results", []):
        raw_path = Path(str(result["path"]))
        if raw_path.is_absolute():
            relative = raw_path.resolve().relative_to(corpus_resolved)
        else:
            normalized = Path(os.path.normpath(str(raw_path)))
            try:
                relative = normalized.resolve().relative_to(corpus_resolved)
            except ValueError:
                parts = normalized.parts
                corpus_parts = corpus.parts
                marker = corpus_parts[-3:]
                start = _subsequence_index(parts, marker)
                relative = (
                    Path(*parts[start + len(marker) :])
                    if start is not None
                    else normalized
                )
        locations.add(
            Location(
                relative.as_posix(),
                int(result["start"]["line"]),
            )
        )
    return locations


def run_opengrep(
    executable: str | Path,
    *,
    corpus: Path = CORPUS,
    rules: Path = RULES,
) -> tuple[set[Location], float, str]:
    command = [
        str(executable),
        "scan",
        "--json",
        "--quiet",
        "--taint-intrafile",
        "--config",
        str(rules),
        str(corpus),
    ]
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    elapsed = time.perf_counter() - started
    if completed.returncode not in (0, 1):
        raise RuntimeError(
            f"Opengrep exited {completed.returncode}: {completed.stderr.strip()}"
        )
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Opengrep did not emit JSON: {completed.stdout[:500]}"
        ) from error
    version = _opengrep_version(executable)
    return parse_opengrep_results(document, corpus=corpus), elapsed, version


def benchmark(
    engines: Sequence[str],
    *,
    opengrep: str | Path | None = None,
    corpus: Path = CORPUS,
) -> dict[str, Any]:
    expected = load_expectations(corpus)
    results: list[dict[str, Any]] = []
    for engine in engines:
        if engine == "builtin":
            reported, elapsed, version = run_builtin(corpus)
        elif engine == "opengrep":
            executable = _resolve_opengrep(opengrep)
            reported, elapsed, version = run_opengrep(
                executable,
                corpus=corpus,
            )
        else:
            raise ValueError(f"Unknown benchmark engine: {engine}")
        metrics = calculate_metrics(expected, reported)
        results.append(
            {
                "engine": engine,
                "version": version,
                "elapsed_seconds": round(elapsed, 6),
                "reported": [asdict(item) for item in sorted(reported)],
                "metrics": asdict(metrics),
            }
        )
    return {
        "corpus": str(corpus.resolve()),
        "expectations": {
            "vulnerable": len(expected.vulnerable),
            "safe": len(expected.safe),
        },
        "results": results,
    }


def render_markdown(document: dict[str, Any]) -> str:
    lines = [
        "# Phase 0 static-engine benchmark",
        "",
        (
            f"Corpus: {document['expectations']['vulnerable']} vulnerable "
            f"and {document['expectations']['safe']} safe labeled sinks."
        ),
        "",
        "| Engine | TP | FP | FN | TN | Precision | Recall | Seconds |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for result in document["results"]:
        metrics = result["metrics"]
        lines.append(
            "| {engine} | {tp} | {fp} | {fn} | {tn} | {precision:.1%} | "
            "{recall:.1%} | {seconds:.4f} |".format(
                engine=result["engine"],
                tp=metrics["true_positives"],
                fp=metrics["false_positives"],
                fn=metrics["false_negatives"],
                tn=metrics["true_negatives"],
                precision=metrics["precision"],
                recall=metrics["recall"],
                seconds=result["elapsed_seconds"],
            )
        )
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--engine",
        choices=("builtin", "opengrep", "all"),
        default="all",
    )
    parser.add_argument("--opengrep", help="Path to the Opengrep executable.")
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    engines = (
        ("builtin", "opengrep")
        if args.engine == "all"
        else (args.engine,)
    )
    try:
        document = benchmark(engines, opengrep=args.opengrep)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"benchmark error: {error}", file=sys.stderr)
        return 2
    rendered_json = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    rendered_markdown = render_markdown(document)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(rendered_json, encoding="utf-8")
    if args.markdown_output:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(rendered_markdown, encoding="utf-8")
    print(rendered_markdown, end="")
    return 0


def _resolve_opengrep(explicit: str | Path | None) -> str:
    candidate = str(explicit) if explicit else shutil.which("opengrep")
    if not candidate:
        raise RuntimeError(
            "Opengrep is unavailable; pass --opengrep or install a pinned binary"
        )
    if not Path(candidate).is_file():
        raise RuntimeError(f"Opengrep executable does not exist: {candidate}")
    return candidate


def _opengrep_version(executable: str | Path) -> str:
    completed = subprocess.run(
        [str(executable), "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    text = (completed.stdout or completed.stderr).strip()
    return text.splitlines()[0] if text else "opengrep-version-unknown"


def _subsequence_index(
    values: Sequence[str],
    subsequence: Sequence[str],
) -> int | None:
    limit = len(values) - len(subsequence) + 1
    for index in range(limit):
        if tuple(values[index : index + len(subsequence)]) == tuple(subsequence):
            return index
    return None


if __name__ == "__main__":
    raise SystemExit(main())
