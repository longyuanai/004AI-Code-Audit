"""Evaluate real AI triage on the same labelled, never-executed source samples."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any

from ai_code_audit.python_security import RULESET_VERSION, scan_python_project
from ai_code_audit.web.worker import analyze


def metrics(counts: dict[str, int]) -> dict[str, Any]:
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    return {
        **counts,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
    }


def outcome(detected: bool, positive: bool) -> str:
    return (
        "tp"
        if detected and positive
        else "fp"
        if detected
        else "fn"
        if positive
        else "tn"
    )


def evaluate(dataset: dict[str, Any], repeat: int) -> list[dict[str, Any]]:
    runs = []
    for run_number in range(1, repeat + 1):
        static_counts = dict.fromkeys(("tp", "fp", "fn", "tn"), 0)
        ai_counts = dict.fromkeys(("tp", "fp", "fn", "tn"), 0)
        cases = []
        with tempfile.TemporaryDirectory(prefix="grad-real-ai-") as directory:
            root = Path(directory)
            for sample in dataset["samples"]:
                (root / "app.py").write_text(sample["source"], encoding="utf-8")
                started = time.perf_counter()
                envelope = scan_python_project(root)
                scan_seconds = time.perf_counter() - started
                findings = envelope["findings"]
                original = json.dumps(envelope, sort_keys=True)
                started = time.perf_counter()
                result = analyze(envelope, root)
                ai_seconds = time.perf_counter() - started
                if original != json.dumps(envelope, sort_keys=True):
                    raise ValueError("AI modified static evidence")
                selected = [
                    index
                    for index, finding in enumerate(findings)
                    if finding["metadata"]["rule_id"] == sample["rule"]
                ]
                # This is an optional triage filter for evaluation only. The product
                # always retains every static finding, including AI-rejected ones.
                retained = any(
                    result["analyses"][index]["status"] != "reviewed"
                    or result["analyses"][index]["confirmed"] is not False
                    for index in selected
                )
                static_result = outcome(bool(selected), sample["positive"])
                ai_result = outcome(retained, sample["positive"])
                static_counts[static_result] += 1
                ai_counts[ai_result] += 1
                cases.append(
                    {
                        "id": sample["id"],
                        "static_outcome": static_result,
                        "ai_filtered_outcome": ai_result,
                        "scan_seconds": scan_seconds,
                        "ai_seconds": ai_seconds,
                        "ai": result,
                        "static_unchanged": True,
                    }
                )
                print(
                    json.dumps(
                        {
                            "run": run_number,
                            "case": sample["id"],
                            "status": result["status"],
                            "seconds": round(ai_seconds, 3),
                        }
                    ),
                    flush=True,
                )
        runs.append(
            {
                "run": run_number,
                "static": metrics(static_counts),
                "ai_filtered": metrics(ai_counts),
                "successful_reviews": sum(
                    a["status"] == "reviewed"
                    for c in cases
                    for a in c["ai"]["analyses"]
                ),
                "failed_reviews": sum(
                    a["status"] == "error" for c in cases for a in c["ai"]["analyses"]
                ),
                "mean_scan_seconds": statistics.mean(c["scan_seconds"] for c in cases),
                "mean_ai_seconds_all_samples": statistics.mean(
                    c["ai_seconds"] for c in cases
                ),
                "cases": cases,
            }
        )
    return runs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--labels", type=Path, default=Path("benchmarks/graduation/labels.json")
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--model-digest", required=True)
    parser.add_argument("--server-version", required=True)
    args = parser.parse_args()
    if not 1 <= args.repeat <= 3:
        parser.error("repeat must be 1..3")
    raw = args.labels.read_bytes()
    dataset = json.loads(raw)
    result = {
        "dataset_version": dataset["dataset_version"],
        "dataset_sha256": hashlib.sha256(raw).hexdigest(),
        "samples": len(dataset["samples"]),
        "repeat": args.repeat,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "ruleset": RULESET_VERSION,
        "server_version": args.server_version,
        "model_digest": args.model_digest,
        "parameters": {
            "temperature": 0,
            "max_tokens": 500,
            "response_format": "json_object",
            "retries": 0,
        },
        "prompt_sources": [
            "src/ai_code_audit/triage.py",
            "src/ai_code_audit/triage_context.py",
            "shared_llm_core/untrusted.py",
        ],
        "policy": "Only confirmed=false removes a candidate in the evaluation filter; errors retain static findings. AI cannot discover missing candidates. Product does not remove findings.",
        "limitations": "20 manually labelled synthetic samples, no independent label review. Repeated local inference does not establish general accuracy or human-confirmed vulnerabilities.",
        "runs": evaluate(dataset, args.repeat),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
    print(
        json.dumps(
            [
                {
                    k: r[k]
                    for k in (
                        "run",
                        "static",
                        "ai_filtered",
                        "successful_reviews",
                        "failed_reviews",
                    )
                }
                for r in result["runs"]
            ]
        )
    )
    return 0 if all(run["failed_reviews"] == 0 for run in result["runs"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
