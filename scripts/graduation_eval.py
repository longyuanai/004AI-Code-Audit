"""Repeat a labelled source-only evaluation; AI metrics remain null without a model."""

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


def evaluate(dataset: dict[str, Any], repeat: int) -> dict[str, Any]:
    runs = []
    for _ in range(repeat):
        counts = dict.fromkeys(("tp", "fp", "fn", "tn"), 0)
        cases = []
        with tempfile.TemporaryDirectory(prefix="grad-eval-") as directory:
            root = Path(directory)
            for sample in dataset["samples"]:
                path = root / "app.py"
                path.write_text(sample["source"], encoding="utf-8")
                started = time.perf_counter()
                envelope = scan_python_project(root)
                duration = time.perf_counter() - started
                detected = any(
                    finding["metadata"]["rule_id"] == sample["rule"]
                    for finding in envelope["findings"]
                )
                outcome = (
                    "tp"
                    if detected and sample["positive"]
                    else "fp"
                    if detected
                    else "fn"
                    if sample["positive"]
                    else "tn"
                )
                counts[outcome] += 1
                cases.append(
                    {
                        "id": sample["id"],
                        "outcome": outcome,
                        "detected_rules": sorted(
                            {f["metadata"]["rule_id"] for f in envelope["findings"]}
                        ),
                        "duration_seconds": duration,
                    }
                )
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        runs.append(
            {
                **counts,
                "precision": tp / (tp + fp) if tp + fp else None,
                "recall": tp / (tp + fn) if tp + fn else None,
                "mean_scan_seconds": statistics.mean(
                    case["duration_seconds"] for case in cases
                ),
                "cases": cases,
            }
        )
    return {
        "dataset_version": dataset["dataset_version"],
        "samples": len(dataset["samples"]),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "ruleset": RULESET_VERSION,
        "repeat": repeat,
        "runs": runs,
        "repeat_counts_identical": all(
            {key: run[key] for key in ("tp", "fp", "fn", "tn")}
            == {key: runs[0][key] for key in ("tp", "fp", "fn", "tn")}
            for run in runs
        ),
        "ai_comparison": {
            "status": "not_run",
            "model": None,
            "precision": None,
            "recall": None,
            "reason": "未配置真实模型；协议 stub/降级测试不作为模型准确率实验",
        },
        "limitations": "20 个手工合成样例，按目标规则的样例级口径，不是项目级或真实世界准确率。标注由实现者准备，尚未独立复核；两种保守常量调用命中按 FP 计。",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--labels", type=Path, default=Path("benchmarks/graduation/labels.json")
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.repeat <= 10:
        parser.error("repeat must be 1..10")
    raw = args.labels.read_bytes()
    result = evaluate(json.loads(raw), args.repeat)
    result["dataset_sha256"] = hashlib.sha256(raw).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                key: result["runs"][0][key]
                for key in (
                    "tp",
                    "fp",
                    "fn",
                    "tn",
                    "precision",
                    "recall",
                    "mean_scan_seconds",
                )
            }
        )
    )
    return 0 if result["repeat_counts_identical"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
