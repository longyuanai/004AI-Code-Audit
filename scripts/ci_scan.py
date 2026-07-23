from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from analyzer.ci_sampling import discover_source_files, select_file_sample


def main() -> int:
    args = parse_args()
    artifacts = (ROOT / args.artifacts).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    files = discover_source_files(ROOT / args.root)
    sampled = select_file_sample(files, rate=args.sample_rate, seed=args.seed)
    if not files:
        raise SystemExit(f"No supported source files found under {args.root}")

    rule_sarif = artifacts / "codeguard-rules.sarif"
    llm_sarif = artifacts / "codeguard-llm-sample.sarif"
    run_scan(files, rule_sarif, dry_run=True)

    llm_enabled = os.getenv("CODEGUARD_ENABLE_LLM") == "1"
    if llm_enabled:
        if not (
            os.getenv("CODEGUARD_LLM_CONFIG")
            or os.getenv("LLM_PROVIDERS")
        ):
            raise SystemExit(
                "CODEGUARD_ENABLE_LLM=1 requires CODEGUARD_LLM_CONFIG "
                "or shared-core LLM_PROVIDERS configuration"
            )
        shared_core = os.getenv("SHARED_LLM_CORE_PATH")
        if not shared_core or not Path(shared_core).is_dir():
            raise SystemExit(
                "CODEGUARD_ENABLE_LLM=1 requires an existing "
                "SHARED_LLM_CORE_PATH"
            )
        run_scan(sampled, llm_sarif, dry_run=False)
    else:
        write_empty_sarif(llm_sarif)

    summary = {
        "total_files": len(files),
        "sampled_files": len(sampled),
        "sample_rate": args.sample_rate,
        "llm_enabled": llm_enabled,
        "sample": [
            path.relative_to(ROOT).as_posix()
            for path in sampled
        ],
    }
    (artifacts / "ci-scan-summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run all-file rule scan plus deterministic sampled LLM scan."
    )
    parser.add_argument("--root", default="src")
    parser.add_argument("--artifacts", default="artifacts")
    parser.add_argument("--sample-rate", type=float, default=0.2)
    parser.add_argument("--seed", default="ai-codeguard-ci-v1")
    return parser.parse_args()


def run_scan(files: list[Path], output: Path, *, dry_run: bool) -> None:
    command = [
        os.getenv("CODEGUARD_NODE", "node"),
        str(ROOT / "dist" / "index.js"),
        "scan",
        *[str(path) for path in files],
        "--output",
        "sarif",
        "--output-file",
        str(output),
        "--fail-on",
        "none",
    ]
    if dry_run:
        command.append("--dry-run")
    subprocess.run(command, cwd=ROOT, check=True)


def write_empty_sarif(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "$schema": (
                    "https://json.schemastore.org/sarif-2.1.0.json"
                ),
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "AI-CodeGuard sampled LLM review",
                                "version": "0.5.0",
                                "rules": [],
                            }
                        },
                        "results": [],
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
