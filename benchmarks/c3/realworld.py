"""Local C3-2 self-audit; no ground truth or recall is inferred from silence.

Run from the Code repository with its source dependencies on PYTHONPATH.
Output must not exist. The sample is reconstructed from a pinned Git commit;
the scanner remains the current checkout, whose source hashes are recorded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch

from benchmarks.c3.opengrep_pin import verify_opengrep

ROOT = Path(__file__).resolve().parents[2]
REVISION = "0fb5b18d32006c8db08997bbeb383ffcf2bc6ede"
SCOPE = "src/ai_code_audit"
# Declared before the first scan, independent of its findings.
REVIEW_SCOPE = {
    "hybrid_cli.py": "repository input, URL validation and clone subprocess",
    "gitutils.py": "diff refs and subprocess argument boundaries",
    "backends/opengrep.py": "execution, errors and report normalization",
    "cli.py": "fast-mode dispatch and envelope file read/write",
    "output/markdown.py": "untrusted report text escaping",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def git(*args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], check=True, capture_output=True,
        timeout=60,
    ).stdout


def source_manifest(root: Path) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): digest(p.read_bytes())
        for p in sorted(root.rglob("*.py")) if p.is_file()
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--opengrep", type=Path,
                        default=ROOT / "tools/opengrep/v1.26.0/opengrep.exe")
    args = parser.parse_args(argv)
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)  # Never overwrite earlier evidence.
    sample = out / "sample"
    sample.mkdir()
    record: dict[str, Any] = {
        "sample_kind": "real_owned_project", "sample_commit": REVISION,
        "sample_scope": SCOPE, "manual_review_scope": REVIEW_SCOPE,
        "python": sys.version, "executable": sys.executable,
        "platform": platform.platform(), "command": sys.argv,
        "backends": [], "precision": None, "recall": None,
        "metrics_reason": "No complete ground truth; verdicts live in manual review.",
        "network": {"python_attempts": [], "native_isolation": "not_verified"},
    }
    exit_code = 4
    try:
        record["scanner_head"] = git("rev-parse", "HEAD").decode().strip()
        record["initial_status"] = git("status", "--short").decode("utf-8")
        paths = git("ls-tree", "-r", "--name-only", REVISION, SCOPE).decode().splitlines()
        workspace: dict[str, str] = {}
        for name in paths:
            if not name.endswith(".py"):
                continue
            relative = Path(name).relative_to(SCOPE)
            target = sample / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(git("show", f"{REVISION}:{name}"))
            workspace[relative.as_posix()] = digest((ROOT / name).read_bytes())
        manifest = source_manifest(sample)
        record["sample_files"] = manifest
        record["sample_sha256"] = digest(json.dumps(manifest, sort_keys=True).encode())
        record["sample_lines"] = sum(len(p.read_bytes().splitlines()) for p in sample.rglob("*.py"))
        record["workspace_files"] = workspace
        record["scanner_sources"] = source_manifest(ROOT / "src")
        record["shared_sources"] = source_manifest(ROOT.parent / "000shared-llm-core/src")
        record["rule_sha256"] = digest((ROOT / "rules/opengrep/taint.yaml").read_bytes())
        record["runner_sha256"] = digest(Path(__file__).read_bytes())
        write_json(out / "scope-before-scan.json", record)
        environment = {
            k: v for k, v in os.environ.items()
            if not k.startswith(("CODEGUARD_", "OPENAI", "ANTHROPIC", "LLM_", "OTEL_"))
        }
        environment.update(
            CODEGUARD_OPENGREP_PATH=str(args.opengrep.resolve()),
            CODEGUARD_OPENGREP_RULES=str(ROOT / "rules/opengrep/taint.yaml"),
            SEMGREP_SEND_METRICS="off", OPENGREP_SEND_METRICS="off",
            OTEL_SDK_DISABLED="true",
        )

        def deny(*_args: Any, **_kwargs: Any) -> Any:
            record["network"]["python_attempts"].append("blocked socket/DNS request")
            raise OSError("C3-2 Python network blocked")

        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, environment, clear=True))
            for name in ("connect", "connect_ex", "send", "sendall", "sendto"):
                stack.enter_context(patch.object(socket.socket, name, deny))
            for name in ("getaddrinfo", "gethostbyname", "create_connection"):
                stack.enter_context(patch.object(socket, name, deny))
            from ai_code_audit.cli import scan_payload

            for backend in ("builtin", "opengrep"):
                entry: dict[str, Any] = {"backend": backend, "status": "error", "findings": None}
                record["backends"].append(entry)
                try:
                    if backend == "opengrep":
                        pin = verify_opengrep(args.opengrep)
                        entry["pin"] = {"sha256": pin.sha256, "expected_version": pin.version}
                        version = subprocess.run(
                            [str(pin.executable), "--version"], capture_output=True,
                            text=True, encoding="utf-8", timeout=30, check=False,
                        )
                        entry["version_check"] = {
                            "command": version.args, "exit_code": version.returncode,
                            "stdout": version.stdout, "stderr": version.stderr,
                        }
                        if version.returncode or version.stdout.strip() != pin.version:
                            raise RuntimeError("Opengrep runtime version mismatch")
                    payload = {"repo_path": str(sample), "languages": ["python"],
                               "backend": backend, "mode": "fast", "fail_on": "none"}
                    entry["payload"] = payload
                    envelopes = []
                    native_run = subprocess.run
                    for index in (1, 2):
                        def capture(
                            *cmd: Any, _run: Any = native_run,
                            _log: Path = out / f"{backend}-{index}-native.json",
                            **kwargs: Any,
                        ) -> Any:
                            completed = _run(*cmd, **kwargs)
                            write_json(_log, {
                                "command": completed.args, "exit_code": completed.returncode,
                                "stdout": completed.stdout, "stderr": completed.stderr,
                            })
                            return completed

                        with patch("subprocess.run", side_effect=capture):
                            envelope = scan_payload(payload)
                        envelopes.append(envelope)
                        write_json(out / f"{backend}-{index}.json", envelope)
                    entry["repeat_identical"] = envelopes[0] == envelopes[1]
                    entry["findings"] = len(envelopes[0]["findings"])  # type: ignore[arg-type]
                    entry["files_scanned"] = envelopes[0]["summary"]["files_scanned"]  # type: ignore[index]
                    if any(e["warnings"] for e in envelopes):
                        raise RuntimeError("Scan warnings require review; not a clean success")
                    if entry["files_scanned"] != len(manifest):
                        raise RuntimeError("Discovered file count does not match sample")
                    entry["status"] = "ok" if entry["repeat_identical"] else "repeat_mismatch"
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
                    entry["error"] = f"{type(error).__name__}: {error}"
                    entry["findings"] = None
        record["sample_unchanged"] = manifest == source_manifest(sample)
        exit_code = 0 if (
            all(e["status"] == "ok" for e in record["backends"])
            and record["sample_unchanged"] and not record["network"]["python_attempts"]
        ) else 4
    except (OSError, RuntimeError, ValueError, ImportError, subprocess.SubprocessError) as error:
        record["error"] = f"{type(error).__name__}: {error}"
    finally:
        record["exit_code"] = exit_code
        write_json(out / "run.json", record)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
