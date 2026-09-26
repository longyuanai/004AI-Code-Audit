"""C3 delivery demo: scan -> fix -> re-check, reports, and enrich.

    python scripts/c3_demo.py --output-dir <empty or new dir> [--backend builtin|opengrep]

Exit codes: 0 every check passed; 1 at least one check failed; 2 usage or
missing prerequisite; 4 the selected Opengrep binary failed the pin check
(missing, unreadable, invalid lock or SHA-256 mismatch against
benchmarks/phase0/OPENGREP.lock) and nothing was run. The builtin backend
never needs Opengrep.

Runs the real CLI (``python -m ai_code_audit``) in child processes on the
synthetic project in ``benchmarks/c3/demo_project`` and writes every report
plus ``demo-summary.json`` (commands, expected vs actual exit codes, finding
locations, checks) into the output directory. It needs only this repository,
``modules/vulnerability-analysis`` and a sibling ``000shared-llm-core``; it
does not use the suite root ``suite.py``.

Network scope (what is and is not verified):

- Python layer, verified: every ``python -m ai_code_audit`` child gets a
  sitecustomize that blocks socket/DNS/httpx and logs attempts; the log
  must stay empty. Proxies point at a dead loopback port; mode stays
  ``fast`` (no LLM); every enrich call passes an explicit ``--cache`` in the
  output directory, so the user's real intel cache is never opened.
- Native subprocesses, NOT verified: ``git`` (demo repo and diff scans) and
  the Opengrep binary run outside the Python guard. No OS-level egress
  block is applied, so zero network for the whole process tree is not
  proven. Opengrep metrics are switched off by the product's env settings,
  which is configuration, not isolation.
- The demo driver process itself is not guarded; it only writes the
  synthetic cache through fake in-memory providers.

The CVE envelope is synthetic and labeled as such; real scan findings never
get a CVE.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT = Path(__file__).resolve().parents[1]
SUITE = PROJECT.parent
DEMO = PROJECT / "benchmarks" / "c3" / "demo_project"
VULN_SRC = PROJECT / "modules" / "vulnerability-analysis" / "src"
DEFAULT_OPENGREP = PROJECT / "tools" / "opengrep" / "v1.26.0" / "opengrep.exe"
DEAD_PROXY = "http://127.0.0.1:9"
# write_baseline only accepts paths inside the scanned repository (a
# committed baseline); the demo keeps it across the before/after commits.
BASELINE_DIR = ".codeguard"
BASELINE = f"{BASELINE_DIR}/baseline.json"
SYNTHETIC_CVES = {
    "fresh": "CVE-2024-1111",
    "not_listed": "CVE-2024-3333",
    "missing": "CVE-2024-4444",
}
# Expected finding files per backend (hand-derived from the demo README; the
# opengrep pack has no CWE-78 rule, so report.py is not expected there).
EXPECTED = {
    "builtin": {
        "before": {"app/calculator.py", "app/report.py"},
        "after": {"app/admin.py", "app/report.py"},
    },
    "opengrep": {
        "before": {"app/calculator.py"},
        "after": {"app/admin.py"},
    },
}
GUARD = '''
import os, socket
_LOG = os.environ["C3_DEMO_NET_GUARD_LOG"]
def _deny(name):
    def _blocked(*args, **kwargs):
        with open(_LOG, "a", encoding="utf-8") as handle:
            handle.write(name + "\\n")
        raise OSError("network blocked by c3 demo: " + name)
    return _blocked
for _name in ("connect", "connect_ex", "sendto", "sendall", "send"):
    setattr(socket.socket, _name, _deny("socket." + _name))
for _name in ("create_connection", "getaddrinfo", "gethostbyname"):
    setattr(socket, _name, _deny(_name))
try:
    import httpx
except ImportError:
    pass
else:
    httpx.Client.send = _deny("httpx.Client.send")
    httpx.AsyncClient.send = _deny("httpx.AsyncClient.send")
'''


class Demo:
    def __init__(
        self, out: Path, backend: str, opengrep: Path | None = None
    ) -> None:
        """``opengrep`` must already have passed ``verify_opengrep``."""
        self.out = out
        self.backend = backend
        self.repo = out / "project"
        self.reports = out / "reports"
        self.cache = out / "intel-cache"
        self.guard_log = out / "network-guard.log"
        self.steps: list[dict[str, Any]] = []
        self.checks: list[dict[str, Any]] = []
        self.guard_attempts: int | None = None
        guard_dir = out / "guard"
        guard_dir.mkdir(parents=True)
        (guard_dir / "sitecustomize.py").write_text(GUARD, encoding="utf-8")
        self.guard_log.write_text("", encoding="utf-8")
        paths = [
            guard_dir,
            PROJECT / "src",
            SUITE / "000shared-llm-core" / "src",
            SUITE / "000shared-integration" / "src",
            PROJECT / ".python-deps",
            VULN_SRC,
        ]
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("CODEGUARD_", "OPENAI", "ANTHROPIC", "LLM_"))
        }
        env.update(
            PYTHONPATH=os.pathsep.join(str(p) for p in paths if p.is_dir()),
            PYTHONDONTWRITEBYTECODE="1",
            PYTHONIOENCODING="utf-8",
            C3_DEMO_NET_GUARD_LOG=str(self.guard_log),
            HTTP_PROXY=DEAD_PROXY,
            HTTPS_PROXY=DEAD_PROXY,
            ALL_PROXY=DEAD_PROXY,
        )
        env.pop("NO_PROXY", None)
        if backend == "opengrep":
            if opengrep is None:
                raise ValueError("opengrep backend needs a verified executable")
            env["CODEGUARD_OPENGREP_PATH"] = str(opengrep)
        self.env = env

    # -- helpers -------------------------------------------------------
    def cli(
        self, name: str, args: list[str], expected_exit: int
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, "-m", "ai_code_audit", *args]
        completed = subprocess.run(
            command,
            cwd=self.out,
            env=self.env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
            check=False,
        )
        self.steps.append(
            {
                "step": name,
                "command": ["python", "-m", "ai_code_audit", *map(self.rel, args)],
                "expected_exit": expected_exit,
                "exit": completed.returncode,
                "stderr_tail": completed.stderr.strip().splitlines()[-3:],
            }
        )
        self.check(f"{name}: exit {expected_exit}", completed.returncode == expected_exit)
        return completed

    def scan(
        self, name: str, report: str, expected_exit: int, **payload: Any
    ) -> dict[str, Any]:
        body = self.payload(**payload)
        target = self.reports / report
        self.cli(
            name,
            ["scan", "--json", "--input", json.dumps(body), "--output-file", str(target)],
            expected_exit,
        )
        if not target.is_file():
            self.check(f"{name}: report written", False, str(target))
            return {"findings": [], "summary": {}}
        document: dict[str, Any] = json.loads(target.read_text(encoding="utf-8"))
        return document

    def payload(self, **extra: Any) -> dict[str, Any]:
        # medium: builtin heuristic hits are medium/0.5 since main 5d4d60c;
        # opengrep CG-OG-PY-001 hits are high, so both trigger the gate.
        return {
            "repo_path": str(self.repo),
            "backend": self.backend,
            "fail_on": "medium",
            **extra,
        }

    def check(self, name: str, passed: bool, detail: Any = None) -> None:
        self.checks.append({"check": name, "passed": bool(passed), "detail": detail})

    def rel(self, value: str) -> str:
        """Replace the output dir (plain or JSON-escaped) for stable records."""
        escaped = json.dumps(str(self.out))[1:-1]
        return value.replace(escaped, "<out>").replace(str(self.out), "<out>")

    def git(self, *args: str) -> None:
        subprocess.run(
            ["git", "-c", "core.autocrlf=false", *args],
            cwd=self.repo,
            check=True,
            capture_output=True,
            env={**self.env, "GIT_CONFIG_NOSYSTEM": "1"},
        )

    def commit(self, stage: str) -> None:
        for item in self.repo.iterdir():
            if item.name not in (".git", BASELINE_DIR):
                shutil.rmtree(item) if item.is_dir() else item.unlink()
        shutil.copytree(DEMO / stage, self.repo, dirs_exist_ok=True)
        self.git("add", "-A")
        self.git(
            "-c", "user.name=c3-demo", "-c", "user.email=c3-demo@example.invalid",
            "commit", "-q", "-m", stage,
        )

    # -- scenario ------------------------------------------------------
    def run(self) -> dict[str, Any]:
        self.reports.mkdir(parents=True)
        self.repo.mkdir()
        self.git("init", "-q")
        expected = EXPECTED[self.backend]

        self.commit("before")
        before = self.scan("scan before fix", "before.json", 1)
        self.cli(
            "sarif before fix",
            ["scan", "--output", "sarif", "--input", json.dumps(self.payload()),
             "--output-file", str(self.reports / "before.sarif")],
            1,
        )
        self.scan(
            "write baseline (accept all current findings)", "baseline-scan.json", 1,
            write_baseline=BASELINE,
        )
        self.check_files("before findings", before, expected["before"])
        self.cli(
            "markdown of real scan (enrich skipped, no CVE)",
            ["enrich", "--envelope", str(self.reports / "before.json"),
             "--cache", str(self.cache / "unused"), "--output", "markdown",
             "--output-file", str(self.reports / "before.md")],
            1,
        )
        self.cli(
            "json enrich of real scan",
            ["enrich", "--envelope", str(self.reports / "before.json"),
             "--cache", str(self.cache / "unused"),
             "--output-file", str(self.reports / "before-enriched.json")],
            1,
        )
        real = json.loads((self.reports / "before-enriched.json").read_text("utf-8"))
        stage = real["code_audit_enrichment"]
        self.check(
            "real scan enrich is skipped/no_queryable_cve",
            stage["status"] == "skipped" and stage["reason"] == "no_queryable_cve",
            {"status": stage["status"], "reason": stage["reason"]},
        )
        per_finding = {
            f["metadata"]["code_audit_enrichment"]["status"] for f in real["findings"]
        }
        self.check(
            "real findings are not_applicable, no CVE invented",
            per_finding == {"not_applicable"}
            and all(f.get("cve") is None for f in real["findings"]),
            sorted(per_finding),
        )
        self.check(
            "intel cache was never created",
            not (self.cache / "unused").exists(),
        )

        self.commit("after")
        after = self.scan("scan after fix", "after.json", 1)
        self.check_files("after findings", after, expected["after"])
        fixed = expected["before"] - expected["after"]
        self.check(
            "fixed issue is gone",
            not fixed & self.files(after),
            sorted(fixed),
        )
        rechecked = self.scan(
            "re-check against baseline", "after-vs-baseline.json", 1,
            baseline_path=BASELINE,
        )
        new_files = expected["after"] - expected["before"]
        self.check(
            "baseline hides only accepted issues; new issue still reported",
            self.files(rechecked) == new_files,
            {"reported": sorted(self.files(rechecked)),
             "baselined": rechecked["summary"].get("baselined")},
        )
        diff = self.scan(
            "diff scan HEAD~1..HEAD", "after-diff.json", 1,
            diff={"base": "HEAD~1", "head": "HEAD"},
        )
        self.check(
            "diff scan reports only changed-line issues",
            self.files(diff) == new_files,
            sorted(self.files(diff)),
        )
        self.check(
            "rule id, location and evidence preserved",
            all(
                f["metadata"].get("rule_id")
                and f["metadata"].get("relative_path")
                and f["metadata"].get("line")
                and f.get("evidence")
                for f in (*before["findings"], *after["findings"])
            ),
        )

        self.enrich_synthetic()
        guard = self.guard_log.read_text(encoding="utf-8").strip()
        self.check(
            "no Python-layer network attempts in CLI child processes",
            guard == "",
            guard or None,
        )
        self.guard_attempts = len(guard.splitlines()) if guard else 0
        return self.summary(before, after, rechecked, diff)

    def enrich_synthetic(self) -> None:
        envelope = self.synthetic_envelope()
        source = self.reports / "synthetic-cve-envelope.json"
        source.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
        cache = populate_synthetic_cache(self.cache / "synthetic")
        base = ["enrich", "--envelope", str(source), "--cache", str(cache)]
        for fmt, name in (
            ("envelope", "synthetic-enriched.json"),
            ("sarif", "synthetic-enriched.sarif"),
            ("markdown", "synthetic-enriched.md"),
        ):
            self.cli(
                f"enrich synthetic CVE envelope ({fmt})",
                [*base, "--output", fmt, "--output-file", str(self.reports / name)],
                0,
            )
        self.cli(
            "enrich synthetic with --require-intel (partial -> 3)",
            [*base, "--require-intel", "--output-file",
             str(self.reports / "synthetic-strict.json")],
            3,
        )
        enriched = json.loads(
            (self.reports / "synthetic-enriched.json").read_text("utf-8")
        )
        statuses = [
            f["metadata"]["code_audit_enrichment"]["status"]
            for f in enriched["findings"]
        ]
        self.check(
            "synthetic enrich statuses",
            # tech-spec §5: "enriched" = all three sources fresh ok/not_found,
            # so EPSS-only 3333 (NVD/KEV fresh not_found) is enriched too.
            statuses == ["enriched", "enriched", "unknown", "not_applicable"],
            statuses,
        )
        self.check(
            "synthetic stage partial, network_refresh false",
            enriched["code_audit_enrichment"]["status"] == "partial"
            and enriched["code_audit_enrichment"]["network_refresh"] is False,
        )

    def synthetic_envelope(self) -> dict[str, Any]:
        def finding(index: int, cve: str | None) -> dict[str, Any]:
            return {
                "id": f"synthetic-{index}",
                "source": "004",
                "severity": "medium",
                "confidence": 0.6,
                "title": f"SYNTHETIC demo finding {index} (not a scan result)",
                "description": "Synthetic finding for the C3 enrich demo.",
                "evidence": [f"synthetic evidence {index}"],
                "cve": cve,
                "metadata": {
                    "rule_id": "C3-SYNTHETIC",
                    "relative_path": "synthetic/app.py",
                    "line": index + 1,
                },
            }

        return {
            "findings": [
                finding(0, SYNTHETIC_CVES["fresh"]),
                finding(1, SYNTHETIC_CVES["not_listed"]),
                finding(2, SYNTHETIC_CVES["missing"]),
                finding(3, None),
            ],
            "summary": {"repository_source": "synthetic", "files_scanned": 0},
            "warnings": [],
            "x_c3_demo": "SYNTHETIC envelope with test CVE ids; not produced by a scan",
        }

    @staticmethod
    def files(envelope: dict[str, Any]) -> set[str]:
        return {f["metadata"]["relative_path"] for f in envelope["findings"]}

    def check_files(self, name: str, envelope: dict[str, Any], expected: set[str]) -> None:
        self.check(name, self.files(envelope) == expected, sorted(self.files(envelope)))

    def summary(self, *envelopes: dict[str, Any]) -> dict[str, Any]:
        names = ("before", "after", "after_vs_baseline", "after_diff")
        return {
            "result": {
                "schema_version": 1,
                "backend": self.backend,
                "steps": [
                    {k: v for k, v in step.items() if k != "stderr_tail"}
                    for step in self.steps
                ],
                "findings": {
                    name: sorted(
                        (
                            {
                                "rule_id": f["metadata"]["rule_id"],
                                "path": f["metadata"]["relative_path"],
                                "line": f["metadata"]["line"],
                                "fingerprint": f["metadata"].get("fingerprint"),
                            }
                            for f in envelope["findings"]
                        ),
                        key=lambda item: (item["path"], item["line"], item["rule_id"]),
                    )
                    for name, envelope in zip(names, envelopes)
                },
                "checks": self.checks,
                "passed": all(item["passed"] for item in self.checks),
                "network_verification": network_scope(
                    self.backend, self.guard_attempts
                ),
            },
            "run": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "python": sys.version.split()[0],
                "output_dir": str(self.out),
                "stderr_tails": {s["step"]: s["stderr_tail"] for s in self.steps},
            },
        }


def populate_synthetic_cache(cache_dir: Path) -> Path:
    """Write test intel through the module's own CVEEnricher, fake providers.

    CVE-2024-1111: NVD+KEV+EPSS; CVE-2024-3333: EPSS only (NVD/KEV
    not_found); CVE-2024-4444 is absent. Values are test data.
    """
    from ai_vuln_agent.enrichment.client import CVEEnricher
    from ai_vuln_agent.enrichment.epss import EPSSRecord
    from ai_vuln_agent.enrichment.kev import KEVRecord
    from ai_vuln_agent.enrichment.nvd import NVDRecord
    from ai_vuln_agent.enrichment.store import DATABASE_FILENAME, SQLiteEnrichmentStore

    fresh, listed = SYNTHETIC_CVES["fresh"], SYNTHETIC_CVES["not_listed"]

    class Source:
        def __init__(self, records: dict[str, object]) -> None:
            self.records = records

        async def lookup(self, cve_id: str) -> object:
            return self.records.get(cve_id)

        async def close(self) -> None:
            return None

    store = SQLiteEnrichmentStore(cache_dir)
    enricher = CVEEnricher(
        cache_dir=None,
        store=store,
        nvd=Source({fresh: NVDRecord(fresh, 7.5, "CVSS:3.1/AV:N", "CWE-95", "test")}),
        kev=Source({fresh: KEVRecord(fresh, "test", "2024-01-01", "2024-02-01", "test")}),
        epss=Source({
            fresh: EPSSRecord(fresh, 0.25, 0.8),
            listed: EPSSRecord(listed, 0.01, 0.1),
        }),
    )
    asyncio.run(enricher.enrich_many([fresh, listed]))
    database: Path = cache_dir / DATABASE_FILENAME
    return database


def network_scope(backend: str, attempts: int | None) -> dict[str, Any]:
    native = ["git"] + (["opengrep"] if backend == "opengrep" else [])
    return {
        "python_layer": {
            "status": "guarded",
            "scope": "python -m ai_code_audit child processes: socket, DNS, httpx",
            "attempts_logged": attempts,
        },
        "native_subprocesses": {
            "processes": native,
            "status": "not_verified",
            "why": "sitecustomize cannot hook native binaries; no OS-level "
            "egress block was used",
        },
        "demo_driver_process": "not_guarded (fake in-memory intel providers only)",
        "whole_process_tree_zero_network": "not_verified",
    }


def verify_pin(executable: Path) -> Any:
    """Shared pre-execution gate (benchmarks/c3/opengrep_pin.py)."""
    if str(PROJECT) not in sys.path:
        sys.path.insert(0, str(PROJECT))
    from benchmarks.c3.opengrep_pin import verify_opengrep

    return verify_opengrep(executable)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="C3 delivery demo.")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--backend", choices=("builtin", "opengrep"), default="builtin")
    parser.add_argument("--opengrep", type=Path, default=DEFAULT_OPENGREP)
    args = parser.parse_args(argv)
    out = args.output_dir.resolve()
    if out.exists() and any(out.iterdir()):
        print(f"output directory must be empty or absent: {out}", file=sys.stderr)
        return 2
    # The pin gate runs first so a bad Opengrep binary is reported as such
    # (exit 4) whatever else is missing; builtin never reaches it.
    verified: Path | None = None
    if args.backend == "opengrep":
        if str(PROJECT) not in sys.path:
            sys.path.insert(0, str(PROJECT))
        from benchmarks.c3.opengrep_pin import OpengrepPinError

        try:
            verified = verify_pin(args.opengrep).executable
        except OpengrepPinError as error:
            out.mkdir(parents=True, exist_ok=True)
            failure = {
                "result": {
                    "schema_version": 1,
                    "backend": "opengrep",
                    "passed": False,
                    "opengrep_pin": {"status": "failed", "reason": error.reason},
                    "steps": [],
                },
                "run": {"error": str(error), "opengrep_started": False},
            }
            (out / "demo-summary.json").write_text(
                json.dumps(failure, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            print(f"opengrep pin check failed ({error.reason}): {error}", file=sys.stderr)
            return 4
    missing = [p for p in (VULN_SRC, SUITE / "000shared-llm-core" / "src") if not p.is_dir()]
    if missing or shutil.which("git") is None:
        print(f"missing requirement: {missing or 'git'}", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    sys.path[:0] = [str(VULN_SRC), str(SUITE / "000shared-llm-core" / "src")]
    demo = Demo(out, args.backend, verified)
    summary = demo.run()
    (out / "demo-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    for item in summary["result"]["checks"]:
        print(f"[{'PASS' if item['passed'] else 'FAIL'}] {item['check']}")
    print(f"reports: {out / 'reports'}")
    return 0 if summary["result"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
