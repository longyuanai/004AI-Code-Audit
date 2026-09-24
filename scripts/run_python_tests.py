"""Run the Code Audit Python tests in one of two explicit scopes.

    python scripts/run_python_tests.py --scope unit         [pytest args...]
    python scripts/run_python_tests.py --scope integration  [pytest args...]

``unit`` runs the product on its own: tests marked ``vuln_integration`` are
deselected (reported as deselected, never as skipped or passed).
``integration`` additionally puts the single vulnerability-analysis module
(``modules/vulnerability-analysis/src``) on the test environment's
PYTHONPATH and passes ``--vuln-integration`` so those tests are mandatory:
a missing or foreign ``ai_vuln_agent`` is a usage error, not a skip.

The environment is built explicitly for the pytest process and its children;
nothing here patches ``sys.path`` of the product at runtime. Pytest runs with
``-o addopts=`` and a fresh short ``--basetemp`` outside the repository.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
SUITE = PROJECT.parent
VULN_MODULE_SRC = PROJECT / "modules" / "vulnerability-analysis" / "src"


def build_pythonpath(scope: str) -> list[Path]:
    paths = [PROJECT / "src", SUITE / "000shared-llm-core" / "src"]
    optional = [
        SUITE / "000shared-integration" / "src",
        PROJECT / ".python-deps",
    ]
    paths.extend(path for path in optional if path.is_dir())
    if scope == "integration":
        paths.append(VULN_MODULE_SRC)
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run Code Audit Python tests in an explicit scope."
    )
    parser.add_argument("--scope", choices=("unit", "integration"), required=True)
    args, pytest_args = parser.parse_known_args(argv)

    missing = [
        path
        for path in (SUITE / "000shared-llm-core" / "src",)
        + ((VULN_MODULE_SRC,) if args.scope == "integration" else ())
        if not path.is_dir()
    ]
    if missing:
        for path in missing:
            print(f"required source directory is missing: {path}", file=sys.stderr)
        return 2

    scratch = Path(tempfile.mkdtemp(prefix="cat-"))
    env = dict(os.environ)
    # Replace, not extend: another checkout's sources must not leak in.
    env["PYTHONPATH"] = os.pathsep.join(map(str, build_pythonpath(args.scope)))
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-o",
        "addopts=",
        "-o",
        f"cache_dir={scratch / 'cache'}",
        f"--basetemp={scratch / 'base'}",
        "-p",
        "no:cacheprovider",
        "-rs",
    ]
    if args.scope == "integration":
        command.append("--vuln-integration")
    command.extend(pytest_args or ["tests", "-q"])
    print(f"scope={args.scope} python={sys.executable}", file=sys.stderr)
    print(f"PYTHONPATH={env['PYTHONPATH']}", file=sys.stderr)
    print(f"basetemp={scratch / 'base'}", file=sys.stderr)
    return subprocess.call(command, cwd=PROJECT, env=env)


if __name__ == "__main__":
    sys.exit(main())
