"""Synthetic C3 demo: new issue introduced together with the fix."""

import sys


def run_admin_statement() -> None:
    exec(sys.argv[1])
