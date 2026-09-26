"""Synthetic C3 demo: known legacy issue, accepted into the baseline."""

import os


def legacy_report() -> int:
    name = input("report name: ")
    return os.system("print " + name)
