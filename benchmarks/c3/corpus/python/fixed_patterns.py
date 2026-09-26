"""Synthetic C3 sample: fixed versions of the vulnerable cases.

Each labeled line is the remediated form of a case in code_injection.py or
command_injection.py and must not be reported. Not a real project.
"""

import ast
import os
import subprocess

ALLOWED_OPERATIONS = {"sum": sum, "max": max}


def direct_input_fixed() -> object:
    expression = input("expression: ")
    return ast.literal_eval(expression)  # c3-expect safe PY-FIX-01 fixes=PY-CI-01


def environment_value_fixed() -> object:
    operation = os.getenv("OPERATION", "sum")
    return ALLOWED_OPERATIONS[operation]([1, 2])  # c3-expect safe PY-FIX-02 fixes=PY-CI-02


def ping_host_fixed() -> int:
    host = input("host: ")
    return subprocess.call(["ping", "-n", "1", host])  # c3-expect safe PY-FIX-03 fixes=PY-CMD-01
