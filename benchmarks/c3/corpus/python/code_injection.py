"""Synthetic C3 sample: dynamic code execution (CWE-95). Not a real project."""

import os
import sys


def direct_input() -> object:
    expression = input("expression: ")
    return eval(expression)  # c3-expect vuln CWE-95 PY-CI-01


def environment_value() -> object:
    expression = os.getenv("EXPRESSION", "0")
    return eval(expression)  # c3-expect vuln CWE-95 PY-CI-02


def command_line_argument() -> object:
    return eval(sys.argv[1])  # c3-expect vuln CWE-95 PY-CI-03


def exec_statement() -> None:
    statement = input("statement: ")
    exec(statement)  # c3-expect vuln CWE-95 PY-CI-04
