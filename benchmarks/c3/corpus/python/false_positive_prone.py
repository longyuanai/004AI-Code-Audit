"""Synthetic C3 sample: safe code that text-based matchers may flag.

Every labeled line is safe: the dangerous-looking call never receives
untrusted data. Not a real project.
"""

import ast
import subprocess
import sys


def constant_expression() -> object:
    input("press enter: ")
    return eval("2 + 2")  # c3-expect safe PY-FP-01


def literal_parse() -> object:
    raw = input("literal: ")
    return ast.literal_eval(raw)  # c3-expect safe PY-FP-02


def documented_warning() -> None:
    value = input("value: ")
    # Never pass value to eval(value); parse it instead.  c3-expect safe PY-FP-03
    print(len(value))


def message_mentions_sink() -> None:
    input("name: ")
    print("system(\"reboot\") is not called here")  # c3-expect safe PY-FP-04


def constant_command() -> int:
    input("continue? ")
    return subprocess.call(["git", "status"])  # c3-expect safe PY-FP-05


def constant_statement() -> None:
    print(len(sys.argv))
    exec("print('ready')")  # c3-expect safe PY-FP-06
