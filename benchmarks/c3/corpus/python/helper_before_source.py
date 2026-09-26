"""Synthetic C3 sample: the sink is defined above the untrusted source.

run_expression is only ever called with text typed by the user, so the
eval is reachable with attacker data even though it appears first in the
file. (The docstring avoids naming the source call on purpose: the builtin
text heuristic would otherwise treat this comment as the source line.)
Not a real project.
"""


def run_expression(expression: str) -> object:
    return eval(expression)  # c3-expect vuln CWE-95 PY-CI-05


def main() -> object:
    return run_expression(input("expression: "))
