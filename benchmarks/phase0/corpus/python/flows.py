import os


def alternate_source() -> object:
    expression = os.getenv("EXPRESSION")
    return eval(expression)  # phase0-expect vuln


def direct_source() -> object:
    expression = input("expression: ")
    return eval(expression)  # phase0-expect vuln


def constant_sink() -> object:
    input("ignored: ")
    return eval("2 + 2")  # phase0-expect safe
