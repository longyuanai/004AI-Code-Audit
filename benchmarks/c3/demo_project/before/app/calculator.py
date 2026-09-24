"""Synthetic C3 demo service. Authorized sample, not a real project."""


def calculate() -> object:
    expression = input("expression: ")
    return eval(expression)
