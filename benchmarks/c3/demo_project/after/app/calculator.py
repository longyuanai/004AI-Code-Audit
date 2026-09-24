"""Synthetic C3 demo service. Authorized sample, not a real project."""

import ast


def calculate() -> object:
    expression = input("expression: ")
    return ast.literal_eval(expression)
