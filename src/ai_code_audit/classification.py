"""Lightweight sensitive-data classification for CodeGuard findings."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar, Protocol, runtime_checkable


@dataclass(frozen=True)
class CodeContext:
    """Small, local-only code context used by deterministic classifiers."""

    path: str
    language: str
    content: str


@dataclass(frozen=True)
class DataClassification:
    """A deterministic sensitive-data label and its explainable evidence."""

    category: str
    confidence: float
    sensitivity_weight: float
    indicators: tuple[str, ...]


@runtime_checkable
class DataClassifier(Protocol):
    """Classify sensitive-data concepts without exposing raw values."""

    def classify(self, context: CodeContext) -> list[DataClassification]: ...


class DefaultDataClassifier:
    """Conservative identifier-based classifier inspired by Bearer's pipeline."""

    _CATEGORY_RULES: ClassVar[
        tuple[tuple[str, float, float, tuple[str, ...]], ...]
    ] = (
        (
            "credentials",
            0.90,
            1.50,
            (
                r"api[_-]?key",
                r"client[_-]?secret",
                r"password",
                r"private[_-]?key",
            ),
        ),
        (
            "personal_data",
            0.82,
            1.25,
            (
                r"date[_-]?of[_-]?birth",
                r"email[_-]?address",
                r"passport[_-]?(?:id|number)",
                r"phone[_-]?number",
                r"social[_-]?security",
                r"\bssn\b",
            ),
        ),
        (
            "health_data",
            0.88,
            1.50,
            (
                r"diagnosis",
                r"health[_-]?condition",
                r"medical[_-]?record",
                r"patient[_-]?id",
                r"prescription",
            ),
        ),
        (
            "payment_data",
            0.90,
            1.50,
            (
                r"bank[_-]?account",
                r"card[_-]?number",
                r"credit[_-]?card",
                r"\bcvv\b",
                r"\biban\b",
            ),
        ),
        (
            "authentication_data",
            0.86,
            1.35,
            (
                r"access[_-]?token",
                r"auth[_-]?token",
                r"refresh[_-]?token",
                r"session[_-]?id",
                r"\bjwt\b",
                r"mfa[_-]?(?:code|secret)",
            ),
        ),
        (
            "confidential_business_data",
            0.78,
            1.20,
            (
                r"confidential",
                r"customer[_-]?list",
                r"internal[_-]?only",
                r"trade[_-]?secret",
            ),
        ),
    )

    def classify(self, context: CodeContext) -> list[DataClassification]:
        normalized = context.content.casefold()
        classifications: list[DataClassification] = []
        for category, confidence, weight, patterns in self._CATEGORY_RULES:
            indicators = tuple(
                pattern
                for pattern in patterns
                if re.search(pattern, normalized, re.IGNORECASE)
            )
            if not indicators:
                continue
            classifications.append(
                DataClassification(
                    category=category,
                    confidence=confidence,
                    sensitivity_weight=weight,
                    indicators=indicators,
                )
            )
        return classifications


__all__ = [
    "CodeContext",
    "DataClassification",
    "DataClassifier",
    "DefaultDataClassifier",
]
