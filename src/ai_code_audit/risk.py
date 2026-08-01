"""Explainable risk scoring without changing the frozen Finding contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from ai_code_audit.classification import DataClassification


@dataclass(frozen=True)
class RiskConfig:
    """Weights and thresholds used by the deterministic risk scorer."""

    severity_weights: Mapping[str, float] = field(
        default_factory=lambda: {
            "low": 0.50,
            "medium": 1.00,
            "high": 2.00,
            "critical": 3.00,
        }
    )
    reachable_weight: float = 1.25
    unreachable_weight: float = 0.85
    changed_weight: float = 1.15
    unchanged_weight: float = 0.90
    high_threshold: float = 1.75
    critical_threshold: float = 3.00
    medium_threshold: float = 0.75


@dataclass(frozen=True)
class RiskAssessment:
    """Risk score plus every factor needed to explain it."""

    score: float
    level: str
    severity_weight: float
    confidence: float
    reachability_weight: float
    data_sensitivity_weight: float
    change_scope_weight: float

    def to_metadata(self) -> dict[str, object]:
        return {
            "score": self.score,
            "level": self.level,
            "formula": (
                "severity_weight * confidence * reachability_weight * "
                "data_sensitivity_weight * change_scope_weight"
            ),
            "factors": {
                "severity_weight": self.severity_weight,
                "confidence": self.confidence,
                "reachability_weight": self.reachability_weight,
                "data_sensitivity_weight": self.data_sensitivity_weight,
                "change_scope_weight": self.change_scope_weight,
            },
        }


def assess_risk(
    finding: Mapping[str, Any],
    classifications: Iterable[DataClassification] = (),
    *,
    reachable: bool | None = None,
    in_diff: bool | None = None,
    config: RiskConfig | None = None,
) -> RiskAssessment:
    """Score one Finding using deterministic and externally visible factors."""

    selected = config or RiskConfig()
    severity = finding.get("severity", "medium")
    if hasattr(severity, "value"):
        severity = severity.value
    severity_weight = float(
        selected.severity_weights.get(str(severity).lower(), 1.00)
    )
    confidence = _confidence(finding.get("confidence"))
    reachability_weight = _boolean_weight(
        reachable,
        positive=selected.reachable_weight,
        negative=selected.unreachable_weight,
    )
    change_scope_weight = _boolean_weight(
        in_diff,
        positive=selected.changed_weight,
        negative=selected.unchanged_weight,
    )
    data_sensitivity_weight = max(
        (item.sensitivity_weight for item in classifications),
        default=1.00,
    )
    score = round(
        severity_weight
        * confidence
        * reachability_weight
        * data_sensitivity_weight
        * change_scope_weight,
        3,
    )
    return RiskAssessment(
        score=score,
        level=_risk_level(score, selected),
        severity_weight=severity_weight,
        confidence=confidence,
        reachability_weight=reachability_weight,
        data_sensitivity_weight=data_sensitivity_weight,
        change_scope_weight=change_scope_weight,
    )


def _confidence(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.50
    return min(max(float(value), 0.00), 1.00)


def _boolean_weight(
    value: bool | None,
    *,
    positive: float,
    negative: float,
) -> float:
    if value is None:
        return 1.00
    return positive if value else negative


def _risk_level(score: float, config: RiskConfig) -> str:
    if score >= config.critical_threshold:
        return "critical"
    if score >= config.high_threshold:
        return "high"
    if score >= config.medium_threshold:
        return "medium"
    return "low"


__all__ = ["RiskAssessment", "RiskConfig", "assess_risk"]
