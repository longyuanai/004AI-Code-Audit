from __future__ import annotations

from ai_code_audit.classification import DataClassification
from ai_code_audit.risk import RiskConfig, assess_risk


def test_sensitive_reachable_high_finding_becomes_critical() -> None:
    assessment = assess_risk(
        _finding("high", 0.90),
        [_classification("credentials", 1.50)],
        reachable=True,
        in_diff=True,
    )

    assert assessment.level == "critical"
    assert assessment.score == 3.881


def test_data_sensitivity_uses_highest_classification_weight() -> None:
    assessment = assess_risk(
        _finding("medium", 1.00),
        [
            _classification("personal_data", 1.25),
            _classification("health_data", 1.50),
        ],
    )

    assert assessment.data_sensitivity_weight == 1.50
    assert assessment.score == 1.50


def test_unchanged_unreachable_finding_is_deprioritized() -> None:
    assessment = assess_risk(
        _finding("high", 0.80),
        reachable=False,
        in_diff=False,
    )

    assert assessment.score == 1.224
    assert assessment.level == "medium"


def test_unknown_factors_have_neutral_weight() -> None:
    assessment = assess_risk(_finding("medium", 0.80))

    assert assessment.reachability_weight == 1.00
    assert assessment.change_scope_weight == 1.00
    assert assessment.data_sensitivity_weight == 1.00
    assert assessment.score == 0.80


def test_risk_metadata_explains_formula_and_factors() -> None:
    metadata = assess_risk(
        _finding("critical", 0.75),
        reachable=True,
    ).to_metadata()

    assert metadata["formula"].startswith("severity_weight * confidence")
    assert metadata["factors"]["confidence"] == 0.75
    assert metadata["level"] == "high"


def test_risk_config_is_injectable() -> None:
    config = RiskConfig(
        severity_weights={"high": 10.0},
        high_threshold=5.0,
        critical_threshold=9.0,
    )

    assessment = assess_risk(_finding("high", 1.0), config=config)

    assert assessment.score == 10.0
    assert assessment.level == "critical"


def test_confidence_is_clamped_and_invalid_values_are_safe() -> None:
    high = assess_risk(_finding("medium", 4.0))
    low = assess_risk(_finding("medium", -2.0))
    invalid = assess_risk(_finding("medium", "unknown"))

    assert high.confidence == 1.0
    assert low.confidence == 0.0
    assert invalid.confidence == 0.5


def _finding(severity: str, confidence: object) -> dict[str, object]:
    return {"severity": severity, "confidence": confidence}


def _classification(category: str, weight: float) -> DataClassification:
    return DataClassification(
        category=category,
        confidence=0.9,
        sensitivity_weight=weight,
        indicators=(category,),
    )
