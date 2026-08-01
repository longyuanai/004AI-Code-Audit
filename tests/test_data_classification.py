from __future__ import annotations

from ai_code_audit.classification import (
    CodeContext,
    DataClassifier,
    DefaultDataClassifier,
)


def test_default_classifier_implements_protocol() -> None:
    assert isinstance(DefaultDataClassifier(), DataClassifier)


def test_classifier_returns_no_labels_for_ordinary_code() -> None:
    classifications = _classify("result = calculate_total(items)")

    assert classifications == []


def test_classifier_detects_credentials_without_storing_secret_value() -> None:
    classifications = _classify('api_key = "sk-example-sensitive-value"')

    assert [item.category for item in classifications] == ["credentials"]
    assert "sk-example-sensitive-value" not in repr(classifications)
    assert classifications[0].sensitivity_weight == 1.50


def test_classifier_detects_multiple_sensitive_categories() -> None:
    classifications = _classify(
        "patient_id = request.body.patient_id\n"
        "card_number = request.body.card_number"
    )

    assert [item.category for item in classifications] == [
        "health_data",
        "payment_data",
    ]


def test_classifier_recognizes_common_naming_styles() -> None:
    classifications = _classify(
        "emailAddress = user.emailAddress\nrefresh-token = response.token"
    )

    assert [item.category for item in classifications] == [
        "personal_data",
        "authentication_data",
    ]


def test_classification_order_is_deterministic() -> None:
    source = "confidential = True\npassword = value\nssn = value"

    first = _classify(source)
    second = _classify(source)

    assert first == second
    assert [item.category for item in first] == [
        "credentials",
        "personal_data",
        "confidential_business_data",
    ]


def _classify(content: str):
    return DefaultDataClassifier().classify(
        CodeContext(path="app.py", language="python", content=content)
    )
