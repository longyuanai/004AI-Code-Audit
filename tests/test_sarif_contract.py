"""Python-side conformance with contracts/sarif.json.

The TypeScript reporter and this exporter both upload SARIF to the same
GitHub Code Scanning instance, so tool identity and severity mapping have to
agree. They had drifted: this exporter called itself "longyuanai-codeguard"
while the TypeScript one used "AI-CodeGuard", the two used different $schema
URLs, and both pointed informationUri at an unrelated repository.

tests/unit/sarif-contract.test.ts asserts the same file from the other side,
so a change to the contract fails both suites until both stacks follow it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ai_code_audit import __version__
from ai_code_audit.output.sarif import (
    DRIVER_INFORMATION_URI,
    DRIVER_NAME,
    LEVELS,
    SARIF_SCHEMA_URL,
    SARIF_VERSION,
    URI_BASE_ID,
    export_sarif,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts" / "sarif.json").read_text(encoding="utf-8")
)


def test_sarif_version_matches_contract() -> None:
    assert SARIF_VERSION == CONTRACT["sarifVersion"]


def test_schema_uri_matches_contract() -> None:
    assert SARIF_SCHEMA_URL == CONTRACT["schemaUri"]


def test_driver_identity_matches_contract() -> None:
    assert DRIVER_NAME == CONTRACT["driver"]["name"]
    assert DRIVER_INFORMATION_URI == CONTRACT["driver"]["informationUri"]


def test_uri_base_id_matches_contract() -> None:
    assert URI_BASE_ID == CONTRACT["uriBaseId"]


def test_severity_level_mapping_matches_contract() -> None:
    assert LEVELS == CONTRACT["severityLevels"]


def test_exported_document_carries_contract_identity() -> None:
    document = export_sarif([])
    driver = document["runs"][0]["tool"]["driver"]

    assert document["version"] == CONTRACT["sarifVersion"]
    assert document["$schema"] == CONTRACT["schemaUri"]
    assert driver["name"] == CONTRACT["driver"]["name"]
    assert driver["informationUri"] == CONTRACT["driver"]["informationUri"]


def test_driver_version_defaults_to_package_version() -> None:
    """Previously a literal "0.6" that could not track pyproject's 0.6.0."""

    driver = export_sarif([])["runs"][0]["tool"]["driver"]

    assert driver["version"] == __version__


def test_explicit_tool_version_still_wins() -> None:
    driver = export_sarif([], tool_version="9.9.9")["runs"][0]["tool"]["driver"]

    assert driver["version"] == "9.9.9"


def test_results_anchor_paths_with_the_contract_uri_base_id() -> None:
    document = export_sarif(
        [{"id": "x", "severity": "high", "metadata": {"relative_path": "a.py"}}]
    )
    location = document["runs"][0]["results"][0]["locations"][0]

    assert (
        location["physicalLocation"]["artifactLocation"]["uriBaseId"]
        == CONTRACT["uriBaseId"]
    )


@pytest.mark.parametrize(
    "rule_id",
    ["004-taint-source-to-sink", "004-cross-function-dataflow", "004-phase2-taint"],
)
def test_python_rule_ids_match_their_namespace(rule_id: str) -> None:
    pattern = CONTRACT["ruleIdNamespaces"]["python"]["pattern"]

    assert re.match(pattern, rule_id), f"{rule_id} violates {pattern}"


def test_python_rule_ids_do_not_collide_with_the_typescript_namespace() -> None:
    typescript = CONTRACT["ruleIdNamespaces"]["typescript"]["pattern"]

    for rule_id in (
        "004-taint-source-to-sink",
        "004-cross-function-dataflow",
        "004-phase2-taint",
    ):
        assert not re.match(typescript, rule_id)
