import json

from ai_code_audit import __version__
from ai_code_audit.output.sarif import (
    SARIF_SCHEMA_URL,
    export_sarif,
    render_sarif,
    validate_sarif,
)


def test_sarif_export_snapshot_and_jsonschema_validation() -> None:
    document = export_sarif(
        [
            {
                "id": "code-cp-001",
                "severity": "high",
                "confidence": 0.85,
                "title": "Potential taint flow",
                "host": "demo.cpp",
                "metadata": {
                    "rule_id": "004-phase2-taint",
                    "relative_path": "demo.cpp",
                    "line": 7,
                },
            }
        ]
    )

    validate_sarif(document)
    assert document["version"] == "2.1.0"
    assert document["$schema"] == SARIF_SCHEMA_URL
    # Driver identity is fixed by contracts/sarif.json so this exporter and
    # the TypeScript reporter describe one tool, not two, in Code Scanning.
    # tests/test_sarif_contract.py checks it against the contract itself.
    assert document["runs"][0]["tool"]["driver"] == {
        "name": "AI-CodeGuard",
        "version": __version__,
        "informationUri": "https://github.com/longyuanai/004AI-Code-Audit",
    }
    assert document["runs"][0]["results"][0]["ruleId"] == "004-phase2-taint"


def test_render_sarif_is_valid_utf8_json() -> None:
    rendered = render_sarif(export_sarif([]))

    assert rendered.endswith("\n")
    assert json.loads(rendered)["runs"][0]["results"] == []
