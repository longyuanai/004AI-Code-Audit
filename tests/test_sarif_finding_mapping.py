from ai_code_audit.output.sarif import finding_to_result


def test_finding_maps_to_sarif_result_fields() -> None:
    result = finding_to_result(
        {
            "id": "code-001",
            "severity": "high",
            "confidence": 0.92,
            "title": "SQL injection",
            "narrative": "SQL injection via string concat",
            "host": "C:\\repo\\src\\api\\users.py",
            "cve": None,
            "metadata": {
                "rule_id": "CG-005-SQLI",
                "relative_path": "src/api/users.py",
                "line": 42,
                "column": 8,
                "end_line": 42,
                "end_column": 30,
            },
        }
    )

    assert result["ruleId"] == "CG-005-SQLI"
    assert result["level"] == "error"
    assert result["message"]["text"] == "SQL injection via string concat"
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/api/users.py"
    assert location["region"] == {
        "startLine": 42,
        "startColumn": 8,
        "endLine": 42,
        "endColumn": 30,
    }
    assert result["properties"]["longyuanai:finding-id"] == "code-001"


def test_sarif_severity_levels_are_normalized() -> None:
    assert finding_to_result({"severity": "critical"})["level"] == "error"
    assert finding_to_result({"severity": "medium"})["level"] == "warning"
    assert finding_to_result({"severity": "low"})["level"] == "note"


def test_mapping_uses_safe_defaults() -> None:
    result = finding_to_result({})
    region = result["locations"][0]["physicalLocation"]["region"]

    assert result["ruleId"] == "004-codeguard"
    assert result["level"] == "warning"
    assert result["properties"]["confidence"] == 0.5
    assert region["startLine"] == 1
