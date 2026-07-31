"""SARIF 2.1.0 export for CodeGuard Finding envelopes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Focused schema for fields emitted by this module. It deliberately rejects
# malformed SARIF without fetching a network schema during offline CI.
SARIF_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["version", "$schema", "runs"],
    "properties": {
        "version": {"const": SARIF_VERSION},
        "$schema": {"const": SARIF_SCHEMA_URL},
        "runs": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["tool", "results"],
                "properties": {
                    "tool": {
                        "type": "object",
                        "required": ["driver"],
                        "properties": {
                            "driver": {
                                "type": "object",
                                "required": ["name", "version"],
                            }
                        },
                    },
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": [
                                "ruleId",
                                "level",
                                "message",
                                "locations",
                                "properties",
                            ],
                        },
                    },
                },
            },
        },
    },
}


def finding_to_result(finding: Mapping[str, Any]) -> dict[str, Any]:
    metadata = finding.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    severity = str(finding.get("severity", "medium")).lower()
    line = _positive_int(metadata.get("line"), default=1)
    column = _positive_int(metadata.get("column"), default=1)
    end_line = _positive_int(metadata.get("end_line"), default=line)
    end_column = _positive_int(metadata.get("end_column"), default=column)
    message = (
        finding.get("narrative")
        or finding.get("description")
        or finding.get("title")
        or "CodeGuard finding"
    )
    result = {
        "ruleId": str(
            metadata.get("rule_id")
            or finding.get("id")
            or "004-codeguard"
        ),
        "level": LEVELS.get(severity, "warning"),
        "message": {"text": str(message)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _artifact_uri(finding, metadata)
                    },
                    "region": {
                        "startLine": line,
                        "startColumn": column,
                        "endLine": end_line,
                        "endColumn": end_column,
                    },
                }
            }
        ],
        "properties": {
            "confidence": float(finding.get("confidence", 0.5)),
            "severity": severity,
            "cve": finding.get("cve"),
            "longyuanai:finding-id": str(finding.get("id", "")),
        },
    }
    fingerprint = metadata.get("fingerprint")
    if isinstance(fingerprint, str) and fingerprint:
        result["partialFingerprints"] = {
            "codeguardFingerprint/v1": fingerprint
        }
    code_flows = _sarif_code_flows(metadata.get("code_flows"))
    if code_flows:
        result["codeFlows"] = code_flows
    return result


def export_sarif(
    findings: Iterable[Mapping[str, Any]],
    *,
    tool_version: str = "0.6",
) -> dict[str, Any]:
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA_URL,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "longyuanai-codeguard",
                        "version": tool_version,
                        "informationUri": (
                            "https://github.com/hzj-Jeff-07/AI-CodeGuard"
                        ),
                    }
                },
                "results": [finding_to_result(item) for item in findings],
            }
        ],
    }


def render_sarif(document: Mapping[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def validate_sarif(document: Mapping[str, Any]) -> None:
    from jsonschema import validate

    validate(instance=document, schema=SARIF_SCHEMA)


def _artifact_uri(
    finding: Mapping[str, Any],
    metadata: Mapping[str, Any],
) -> str:
    relative = metadata.get("relative_path")
    if isinstance(relative, str) and relative:
        return relative.replace("\\", "/")
    host = finding.get("host")
    if isinstance(host, str) and host:
        return Path(host).as_posix()
    return "unknown"


def _positive_int(value: Any, *, default: int) -> int:
    return value if isinstance(value, int) and value > 0 else default


def _sarif_code_flows(raw_steps: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_steps, list):
        return []
    locations: list[dict[str, Any]] = []
    for step in raw_steps:
        if not isinstance(step, Mapping):
            continue
        path = step.get("path")
        if not isinstance(path, str) or not path:
            continue
        line = _positive_int(step.get("line"), default=1)
        column = _positive_int(step.get("column"), default=1)
        end_line = _positive_int(step.get("end_line"), default=line)
        end_column = _positive_int(
            step.get("end_column"),
            default=column,
        )
        locations.append(
            {
                "location": {
                    "message": {
                        "text": str(step.get("message") or step.get("kind") or "")
                    },
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": path.replace("\\", "/")
                        },
                        "region": {
                            "startLine": line,
                            "startColumn": column,
                            "endLine": end_line,
                            "endColumn": end_column,
                        },
                    },
                }
            }
        )
    if not locations:
        return []
    return [{"threadFlows": [{"locations": locations}]}]


__all__ = [
    "SARIF_SCHEMA",
    "SARIF_SCHEMA_URL",
    "SARIF_VERSION",
    "export_sarif",
    "finding_to_result",
    "render_sarif",
    "validate_sarif",
]
