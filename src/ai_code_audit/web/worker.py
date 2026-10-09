"""Trusted subprocess entry point: parse source, never import or run it."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ai_code_audit.python_security import scan_python_project

MAX_RESULT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 2000


def analyze(envelope: dict[str, Any], root: Path) -> dict[str, Any]:
    from shared_llm_core import LLMRouter, RouteRule, TaskTier
    from shared_llm_core.config import load_config

    from ai_code_audit.triage import FindingTriageReviewer

    findings = envelope["findings"]
    if not findings:
        return {"analyses": [], "status": "not_applicable"}
    cfg = load_config()
    enabled = [provider for provider in cfg.providers.values() if provider.enabled]
    if not enabled:
        raise ValueError("No enabled model provider")
    provider = enabled[0]
    # Use the existing gateway but explicitly disable raw prompt/response audit.
    router = LLMRouter(
        cfg,
        [RouteRule(TaskTier.CHEAP, provider.name, provider.default_model)],
        audit=None,
    )
    reviewer = FindingTriageReviewer(router, model_version=provider.default_model)
    analyses = []
    try:
        for finding in findings[:20]:
            result = reviewer.review(finding, repo_path=root)
            metadata = result.to_metadata()
            if result.status == "error":
                # Provider exceptions may contain connection headers or payloads.
                metadata["error"] = (
                    "模型调用失败（连接、超时、限流或响应格式）；静态证据已保留"
                )
            analyses.append(metadata)
    finally:
        router.close()
    errors = sum(item["status"] == "error" for item in analyses)
    return {
        "analyses": analyses,
        "status": "unavailable"
        if errors == len(analyses)
        else "partial"
        if errors or len(findings) > 20
        else "completed",
    }


def main() -> int:
    mode, root_raw, input_raw, output_raw = sys.argv[1:]
    root = Path(root_raw)
    try:
        if mode == "scan":
            result = scan_python_project(root)
            if len(result["findings"]) > MAX_FINDINGS:
                raise ValueError("Too many findings")
        elif mode == "ai":
            result = analyze(
                json.loads(Path(input_raw).read_text(encoding="utf-8")), root
            )
        else:
            raise ValueError("Unsupported worker mode")
        text = json.dumps(result, ensure_ascii=False)
        if len(text.encode("utf-8")) > MAX_RESULT_BYTES:
            raise ValueError("Result limit exceeded")
        with Path(output_raw).open("x", encoding="utf-8") as stream:
            stream.write(text)
        return 0
    except Exception as error:  # noqa: BLE001 - containment boundary, no input/provider values
        print(type(error).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
