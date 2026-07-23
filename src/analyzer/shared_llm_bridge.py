"""JSON bridge from the Node CLI to shared_llm_core.LLMRouter.

The bridge deliberately contains no provider-specific code. Provider and model
selection stay inside the frozen shared_llm_core contract.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from shared_llm_core import ChatRequest, LLMRouter, TaskTier


def run(payload: dict[str, Any]) -> dict[str, Any]:
    request = ChatRequest.model_validate(payload["request"])
    tier = TaskTier(payload["tier"])
    yaml_path = payload.get("yaml_path")

    with LLMRouter.from_env(yaml_path=yaml_path) as router:
        response = router.chat(tier, request)

    return response.model_dump(mode="json")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        json.dump(run(payload), sys.stdout, ensure_ascii=False)
        return 0
    except Exception as error:  # bridge boundary: preserve the useful Python error
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

