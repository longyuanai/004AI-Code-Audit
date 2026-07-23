import pytest

from shared_llm_core import TaskTier

from codeguard.dataflow import CallEdge, DataflowPath
from codeguard.explain import (
    DataflowExplainer,
    build_explanation_prompt,
)
from codeguard.taint import TaintStep


def _path(*, variable: str = "query") -> DataflowPath:
    return DataflowPath(
        language="python",
        variable=variable,
        source=TaintStep(
            kind="source",
            name="request.json.get",
            file="app.py",
            function="read_body",
            line=23,
            column=12,
            detail='request.json.get("query")',
        ),
        calls=(
            CallEdge(
                caller="handler",
                callee="read_body",
                file="app.py",
                line=40,
                arguments=("request",),
            ),
            CallEdge(
                caller="handler",
                callee="run_query",
                file="app.py",
                line=44,
                arguments=("cursor", "query"),
            ),
        ),
        propagations=(),
        sink=TaintStep(
            kind="sink",
            name="cursor.execute",
            file="app.py",
            function="run_query",
            line=45,
            column=5,
            detail="cursor.execute(sql + query)",
        ),
    )


def test_prompt_contains_source_call_chain_and_sink() -> None:
    prompt = build_explanation_prompt(_path())

    assert '"function": "read_body"' in prompt
    assert '"callee": "run_query"' in prompt
    assert '"name": "cursor.execute"' in prompt
    assert '"variable": "query"' in prompt


def test_explainer_uses_frozen_chat_signature_and_cheap_tier(
    stub_router_with,
) -> None:
    router = stub_router_with(
        content=(
            '{"explanation":"变量 query 在 read_body:23 接收 HTTP body，'
            '在 run_query:45 流入 SQL，触发 SQLi。"}'
        ),
        model="stub-cheap",
    )

    result = DataflowExplainer(router).explain(_path())

    assert result.text.endswith("触发 SQLi。")
    assert result.model == "stub-cheap"
    assert len(router.calls) == 1
    tier, request = router.calls[0]
    assert tier is TaskTier.CHEAP
    assert request.temperature == 0
    assert request.response_format == {"type": "json_object"}
    assert request.request_id


def test_explain_all_preserves_path_order(stub_router_with) -> None:
    router = stub_router_with(
        content='{"explanation":"已解释一条数据流。"}'
    )
    paths = [_path(variable="first"), _path(variable="second")]

    results = DataflowExplainer(router).explain_all(paths)

    assert [result.text for result in results] == [
        "已解释一条数据流。",
        "已解释一条数据流。",
    ]
    assert len(router.calls) == 2
    assert '"variable": "first"' in router.calls[0][1].messages[1].content
    assert '"variable": "second"' in router.calls[1][1].messages[1].content


def test_invalid_llm_payload_is_rejected(stub_router_with) -> None:
    router = stub_router_with(content="not-json")

    with pytest.raises(ValueError, match="not valid JSON"):
        DataflowExplainer(router).explain(_path())
