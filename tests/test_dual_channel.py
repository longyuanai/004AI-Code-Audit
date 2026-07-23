from analyzer.dual_channel import DualChannelScheduler, RuleMatch
from analyzer.providers.claude_v2 import ClaudeV2Provider


def match(**overrides) -> RuleMatch:
    values = {
        "rule_id": "CG-001",
        "file": "samples/demo.py",
        "line": 5,
        "severity": "critical",
        "snippet": 'query = f"SELECT ... {user}"',
        "language": "python",
    }
    values.update(overrides)
    return RuleMatch(**values)


def test_empty_rule_channel_never_calls_llm(stub_router) -> None:
    report = DualChannelScheduler(ClaudeV2Provider(stub_router)).schedule([])

    assert report.stats.rule_matches == 0
    assert report.stats.llm_reviews == 0
    assert stub_router.calls == []


def test_rule_match_flows_to_v2_llm_review(stub_router) -> None:
    report = DualChannelScheduler(ClaudeV2Provider(stub_router)).schedule([match()])

    assert report.stats == report.stats.__class__(
        rule_matches=1,
        llm_reviews=1,
        confirmed=1,
        dismissed=0,
        rule_only=0,
    )
    assert report.findings[0].channel == "rule_match->llm_review"
    assert report.findings[0].llm_review.confirmed is True
    assert len(stub_router.calls) == 1


def test_review_predicate_keeps_unselected_match_rule_only(stub_router) -> None:
    report = DualChannelScheduler(ClaudeV2Provider(stub_router)).schedule(
        [match()],
        should_review=lambda _match: False,
    )

    assert report.stats.rule_only == 1
    assert report.findings[0].llm_review is None
    assert stub_router.calls == []


def test_router_failure_preserves_rule_finding(stub_router) -> None:
    stub_router.error = RuntimeError("offline")
    report = DualChannelScheduler(ClaudeV2Provider(stub_router)).schedule([match()])

    assert report.stats.rule_only == 1
    assert report.findings[0].rule_match.rule_id == "CG-001"
    assert "RuntimeError: offline" in report.findings[0].review_error


def test_malformed_llm_json_preserves_rule_finding(stub_router) -> None:
    stub_router.content = "not-json"
    report = DualChannelScheduler(ClaudeV2Provider(stub_router)).schedule([match()])

    assert report.stats.llm_reviews == 0
    assert report.stats.rule_only == 1
    assert report.findings[0].review_error.startswith("JSONDecodeError:")

