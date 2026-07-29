from pathlib import Path

from benchmarks.phase0.benchmark import (
    CorpusExpectations,
    Location,
    calculate_metrics,
    load_expectations,
    parse_opengrep_results,
    run_builtin,
)


def test_phase0_corpus_has_two_vulnerable_and_one_safe_sink_per_language() -> None:
    expectations = load_expectations()

    assert len(expectations.vulnerable) == 10
    assert len(expectations.safe) == 5
    assert {item.path.split("/", 1)[0] for item in expectations.vulnerable} == {
        "cpp",
        "go",
        "java",
        "python",
        "typescript",
    }


def test_metrics_count_unexpected_and_safe_reports_as_false_positives() -> None:
    expectations = CorpusExpectations(
        vulnerable=frozenset(
            {Location("demo.py", 2), Location("demo.py", 8)}
        ),
        safe=frozenset({Location("demo.py", 12)}),
    )

    metrics = calculate_metrics(
        expectations,
        {
            Location("demo.py", 2),
            Location("demo.py", 12),
            Location("demo.py", 20),
        },
    )

    assert metrics.true_positives == 1
    assert metrics.false_positives == 2
    assert metrics.false_negatives == 1
    assert metrics.true_negatives == 0
    assert metrics.precision == 1 / 3
    assert metrics.recall == 1 / 2


def test_opengrep_json_locations_are_normalized_to_corpus_paths(
    tmp_path: Path,
) -> None:
    corpus = tmp_path / "corpus"
    target = corpus / "python" / "demo.py"
    target.parent.mkdir(parents=True)
    target.write_text("eval(value)\n", encoding="utf-8")
    document = {
        "results": [
            {
                "path": str(target),
                "start": {"line": 1, "col": 1},
            }
        ]
    }

    assert parse_opengrep_results(document, corpus=corpus) == {
        Location("python/demo.py", 1)
    }


def test_builtin_phase0_baseline_exposes_dataflow_limit(
    cp314_tree_sitter_binding,
) -> None:
    expectations = load_expectations()
    reported, elapsed, version = run_builtin()
    metrics = calculate_metrics(expectations, reported)

    assert version == "builtin-tree-sitter-heuristic"
    assert elapsed >= 0
    assert metrics.true_positives == 5
    assert metrics.false_positives == 5
    assert metrics.false_negatives == 5
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
