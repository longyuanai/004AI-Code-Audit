from pathlib import Path

import pytest
import yaml

from analyzer.ci_sampling import select_file_sample


ROOT = Path(__file__).resolve().parents[1]


def test_sampling_is_deterministic_and_exactly_twenty_percent(tmp_path) -> None:
    files = [tmp_path / f"file-{index}.py" for index in range(10)]
    first = select_file_sample(files, rate=0.2)
    second = select_file_sample(reversed(files), rate=0.2)

    assert first == second
    assert len(first) == 2


def test_sampling_keeps_one_file_for_small_nonempty_input(tmp_path) -> None:
    files = [tmp_path / "one.py", tmp_path / "two.go"]
    assert len(select_file_sample(files, rate=0.2)) == 1


def test_sampling_rejects_invalid_rate(tmp_path) -> None:
    with pytest.raises(ValueError, match="between 0 and 1"):
        select_file_sample([tmp_path / "one.py"], rate=1.2)


def test_github_workflow_has_cross_platform_matrix_and_sarif_upload() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "code-guard.yml").read_text(
            encoding="utf-8"
        )
    )
    assert workflow["jobs"]["verify"]["strategy"]["matrix"]["os"] == [
        "ubuntu-latest",
        "windows-latest",
    ]
    assert workflow["jobs"]["scan"]["strategy"]["matrix"]["os"] == [
        "ubuntu-latest",
        "windows-latest",
    ]
    scan_steps = workflow["jobs"]["scan"]["steps"]
    assert any(
        step.get("uses") == "github/codeql-action/upload-sarif@v3"
        for step in scan_steps
    )


def test_ci_configs_run_twenty_percent_sample_and_publish_artifacts() -> None:
    github = (
        ROOT / ".github" / "workflows" / "code-guard.yml"
    ).read_text(encoding="utf-8")
    gitlab = (ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")

    assert "--sample-rate 0.20" in github
    assert "artifacts/codeguard-rules.sarif" in github
    assert "--sample-rate 0.20" in gitlab
    assert "artifacts/codeguard-llm-sample.sarif" in gitlab

