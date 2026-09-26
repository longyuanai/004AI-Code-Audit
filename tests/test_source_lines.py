"""Python line numbering must match tree-sitter (contracts/suppression.json,
``lineNumbering``): only LF separates lines."""

from __future__ import annotations

import importlib.util
import random
import sys
import types
from pathlib import Path

import pytest
import tree_sitter_python
from tree_sitter import Language, Parser

from ai_code_audit.classification import CodeContext, DataClassification
from ai_code_audit.postprocess import enrich_findings
from ai_code_audit.scanner import scan_repository
from ai_code_audit.source_lines import read_source_lines, split_source_lines

SEPARATORS = {
    "CR": "\r", "VT": "\x0b", "FF": "\x0c", "FS": "\x1c", "GS": "\x1d",
    "RS": "\x1e", "NEL": "\x85", "LS": " ", "PS": " ",
}
PARSER = Parser(Language(tree_sitter_python.language()))


def _call_row(source: str) -> int:
    stack = [PARSER.parse(source.encode("utf-8")).root_node]
    while stack:
        node = stack.pop()
        if node.type == "call":
            return node.start_point[0] + 1
        stack.extend(node.children)
    raise AssertionError("no call node")


def test_matches_splitlines_for_lf_and_crlf_files(tmp_path: Path) -> None:
    """The switch must not change anything for ordinary files."""

    rng = random.Random(4)
    alphabet = ["a", "b", " ", "\t", "é", "中", "#", "(", ")", "\n", "\r\n"]
    for index in range(2000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        path = tmp_path / f"f{index}.py"
        path.write_bytes(text.encode("utf-8"))
        assert read_source_lines(path) == path.read_text(encoding="utf-8").splitlines()


@pytest.mark.parametrize("name", list(SEPARATORS))
def test_line_numbers_follow_tree_sitter(name: str) -> None:
    source = f"x = 1{SEPARATORS[name]}y = 2\neval(y)\n"

    assert split_source_lines(source).index("eval(y)") + 1 == _call_row(source) == 2


@pytest.mark.parametrize("name", list(SEPARATORS))
@pytest.mark.parametrize("placement", ["code", "comment"])
def test_scanner_reports_tree_sitter_lines_with_matching_evidence(
    tree_sitter_binding, tmp_path: Path, name: str, placement: str
) -> None:
    separator = SEPARATORS[name]
    first = f"x = 1{separator}y = 2" if placement == "code" else f"# a{separator}b"
    source = f"{first}\nvalue = input('v')\neval(value)\n"
    (tmp_path / "app.py").write_bytes(source.encode("utf-8"))

    findings = scan_repository(tmp_path, ["python"])["findings"]

    # Python takes the dataflow path; its evidence is the rendered chain.
    assert [f["metadata"]["line"] for f in findings] == [_call_row(source)] == [3]
    assert findings[0]["metadata"]["analysis"] == "dataflow"
    assert findings[0]["evidence"][-1] == "sink:eval at <module>:3:1 (eval(value))"
    assert findings[0]["metadata"]["snippet"] == "eval(value)"


@pytest.mark.parametrize("name", list(SEPARATORS))
@pytest.mark.parametrize("placement", ["code", "comment"])
def test_heuristic_scanner_reports_tree_sitter_lines(
    tree_sitter_binding, tmp_path: Path, name: str, placement: str
) -> None:
    """TypeScript still takes the co-occurrence heuristic, which splits lines itself."""
    separator = SEPARATORS[name]
    first = f"const x = 1{separator}const y = 2" if placement == "code" else f"// a{separator}b"
    source = f"{first}\nconst value = req.query.v\neval(value)\n"
    (tmp_path / "app.ts").write_bytes(source.encode("utf-8"))

    findings = scan_repository(tmp_path, ["typescript"])["findings"]

    assert [f["metadata"]["line"] for f in findings] == [3]
    assert findings[0]["metadata"]["analysis"] == "heuristic-cooccurrence"
    assert findings[0]["evidence"][-1] == "sink line 3: eval(value)"


def test_classification_context_is_read_from_the_finding_line(tmp_path: Path) -> None:
    lines = ["\x0c"] * 10 + ["password = request.args['p']"] + ["\x0c"] * 10
    (tmp_path / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    seen: list[str] = []

    class Capture:
        def classify(self, context: CodeContext) -> list[DataClassification]:
            seen.append(context.content)
            return []

    enrich_findings(
        [{"id": "f", "severity": "high", "metadata": {"relative_path": "app.py", "line": 11}}],
        repo_path=tmp_path,
        classifier=Capture(),
        in_diff=False,
    )

    assert seen and "password" in seen[0]


def _load_triage_context(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """Load triage_context under a private name.

    The module needs shared_llm_core only for wrap_untrusted, which the excerpt
    code never calls. When the sibling checkout is absent, a stand-in that
    raises on use is installed for this test alone, so it cannot make anything
    pass by accident and cannot leak into other test modules.
    """

    if importlib.util.find_spec("shared_llm_core") is None:
        def refuse(*_args: object, **_kwargs: object) -> str:
            raise AssertionError("wrap_untrusted must not be reached here")

        package = types.ModuleType("shared_llm_core")
        untrusted = types.ModuleType("shared_llm_core.untrusted")
        untrusted.wrap_untrusted = refuse  # type: ignore[attr-defined]
        package.untrusted = untrusted  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "shared_llm_core", package)
        monkeypatch.setitem(sys.modules, "shared_llm_core.untrusted", untrusted)

    path = Path(__file__).resolve().parents[1] / "src" / "ai_code_audit" / "triage_context.py"
    spec = importlib.util.spec_from_file_location("_triage_context_under_test", path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    # @dataclass resolves annotations through sys.modules; removed at teardown.
    monkeypatch.setitem(sys.modules, spec.name, module)  # type: ignore[union-attr]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_triage_excerpt_labels_and_lines_follow_tree_sitter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The LLM sees "N: code"; both must be the finding's real line."""

    triage_context = _load_triage_context(monkeypatch)
    lines = [f"x{index} = 0" for index in range(1, 30)]
    lines[1] = "x2 = 0\x0c\x0c\x0c"  # form feeds before the finding
    lines[19] = "eval(user_input)"  # line 20
    (tmp_path / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")

    context = triage_context.build_triage_context(
        {"id": "f", "metadata": {"relative_path": "app.py", "line": 20}},
        repo_path=tmp_path,
    )

    rendered = dict(
        entry.split(": ", 1) for entry in context.code_excerpt.split("\n")
    )
    assert rendered["20"] == "eval(user_input)"
    # Every label names the real line, whatever the context radius is.
    assert all(text == lines[int(label) - 1] for label, text in rendered.items())
