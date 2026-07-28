"""Scope and literal-masking behaviour of the Phase-2 heuristic scanner.

`_security_findings` is a co-occurrence heuristic, not a dataflow analysis.
These tests pin the two properties that keep it from being noise: it must not
match inside comments or string literals, and a source must be in scope for
the sink it is paired with.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ai_code_audit.scanner import scan_repository


def _scan(tmp_path: Path, filename: str, body: str) -> list[dict]:
    (tmp_path / filename).write_text(body, encoding="utf-8")
    return scan_repository(tmp_path)["findings"]


def test_docstring_mentioning_input_is_not_a_source(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    findings = _scan(
        tmp_path,
        "safe.py",
        '"""Parameterized only. No user input is trusted."""\n'
        "import sqlite3\n"
        "\n"
        "def list_users(conn, limit):\n"
        '    return conn.execute("SELECT n FROM t LIMIT ?", (limit,))\n',
    )

    assert findings == []


def test_comment_mentioning_input_is_not_a_source(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    findings = _scan(
        tmp_path,
        "commented.py",
        "def run(conn, limit):\n"
        "    # reads form input from the request\n"
        '    return conn.execute("SELECT 1 LIMIT ?", (limit,))\n',
    )

    assert findings == []


def test_sink_name_inside_a_string_literal_is_ignored(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    findings = _scan(
        tmp_path,
        "prose.py",
        "def describe():\n"
        "    value = input('x')\n"
        '    return "we never call execute(value) here"\n',
    )

    assert findings == []


def test_source_and_sink_in_unrelated_functions_are_not_paired(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    findings = _scan(
        tmp_path,
        "scoped.py",
        "def read_config():\n"
        "    value = input('path')\n"
        "    return value.strip()\n"
        "\n"
        "def run_report(conn, report_id):\n"
        '    return conn.execute("SELECT 1 WHERE id = ?", (report_id,))\n',
    )

    assert findings == []


def test_source_and_sink_in_the_same_function_are_reported(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    """Python is a dataflow language, so this is proven rather than guessed."""

    findings = _scan(
        tmp_path,
        "vuln.py",
        "def handler(conn):\n"
        "    name = input('name')\n"
        '    return conn.execute("SELECT * FROM u WHERE n = " + name)\n',
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["metadata"]["line"] == 3
    assert finding["metadata"]["analysis"] == "dataflow"
    assert finding["metadata"]["variable"] == "name"
    assert finding["metadata"]["scope"] == "handler"
    assert finding["severity"] == "high"
    assert finding["confidence"] == 0.9
    assert "dataflow" in finding["tags"]


def test_proven_flow_is_not_also_reported_by_the_heuristic(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    """Both engines see this sink; only the stronger finding is kept."""

    findings = _scan(
        tmp_path,
        "vuln.py",
        "def handler(conn):\n"
        "    name = input('name')\n"
        '    return conn.execute("SELECT * FROM u WHERE n = " + name)\n',
    )

    lines = [finding["metadata"]["line"] for finding in findings]
    assert lines == [3], "sink line 3 must be reported exactly once"


def test_module_level_source_reaches_a_sink_inside_a_function(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    findings = _scan(
        tmp_path,
        "modlevel.py",
        "data = input('global')\n"
        "\n"
        "def use_it(conn):\n"
        "    return conn.execute(data)\n",
    )

    assert len(findings) == 1
    assert findings[0]["metadata"]["line"] == 4


def test_sink_before_any_source_is_not_reported(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    findings = _scan(
        tmp_path,
        "ordered.py",
        "def handler(conn):\n"
        "    conn.execute('SELECT 1')\n"
        "    value = input('late')\n"
        "    return value\n",
    )

    assert findings == []


def test_heuristic_findings_are_labelled_as_unproven(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    """Severity must reflect that no dataflow proof exists.

    These were emitted as high/0.85 regardless of evidence strength, which
    made every hit indistinguishable from a confirmed injection. TypeScript
    is used here because the dataflow engine does not cover it, so this file
    exercises the heuristic path.
    """

    findings = _scan(
        tmp_path,
        "app.ts",
        "export function handler(req, db) {\n"
        "  const name = req.body.name;\n"
        '  return db.query("SELECT * FROM u WHERE n = " + name);\n'
        "}\n",
    )

    finding = findings[0]
    assert finding["severity"] == "medium"
    assert finding["confidence"] == 0.5
    assert "heuristic" in finding["tags"]
    assert finding["metadata"]["analysis"] == "heuristic-cooccurrence"
    assert "no dataflow proof" in finding["narrative"]


def test_languages_without_dataflow_still_get_heuristic_coverage(
    tree_sitter_binding,
    tmp_path: Path,
) -> None:
    """C++ and TypeScript must not lose coverage to the dataflow split."""

    findings = _scan(
        tmp_path,
        "app.ts",
        "export function handler(req, db) {\n"
        "  const name = req.body.name;\n"
        '  return db.query("SELECT " + name);\n'
        "}\n",
    )

    assert len(findings) == 1
    assert findings[0]["metadata"]["analysis"] == "heuristic-cooccurrence"


@pytest.mark.parametrize(
    ("filename", "body", "variable", "sink"),
    [
        (
            "app.go",
            "package main\n"
            "func handler(db *DB, r *Request) {\n"
            '    name := r.FormValue("name")\n'
            '    db.Query("SELECT " + name)\n'
            "}\n",
            "name",
            "db.Query",
        ),
        (
            "App.java",
            "class App {\n"
            "  void run(Conn c, Request req) {\n"
            '    String n = req.getParameter("n");\n'
            '    c.executeQuery("SELECT " + n);\n'
            "  }\n"
            "}\n",
            "n",
            "c.executeQuery",
        ),
    ],
)
def test_dataflow_covers_go_and_java(
    tree_sitter_binding,
    tmp_path: Path,
    filename: str,
    body: str,
    variable: str,
    sink: str,
) -> None:
    findings = _scan(tmp_path, filename, body)

    assert len(findings) == 1
    metadata = findings[0]["metadata"]
    assert metadata["analysis"] == "dataflow"
    assert metadata["variable"] == variable
    assert sink in findings[0]["narrative"]


@pytest.mark.parametrize(
    ("filename", "body"),
    [
        (
            "app.go",
            "package main\n"
            "func handler(db *DB, r *Request) {\n"
            "    // reads request body input here\n"
            '    db.Query("SELECT 1")\n'
            "}\n",
        ),
        (
            "App.java",
            "class App {\n"
            "  void run(Conn c) {\n"
            "    // getParameter input is described in this comment\n"
            '    c.executeQuery("SELECT 1");\n'
            "  }\n"
            "}\n",
        ),
    ],
)
def test_comment_masking_applies_across_languages(
    tree_sitter_binding,
    tmp_path: Path,
    filename: str,
    body: str,
) -> None:
    assert _scan(tmp_path, filename, body) == []
