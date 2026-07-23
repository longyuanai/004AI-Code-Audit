from codeguard.taint import TaintAnalyzer, TaintRule, register_taint_rule
from codeguard.v05 import (
    FindingSeverity,
    FindingSource,
    RuleContext,
    RuleEngine,
)


def test_python_input_flows_through_assignment_to_eval() -> None:
    source = """
def render():
    raw = input("expression")
    expression = raw.strip()
    return eval(expression)
"""
    paths = TaintAnalyzer().analyze(source, "python", file="demo.py")

    assert len(paths) == 1
    assert paths[0].source.name == "input"
    assert paths[0].sink.name == "eval"
    assert [step.name for step in paths[0].propagations] == [
        "raw",
        "expression",
    ]


def test_go_http_parameter_flows_to_command_execution() -> None:
    source = """
package demo
func run(r *http.Request) {
    command := r.FormValue("command")
    exec.Command("sh", "-c", command)
}
"""
    paths = TaintAnalyzer().analyze(source, "go", file="demo.go")

    assert len(paths) == 1
    assert paths[0].source.name == "r.FormValue"
    assert paths[0].sink.name == "exec.Command"


def test_java_http_parameter_flows_to_sql_sink() -> None:
    source = """
class Demo {
    void find(HttpServletRequest request, Statement statement)
            throws Exception {
        String owner = request.getParameter("owner");
        String sql = "SELECT * FROM reports WHERE owner='" + owner + "'";
        statement.executeQuery(sql);
    }
}
"""
    paths = TaintAnalyzer().analyze(source, "java", file="Demo.java")

    assert len(paths) == 1
    assert paths[0].source.name == "request.getParameter"
    assert paths[0].sink.name == "statement.executeQuery"
    assert paths[0].variable == "sql"


def test_safe_value_does_not_produce_taint_path() -> None:
    source = """
def render():
    expression = "1 + 1"
    return eval(expression)
"""
    assert TaintAnalyzer().analyze(source, "python") == []


def test_taint_rule_is_registered_and_returns_v05_finding() -> None:
    registry = register_taint_rule()
    engine = RuleEngine(registry)
    context = RuleContext(
        subject="demo.py",
        facts={
            "language": "python",
            "file": "demo.py",
            "source": "value = input('value')\neval(value)\n",
        },
    )

    findings = engine.evaluate(context, rule_ids=[TaintRule.id])

    assert registry.get(TaintRule.id).id == TaintRule.id
    assert len(findings) == 1
    assert findings[0].source is FindingSource.CODE
    assert findings[0].severity is FindingSeverity.CRITICAL
    assert findings[0].metadata["rule_id"] == TaintRule.id
