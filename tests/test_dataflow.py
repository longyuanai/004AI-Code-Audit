from codeguard.dataflow import (
    DataflowAnalyzer,
    DataflowRule,
    register_dataflow_rule,
)
from codeguard.taint import register_taint_rule
from codeguard.v05 import FindingSource, RuleContext, RuleEngine


def test_python_tracks_return_value_into_second_function() -> None:
    source = """
def read_body(request):
    return request.json.get("query")

def run_query(cursor, query):
    cursor.execute("SELECT * FROM reports WHERE owner='" + query + "'")

def handler(request, cursor):
    value = read_body(request)
    run_query(cursor, value)
"""
    report = DataflowAnalyzer().analyze(source, "python", file="app.py")

    assert len(report.paths) == 1
    assert report.paths[0].source.function == "read_body"
    assert report.paths[0].sink.function == "run_query"
    assert [(edge.caller, edge.callee) for edge in report.paths[0].calls] == [
        ("handler", "read_body"),
        ("handler", "run_query"),
    ]


def test_go_tracks_http_value_across_function_calls() -> None:
    source = """
package demo
func readCommand(r *http.Request) string {
    return r.FormValue("command")
}
func execute(command string) {
    exec.Command("sh", "-c", command)
}
func handler(r *http.Request) {
    command := readCommand(r)
    execute(command)
}
"""
    report = DataflowAnalyzer().analyze(source, "go", file="handler.go")

    assert len(report.paths) == 1
    assert report.paths[0].source.function == "readCommand"
    assert report.paths[0].sink.name == "exec.Command"
    assert len(report.paths[0].calls) == 2


def test_java_tracks_parameter_to_sql_method() -> None:
    source = """
class Demo {
    String readOwner(HttpServletRequest request) {
        return request.getParameter("owner");
    }
    void query(Statement statement, String owner) throws Exception {
        statement.executeQuery("SELECT * FROM reports WHERE owner='" + owner + "'");
    }
    void handle(HttpServletRequest request, Statement statement)
            throws Exception {
        String owner = readOwner(request);
        query(statement, owner);
    }
}
"""
    report = DataflowAnalyzer().analyze(source, "java", file="Demo.java")

    assert len(report.paths) == 1
    assert report.paths[0].source.name == "request.getParameter"
    assert report.paths[0].sink.function == "query"
    assert {edge.callee for edge in report.call_graph} == {
        "readOwner",
        "query",
    }


def test_call_graph_is_emitted_without_taint_path() -> None:
    source = """
def normalize(value):
    return value.strip()

def handler():
    clean = normalize("constant")
    print(clean)
"""
    report = DataflowAnalyzer().analyze(source, "python")

    assert [(edge.caller, edge.callee) for edge in report.call_graph] == [
        ("handler", "normalize")
    ]
    assert report.paths == ()


def test_dataflow_rule_registers_alongside_taint_rule() -> None:
    registry = register_taint_rule()
    register_dataflow_rule(registry)
    engine = RuleEngine(registry)
    context = RuleContext(
        subject="app.py",
        facts={
            "language": "python",
            "file": "app.py",
            "source": """
def read():
    return input("query")
def use(value):
    eval(value)
def main():
    value = read()
    use(value)
""",
        },
    )

    findings = engine.evaluate(
        context,
        rule_ids=[DataflowRule.id],
    )

    assert {rule.id for rule in registry.all()} == {
        "004-taint-source-to-sink",
        "004-cross-function-dataflow",
    }
    assert len(findings) == 1
    assert findings[0].source is FindingSource.CODE
    assert findings[0].metadata["rule_id"] == DataflowRule.id
