"""Supplement the existing heuristic with bounded Python AST safety rules.

Findings are review candidates, never executed or represented as verified exploits.
The existing CLI and its baseline/fingerprint semantics remain unchanged.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Any

from ai_code_audit import __version__
from ai_code_audit.scanner import scan_repository
from ai_code_audit.triage_context import redact_sensitive_text

RULESET_VERSION = "graduation-python-1"
SECRET_NAME = re.compile(
    r"(?:password|passwd|api_?key|secret|access_?token|private_?key)$", re.IGNORECASE
)
PLACEHOLDERS = {
    "",
    "example",
    "placeholder",
    "changeme",
    "your-key",
    "test",
    "[redacted]",
}
RULES = {
    "CG-PY-001": (
        "命令注入风险",
        "CWE-78",
        "使用参数数组及 shell=False；对允许执行的程序和参数做白名单校验。",
    ),
    "CG-PY-002": (
        "SQL 注入风险",
        "CWE-89",
        "使用数据库参数绑定，避免拼接、格式化查询；动态表名使用白名单。",
    ),
    "CG-PY-003": (
        "不安全反序列化",
        "CWE-502",
        "使用 JSON 等数据格式，避免反序列化不可信对象；YAML 使用 safe_load。",
    ),
    "CG-PY-004": (
        "动态代码执行",
        "CWE-95",
        "移除 eval/exec；按业务需要使用明确的解析器，字面量可使用 ast.literal_eval。",
    ),
    "CG-PY-005": (
        "硬编码敏感信息",
        "CWE-798",
        "将凭据移至环境变量或密钥管理服务；若已暴露，应撤销并轮换。",
    ),
}


def analyze_python(source: str, relative_path: str) -> list[dict[str, Any]]:
    """Resolve common import aliases; flag syntax-supported dangerous patterns."""
    tree = ast.parse(source, filename=relative_path)
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{name(node.value)}.{node.attr}"
        return ""

    findings: list[dict[str, Any]] = []

    def emit(
        node: ast.AST,
        rule: str,
        reason: str,
        *,
        severity: str = "high",
        secret: bool = False,
    ) -> None:
        line = getattr(node, "lineno", 1)
        column = getattr(node, "col_offset", 0) + 1
        title, cwe, remediation = RULES[rule]
        snippet = (
            "[REDACTED_SECRET_ASSIGNMENT]"
            if secret
            else redact_sensitive_text(ast.get_source_segment(source, node) or "")[
                :1000
            ]
        )
        digest = hashlib.sha256(
            f"{relative_path}:{line}:{column}:{rule}".encode()
        ).hexdigest()[:16]
        findings.append(
            {
                "id": f"code-py-{digest}",
                "source": "004",
                "severity": severity,
                "confidence": 0.7,
                "title": title,
                "description": reason,
                "narrative": reason,
                "host": relative_path,
                "evidence": [f"{relative_path}:{line}:{column}: {snippet}"],
                "tags": ["python", "potential-risk", cwe],
                "metadata": {
                    "rule_id": rule,
                    "cwe": cwe,
                    "relative_path": relative_path,
                    "language": "python",
                    "line": line,
                    "column": column,
                    "analysis": "ast-pattern",
                    "remediation": remediation,
                    "verification": "unverified",
                    "snippet": snippet,
                },
            }
        )

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if (
                isinstance(value, ast.Constant)
                and isinstance(value.value, str)
                and value.value.lower() not in PLACEHOLDERS
                and any(
                    isinstance(target, (ast.Name, ast.Attribute))
                    and SECRET_NAME.search(name(target).split(".")[-1])
                    for target in targets
                )
            ):
                emit(
                    node,
                    "CG-PY-005",
                    "凭据字段赋值为字符串常量；需人工确认是否为有效秘密。",
                    secret=True,
                )
        if not isinstance(node, ast.Call):
            continue
        callee = name(node.func)
        if callee in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            emit(node, "CG-PY-004", f"调用 {callee} 动态解释代码，输入可信性尚未验证。")
        shell = any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )
        if callee in {
            "os.system",
            "os.popen",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
        } or (callee.startswith("subprocess.") and shell):
            emit(node, "CG-PY-001", f"{callee} 通过 shell 解释命令，存在潜在注入风险。")
        if callee in {
            "pickle.load",
            "pickle.loads",
            "_pickle.load",
            "_pickle.loads",
            "dill.load",
            "dill.loads",
            "marshal.load",
            "marshal.loads",
        }:
            emit(
                node, "CG-PY-003", f"{callee} 接收对象序列化数据，来源可信性尚未验证。"
            )
        if callee in {"yaml.load", "yaml.unsafe_load"}:
            safe = any(
                keyword.arg == "Loader"
                and name(keyword.value) in {"yaml.SafeLoader", "yaml.CSafeLoader"}
                for keyword in node.keywords
            )
            safe = safe or (
                len(node.args) > 1
                and name(node.args[1]) in {"yaml.SafeLoader", "yaml.CSafeLoader"}
            )
            if not safe:
                emit(node, "CG-PY-003", "YAML 对象加载未显式采用 SafeLoader。")
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"execute", "executemany", "executescript"}
            and node.args
        ):
            query = node.args[0]
            dynamic = isinstance(query, (ast.JoinedStr, ast.BinOp)) or (
                isinstance(query, ast.Call)
                and isinstance(query.func, ast.Attribute)
                and query.func.attr == "format"
            )
            if dynamic:
                emit(
                    node,
                    "CG-PY-002",
                    "查询参数使用字符串拼接或格式化；需确认数据库调用及输入来源。",
                )
    return sorted(
        findings,
        key=lambda finding: (
            finding["metadata"]["line"],
            finding["metadata"]["column"],
            finding["id"],
        ),
    )


def scan_python_project(root: Path) -> dict[str, Any]:
    """Reuse tree-sitter scanning and add five targeted Python risk classes."""
    envelope = scan_repository(root, ["python"])
    supplemental: list[dict[str, Any]] = []
    for path in sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() == ".py"
    ):
        supplemental.extend(
            analyze_python(
                path.read_text(encoding="utf-8"), path.relative_to(root).as_posix()
            )
        )
    covered = {
        (f["metadata"]["relative_path"], f["metadata"]["line"]) for f in supplemental
    }
    findings = envelope["findings"]
    assert isinstance(findings, list)
    kept = [
        finding
        for finding in findings
        if (finding["metadata"]["relative_path"], finding["metadata"]["line"])
        not in covered
    ]
    for finding in kept:
        finding["host"] = finding["metadata"]["relative_path"]
        finding["metadata"]["verification"] = "unverified"
        finding["metadata"]["remediation"] = (
            "检查输入来源和危险调用；按风险类型使用参数绑定、白名单或安全解析器。"
        )
    envelope["findings"] = kept + supplemental
    summary = envelope["summary"]
    assert isinstance(summary, dict)
    summary.pop("repo_path", None)
    summary.update(
        {
            "tool": "AI-CodeGuard",
            "tool_version": __version__,
            "ruleset": RULESET_VERSION,
            "scope": "Python; tree-sitter heuristic + AST safety patterns",
        }
    )
    return envelope
