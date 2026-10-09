"""Bounded local task orchestration, recoverable persistence and safe reports."""

from __future__ import annotations

import hashlib
import html
import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from uuid import uuid4

from ai_code_audit.output.sarif import export_sarif
from ai_code_audit.web.imports import ImportRejected, validate_upload, write_snapshot
from ai_code_audit.web.store import Store, now
from ai_code_audit.web.worker import MAX_FINDINGS, MAX_RESULT_BYTES


class BusyError(ValueError):
    """The bounded local project/task/queue capacity has been reached."""


class Service:
    def __init__(
        self, data_dir: Path, *, scan_timeout: float = 60, ai_timeout: float = 90
    ) -> None:
        if not 0 < scan_timeout <= 300 or not 0 < ai_timeout <= 300:
            raise ValueError("Timeout must be in (0, 300] seconds")
        self.root = data_dir.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        # Lifetime singleton lock prevents a second service recovering live jobs.
        self.lock_stream = (self.root / "service.lock").open("a+b")
        try:
            if sys.platform == "win32":
                import msvcrt

                self.lock_stream.seek(0)
                if not self.lock_stream.read(1):
                    self.lock_stream.write(b"0")
                    self.lock_stream.flush()
                self.lock_stream.seek(0)
                msvcrt.locking(self.lock_stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock_stream.close()
            raise BusyError("此数据目录已被另一个服务使用") from None
        try:
            self.store = Store(self.root / "audit.sqlite3")
            self.store.recover()
        except (OSError, ValueError, sqlite3.Error):
            self.lock_stream.close()
            raise
        self.scan_timeout = scan_timeout
        self.ai_timeout = ai_timeout
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="audit-worker")
        self.lock = threading.Lock()
        self.pending = 0
        self.closed = False

    def close(self) -> None:
        with self.lock:
            self.closed = True
        self.pool.shutdown(wait=True)
        self.lock_stream.close()

    def import_project(self, payload: dict[str, Any]) -> dict[str, Any]:
        name = payload.get("name")
        if (
            not isinstance(name, str)
            or not name.strip()
            or len(name) > 80
            or any(ord(char) < 32 for char in name)
        ):
            raise ImportRejected("项目名称须为 1 至 80 个可打印字符")
        files = validate_upload(payload)
        project_id = uuid4().hex
        with self.lock:
            if self.closed or self.store.count("projects") >= 30:
                raise BusyError("项目上限为 30；请归档数据目录后使用新的数据目录")
            # Stage inside owned storage; never remove an existing project.
            with tempfile.TemporaryDirectory(
                prefix="import-", dir=self.root
            ) as staging:
                source = Path(staging) / "source"
                write_snapshot(source, files)
                destination = self.root / "projects" / project_id
                destination.parent.mkdir(exist_ok=True)
                source.rename(destination)
                manifest = [
                    {
                        "path": filename,
                        "bytes": len(data.removeprefix(b"\xef\xbb\xbf")),
                        "sha256": hashlib.sha256(
                            data.removeprefix(b"\xef\xbb\xbf")
                        ).hexdigest(),
                    }
                    for filename, data in files
                ]
                try:
                    self.store.add_project(project_id, name.strip(), manifest)
                except (sqlite3.Error, OSError, ValueError):
                    # Both locations belong to this unique import. Moving it back
                    # lets TemporaryDirectory roll back a failed database insert.
                    destination.rename(source)
                    raise
        return self.store.project(project_id)

    def create_task(self, project_id: str) -> dict[str, Any]:
        self.store.project(project_id)
        task_id = uuid4().hex
        with self.lock:
            if self.closed or self.pending >= 4 or self.store.count("tasks") >= 200:
                raise BusyError("任务队列已满或已达 200 个历史任务上限")
            self.store.add_task(task_id, project_id)
            self.pending += 1
            self.pool.submit(self._run, task_id, "scan")
        return self.store.task(task_id)

    def request_ai(self, task_id: str) -> dict[str, Any]:
        with self.lock:
            task = self.store.task(task_id)
            if task["status"] != "completed":
                raise BusyError("静态扫描完成后才能请求 AI 分析")
            if (
                self.closed
                or self.pending >= 4
                or task["ai_status"]
                in {"queued", "running", "completed", "partial", "not_applicable"}
            ):
                raise BusyError("AI 分析已在执行、已完成或任务队列已满")
            self.store.update(task_id, ai_status="queued", ai_error=None)
            self.pending += 1
            self.pool.submit(self._run, task_id, "ai")
        return self.store.task(task_id)

    def _run(self, task_id: str, mode: str) -> None:
        started = time.perf_counter()
        try:
            task = self.store.task(task_id)
            root = self.root / "projects" / task["project_id"]
            self._check_snapshot(
                root, self.store.project(task["project_id"])["manifest"]
            )
            self.store.update(
                task_id,
                **(
                    {"status": "running"}
                    if mode == "scan"
                    else {"ai_status": "running"}
                ),
            )
            with tempfile.TemporaryDirectory(prefix="job-", dir=self.root) as scratch:
                input_path = Path(scratch) / "input.json"
                output_path = Path(scratch) / "output.json"
                input_path.write_text(
                    json.dumps(task["envelope"], ensure_ascii=False), encoding="utf-8"
                )
                # Pure scanner/HTTP router only: this trusted worker spawns no children.
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "ai_code_audit.web.worker",
                        mode,
                        str(root),
                        str(input_path),
                        str(output_path),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    check=False,
                    timeout=self.scan_timeout if mode == "scan" else self.ai_timeout,
                )
                if result.returncode != 0:
                    raise ValueError("Worker failed")
                if output_path.stat().st_size > MAX_RESULT_BYTES:
                    raise ValueError("Worker result too large")
                data = json.loads(output_path.read_text(encoding="utf-8"))
                if mode == "scan":
                    self._validate_scan(data)
                    self.store.complete(task_id, data, time.perf_counter() - started)
                else:
                    self._validate_ai(data, len(task["envelope"]["findings"]))
                    self.store.save_ai(task_id, data["analyses"])
                    status = data["status"]
                    self.store.update(
                        task_id,
                        ai_status=status,
                        ai_error="部分或全部模型调用失败；静态扫描证据仍可查看和导出"
                        if status in {"partial", "unavailable"}
                        else None,
                    )
        except Exception as error:  # noqa: BLE001 - every job must end in a persisted failure
            timed_out = isinstance(error, subprocess.TimeoutExpired)
            if mode == "scan":
                self.store.update(
                    task_id,
                    status="failed",
                    finished_at=now(),
                    duration_seconds=time.perf_counter() - started,
                    error="扫描超时，工作进程已终止"
                    if timed_out
                    else "扫描失败：源代码语法、快照完整性或扫描器错误；请检查文件后重试",
                )
            else:
                self.store.update(
                    task_id,
                    ai_status="unavailable",
                    ai_error="AI 超时，工作进程已终止；静态证据已保留"
                    if timed_out
                    else "AI 不可用：请检查服务端模型配置、连接或响应；静态证据已保留",
                )
        finally:
            with self.lock:
                self.pending -= 1

    @staticmethod
    def _check_snapshot(root: Path, manifest: list[dict[str, Any]]) -> None:
        for entry in manifest:
            path = root / entry["path"]
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("Unsafe snapshot path")
            if path.stat().st_size != entry["bytes"]:
                raise ValueError("Snapshot size changed")
            if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
                raise ValueError("Snapshot modified")
        actual = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
        }
        if actual != {entry["path"] for entry in manifest}:
            raise ValueError("Snapshot file set changed")

    @staticmethod
    def _validate_scan(data: Any) -> None:
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("summary"), dict)
            or not isinstance(data.get("warnings"), list)
        ):
            raise TypeError("Invalid scan envelope")
        findings = data.get("findings")
        if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
            raise ValueError("Invalid findings")
        for finding in findings:
            if (
                not isinstance(finding, dict)
                or not isinstance(finding.get("metadata"), dict)
                or not isinstance(finding.get("id"), str)
            ):
                raise TypeError("Invalid finding")

    @staticmethod
    def _validate_ai(data: Any, finding_count: int) -> None:
        if not isinstance(data, dict) or data.get("status") not in {
            "completed",
            "partial",
            "unavailable",
            "not_applicable",
        }:
            raise ValueError("Invalid AI status")
        analyses = data.get("analyses")
        if (
            not isinstance(analyses, list)
            or len(analyses) != min(20, finding_count)
            or any(
                not isinstance(item, dict)
                or item.get("status") not in {"reviewed", "error"}
                for item in analyses
            )
        ):
            raise ValueError("Invalid AI result")

    def report(self, task_id: str, format_name: str) -> tuple[bytes, str]:
        task = self.store.task(task_id)
        if task["status"] != "completed":
            raise BusyError("只有完成的扫描任务可以导出报告")
        if format_name == "json":
            return json.dumps(
                task, ensure_ascii=False, indent=2
            ).encode(), "application/json; charset=utf-8"
        if format_name == "sarif":
            return json.dumps(
                export_sarif(
                    task["envelope"]["findings"],
                    run_properties=task["envelope"]["summary"],
                ),
                ensure_ascii=False,
                indent=2,
            ).encode(), "application/sarif+json; charset=utf-8"
        if format_name != "html":
            raise ValueError("仅支持 html/json/sarif")

        def escape(value: object) -> str:
            return html.escape(str(value), quote=True)

        counts = Counter(
            finding["severity"] for finding in task["envelope"]["findings"]
        )
        body = [
            f"<h1>{escape(task['project_name'])} · 源代码安全检测报告</h1>",
            f"<p>任务：{escape(task_id)}<br>检测时间：{escape(task['finished_at'])}<br>扫描耗时：{task['duration_seconds']:.3f} 秒<br>AI 状态：{escape(task['ai_status'])}</p>",
            f"<h2>检测范围与工具</h2><pre>{escape(json.dumps(task['envelope']['summary'], ensure_ascii=False, indent=2))}</pre>",
            f"<h2>风险统计</h2><p>{escape(dict(counts))}</p>",
        ]
        for finding in task["envelope"]["findings"]:
            metadata = finding["metadata"]
            body.extend(
                [
                    f"<article><h2>{escape(finding['title'])} · {escape(finding['severity'])}</h2>",
                    f"<p>静态规则发现 · 潜在风险 · 未人工确认/未验证<br>{escape(metadata['rule_id'])} · {escape(metadata['relative_path'])}:{escape(metadata['line'])}</p>",
                    f"<p>{escape(finding['description'])}</p><pre>{escape(chr(10).join(finding['evidence']))}</pre>",
                    f"<p>修复建议：{escape(metadata.get('remediation', '需人工复核'))}</p>",
                ]
            )
            if "llm_triage" in metadata:
                body.append(
                    f"<h3>AI 推断（不等同于人工确认或已验证漏洞）</h3><pre>{escape(json.dumps(metadata['llm_triage'], ensure_ascii=False, indent=2))}</pre>"
                )
            body.append("</article>")
        body.append(
            "<h2>检测局限性</h2><p>仅扫描导入的 Python 快照；AST 模式及共现启发式可能误报和漏报，不证明可利用性；没有执行样本。未覆盖跨文件动态数据流、依赖漏洞或运行配置。零发现不代表安全。AI 输出仅作辅助，最多分析 20 项。需人工复核后决定修复。</p>"
        )
        document = (
            '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>检测报告</title><style>body{font:16px/1.65 system-ui;max-width:1000px;margin:40px auto;padding:20px;color:#20304a}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6fa;padding:18px}article{border-top:1px solid #cad4e4;padding:20px 0}</style>'
            + "".join(body)
            + "</html>"
        )
        return document.encode(), "text/html; charset=utf-8"
