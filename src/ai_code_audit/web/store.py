"""SQLite task persistence with separate immutable evidence and AI records."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, 1}:
                raise ValueError(
                    "Unsupported task database version; restore a compatible backup"
                )
            db.executescript("""
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL,
                    manifest TEXT NOT NULL, file_count INTEGER NOT NULL, total_bytes INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
                    status TEXT NOT NULL, created_at TEXT NOT NULL, finished_at TEXT,
                    duration_seconds REAL, error TEXT, summary TEXT,
                    ai_status TEXT NOT NULL DEFAULT 'not_requested', ai_error TEXT
                );
                CREATE TABLE IF NOT EXISTS findings (
                    task_id TEXT NOT NULL REFERENCES tasks(id), ordinal INTEGER NOT NULL,
                    evidence TEXT NOT NULL, PRIMARY KEY(task_id, ordinal)
                );
                CREATE TABLE IF NOT EXISTS ai_results (
                    task_id TEXT NOT NULL, ordinal INTEGER NOT NULL, analysis TEXT NOT NULL,
                    PRIMARY KEY(task_id, ordinal),
                    FOREIGN KEY(task_id, ordinal) REFERENCES findings(task_id, ordinal)
                );
                PRAGMA user_version=1;
            """)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def recover(self) -> None:
        with self.connection() as db:
            db.execute(
                "UPDATE tasks SET status='interrupted', error='服务重启，任务中断，请重新创建扫描', finished_at=? WHERE status IN ('queued','running')",
                (now(),),
            )
            db.execute(
                "UPDATE tasks SET ai_status='unavailable', ai_error='服务重启，AI 分析中断，可重试' WHERE ai_status IN ('queued','running')"
            )

    def count(self, table: str) -> int:
        if table not in {"projects", "tasks"}:
            raise ValueError("Invalid table")
        with self.connection() as db:
            return int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def add_project(
        self, project_id: str, name: str, manifest: list[dict[str, Any]]
    ) -> None:
        with self.connection() as db:
            db.execute(
                "INSERT INTO projects VALUES (?,?,?,?,?,?)",
                (
                    project_id,
                    name,
                    now(),
                    json.dumps(manifest),
                    len(manifest),
                    sum(item["bytes"] for item in manifest),
                ),
            )

    def projects(self) -> list[dict[str, Any]]:
        with self.connection() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT id,name,created_at,file_count,total_bytes FROM projects ORDER BY created_at DESC"
                )
            ]

    def project(self, project_id: str) -> dict[str, Any]:
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM projects WHERE id=?", (project_id,)
            ).fetchone()
        if row is None:
            raise KeyError("项目不存在")
        result = dict(row)
        result["manifest"] = json.loads(result["manifest"])
        return result

    def add_task(self, task_id: str, project_id: str) -> None:
        with self.connection() as db:
            db.execute(
                "INSERT INTO tasks(id,project_id,status,created_at) VALUES (?,?,'queued',?)",
                (task_id, project_id, now()),
            )

    def update(self, task_id: str, **fields: Any) -> None:
        if not fields or not set(fields) <= {
            "status",
            "finished_at",
            "duration_seconds",
            "error",
            "ai_status",
            "ai_error",
        }:
            raise ValueError("Invalid task update")
        with self.connection() as db:
            db.execute(
                f"UPDATE tasks SET {','.join(f'{key}=?' for key in fields)} WHERE id=?",
                (*fields.values(), task_id),
            )

    def complete(self, task_id: str, envelope: dict[str, Any], duration: float) -> None:
        findings = envelope["findings"]
        with self.connection() as db:
            for ordinal, finding in enumerate(findings):
                db.execute(
                    "INSERT INTO findings VALUES (?,?,?)",
                    (task_id, ordinal, json.dumps(finding, ensure_ascii=False)),
                )
            db.execute(
                "UPDATE tasks SET status='completed', summary=?, finished_at=?, duration_seconds=? WHERE id=?",
                (
                    json.dumps(
                        {
                            "summary": envelope["summary"],
                            "warnings": envelope["warnings"],
                        },
                        ensure_ascii=False,
                    ),
                    now(),
                    duration,
                    task_id,
                ),
            )

    def save_ai(self, task_id: str, analyses: list[dict[str, Any]]) -> None:
        with self.connection() as db:
            for ordinal, analysis in enumerate(analyses):
                db.execute(
                    "INSERT OR REPLACE INTO ai_results VALUES (?,?,?)",
                    (task_id, ordinal, json.dumps(analysis, ensure_ascii=False)),
                )

    def tasks(self) -> list[dict[str, Any]]:
        with self.connection() as db:
            rows = db.execute(
                "SELECT t.id,t.project_id,p.name AS project_name,t.status,t.created_at,t.finished_at,t.duration_seconds,t.error,t.ai_status,t.ai_error FROM tasks t JOIN projects p ON p.id=t.project_id ORDER BY t.created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def task(self, task_id: str) -> dict[str, Any]:
        with self.connection() as db:
            row = db.execute(
                "SELECT t.*,p.name AS project_name FROM tasks t JOIN projects p ON p.id=t.project_id WHERE t.id=?",
                (task_id,),
            ).fetchone()
            if row is None:
                raise KeyError("任务不存在")
            records = db.execute(
                "SELECT f.ordinal,f.evidence,a.analysis FROM findings f LEFT JOIN ai_results a ON a.task_id=f.task_id AND a.ordinal=f.ordinal WHERE f.task_id=? ORDER BY f.ordinal",
                (task_id,),
            ).fetchall()
        result = dict(row)
        envelope = (
            json.loads(result.pop("summary"))
            if result.get("summary")
            else {"summary": {}, "warnings": []}
        )
        result["envelope"] = {**envelope, "findings": []}
        for record in records:
            finding = json.loads(record["evidence"])
            finding["ordinal"] = record["ordinal"]
            if record["analysis"]:
                finding.setdefault("metadata", {})["llm_triage"] = json.loads(
                    record["analysis"]
                )
            result["envelope"]["findings"].append(finding)
        return result
