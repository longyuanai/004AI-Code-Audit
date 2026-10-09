"""Loopback-only HTTP UI with explicit CSRF, request and thread limits."""

from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
import socket
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ai_code_audit.web.imports import MAX_REQUEST_BYTES, ImportRejected
from ai_code_audit.web.service import BusyError, Service

STATIC_ROOT = Path(__file__).parent / "static"


class AuditServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True

    def __init__(self, service: Service, port: int) -> None:
        self.service = service
        self.token = secrets.token_urlsafe(32)
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(("127.0.0.1", port), Handler)
        actual_port = self.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{actual_port}", f"localhost:{actual_port}"}
        self.allowed_origins = {f"http://{host}" for host in self.allowed_hosts}

    def process_request(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: Any
    ) -> None:
        if not isinstance(request, socket.socket):
            raise TypeError("TCP socket required")
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.0 503 Busy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: Any
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server: AuditServer

    def setup(self) -> None:
        self.request.settimeout(10)
        super().setup()

    def log_message(self, format: str, *args: Any) -> None:
        # Avoid printing filenames, snippets, model output or request contents.
        pass

    def _respond(
        self,
        status: int,
        content: bytes,
        content_type: str = "application/json; charset=utf-8",
        *,
        download: str | None = None,
    ) -> None:
        # Windows may reset a socket closed with unread request data, hiding
        # the rejection response. Drain a bounded fragment for early rejects.
        if self.command == "POST" and not getattr(self, "body_read", False):
            try:
                self.connection.settimeout(0.05)
                length = self.headers.get("Content-Length", "")
                if length.isascii() and length.isdigit() and 0 < int(length) <= 65536:
                    self.rfile.read(int(length))
                else:
                    self.rfile.read1(65536)
            except (OSError, ValueError):
                pass
        self.send_response(status)
        self.send_header("Connection", "close")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        if download:
            self.send_header(
                "Content-Disposition", f'attachment; filename="{download}"'
            )
        self.end_headers()
        self.wfile.write(content)

    def _json(self, status: int, data: Any) -> None:
        self._respond(status, json.dumps(data, ensure_ascii=False).encode())

    def _origin_ok(self) -> bool:
        if self.headers.get("Host") not in self.server.allowed_hosts:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in self.server.allowed_origins

    def do_GET(self) -> None:
        try:
            if not self._origin_ok():
                self._json(403, {"error": "来源或 Host 不允许"})
                return
            path = urlsplit(self.path).path
            if path in {"/", "/app.js", "/style.css"}:
                filename = {
                    "/": "index.html",
                    "/app.js": "app.js",
                    "/style.css": "style.css",
                }[path]
                mime = {
                    "/": "text/html",
                    "/app.js": "text/javascript",
                    "/style.css": "text/css",
                }[path]
                self._respond(
                    200, (STATIC_ROOT / filename).read_bytes(), mime + "; charset=utf-8"
                )
            elif path == "/api/session":
                self._json(
                    200,
                    {
                        "token": self.server.token,
                        "mode": "local-single-user",
                        "limits": {
                            "files": 100,
                            "file_bytes": 512 * 1024,
                            "total_bytes": 8 * 1024 * 1024,
                        },
                    },
                )
            elif path == "/api/projects":
                self._json(200, self.server.service.store.projects())
            elif path == "/api/tasks":
                self._json(200, self.server.service.store.tasks())
            elif path.startswith("/api/tasks/"):
                parts = path.split("/")
                task_id = parts[3]
                if len(task_id) != 32 or any(
                    char not in "0123456789abcdef" for char in task_id
                ):
                    raise KeyError("任务不存在")
                if len(parts) == 4:
                    self._json(200, self.server.service.store.task(task_id))
                elif len(parts) == 5 and parts[4].startswith("report."):
                    format_name = parts[4].removeprefix("report.")
                    content, mime = self.server.service.report(task_id, format_name)
                    self._respond(
                        200, content, mime, download=f"audit-{task_id}.{format_name}"
                    )
                else:
                    raise KeyError("接口不存在")
            else:
                raise KeyError("接口不存在")
        except KeyError as error:
            self._json(404, {"error": str(error.args[0])})
        except (ValueError, BusyError) as error:
            self._json(409, {"error": str(error)})
        except (OSError, sqlite3.Error):
            self._json(500, {"error": "存储读取失败，请检查数据目录权限和可用空间"})

    def do_POST(self) -> None:
        try:
            request_token = self.headers.get("X-Audit-Token", "")
            if (
                not self._origin_ok()
                or not request_token.isascii()
                or not hmac.compare_digest(request_token, self.server.token)
            ):
                self._json(403, {"error": "请求令牌或来源校验失败，请刷新本地页面"})
                return
            lengths = self.headers.get_all("Content-Length") or []
            if (
                self.headers.get("Transfer-Encoding")
                or len(lengths) != 1
                or not lengths[0].isascii()
                or not lengths[0].isdigit()
            ):
                self._json(400, {"error": "请求必须具有唯一 Content-Length"})
                return
            length = int(lengths[0])
            if not 0 < length <= MAX_REQUEST_BYTES:
                self._json(413, {"error": "请求大小超过 12 MiB 或为空"})
                return
            if self.headers.get("Content-Type", "").split(";")[
                0
            ] != "application/json" or self.headers.get("Content-Encoding"):
                self._json(415, {"error": "仅接受未压缩的 application/json"})
                return
            data = self.rfile.read(length)
            self.body_read = True
            if len(data) != length:
                raise ImportRejected("请求内容不完整")
            payload = json.loads(data)
            if not isinstance(payload, dict):
                raise ImportRejected("JSON 请求必须为对象")
            path = urlsplit(self.path).path
            if path == "/api/projects":
                self._json(201, self.server.service.import_project(payload))
            elif path == "/api/tasks":
                project_id = payload.get("project_id")
                if not isinstance(project_id, str):
                    raise ImportRejected("project_id 必须为字符串")
                self._json(202, self.server.service.create_task(project_id))
            elif path.startswith("/api/tasks/") and path.endswith("/ai"):
                if payload.get("consent") is not True:
                    raise ImportRejected(
                        "请明确同意将脱敏的有限代码片段发送给服务端配置的模型"
                    )
                parts = path.split("/")
                if len(parts) != 5:
                    raise KeyError("接口不存在")
                self._json(202, self.server.service.request_ai(parts[3]))
            else:
                raise KeyError("接口不存在")
        except KeyError as error:
            self._json(404, {"error": str(error.args[0])})
        except BusyError as error:
            self._json(409, {"error": str(error)})
        except (ValueError, UnicodeDecodeError, RecursionError):
            self._json(
                400,
                {
                    "error": "输入无效：请检查名称、Python 文件类型、路径、编码和大小；ZIP 不允许链接、穿越、加密或高压缩比"
                },
            )
        except TimeoutError:
            self._json(408, {"error": "请求读取超时"})
        except (OSError, sqlite3.Error):
            self._json(500, {"error": "存储操作失败，请检查数据目录权限和可用空间"})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="AI-Code-Audit 本地单用户 Web；仅监听 127.0.0.1"
    )
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("AUDIT_WEB_PORT", "8765"))
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(os.environ.get("AUDIT_WEB_DATA_DIR", "artifacts/web-data")),
    )
    parser.add_argument("--scan-timeout", type=float, default=60)
    parser.add_argument("--ai-timeout", type=float, default=90)
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("port must be 0..65535")
    try:
        service = Service(
            args.data_dir, scan_timeout=args.scan_timeout, ai_timeout=args.ai_timeout
        )
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.exit(
            2,
            f"启动失败：{type(error).__name__}；检查数据目录/超时配置，勿覆盖已有数据库。\n",
        )
    try:
        with AuditServer(service, args.port) as server:
            print(f"AI-Code-Audit: http://127.0.0.1:{server.server_port}", flush=True)
            server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        service.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
