"""Validate a complete upload before writing an immutable source snapshot."""

from __future__ import annotations

import base64
import binascii
import io
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

MAX_FILES = 100
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_REQUEST_BYTES = 12 * 1024 * 1024
RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.IGNORECASE)


class ImportRejected(ValueError):
    """User input violates the bounded Python source import contract."""


def safe_name(raw: Any) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > 200:
        raise ImportRejected("文件路径为空或过长")
    path = PurePosixPath(raw)
    if "\\" in raw or path.is_absolute() or str(path) != raw:
        raise ImportRejected("文件路径必须为规范的相对路径")
    for part in path.parts:
        if (
            part in {".", ".."}
            or part.startswith(".")
            or part.endswith((" ", "."))
            or RESERVED.match(part)
            or any(ord(char) < 32 or char in ':<>"|?*' for char in part)
        ):
            raise ImportRejected("文件路径包含不安全字符或目录")
    if path.suffix.lower() != ".py":
        raise ImportRejected("第一版仅支持 .py 源代码")
    return path.as_posix()


def decode_data(raw: Any) -> bytes:
    if not isinstance(raw, str) or len(raw) > MAX_REQUEST_BYTES:
        raise ImportRejected("文件内容缺失或超过限制")
    try:
        return base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ImportRejected("文件内容必须为合法 Base64") from error


def validate_upload(payload: dict[str, Any]) -> list[tuple[str, bytes]]:
    files: list[tuple[str, bytes]] = []
    if "zip_base64" in payload:
        if "files" in payload:
            raise ImportRejected("文件和 ZIP 只能选择一种")
        raw_zip = decode_data(payload["zip_base64"])
        if len(raw_zip) > MAX_TOTAL_BYTES:
            raise ImportRejected("ZIP 压缩体积超限")
        try:
            with zipfile.ZipFile(io.BytesIO(raw_zip)) as archive:
                entries = archive.infolist()
                if len(entries) > MAX_FILES * 2:
                    raise ImportRejected("ZIP 条目数量超限")
                declared = 0
                for entry in entries:
                    kind = stat.S_IFMT(entry.external_attr >> 16)
                    if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                        raise ImportRejected("ZIP 不允许符号链接或特殊文件")
                    if entry.is_dir():
                        # Validate directory paths using a synthetic Python child.
                        safe_name(entry.filename + "directory_check.py")
                        continue
                    filename = safe_name(entry.filename)
                    declared += entry.file_size
                    if (
                        entry.flag_bits & 1
                        or entry.file_size > MAX_FILE_BYTES
                        or declared > MAX_TOTAL_BYTES
                        or entry.file_size > max(1, entry.compress_size) * 100
                    ):
                        raise ImportRejected("ZIP 加密、解压体积或压缩比超限")
                    with archive.open(entry) as stream:
                        data = stream.read(MAX_FILE_BYTES + 1)
                    files.append((filename, data))
        except (
            zipfile.BadZipFile,
            NotImplementedError,
            RuntimeError,
            OSError,
        ) as error:
            raise ImportRejected("ZIP 无效或不支持") from error
    else:
        raw_files = payload.get("files")
        if not isinstance(raw_files, list) or not 1 <= len(raw_files) <= MAX_FILES:
            raise ImportRejected("请上传 1 至 100 个 Python 文件")
        for entry in raw_files:
            if not isinstance(entry, dict):
                raise ImportRejected("文件条目必须为对象")
            files.append(
                (safe_name(entry.get("path")), decode_data(entry.get("content_base64")))
            )
    if not 1 <= len(files) <= MAX_FILES:
        raise ImportRejected("请上传 1 至 100 个 Python 文件")
    total = 0
    names: set[str] = set()
    for filename, data in files:
        key = filename.casefold()
        if key in names or len(data) > MAX_FILE_BYTES:
            raise ImportRejected("文件路径重复或单文件超限")
        names.add(key)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ImportRejected("项目总大小超过 8 MiB")
        try:
            data.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ImportRejected("仅支持 UTF-8 Python 源代码") from error
        if b"\0" in data:
            raise ImportRejected("文件包含空字节")
    for filename in names:
        if any(
            parent.as_posix().casefold() in names
            for parent in PurePosixPath(filename).parents
        ):
            raise ImportRejected("文件路径与目录路径冲突")
    return files


def write_snapshot(root: Path, files: list[tuple[str, bytes]]) -> None:
    root.mkdir(parents=True, exist_ok=False)
    for filename, data in files:
        target = root / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data.removeprefix(b"\xef\xbb\xbf"))
