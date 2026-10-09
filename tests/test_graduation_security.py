"""Source-only rule and adversarial upload checks; samples are never run."""

from __future__ import annotations

import base64
import io
import stat
import zipfile

import pytest

from ai_code_audit.python_security import analyze_python
from ai_code_audit.triage_context import redact_sensitive_text
from ai_code_audit.web.imports import MAX_FILE_BYTES, ImportRejected, validate_upload


def encoded(data: bytes) -> str:
    return base64.b64encode(data).decode()


def payload(path: str = "app.py", content: bytes = b"print('hello')\n") -> dict:
    return {
        "name": "测试项目",
        "files": [{"path": path, "content_base64": encoded(content)}],
    }


@pytest.mark.parametrize(
    ("source", "rule"),
    [
        ("import os as operating\noperating.system(input())", "CG-PY-001"),
        (
            "from subprocess import run as invoke\ninvoke(input(), shell=True)",
            "CG-PY-001",
        ),
        ('cursor.execute(f"SELECT * FROM users WHERE name={name}")', "CG-PY-002"),
        ('cursor.execute("SELECT * FROM users WHERE name=" + name)', "CG-PY-002"),
        ("import pickle as p\np.loads(data)", "CG-PY-003"),
        ("import yaml\nyaml.load(data)", "CG-PY-003"),
        ("eval(input())", "CG-PY-004"),
        ("exec(code)", "CG-PY-004"),
        ('API_KEY = "synthetic-value-only"', "CG-PY-005"),
    ],
)
def test_five_risk_classes(source, rule):
    findings = analyze_python(source, "app.py")
    assert rule in {finding["metadata"]["rule_id"] for finding in findings}
    assert all(
        finding["source"] == "004"
        and finding["metadata"]["verification"] == "unverified"
        for finding in findings
    )
    if rule == "CG-PY-005":
        assert "synthetic-value-only" not in str(findings)


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run(['echo', value], shell=False)",
        'cursor.execute("SELECT * FROM users WHERE name=?", (name,))',
        "import json\njson.loads(data)",
        "import yaml\nyaml.safe_load(data)",
        "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)",
        "from yaml import load, SafeLoader\nload(data, SafeLoader)",
        "import ast\nast.literal_eval(data)",
        "import os\nAPI_KEY = os.environ['API_KEY']",
        '# eval(input())\ntext = "pickle.loads(data)"',
    ],
)
def test_safe_patterns(source):
    assert analyze_python(source, "safe.py") == []


@pytest.mark.parametrize(
    "path",
    [
        "../escape.py",
        "/absolute.py",
        "C:/escape.py",
        "a\\b.py",
        "a//b.py",
        "a/./b.py",
        ".env",
        "NUL.py",
        "CON/app.py",
        "a:stream.py",
        "a./b.py",
        "app.txt",
        "a\x00.py",
        ".git/app.py",
    ],
)
def test_unsafe_paths(path):
    with pytest.raises(ImportRejected):
        validate_upload(payload(path))


@pytest.mark.parametrize(
    "content",
    [b"x\0y", b"\xff\xfe", b"x" * (MAX_FILE_BYTES + 1)],
    ids=["nul", "invalid-utf8", "oversize"],
)
def test_bad_content(content):
    with pytest.raises(ImportRejected):
        validate_upload(payload(content=content))


def test_case_collision_and_invalid_base64():
    data = payload()
    data["files"].append({"path": "APP.py", "content_base64": encoded(b"pass")})
    with pytest.raises(ImportRejected):
        validate_upload(data)
    data = payload()
    data["files"][0]["content_base64"] = "%%%"
    with pytest.raises(ImportRejected):
        validate_upload(data)


def zip_payload(name="app.py", content=b"pass\n", *, mode=stat.S_IFREG):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo(name)
        info.external_attr = (mode | 0o644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, content)
    return {"name": "ZIP 测试", "zip_base64": encoded(stream.getvalue())}


@pytest.mark.parametrize(
    "data",
    [
        zip_payload("../escape.py"),
        zip_payload(mode=stat.S_IFLNK),
        zip_payload(mode=stat.S_IFIFO),
        zip_payload(content=b"a" * MAX_FILE_BYTES),
    ],
)
def test_zip_traversal_symlink_and_bomb(data):
    with pytest.raises(ImportRejected):
        validate_upload(data)


def test_valid_zip_and_utf8_bom():
    assert validate_upload(zip_payload("src/app.py")) == [("src/app.py", b"pass\n")]
    assert validate_upload(payload(content=b"\xef\xbb\xbfpass\n"))[0][1].startswith(
        b"\xef\xbb\xbf"
    )


def test_empty_overcount_and_bad_zip():
    for data in (
        {"files": []},
        {"files": payload()["files"] * 101},
        {"zip_base64": encoded(b"not a zip")},
    ):
        with pytest.raises(ImportRejected):
            validate_upload(data)


@pytest.mark.parametrize("field", ["secret", "passwd", "private_key", "auth_token"])
def test_additional_credentials_redacted_before_ai(field):
    assert "synthetic-private-value" not in redact_sensitive_text(
        f'{field} = "synthetic-private-value"'
    )


def test_file_directory_collision_rejected():
    data = payload()
    data["files"].append(
        {"path": "APP.py/nested.py", "content_base64": encoded(b"pass")}
    )
    with pytest.raises(ImportRejected):
        validate_upload(data)
