"""Prepare a portable, hash-locked wheelhouse without changing source dependencies.

Poetry's sibling path dependency is valid during suite development but embeds
an absolute file URL in a built wheel. For the standalone installation artifact
only, pin it to the version of the included shared-core wheel and regenerate
the wheel's RECORD. Original wheels are retained untouched.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import zipfile
from email.parser import Parser
from pathlib import Path


def metadata(wheel: Path) -> tuple[str, str]:
    with zipfile.ZipFile(wheel) as archive:
        filename = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        parsed = Parser().parsestr(archive.read(filename).decode())
    return str(parsed["Name"]), str(parsed["Version"])


def prepare(source: Path, destination: Path) -> dict[str, object]:
    wheels = sorted(source.glob("*.whl"))
    core = [wheel for wheel in wheels if metadata(wheel)[0] == "shared-llm-core"]
    product = [
        wheel for wheel in wheels if metadata(wheel)[0] == "ai-codeguard-upgrade"
    ]
    if len(core) != 1 or len(product) != 1:
        raise ValueError("Exactly one product and one shared-core wheel required")
    core_version = metadata(core[0])[1]
    destination.mkdir(parents=True, exist_ok=False)
    records = []
    for wheel in wheels:
        target = destination / wheel.name
        if wheel == product[0]:
            with zipfile.ZipFile(wheel) as archive:
                entries = {name: archive.read(name) for name in archive.namelist()}
            metadata_path = next(
                name for name in entries if name.endswith(".dist-info/METADATA")
            )
            content, replacements = re.subn(
                r"^Requires-Dist: shared-llm-core @ file:.*$",
                f"Requires-Dist: shared-llm-core (=={core_version})",
                entries[metadata_path].decode(),
                flags=re.MULTILINE,
            )
            if replacements != 1:
                raise ValueError("Expected the existing sibling shared-core dependency")
            entries[metadata_path] = content.encode()
            record_path = next(
                name for name in entries if name.endswith(".dist-info/RECORD")
            )
            entries.pop(record_path)
            output = io.StringIO(newline="")
            writer = csv.writer(output, lineterminator="\n")
            for name, data in entries.items():
                digest = (
                    base64.urlsafe_b64encode(hashlib.sha256(data).digest())
                    .rstrip(b"=")
                    .decode()
                )
                writer.writerow((name, "sha256=" + digest, len(data)))
            writer.writerow((record_path, "", ""))
            entries[record_path] = output.getvalue().encode()
            with zipfile.ZipFile(
                target, "x", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                for name, data in entries.items():
                    archive.writestr(name, data)
        else:
            with target.open("xb") as stream:
                stream.write(wheel.read_bytes())
        package_name, version = metadata(target)
        records.append(
            {
                "name": package_name,
                "version": version,
                "filename": target.name,
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            }
        )
    lock = (
        "\n".join(
            f"{item['name']}=={item['version']} --hash=sha256:{item['sha256']}"
            for item in sorted(records, key=lambda item: item["name"])
        )
        + "\n"
    )
    (destination / "requirements.txt").write_text(lock, encoding="utf-8")
    manifest = {
        "schema": 1,
        "scope": "Windows x64 / CPython 3.14 wheelhouse; no OS/other-Python validation",
        "metadata_change": "Only standalone product wheel: shared-llm-core file URL replaced with included version requirement; RECORD regenerated",
        "packages": records,
    }
    (destination / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    manifest = prepare(args.source, args.destination)
    packages = manifest["packages"]
    assert isinstance(packages, list)
    print(f"Prepared {len(packages)} hash-locked wheels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
