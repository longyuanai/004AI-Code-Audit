"""Offline probes of manual-review leads; not real scan findings or labels."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

from ai_code_audit.cli import _write_output
from ai_code_audit.hybrid_cli import _validate_git_url


def main() -> None:
    import tempfile

    accepted = []
    with patch.dict(os.environ, {}, clear=True):
        for url in ("https://127.0.0.1/owned-test.git", "https://192.0.2.1/owned-test.git"):
            _validate_git_url(url)  # Validation only: never clone or connect.
            accepted.append(url)
    with tempfile.TemporaryDirectory(prefix="c3-2-owned-probe-") as scratch:
        target = Path(scratch) / "report.json"
        collision = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        collision.write_text("owned probe sentinel", encoding="utf-8")
        _write_output(str(target), "new report")
        collision_removed = not collision.exists()
        assert target.read_text(encoding="utf-8") == "new report"
        assert collision_removed
    print(json.dumps({
        "kind": "synthetic_offline_manual_probe_not_scan_result",
        "accepted_urls_without_network": accepted,
        "predictable_temporary_file_collision_removed": collision_removed,
        "security_verdict": "unconfirmed: deployment/attacker permissions not established",
        "network_requests": "none: only URL validator and owned temporary files used",
    }, indent=2))


if __name__ == "__main__":
    main()
