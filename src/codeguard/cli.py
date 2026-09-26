"""Compatibility entrypoint used by shared-integration's CodeAdapter."""

from ai_code_audit.hybrid_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
