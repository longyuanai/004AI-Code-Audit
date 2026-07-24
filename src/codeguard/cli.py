"""Compatibility entrypoint used by shared-integration's CodeAdapter."""

from ai_codeguard.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
