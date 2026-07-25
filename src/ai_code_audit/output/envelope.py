"""Frozen v0.5 §15 envelope JSON rendering."""

from __future__ import annotations

import json
from typing import Mapping, Any


def render_envelope(envelope: Mapping[str, Any]) -> str:
    return json.dumps(envelope, ensure_ascii=False)


__all__ = ["render_envelope"]
