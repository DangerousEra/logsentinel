"""Turns detector output into human-readable or JSON reports."""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, List


def to_text(alerts: List[Any], title: str) -> str:
    lines = [f"=== {title} ===", f"{len(alerts)} alert(s) found", ""]
    if not alerts:
        lines.append("No issues detected.")
    for alert in alerts:
        lines.append(alert.summary())
    return "\n".join(lines)


def to_json(alerts: List[Any]) -> str:
    def default(obj):
        return str(obj)

    return json.dumps([asdict(a) for a in alerts], indent=2, default=default)
