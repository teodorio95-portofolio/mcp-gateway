"""Append-only JSONL audit log — one line per gateway decision.

Every authenticated request that reaches a tool is recorded: who, what tool,
the verdict (allowed / denied / sanitized), and why. This is the evidence trail
that turns "the gateway blocked it" into something you can show.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def record(audit_path: Path, **fields: Any) -> None:
    """Append one structured audit event as a JSON line."""
    event = {"ts": datetime.now(timezone.utc).isoformat(), **fields}
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")
