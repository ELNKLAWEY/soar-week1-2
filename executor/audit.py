"""Append-only action audit stub (JSONL). Week 3 may swap to Mongo."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from common.schemas.actions import ActionRequest, ActionResult

DEFAULT_AUDIT_PATH = Path(__file__).resolve().parents[1] / "logs" / "actions.jsonl"


class AuditLog:
    """Writes one JSON object per line for each handled ActionRequest/Result."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_AUDIT_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, request: ActionRequest, result: ActionResult) -> dict[str, Any]:
        entry = {
            "request": request.model_dump(mode="json"),
            "result": result.model_dump(mode="json"),
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
        return entry

    def clear(self) -> None:
        if self.path.exists():
            self.path.write_text("", encoding="utf-8")
