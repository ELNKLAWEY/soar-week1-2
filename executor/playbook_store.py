"""Playbook versions and run history (M9 backend). Every save is a new version; rollback
re-publishes an old version as the newest one, so history is never rewritten."""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from executor.playbook_engine import PlaybookEngine, PlaybookRun

SEED_DIR = Path(__file__).parent / "playbooks"


class PlaybookStore:
    def __init__(self, conn: sqlite3.Connection, engine: PlaybookEngine | None = None) -> None:
        self.conn = conn
        self.engine = engine or PlaybookEngine()

    def seed(self, directory: Path = SEED_DIR) -> None:
        """Load the YAML files in the repo as version 1 of any playbook not stored yet."""
        for path in sorted(directory.glob("*.yaml")):
            text = path.read_text(encoding="utf-8")
            name = self.engine.parse(text)["name"]
            if self.latest_version(name) == 0:
                self.save(name, text, note=f"seeded from {path.name}")

    def latest_version(self, name: str) -> int:
        row = self.conn.execute(
            "SELECT MAX(version) AS v FROM playbook_versions WHERE name = ?", (name,)
        ).fetchone()
        return row["v"] or 0

    def save(self, name: str, text: str, note: str = "") -> dict:
        pb = self.engine.parse(text)
        if pb["name"] != name:
            raise ValueError(f"YAML name {pb['name']!r} does not match {name!r}")
        version = self.latest_version(name) + 1
        self.conn.execute(
            "INSERT INTO playbook_versions (name, version, yaml, created_at, note) VALUES (?, ?, ?, ?, ?)",
            (name, version, text, _now(), note),
        )
        return {"name": name, "version": version}

    def get(self, name: str, version: int | None = None) -> dict:
        version = version or self.latest_version(name)
        row = self.conn.execute(
            "SELECT * FROM playbook_versions WHERE name = ? AND version = ?", (name, version)
        ).fetchone()
        if row is None:
            raise KeyError(f"{name} v{version}")
        return dict(row)

    def versions(self, name: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT version, created_at, note FROM playbook_versions WHERE name = ? ORDER BY version DESC",
            (name,),
        ).fetchall()
        return [dict(r) for r in rows]

    def rollback(self, name: str, version: int) -> dict:
        return self.save(name, self.get(name, version)["yaml"], note=f"rollback to v{version}")

    def list(self) -> list[dict]:
        rows = self.conn.execute(
            """SELECT v.name, MAX(v.version) AS version,
                      (SELECT MAX(started_at) FROM playbook_runs r WHERE r.name = v.name) AS last_run,
                      (SELECT COUNT(*) FROM playbook_runs r WHERE r.name = v.name) AS runs,
                      (SELECT AVG(ok) FROM playbook_runs r WHERE r.name = v.name) AS success_rate
               FROM playbook_versions v GROUP BY v.name ORDER BY v.name"""
        ).fetchall()
        out = []
        for r in rows:
            pb = self.engine.parse(self.get(r["name"])["yaml"])
            out.append({**dict(r), "trigger": pb.get("trigger", {})})
        return out

    def run(self, name: str, context: dict, *, dry_run: bool = True, action_handler=None,
            text: str | None = None) -> dict:
        """Run the latest version (or unsaved `text` from the editor) and store the run."""
        version = 0 if text is not None else self.latest_version(name)
        pb = self.engine.parse(text if text is not None else self.get(name)["yaml"])
        started = _now()
        t0 = time.perf_counter()
        run = self.engine.run(pb, context, dry_run=dry_run, action_handler=action_handler)
        duration_ms = int((time.perf_counter() - t0) * 1000)
        steps = _steps(run)
        ok = all(s["output"].get("status") not in ("failed", "rejected") for s in steps)
        cur = self.conn.execute(
            "INSERT INTO playbook_runs (name, version, dry_run, ok, started_at, duration_ms, steps) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, version, int(dry_run), int(ok), started, duration_ms, json.dumps(steps)),
        )
        return {"id": cur.lastrowid, "name": name, "version": version, "dry_run": dry_run,
                "ok": ok, "started_at": started, "duration_ms": duration_ms, "steps": steps}

    def runs(self, name: str, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM playbook_runs WHERE name = ? ORDER BY id DESC LIMIT ?", (name, limit)
        ).fetchall()
        return [{**dict(r), "steps": json.loads(r["steps"]), "ok": bool(r["ok"]), "dry_run": bool(r["dry_run"])} for r in rows]


def _steps(run: PlaybookRun) -> list[dict]:
    return [
        {"id": s.id, "action": s.action, "skipped": s.skipped, "args": s.args, "output": s.output}
        for s in run.steps
    ]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
