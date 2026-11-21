"""SQLite storage for executor-owned records: cases, playbook versions/runs, allowlist.

shortcut: SQLite file per executor; move to the shared MongoDB `cases` / `playbooks` /
`runs` / `allowlist` collections once the team's database service exists.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[1] / "logs" / "executor.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    incident_id TEXT UNIQUE,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    owner TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS playbook_versions (
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    yaml TEXT NOT NULL,
    created_at TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (name, version)
);
CREATE TABLE IF NOT EXISTS playbook_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    dry_run INTEGER NOT NULL,
    ok INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    steps TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS allowlist (
    ip TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    reason TEXT NOT NULL
);
"""


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(path or os.getenv("SENTINEL_DB") or DEFAULT_DB)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn
