"""Case management backend (M8, Project Details §11).

Rules: a case opens automatically for every incident above Low severity and for every
uncertain decision (one case per incident). States, allowed transitions, SLA timers
(acknowledge / contain / resolve), notes, timeline and a closure form.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from uuid import uuid4

SEVERITIES = ("low", "medium", "high", "critical")

STATES = (
    "new",
    "triaged",
    "contained",
    "investigating",
    "pending_review",
    "resolved",
    "closed",
    "false_positive",
    "reopened",
)
_OPEN = {"new", "triaged", "contained", "investigating", "pending_review", "reopened"}
TRANSITIONS: dict[str, set[str]] = {
    # reopened is only reachable from a finished case
    **{s: (_OPEN - {"reopened"}) | {"resolved", "false_positive"} for s in _OPEN},
    "resolved": {"closed", "false_positive", "reopened"},
    "closed": {"reopened"},
    "false_positive": {"reopened"},
}
FINAL_STATES = {"closed", "false_positive"}

# minutes to acknowledge / contain / resolve, per severity
SLA_MINUTES = {
    "critical": (15, 60, 240),
    "high": (30, 120, 480),
    "medium": (60, 240, 1440),
    "low": (240, 1440, 4320),
}
# which status change stops which SLA clock
_STOPS = {"triaged": "acknowledge", "contained": "contain", "resolved": "resolve"}


class CaseError(ValueError):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def should_open_case(incident: dict) -> bool:
    severity = str(incident.get("severity", "low")).lower()
    return severity in SEVERITIES[1:] or incident.get("verdict") == "uncertain"


class CaseStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self._lock = threading.Lock()

    # --- creation ---

    def open_for_incident(self, incident: dict) -> dict | None:
        """Auto-create rule. Returns the case (existing one if already opened), or None."""
        if not should_open_case(incident):
            return None
        incident_id = str(incident["id"])
        existing = self.get_by_incident(incident_id)
        if existing:
            return existing
        severity = str(incident.get("severity", "medium")).lower()
        if severity not in SEVERITIES:
            raise CaseError(f"unknown severity {severity}")
        now = utcnow()
        ack, contain, resolve = SLA_MINUTES[severity]
        case = {
            "id": f"case-{uuid4().hex[:10]}",
            "title": incident.get("title") or f"{incident.get('type', 'incident')} from {incident.get('src_ip', '?')}",
            "severity": severity,
            "status": "new",
            "owner": "agent",
            "incident_ids": [incident_id],
            "assets": incident.get("assets", []),
            "identities": incident.get("identities", []),
            "indicators": [i for i in [incident.get("src_ip")] if i],
            "techniques": incident.get("techniques", []),
            "tags": ["needs_human_review"] if incident.get("verdict") == "uncertain" else [],
            "created_at": now.isoformat(),
            "sla": {
                name: {"due": (now + timedelta(minutes=m)).isoformat(), "met_at": None}
                for name, m in (("acknowledge", ack), ("contain", contain), ("resolve", resolve))
            },
            "notes": [],
            "timeline": [],
            "closure": None,
        }
        self._timeline(case, "agent", "case_opened", {"incident_id": incident_id})
        with self._lock:
            try:
                self._insert(case, incident_id)
            except sqlite3.IntegrityError:  # opened concurrently by another consumer
                return self.get_by_incident(incident_id)
        return self._with_sla_state(case)

    # --- reads ---

    def get(self, case_id: str) -> dict:
        row = self.conn.execute("SELECT data FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise KeyError(case_id)
        return self._with_sla_state(json.loads(row["data"]))

    def get_by_incident(self, incident_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT data FROM cases WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        return self._with_sla_state(json.loads(row["data"])) if row else None

    def list(self, status: str | None = None, owner: str | None = None, severity: str | None = None) -> list[dict]:
        sql, params = "SELECT data FROM cases WHERE 1=1", []
        for col, val in (("status", status), ("owner", owner), ("severity", severity)):
            if val:
                sql += f" AND {col} = ?"
                params.append(val)
        rows = self.conn.execute(sql + " ORDER BY rowid DESC", params).fetchall()
        return [self._with_sla_state(json.loads(r["data"])) for r in rows]

    # --- changes ---

    def update(self, case_id: str, actor: str, *, status: str | None = None, owner: str | None = None,
               severity: str | None = None, tags: list[str] | None = None) -> dict:
        with self._lock:
            case = self.get(case_id)
            if status and status != case["status"]:
                self._change_status(case, actor, status)
            if owner and owner != case["owner"]:
                self._timeline(case, actor, "reassigned", {"from": case["owner"], "to": owner})
                case["owner"] = owner
            if severity and severity != case["severity"]:
                if severity not in SEVERITIES:
                    raise CaseError(f"unknown severity {severity}")
                self._timeline(case, actor, "severity_changed", {"from": case["severity"], "to": severity})
                case["severity"] = severity
            for tag in tags or []:
                if tag not in case["tags"]:
                    case["tags"].append(tag)
                    self._timeline(case, actor, "tagged", {"tag": tag})
            self._save(case)
        return case

    def add_note(self, case_id: str, author: str, text: str) -> dict:
        if not text.strip():
            raise CaseError("note text is empty")
        with self._lock:
            case = self.get(case_id)
            note = {"author": author, "text": text, "at": utcnow().isoformat()}
            case["notes"].append(note)
            self._timeline(case, author, "note_added", {"text": text[:200]})
            self._save(case)
        return case

    def add_timeline(self, case_id: str, actor: str, event: str, detail: dict) -> dict:
        with self._lock:
            case = self.get(case_id)
            self._timeline(case, actor, event, detail)
            self._save(case)
        return case

    def close(self, case_id: str, actor: str, root_cause: str, lessons_learned: str,
              false_positive: bool = False) -> dict:
        """Closure form: root cause and lessons learned are mandatory."""
        if not root_cause.strip() or not lessons_learned.strip():
            raise CaseError("root_cause and lessons_learned are required to close a case")
        with self._lock:
            case = self.get(case_id)
            target = "false_positive" if false_positive else "closed"
            if case["status"] != "resolved" and target == "closed":
                self._change_status(case, actor, "resolved")
            self._change_status(case, actor, target)
            case["closure"] = {
                "root_cause": root_cause,
                "lessons_learned": lessons_learned,
                "closed_by": actor,
                "closed_at": utcnow().isoformat(),
            }
            self._save(case)
        return case

    def apply_update_case_action(self, incident_id: str, actor: str, args: dict) -> dict:
        """Executor `update_case` tool: note / status / tags on the incident's case."""
        case = self.get_by_incident(incident_id)
        if case is None:
            raise CaseError(f"no case for incident {incident_id}")
        if args.get("note"):
            case = self.add_note(case["id"], actor, str(args["note"]))
        tags = args.get("tags") or ([args["tag"]] if args.get("tag") else [])
        case = self.update(case["id"], actor, status=args.get("status") or None, tags=tags)
        return {"case_id": case["id"], "status": case["status"], "tags": case["tags"]}

    # --- internals ---

    def _change_status(self, case: dict, actor: str, status: str) -> None:
        if status not in STATES:
            raise CaseError(f"unknown status {status}")
        if status not in TRANSITIONS[case["status"]]:
            raise CaseError(f"cannot move case from {case['status']} to {status}")
        now = utcnow().isoformat()
        clocks = [_STOPS[status]] if status in _STOPS else []
        if status in FINAL_STATES:
            clocks = ["acknowledge", "contain", "resolve"]
        for clock in clocks:
            if case["sla"][clock]["met_at"] is None:
                case["sla"][clock]["met_at"] = now
        if status == "reopened":
            case["closure"] = None
        self._timeline(case, actor, "status_changed", {"from": case["status"], "to": status})
        case["status"] = status

    @staticmethod
    def _timeline(case: dict, actor: str, event: str, detail: dict) -> None:
        case["timeline"].append({"at": utcnow().isoformat(), "actor": actor, "event": event, "detail": detail})

    @staticmethod
    def _with_sla_state(case: dict) -> dict:
        now = utcnow()
        for clock in case["sla"].values():
            due = datetime.fromisoformat(clock["due"])
            done = datetime.fromisoformat(clock["met_at"]) if clock["met_at"] else None
            clock["breached"] = (done or now) > due
            # at risk: still open and less than a quarter of the SLA window left
            window = due - datetime.fromisoformat(case["created_at"])
            clock["at_risk"] = done is None and not clock["breached"] and (due - now) < window * 0.25
        return case

    def _insert(self, case: dict, incident_id: str) -> None:
        self.conn.execute(
            "INSERT INTO cases (id, incident_id, status, severity, owner, data) VALUES (?, ?, ?, ?, ?, ?)",
            (case["id"], incident_id, case["status"], case["severity"], case["owner"], json.dumps(case)),
        )

    def _save(self, case: dict) -> None:
        # breached / at_risk are computed on read, never stored
        stored = {**case, "sla": {n: {"due": c["due"], "met_at": c["met_at"]} for n, c in case["sla"].items()}}
        self.conn.execute(
            "UPDATE cases SET status = ?, severity = ?, owner = ?, data = ? WHERE id = ?",
            (case["status"], case["severity"], case["owner"], json.dumps(stored), case["id"]),
        )
