"""Executor service: action consumer loop + REST API + Playbook Studio / Actions Ledger pages.

Run: uvicorn executor.api:app --port 8080   (pages at /ui/studio.html and /ui/ledger.html)
One process owns the worker, so API actions (Undo / Extend) and queued actions share the
same Policy Guard, HAProxy connector and idempotency store.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

import redis
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from common.schemas.actions import ActionRequest, Gate
from executor.cases import CaseError, CaseStore
from executor.db import connect
from executor.playbook_store import PlaybookStore
from executor.queue import redis_from_env
from executor.worker import ActionWorker

log = logging.getLogger("executor")

conn = connect()
cases = CaseStore(conn)
playbooks = PlaybookStore(conn)
worker = ActionWorker.from_env(cases=cases)
_lock = threading.Lock()  # one action at a time through the worker
_stop = threading.Event()


def _load_allowlist() -> None:
    for row in conn.execute("SELECT ip FROM allowlist"):
        worker.guard.config.allowlist.add(row["ip"])


def handle(request: ActionRequest):
    with _lock:
        return worker.handle(request)


def _loop() -> None:
    """Consume `actions`, open cases from `incidents`, run the TTL scheduler."""
    r = redis_from_env()
    if r is not None:
        try:
            r.xgroup_create("incidents", "cases", id="0", mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
    while not _stop.is_set():
        try:
            with _lock:
                worker.process_queue(max_items=50)
                worker.haproxy.expire_due()
            if r is not None:
                _consume_incidents(r)  # blocks up to 1s, paces the loop
            else:
                _stop.wait(1)
        except Exception:  # noqa: BLE001 — keep the service alive, log and retry
            log.exception("executor loop error")
            _stop.wait(2)


def _consume_incidents(r: redis.Redis) -> None:
    resp = r.xreadgroup("cases", "executor-1", {"incidents": ">"}, count=50, block=1000)
    for _, messages in resp or []:
        for mid, fields in messages:
            try:
                cases.open_for_incident(json.loads(fields["incident"]))
            except (KeyError, ValueError) as exc:
                r.xadd("incidents:dlq", {"message_id": mid, "error": str(exc)[:500]})
            r.xack("incidents", "cases", mid)


@asynccontextmanager
async def lifespan(_: FastAPI):
    playbooks.seed()
    _load_allowlist()
    t = None
    if os.getenv("EXECUTOR_LOOP", "1") == "1":
        t = threading.Thread(target=_loop, daemon=True, name="executor-loop")
        t.start()
    yield
    _stop.set()
    if t:
        t.join(timeout=5)


app = FastAPI(title="Sentinel executor", lifespan=lifespan)
app.mount("/ui", StaticFiles(directory=Path(__file__).parent / "ui", html=True), name="ui")


@app.get("/")
def root():
    return RedirectResponse("/ui/ledger.html")


@app.get("/health")
def health() -> dict:
    return {"ok": True, "mode": worker.autonomy.mode.value}


# ---------------- Playbook Studio (M9) ----------------


class PlaybookText(BaseModel):
    yaml: str
    note: str = ""


class DryRun(BaseModel):
    context: dict = Field(default_factory=dict)
    yaml: str | None = None  # unsaved editor content; latest saved version when empty


class Rollback(BaseModel):
    version: int


@app.get("/api/playbooks")
def list_playbooks() -> list[dict]:
    return playbooks.list()


@app.get("/api/playbooks/{name}")
def get_playbook(name: str, version: int | None = None) -> dict:
    try:
        return playbooks.get(name, version)
    except KeyError:
        raise HTTPException(404, "playbook not found")


@app.get("/api/playbooks/{name}/versions")
def playbook_versions(name: str) -> list[dict]:
    return playbooks.versions(name)


@app.post("/api/playbooks/validate")
def validate_playbook(body: PlaybookText) -> dict:
    try:
        pb = playbooks.engine.parse(body.yaml)
    except ValueError as exc:
        return {"valid": False, "error": str(exc)}
    return {"valid": True, "name": pb["name"], "steps": len(pb["steps"])}


@app.put("/api/playbooks/{name}")
def save_playbook(name: str, body: PlaybookText) -> dict:
    try:
        return playbooks.save(name, body.yaml, note=body.note)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.post("/api/playbooks/{name}/rollback")
def rollback_playbook(name: str, body: Rollback) -> dict:
    try:
        return playbooks.rollback(name, body.version)
    except KeyError:
        raise HTTPException(404, "version not found")


@app.post("/api/playbooks/{name}/dry-run")
def dry_run_playbook(name: str, body: DryRun) -> dict:
    try:
        return playbooks.run(name, body.context, dry_run=True, text=body.yaml or None)
    except (KeyError, ValueError) as exc:
        raise HTTPException(422, str(exc))


@app.get("/api/playbooks/{name}/runs")
def playbook_runs(name: str) -> list[dict]:
    return playbooks.runs(name)


# ---------------- Actions Ledger + Response (M10) ----------------


class Extend(BaseModel):
    minutes: int = Field(gt=0)


class AllowEntry(BaseModel):
    ip: str
    owner: str
    reason: str


def _ledger() -> list[dict]:
    path = worker.audit.path if worker.audit else None
    if not path or not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in reversed(lines) if line.strip()]


def _find(action_id: str) -> dict:
    for entry in _ledger():
        if entry["request"]["id"] == action_id:
            return entry
    raise HTTPException(404, "action not found")


@app.get("/api/actions")
def list_actions(actor: str | None = None, tool: str | None = None, status: str | None = None,
                 limit: int = 200) -> list[dict]:
    out = []
    for e in _ledger():
        req, res = e["request"], e["result"]
        if (actor and not req["actor"].startswith(actor)) or (tool and req["tool"] != tool) \
                or (status and res["status"] != status):
            continue
        out.append(e)
        if len(out) >= limit:
            break
    return out


@app.post("/api/actions/{action_id}/undo")
def undo_action(action_id: str) -> dict:
    entry = _find(action_id)
    rollback = entry["result"].get("rollback")
    if not rollback or entry["result"]["status"] != "success":
        raise HTTPException(409, "this action has nothing to undo")
    result = handle(ActionRequest(
        incident_id=entry["request"]["incident_id"],
        correlation_id=entry["request"]["correlation_id"],
        actor="analyst",
        tool=rollback["tool"],
        args=rollback["args"],
        gate=Gate.G1,
        idempotency_key=f"undo:{action_id}",
    ))
    return result.model_dump(mode="json")


@app.post("/api/actions/{action_id}/extend")
def extend_action(action_id: str, body: Extend) -> dict:
    req = _find(action_id)["request"]
    if req["tool"] not in {"block_ip", "rate_limit_ip", "tarpit_ip"}:
        raise HTTPException(409, "only IP containment can be extended")
    result = handle(ActionRequest(
        incident_id=req["incident_id"],
        correlation_id=req["correlation_id"],
        actor="analyst",
        tool=req["tool"],
        args={**req["args"], "ttl_minutes": body.minutes},
        gate=Gate(req["gate"]),  # Policy Guard still caps the new TTL for this gate
        idempotency_key=f"extend:{action_id}:{uuid4().hex[:8]}",
    ))
    return result.model_dump(mode="json")


@app.get("/api/blocks")
def active_blocks() -> dict:
    return {kind: worker.haproxy.show_acl(kind=kind)["entries"] for kind in ("block", "tarpit", "ratelimit")}


@app.get("/api/haproxy/sync")
def haproxy_sync() -> dict:
    return worker.haproxy.sync_status()


@app.post("/api/haproxy/reconcile")
def haproxy_reconcile() -> dict:
    with _lock:
        return worker.haproxy.reconcile()


@app.get("/api/allowlist")
def get_allowlist() -> list[dict]:
    stored = {r["ip"]: dict(r) for r in conn.execute("SELECT * FROM allowlist")}
    return [stored.get(ip, {"ip": ip, "owner": "built-in", "reason": "Policy Guard default"})
            for ip in sorted(worker.guard.config.allowlist)]


@app.post("/api/allowlist")
def add_allowlist(body: AllowEntry) -> dict:
    try:
        ipaddress.ip_address(body.ip)
    except ValueError:
        raise HTTPException(422, "invalid ip")
    if not body.owner.strip() or not body.reason.strip():
        raise HTTPException(422, "owner and reason are required")
    conn.execute("INSERT OR REPLACE INTO allowlist (ip, owner, reason) VALUES (?, ?, ?)",
                 (body.ip, body.owner, body.reason))
    worker.guard.config.allowlist.add(body.ip)
    return body.model_dump()


@app.delete("/api/allowlist/{ip}")
def remove_allowlist(ip: str) -> dict:
    deleted = conn.execute("DELETE FROM allowlist WHERE ip = ?", (ip,)).rowcount
    if not deleted:
        raise HTTPException(404, "only entries added from the ledger can be removed here")
    worker.guard.config.allowlist.discard(ip)
    return {"ip": ip, "removed": True}


# ---------------- Cases (M8) ----------------


class IncidentIn(BaseModel):
    id: str
    severity: str
    verdict: str | None = None
    title: str | None = None
    type: str | None = None
    src_ip: str | None = None
    assets: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)


class CasePatch(BaseModel):
    actor: str = "analyst"
    status: str | None = None
    owner: str | None = None
    severity: str | None = None
    tags: list[str] | None = None


class NoteIn(BaseModel):
    author: str
    text: str


class CloseIn(BaseModel):
    actor: str = "analyst"
    root_cause: str
    lessons_learned: str
    false_positive: bool = False


def _case_call(fn, *args, **kwargs) -> dict:
    try:
        return fn(*args, **kwargs)
    except KeyError:
        raise HTTPException(404, "case not found")
    except CaseError as exc:
        raise HTTPException(422, str(exc))


@app.post("/api/cases/from-incident")
def case_from_incident(body: IncidentIn) -> dict:
    case = _case_call(cases.open_for_incident, body.model_dump(exclude_none=True))
    return {"opened": case is not None, "case": case}


@app.get("/api/cases")
def list_cases(status: str | None = None, owner: str | None = None, severity: str | None = None) -> list[dict]:
    return cases.list(status=status, owner=owner, severity=severity)


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> dict:
    return _case_call(cases.get, case_id)


@app.patch("/api/cases/{case_id}")
def patch_case(case_id: str, body: CasePatch) -> dict:
    return _case_call(cases.update, case_id, body.actor, status=body.status, owner=body.owner,
                      severity=body.severity, tags=body.tags)


@app.post("/api/cases/{case_id}/notes")
def add_case_note(case_id: str, body: NoteIn) -> dict:
    return _case_call(cases.add_note, case_id, body.author, body.text)


@app.post("/api/cases/{case_id}/close")
def close_case(case_id: str, body: CloseIn) -> dict:
    return _case_call(cases.close, case_id, body.actor, body.root_cause, body.lessons_learned,
                      body.false_positive)
