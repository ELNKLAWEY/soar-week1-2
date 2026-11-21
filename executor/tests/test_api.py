"""M9 Playbook Studio + M10 Actions Ledger + M8 case endpoints."""

import importlib

import pytest
from fastapi.testclient import TestClient

from common.schemas.actions import ActionRequest, Gate


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DB", str(tmp_path / "db.sqlite"))
    monkeypatch.setenv("SENTINEL_AUDIT_PATH", str(tmp_path / "actions.jsonl"))
    monkeypatch.setenv("EXECUTOR_LOOP", "0")
    for var in ("SENTINEL_ACTION_QUEUE", "HAPROXY_SOCKET", "WEBSITE_URL"):
        monkeypatch.delenv(var, raising=False)
    import executor.api as mod

    mod = importlib.reload(mod)
    with TestClient(mod.app) as client:
        yield mod, client


def test_ledger_undo_removes_block_and_extend_respects_gate(api):
    mod, client = api
    res = mod.handle(ActionRequest(incident_id="inc-a", tool="block_ip", gate=Gate.G1,
                                   args={"ip": "203.0.113.30", "ttl_minutes": 10}))
    rows = client.get("/api/actions", params={"tool": "block_ip"}).json()
    assert rows[0]["result"]["status"] == "success"
    assert client.get("/api/blocks").json()["block"][0]["ip"] == "203.0.113.30"

    too_long = client.post(f"/api/actions/{res.action_id}/extend", json={"minutes": 600}).json()
    assert too_long["rejection_code"] == "ttl_too_long"  # G1 caps at 15 minutes
    assert client.post(f"/api/actions/{res.action_id}/extend", json={"minutes": 15}).json()["status"] == "success"

    undo = client.post(f"/api/actions/{res.action_id}/undo").json()
    assert undo["status"] == "success" and undo["tool"] == "unblock_ip"
    assert mod.worker.haproxy.show_acl("203.0.113.30")["blocked"] is False
    assert client.get("/api/actions", params={"actor": "analyst"}).json()[0]["request"]["tool"] == "unblock_ip"


def test_allowlist_management_feeds_policy_guard(api):
    mod, client = api
    assert client.post("/api/allowlist", json={"ip": "bad", "owner": "x", "reason": "y"}).status_code == 422
    client.post("/api/allowlist", json={"ip": "203.0.113.31", "owner": "ops", "reason": "monitoring"})
    res = mod.handle(ActionRequest(incident_id="inc-b", tool="block_ip", gate=Gate.G1,
                                   args={"ip": "203.0.113.31", "ttl_minutes": 10}))
    assert res.rejection_code.value == "allowlisted"
    assert client.delete("/api/allowlist/127.0.0.1").status_code == 404  # built-ins stay
    assert client.delete("/api/allowlist/203.0.113.31").json()["removed"] is True


def test_studio_validate_save_dry_run_and_rollback(api):
    _, client = api
    names = [p["name"] for p in client.get("/api/playbooks").json()]
    assert len(names) == 10
    pb = client.get("/api/playbooks/port_scan_response").json()
    assert pb["version"] == 1

    assert client.post("/api/playbooks/validate", json={"yaml": "name: x\nsteps: []"}).json()["valid"] is False
    edited = pb["yaml"].replace("ttl_minutes: 15\n      reason: scan", "ttl_minutes: 10\n      reason: scan")
    assert client.put("/api/playbooks/port_scan_response", json={"yaml": edited, "note": "shorter"}).json()["version"] == 2
    assert client.put("/api/playbooks/port_scan_response", json={"yaml": "name: other\nsteps: [{id: a, action: b}]"}).status_code == 422

    run = client.post("/api/playbooks/port_scan_response/dry-run", json={
        "context": {"incident": {"src_ip": "203.0.113.40"}, "decide": {"verdict": "true_positive"}}}).json()
    block = next(s for s in run["steps"] if s["id"] == "short_block")
    assert block["output"]["args"]["ttl_minutes"] == 10
    assert client.get("/api/playbooks/port_scan_response/runs").json()[0]["id"] == run["id"]

    assert client.post("/api/playbooks/port_scan_response/rollback", json={"version": 1}).json()["version"] == 3
    assert client.get("/api/playbooks/port_scan_response").json()["yaml"] == pb["yaml"]


def test_case_endpoints(api):
    _, client = api
    low = client.post("/api/cases/from-incident", json={"id": "i-l", "severity": "low"}).json()
    assert low["opened"] is False
    case = client.post("/api/cases/from-incident", json={"id": "i-h", "severity": "high", "src_ip": "203.0.113.2"}).json()["case"]
    cid = case["id"]
    assert client.patch(f"/api/cases/{cid}", json={"status": "triaged", "owner": "analyst-1"}).json()["owner"] == "analyst-1"
    assert client.patch(f"/api/cases/{cid}", json={"status": "bogus"}).status_code == 422
    client.post(f"/api/cases/{cid}/notes", json={"author": "analyst-1", "text": "confirmed"})
    closed = client.post(f"/api/cases/{cid}/close", json={"root_cause": "weak pw", "lessons_learned": "MFA"}).json()
    assert closed["status"] == "closed"
    assert client.get("/api/cases", params={"status": "closed"}).json()[0]["id"] == cid
    assert client.get("/api/cases/nope").status_code == 404
