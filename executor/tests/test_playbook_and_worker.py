from pathlib import Path

from common.schemas.actions import ActionRequest, ActionStatus, AutonomyMode, Gate
from executor.audit import AuditLog
from executor.modes import AutonomyController
from executor.playbook_engine import PlaybookEngine
from executor.queue import mock_producer
from executor.worker import ActionWorker

PLAYBOOKS = Path(__file__).resolve().parents[1] / "playbooks"
PLAYBOOK = PLAYBOOKS / "web_bruteforce_response.yaml"
DOS_PLAYBOOK = PLAYBOOKS / "dos_flood_response.yaml"


def test_playbook_dry_run_runs_contain_when_true_positive():
    engine = PlaybookEngine()
    pb = engine.load(PLAYBOOK)
    run = engine.run(
        pb,
        context={
            "incident": {"src_ip": "203.0.113.7"},
            "decide": {
                "verdict": "true_positive",
                "ttl": 30,
                "target_user": "alice",
            },
        },
        dry_run=True,
    )
    by_id = {s.id: s for s in run.steps}
    assert by_id["contain"].skipped is False
    assert by_id["contain"].args["ip"] == "203.0.113.7"
    assert by_id["lock"].skipped is False


def test_playbook_skips_contain_on_false_positive():
    engine = PlaybookEngine()
    pb = engine.load(PLAYBOOK)
    run = engine.run(
        pb,
        context={
            "incident": {"src_ip": "203.0.113.7"},
            "decide": {"verdict": "false_positive", "ttl": 30},
        },
        dry_run=True,
    )
    by_id = {s.id: s for s in run.steps}
    assert by_id["contain"].skipped is True
    assert by_id["lock"].skipped is True


def test_worker_blocks_and_is_idempotent():
    worker = ActionWorker()
    req = ActionRequest(
        incident_id="inc-9",
        tool="block_ip",
        gate=Gate.G2,
        args={"ip": "198.51.100.2", "ttl_minutes": 30},
        idempotency_key="once",
    )
    r1 = worker.handle(req)
    r2 = worker.handle(req)
    assert r1.status == ActionStatus.SUCCESS
    assert r1.verification and r1.verification["verified"] is True
    assert worker.haproxy.show_acl("198.51.100.2")["blocked"] is True
    assert r2.action_id == r1.action_id


def test_paused_skips():
    worker = ActionWorker(autonomy=AutonomyController(AutonomyMode.PAUSED))
    req = ActionRequest(
        incident_id="inc-10",
        tool="block_ip",
        gate=Gate.G1,
        args={"ip": "198.51.100.3", "ttl_minutes": 10},
    )
    r = worker.handle(req)
    assert r.status == ActionStatus.SKIPPED
    assert worker.haproxy.show_acl("198.51.100.3")["blocked"] is False


def test_shadow_records_without_write():
    worker = ActionWorker(autonomy=AutonomyController(AutonomyMode.SHADOW))
    ip = "198.51.100.44"
    req = ActionRequest(
        incident_id="inc-11",
        tool="block_ip",
        gate=Gate.G1,
        args={"ip": ip, "ttl_minutes": 10},
    )
    r = worker.handle(req)
    assert r.status == ActionStatus.DRY_RUN
    assert r.result["would_execute"] == "block_ip"
    assert worker.haproxy.show_acl(ip)["blocked"] is False


def test_queue_consumer_and_audit(tmp_path):
    audit = AuditLog(tmp_path / "actions.jsonl")
    worker = ActionWorker(audit=audit)
    req = ActionRequest(
        incident_id="inc-12",
        tool="block_ip",
        gate=Gate.G2,
        args={"ip": "203.0.113.99", "ttl_minutes": 30},
        idempotency_key="q-once",
    )
    mock_producer(worker.queue, [req])
    assert len(worker.queue) == 1
    results = worker.process_queue()
    assert len(results) == 1
    assert results[0].status == ActionStatus.SUCCESS
    assert len(worker.queue) == 0
    lines = (tmp_path / "actions.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1


def test_dos_playbook_dry_run():
    engine = PlaybookEngine()
    pb = engine.load(DOS_PLAYBOOK)
    run = engine.run(
        pb,
        context={
            "incident": {"src_ip": "198.51.100.50"},
            "decide": {
                "verdict": "true_positive",
                "escalate": "true",
                "ttl": 15,
                "rate_limit": "10r/s",
            },
        },
        dry_run=True,
    )
    by_id = {s.id: s for s in run.steps}
    assert by_id["rate"].skipped is False
    assert by_id["contain"].skipped is False
    assert by_id["contain"].args["ip"] == "198.51.100.50"
