"""Week 1–2 demo: all Definition-of-Done items in one command."""

from __future__ import annotations

import tempfile
from pathlib import Path

from common.schemas.actions import ActionRequest, AutonomyMode, Gate
from executor.audit import AuditLog
from executor.modes import AutonomyController
from executor.playbook_engine import PlaybookEngine
from executor.queue import mock_producer
from executor.worker import ActionWorker

PLAYBOOKS = Path(__file__).parent / "playbooks"


def _print_result(label: str, result) -> None:
    print(f"  status={result.status.value}", end="")
    if result.rejection_code:
        print(f" rejection={result.rejection_code.value}", end="")
    if result.error:
        print(f" error={result.error!r}", end="")
    if result.verification:
        print(f" verified={result.verification.get('verified')}", end="")
    if result.result:
        print(f" result={result.result}", end="")
    print()


def main() -> None:
    audit_path = Path(tempfile.mkdtemp(prefix="sentinel-audit-")) / "actions.jsonl"
    audit = AuditLog(audit_path)
    worker = ActionWorker(audit=audit)

    print("Sentinel SOAR — Mohamed Week 1–2 demo")
    print(f"Audit log: {audit_path}\n")

    print("=== 1) Policy Guard: allowlisted IP rejected ===")
    bad = ActionRequest(
        incident_id="inc-1",
        tool="block_ip",
        gate=Gate.G1,
        args={"ip": "127.0.0.1", "ttl_minutes": 10},
    )
    _print_result("allowlist", worker.handle(bad))

    print("\n=== 2) Queue → Guard → MockHAProxy (idempotent) ===")
    ok = ActionRequest(
        incident_id="inc-2",
        tool="block_ip",
        gate=Gate.G2,
        args={"ip": "203.0.113.7", "ttl_minutes": 60},
        idempotency_key="inc-2:block:203.0.113.7",
    )
    ids = mock_producer(worker.queue, [ok])
    print(f"  enqueued message_ids={ids}")
    results = worker.process_queue()
    for r in results:
        _print_result("block", r)
    print(f"  mock ACL: {worker.haproxy.show_acl('203.0.113.7')}")
    replay = worker.handle(ok)
    print(f"  idempotent replay: rejection={replay.rejection_code}")

    print("\n=== 3) Paused mode: kill switch skips writes ===")
    worker.autonomy = AutonomyController(AutonomyMode.PAUSED)
    paused = ActionRequest(
        incident_id="inc-3",
        tool="block_ip",
        gate=Gate.G1,
        args={"ip": "198.51.100.9", "ttl_minutes": 10},
    )
    _print_result("paused", worker.handle(paused))
    print(f"  mock ACL blocked? {worker.haproxy.show_acl('198.51.100.9')['blocked']}")

    print("\n=== 4) Shadow mode: would-run recorded, no MockHAProxy write ===")
    worker.autonomy = AutonomyController(AutonomyMode.SHADOW)
    shadow_ip = "198.51.100.42"
    shadow = ActionRequest(
        incident_id="inc-4",
        tool="block_ip",
        gate=Gate.G1,
        args={"ip": shadow_ip, "ttl_minutes": 10},
    )
    _print_result("shadow", worker.handle(shadow))
    print(f"  mock ACL blocked? {worker.haproxy.show_acl(shadow_ip)['blocked']}")

    print("\n=== 5) Playbook dry-runs (step history) ===")
    worker.autonomy = AutonomyController(AutonomyMode.AUTONOMOUS)
    engine = PlaybookEngine()
    for name, ctx in [
        (
            "web_bruteforce_response.yaml",
            {
                "incident": {"src_ip": "203.0.113.7"},
                "decide": {
                    "verdict": "true_positive",
                    "ttl": 30,
                    "target_user": "alice",
                },
            },
        ),
        (
            "dos_flood_response.yaml",
            {
                "incident": {"src_ip": "198.51.100.50"},
                "decide": {
                    "verdict": "true_positive",
                    "escalate": "true",
                    "ttl": 15,
                    "rate_limit": "10r/s",
                },
            },
        ),
    ]:
        pb = engine.load(PLAYBOOKS / name)
        run = engine.run(pb, context=ctx, dry_run=True)
        print(f"  playbook={run.name}")
        for step in run.steps:
            flag = "SKIP" if step.skipped else "RUN "
            print(f"    [{flag}] {step.id}: {step.action} -> {step.output or '{}'}")

    print("\n=== 6) Audit stub (JSONL) ===")
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    print(f"  records written: {len(lines)}")
    if lines:
        print(f"  last line (truncated): {lines[-1][:160]}...")

    print("\nDoD Week 1–2 demo complete.")


if __name__ == "__main__":
    main()
