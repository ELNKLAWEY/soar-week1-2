"""M7: every playbook in the library passes a dry-run and a live scenario (mock connectors)."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from executor.cases import CaseStore
from executor.db import connect
from executor.playbook_engine import PlaybookEngine
from executor.worker import ActionWorker

PLAYBOOKS = Path(__file__).resolve().parents[1] / "playbooks"
IP = "203.0.113.50"


def _ctx(incident: dict, decide: dict | None = None) -> dict:
    return {"incident": {"id": "inc-pb", "src_ip": IP, **incident}, "decide": decide or {}}


def _blocked(w, kind="block"):
    return w.haproxy.show_acl(IP, kind)["blocked"]


# name -> (context, check(worker, case, run))
SCENARIOS = {
    "web_bruteforce_response": (
        _ctx({}, {"verdict": "true_positive", "ttl": 60, "gate": "G2", "target_user": "alice"}),
        lambda w, case, run: (
            _blocked(w)
            and "alice" in w.website.locked_accounts
            and "alice" in w.website.revoked_sessions
            and case["status"] == "contained"
        ),
    ),
    "dos_flood_response": (
        _ctx({}, {"verdict": "true_positive", "escalate": "true", "ttl": 15, "rate_limit": "10r/s"}),
        lambda w, case, run: _blocked(w) and _blocked(w, "ratelimit") and _blocked(w, "tarpit"),
    ),
    "web_exploit_response": (
        _ctx({"pattern": "' OR 1=1", "url": "/search"}, {"verdict": "true_positive", "ttl": 60, "gate": "G2"}),
        lambda w, case, run: (
            _blocked(w) and "' OR 1=1" in w.website.waf_patterns and "vulnerable_endpoint" in case["tags"]
        ),
    ),
    "port_scan_response": (
        _ctx({}, {"verdict": "true_positive"}),
        lambda w, case, run: _blocked(w) and _blocked(w, "tarpit") and "watchlist" in case["tags"],
    ),
    "malicious_upload_response": (
        _ctx({"file_path": "/uploads/shell.php"}, {"verdict": "true_positive", "ttl": 60, "gate": "G2"}),
        lambda w, case, run: _blocked(w) and "/uploads/shell.php" in w.website.quarantined,
    ),
    "botnet_beaconing_response": (
        _ctx({"internal": "true", "asset": "skyline-web"}, {"verdict": "true_positive", "ttl": 60, "gate": "G2"}),
        lambda w, case, run: _blocked(w) and w.docker.isolate_container.called,
    ),
    "authorized_pentest": (
        _ctx({"scan_id": "scan-1", "rule_id": "R-SCAN-01"}),
        lambda w, case, run: (
            not _blocked(w) and {"authorized_test", "detection_fired"} <= set(case["tags"])
        ),
    ),
    "repeat_offender_response": (
        _ctx({"offense_tier": "3"}),
        lambda w, case, run: (
            _blocked(w) and [s.id for s in run.steps if not s.skipped][0] == "tier3"
        ),
    ),
    "false_positive_handling": (
        _ctx({"rule_id": "R-BF-02"}, {"verdict": "false_positive", "reason": "office NAT"}),
        lambda w, case, run: not _blocked(w) and case["status"] == "false_positive",
    ),
    "service_health_response": (
        _ctx({"service": "skyline-web", "state": "down"}, {"restart": "true"}),
        lambda w, case, run: w.docker.restart_service.called,
    ),
}


def test_library_has_ten_playbooks():
    names = {PlaybookEngine().load(p)["name"] for p in PLAYBOOKS.glob("*.yaml")}
    assert names == set(SCENARIOS)


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_playbook_dry_run(name):
    engine = PlaybookEngine()
    context, _ = SCENARIOS[name]
    run = engine.run(engine.load(PLAYBOOKS / f"{name}.yaml"), context, dry_run=True)
    ran = [s for s in run.steps if not s.skipped]
    assert ran, "at least one step runs"
    assert all("would_call" in s.output for s in ran)


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_playbook_live_scenario(name, tmp_path):
    cases = CaseStore(connect(tmp_path / "db.sqlite"))
    case = cases.open_for_incident({"id": "inc-pb", "severity": "high", "src_ip": IP})
    worker = ActionWorker(cases=cases, docker=MagicMock())
    worker.docker.isolate_container.return_value = {"isolated": True}
    worker.docker.restart_service.return_value = {"restarted": True}
    if name == "false_positive_handling":
        worker.haproxy.add_acl(IP, 30)  # the earlier (wrong) block that must be undone

    engine = PlaybookEngine()
    context, check = SCENARIOS[name]
    run = engine.run(
        engine.load(PLAYBOOKS / f"{name}.yaml"),
        context,
        dry_run=False,
        action_handler=worker.playbook_handler(name, "inc-pb"),
    )
    statuses = [s.output.get("status") for s in run.steps if s.output]
    assert "failed" not in statuses and "rejected" not in statuses, run.steps
    assert check(worker, cases.get(case["id"]), run)
