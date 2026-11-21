"""M8: case creation rules, states, SLA timers, notes, timeline, closure."""

import pytest

from common.schemas.actions import ActionRequest, Gate
from executor.cases import CaseError, CaseStore
from executor.db import connect
from executor.worker import ActionWorker


@pytest.fixture
def cases(tmp_path):
    return CaseStore(connect(tmp_path / "db.sqlite"))


def test_case_opens_only_above_low_or_uncertain(cases):
    assert cases.open_for_incident({"id": "i-low", "severity": "low"}) is None
    uncertain = cases.open_for_incident({"id": "i-unc", "severity": "low", "verdict": "uncertain"})
    assert uncertain and "needs_human_review" in uncertain["tags"]
    high = cases.open_for_incident({"id": "i-high", "severity": "high", "src_ip": "203.0.113.5"})
    assert high["status"] == "new" and high["indicators"] == ["203.0.113.5"]
    # one case per incident
    assert cases.open_for_incident({"id": "i-high", "severity": "high"})["id"] == high["id"]
    assert len(cases.list()) == 2


def test_states_transitions_and_sla(cases):
    c = cases.open_for_incident({"id": "i1", "severity": "critical"})
    assert c["sla"]["acknowledge"]["breached"] is False
    c = cases.update(c["id"], "analyst", status="triaged", owner="omar")
    assert c["sla"]["acknowledge"]["met_at"] is not None
    assert c["sla"]["contain"]["met_at"] is None
    with pytest.raises(CaseError):
        cases.update(c["id"], "analyst", status="reopened")  # not from an open state
    assert [e["event"] for e in c["timeline"]] == ["case_opened", "status_changed", "reassigned"]


def test_notes_and_closure_form(cases):
    c = cases.open_for_incident({"id": "i2", "severity": "medium"})
    cases.add_note(c["id"], "analyst", "checked the logs")
    with pytest.raises(CaseError):
        cases.close(c["id"], "analyst", root_cause="", lessons_learned="x")
    c = cases.close(c["id"], "analyst", root_cause="weak password", lessons_learned="enforce MFA")
    assert c["status"] == "closed"
    assert c["closure"]["root_cause"] == "weak password"
    assert c["notes"][0]["text"] == "checked the logs"
    c = cases.update(c["id"], "analyst", status="reopened")
    assert c["closure"] is None


def test_worker_actions_land_on_case_timeline(cases):
    c = cases.open_for_incident({"id": "i3", "severity": "high"})
    worker = ActionWorker(cases=cases)
    worker.handle(ActionRequest(incident_id="i3", tool="block_ip", gate=Gate.G2,
                                args={"ip": "203.0.113.9", "ttl_minutes": 60}))
    worker.handle(ActionRequest(incident_id="i3", tool="update_case", gate=Gate.G0,
                                args={"status": "contained", "note": "blocked"}))
    c = cases.get(c["id"])
    assert c["status"] == "contained"
    assert any(e["event"] == "action" and e["detail"]["tool"] == "block_ip" for e in c["timeline"])
