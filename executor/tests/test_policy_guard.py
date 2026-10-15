from common.schemas.actions import ActionRequest, Gate, RejectionCode
from executor.policy_guard import PolicyGuard


def test_allowlisted_ip_rejected():
    guard = PolicyGuard()
    req = ActionRequest(
        incident_id="i1",
        tool="block_ip",
        gate=Gate.G1,
        args={"ip": "127.0.0.1", "ttl_minutes": 10},
    )
    d = guard.evaluate(req)
    assert d.allowed is False
    assert d.rejection_code == RejectionCode.ALLOWLISTED


def test_ttl_too_long_for_gate():
    guard = PolicyGuard()
    req = ActionRequest(
        incident_id="i1",
        tool="block_ip",
        gate=Gate.G1,
        args={"ip": "203.0.113.10", "ttl_minutes": 120},  # G1 max 15
    )
    d = guard.evaluate(req)
    assert d.allowed is False
    assert d.rejection_code == RejectionCode.TTL_TOO_LONG


def test_valid_block_accepted():
    guard = PolicyGuard()
    req = ActionRequest(
        incident_id="i1",
        tool="block_ip",
        gate=Gate.G2,
        args={"ip": "203.0.113.10", "ttl_minutes": 60},
    )
    d = guard.evaluate(req)
    assert d.allowed is True


def test_unknown_tool():
    guard = PolicyGuard()
    req = ActionRequest(incident_id="i1", tool="launch_missiles", gate=Gate.G3)
    d = guard.evaluate(req)
    assert d.rejection_code == RejectionCode.UNKNOWN_TOOL


def test_gate_too_low_for_lock():
    guard = PolicyGuard()
    req = ActionRequest(
        incident_id="i1",
        tool="lock_account",
        gate=Gate.G1,
        args={"user": "bob"},
    )
    d = guard.evaluate(req)
    assert d.rejection_code == RejectionCode.GATE_TOO_LOW
