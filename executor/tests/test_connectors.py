"""Redis Streams queue, HAProxy Runtime API connector and website HTTP connector."""

import socketserver
import threading
from datetime import datetime, timedelta, timezone

import fakeredis
import pytest
from fastapi.testclient import TestClient

from common.schemas.actions import ActionRequest, ActionStatus, Gate, RejectionCode
from executor.connectors import HAProxyRuntimeConnector, WebsiteHTTPConnector
from executor.queue import RedisActionQueue, RedisResultStore
from executor.worker import ActionWorker
from website_hooks import app as website


# ---------- Redis Streams ----------


def _block(ip="203.0.113.70", key=None):
    return ActionRequest(
        incident_id="inc-r", tool="block_ip", gate=Gate.G2,
        args={"ip": ip, "ttl_minutes": 30}, idempotency_key=key,
    )


def test_redis_queue_consume_and_ack():
    r = fakeredis.FakeRedis(decode_responses=True)
    q = RedisActionQueue(r)
    q.enqueue(_block())
    assert len(q) == 1
    worker = ActionWorker(queue=q, seen=RedisResultStore(r))
    results = worker.process_queue()
    assert [x.status for x in results] == [ActionStatus.SUCCESS]
    assert len(q) == 0
    assert r.xpending("actions", "executor")["pending"] == 0


def test_redis_redelivers_unacked_message_after_crash():
    r = fakeredis.FakeRedis(decode_responses=True)
    q = RedisActionQueue(r)
    q.enqueue(_block())
    q.consume(1)  # consumer crashes before ACK
    restarted = RedisActionQueue(r)  # same group + consumer name after restart
    again = restarted.consume(1)
    assert len(again) == 1 and again[0].request.args["ip"] == "203.0.113.70"


def test_redis_idempotency_survives_worker_restart():
    r = fakeredis.FakeRedis(decode_responses=True)
    first = ActionWorker(seen=RedisResultStore(r))
    assert first.handle(_block(key="k1")).status == ActionStatus.SUCCESS
    second = ActionWorker(seen=RedisResultStore(r))  # new process, empty memory
    replay = second.handle(_block(key="k1"))
    assert replay.rejection_code == RejectionCode.IDEMPOTENT_REPLAY
    assert second.haproxy.show_acl("203.0.113.70")["blocked"] is False  # not executed twice


def test_redis_bad_message_goes_to_dead_letter():
    r = fakeredis.FakeRedis(decode_responses=True)
    q = RedisActionQueue(r)
    r.xadd("actions", {"request": "{not json"})
    assert q.consume(1) == []
    assert r.xlen("actions:dlq") == 1
    assert r.xpending("actions", "executor")["pending"] == 0


# ---------- HAProxy Runtime API ----------


class FakeHAProxy(socketserver.ThreadingTCPServer):
    """Speaks the Runtime API subset we use: add/del/show acl <file> [<ip>]."""

    allow_reuse_address = True

    def __init__(self):
        self.acls: dict[str, list[str]] = {}
        self.commands: list[str] = []
        super().__init__(("127.0.0.1", 0), self._Handler)

    class _Handler(socketserver.StreamRequestHandler):
        def handle(self):
            srv = self.server
            line = self.rfile.readline().decode().strip()
            srv.commands.append(line)
            verb, _, ref, *rest = line.split()
            entries = srv.acls.setdefault(ref, [])
            if verb == "add":
                entries.append(rest[0])
                out = "\n"
            elif verb == "del":
                out = "\n" if rest[0] in entries else "Key not found.\n"
                if rest[0] in entries:
                    entries.remove(rest[0])
            else:
                out = "".join(f"0x{i:012x} {ip}\n" for i, ip in enumerate(entries)) + "\n"
            self.wfile.write(out.encode())


@pytest.fixture
def haproxy(tmp_path):
    srv = FakeHAProxy()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conn = HAProxyRuntimeConnector(f"127.0.0.1:{srv.server_address[1]}", tmp_path)
    yield srv, conn
    srv.shutdown()
    srv.server_close()


def test_runtime_block_unblock_writes_live_acl_and_file(haproxy, tmp_path):
    srv, conn = haproxy
    worker = ActionWorker(haproxy=conn)
    res = worker.handle(_block("203.0.113.80"))
    assert res.status == ActionStatus.SUCCESS
    assert res.verification["verified"] is True
    ref = str(tmp_path / "blocklist.acl")
    assert f"add acl {ref} 203.0.113.80" in srv.commands
    assert (tmp_path / "blocklist.acl").read_text() == "203.0.113.80\n"

    undo = worker.handle(ActionRequest(incident_id="inc-r", tool="unblock_ip", gate=Gate.G1,
                                       args={"ip": "203.0.113.80"}))
    assert undo.status == ActionStatus.SUCCESS
    assert undo.verification["verified"] is True and undo.verification["blocked"] is False
    assert srv.acls[ref] == []
    assert (tmp_path / "blocklist.acl").read_text() == ""


def test_runtime_ttl_scheduler_unblocks_at_expiry(haproxy, tmp_path):
    srv, conn = haproxy
    conn.add_acl("203.0.113.81", 30)
    conn._state["block"]["203.0.113.81"]["expires_at"] = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    ).isoformat()
    assert conn.expire_due() == [{"ip": "203.0.113.81", "kind": "block", "removed": True}]
    assert conn.show_acl("203.0.113.81")["blocked"] is False


def test_runtime_state_survives_restart_and_reconciles(haproxy, tmp_path):
    srv, conn = haproxy
    conn.add_acl("203.0.113.82", 30, kind="tarpit")
    srv.acls.clear()  # HAProxy lost its live ACL (e.g. runtime cleared)
    fresh = HAProxyRuntimeConnector(conn.socket_addr, tmp_path)
    assert fresh.sync_status()["tarpit"]["missing_live"] == ["203.0.113.82"]
    assert fresh.reconcile()["tarpit"]["in_sync"] is True
    assert fresh.verify_block("203.0.113.82", "tarpit")["verified"] is True


def test_runtime_refuses_command_injection(haproxy):
    _, conn = haproxy
    with pytest.raises(ValueError):
        conn.add_acl("1.2.3.4\nclear acl x", 10)
    worker = ActionWorker(haproxy=conn)
    res = worker.handle(_block("1.2.3.4\nclear acl x"))
    assert res.rejection_code == RejectionCode.INVALID_ARGS


# ---------- Website hooks ----------


@pytest.fixture
def site(monkeypatch):
    monkeypatch.setenv("WEBSITE_PLATFORM_TOKEN", "test-token")
    website.accounts.clear()
    return TestClient(website.app)


def test_website_lock_and_revoke_sessions(site):
    site.post("/login/alice")
    site.post("/login/alice")
    worker = ActionWorker(website=WebsiteHTTPConnector("http://testserver", "test-token", client=site))
    for tool in ("revoke_sessions", "lock_account"):
        res = worker.handle(ActionRequest(incident_id="inc-w", tool=tool, gate=Gate.G2, args={"user": "alice"}))
        assert res.status == ActionStatus.SUCCESS, res.error
    status = site.get("/platform/accounts/alice", headers={"Authorization": "Bearer test-token"}).json()
    assert status == {"user": "alice", "locked": True, "active_sessions": 0}
    assert site.post("/login/alice").status_code == 423


def test_website_rejects_bad_token(site):
    worker = ActionWorker(website=WebsiteHTTPConnector("http://testserver", "wrong", client=site))
    res = worker.handle(ActionRequest(incident_id="inc-w", tool="lock_account", gate=Gate.G2, args={"user": "bob"}))
    assert res.status == ActionStatus.FAILED
    assert "401" in res.error
    assert website.accounts.get("bob") is None
