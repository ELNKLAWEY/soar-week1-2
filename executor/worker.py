"""Action worker: queue → kill switch → Policy Guard → connectors → result + audit + case timeline."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from common.schemas.actions import (
    ActionRequest,
    ActionResult,
    ActionStatus,
    Gate,
    RejectionCode,
    WRITE_TOOLS,
)
from executor.audit import AuditLog
from executor.cases import CaseStore
from executor.connectors import (
    DockerConnector,
    HAProxyRuntimeConnector,
    MockHAProxyConnector,
    MockWebsiteConnector,
    WebsiteHTTPConnector,
)
from executor.modes import AutonomyController
from executor.policy_guard import SOFT_DEFAULT_TTL, PolicyGuard
from executor.queue import (
    InMemoryActionQueue,
    QueuedAction,
    RedisActionQueue,
    RedisResultStore,
    redis_from_env,
)

# HAProxy ACL kind used by each IP tool
ACL_KIND = {"block_ip": "block", "rate_limit_ip": "ratelimit", "tarpit_ip": "tarpit"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ActionWorker:
    def __init__(
        self,
        guard: PolicyGuard | None = None,
        haproxy: MockHAProxyConnector | HAProxyRuntimeConnector | None = None,
        website: MockWebsiteConnector | WebsiteHTTPConnector | None = None,
        autonomy: AutonomyController | None = None,
        audit: AuditLog | None = None,
        queue: InMemoryActionQueue | RedisActionQueue | None = None,
        seen: dict | RedisResultStore | None = None,
        cases: CaseStore | None = None,
        docker: DockerConnector | None = None,
    ) -> None:
        self.guard = guard or PolicyGuard()
        self.haproxy = haproxy or MockHAProxyConnector()
        self.website = website or MockWebsiteConnector()
        self.autonomy = autonomy or AutonomyController()
        self.audit = audit
        self.queue = queue if queue is not None else InMemoryActionQueue()
        self._seen = seen if seen is not None else {}
        self.cases = cases
        self.docker = docker

    @classmethod
    def from_env(cls, cases: CaseStore | None = None) -> "ActionWorker":
        """Real connectors when configured, mocks otherwise (see executor/README.md)."""
        r = redis_from_env()
        haproxy = None
        if os.getenv("HAPROXY_SOCKET"):
            haproxy = HAProxyRuntimeConnector(
                os.environ["HAPROXY_SOCKET"], os.getenv("HAPROXY_ACL_DIR", "/acl")
            )
        website = None
        if os.getenv("WEBSITE_URL"):
            website = WebsiteHTTPConnector(
                os.environ["WEBSITE_URL"], os.getenv("WEBSITE_PLATFORM_TOKEN", "")
            )
        return cls(
            haproxy=haproxy,
            website=website,
            audit=AuditLog(os.getenv("SENTINEL_AUDIT_PATH") or None),
            queue=RedisActionQueue(r, block_ms=1000) if r else None,
            seen=RedisResultStore(r) if r else None,
            cases=cases,
            docker=DockerConnector(os.getenv("DOCKER_LAB_NETWORK", "sentinel_lab"))
            if os.getenv("DOCKER_ACTIONS") == "1"
            else None,
        )

    def handle(self, request: ActionRequest) -> ActionResult:
        key = request.effective_idempotency_key()
        if key in self._seen:
            prev = self._seen[key].model_copy()
            prev.rejection_code = RejectionCode.IDEMPOTENT_REPLAY
            prev.error = "idempotent replay — original result returned"
            self._audit(request, prev)
            return prev

        if self.autonomy.is_paused():
            return self._finish(
                key, request, ActionStatus.SKIPPED,
                rejection_code=RejectionCode.KILL_SWITCH, error="autonomy mode is paused",
            )

        decision = self.guard.evaluate(request)
        if not decision.allowed:
            return self._finish(
                key, request, ActionStatus.REJECTED,
                rejection_code=decision.rejection_code, error=decision.reason,
            )

        if request.dry_run or self.autonomy.is_shadow():
            return self._finish(
                key, request, ActionStatus.DRY_RUN,
                result={"would_execute": request.tool, "args": request.args, "mode": self.autonomy.mode.value},
            )

        try:
            payload, verification, expires_at, rollback = self._execute(request)
        except Exception as exc:  # noqa: BLE001 — surface as failed action
            return self._finish(key, request, ActionStatus.FAILED, error=str(exc))

        if request.tool == "block_ip":
            self.guard.register_block(request.args["ip"])

        return self._finish(
            key, request, ActionStatus.SUCCESS,
            result=payload, verification=verification, rollback=rollback, expires_at=expires_at,
        )

    def process_queue(self, max_items: int | None = None) -> list[ActionResult]:
        """Consume queued ActionRequests; each message is ACKed only after it is handled."""
        results: list[ActionResult] = []
        while max_items is None or len(results) < max_items:
            batch = self.queue.consume(1)
            if not batch:
                break
            item: QueuedAction = batch[0]
            results.append(self.handle(item.request))
            self.queue.ack(item.message_id)
        return results

    def playbook_handler(
        self, playbook: str, incident_id: str, gate: Gate = Gate.G1
    ) -> Callable[[str, dict], dict]:
        """Turn playbook steps (e.g. `haproxy.block_ip`) into ActionRequests for this worker.

        Steps that are not executor tools (enrichment.collect, agent.decide) belong to other
        services and return {} here. A step may set `gate` in its args to raise its gate.
        """

        def handler(action: str, args: dict[str, Any]) -> dict:
            tool = action.split(".")[-1]
            tool = "notify" if tool == "send" else tool
            if tool not in WRITE_TOOLS:
                return {}
            args = dict(args)
            step_gate = Gate(args.pop("gate", None) or gate)
            result = self.handle(
                ActionRequest(
                    incident_id=incident_id,
                    actor=f"playbook:{playbook}",
                    tool=tool,
                    args=args,
                    gate=step_gate,
                )
            )
            return result.model_dump(mode="json")

        return handler

    def _finish(self, key: str, request: ActionRequest, status: ActionStatus, **fields) -> ActionResult:
        result = ActionResult(
            action_id=request.id,
            correlation_id=request.correlation_id,
            incident_id=request.incident_id,
            tool=request.tool,
            status=status,
            **fields,
        )
        self._seen[key] = result
        self._audit(request, result)
        return result

    def _audit(self, request: ActionRequest, result: ActionResult) -> None:
        if self.audit is not None:
            self.audit.record(request, result)
        if self.cases is not None and request.tool != "update_case":
            case = self.cases.get_by_incident(request.incident_id)
            if case:
                self.cases.add_timeline(
                    case["id"], request.actor, "action",
                    {"tool": request.tool, "args": request.args, "status": result.status.value,
                     "action_id": request.id, "error": result.error},
                )

    def _execute(self, request: ActionRequest):
        tool = request.tool
        args = request.args

        if tool in ACL_KIND:
            ip = args["ip"]
            kind = ACL_KIND[tool]
            ttl = int(args.get("ttl_minutes") or SOFT_DEFAULT_TTL)
            payload = self.haproxy.add_acl(ip, ttl, reason=args.get("reason", ""), kind=kind)
            verification = self.haproxy.verify_block(ip, kind)
            if not verification["verified"]:
                raise RuntimeError(f"{kind} entry for {ip} not found in live ACL after add")
            expires = utcnow() + timedelta(minutes=ttl)
            rollback = {"tool": "unblock_ip", "args": {"ip": ip, "kind": kind}}
            return payload, verification, expires, rollback

        if tool == "unblock_ip":
            ip = args["ip"]
            kind = args.get("kind", "block")
            payload = self.haproxy.del_acl(ip, kind)
            if kind == "block":
                self.guard.release_block(ip)
            verification = self.haproxy.verify_block(ip, kind)
            verification["verified"] = not verification["blocked"]  # removal confirmed
            return payload, verification, None, None

        if tool == "verify_block":
            verification = self.haproxy.verify_block(args["ip"], args.get("kind", "block"))
            return verification, verification, None, None

        if tool == "lock_account":
            return self.website.lock_account(args["user"]), None, None, None

        if tool == "revoke_sessions":
            return self.website.revoke_sessions(args["user"]), None, None, None

        if tool == "add_waf_rule":
            return self.website.add_waf_rule(args["pattern"]), None, None, None

        if tool == "quarantine_file":
            return self.website.quarantine_file(args["path"]), None, None, None

        if tool in {"isolate_container", "restart_service"}:
            if self.docker is None:
                raise RuntimeError("container actions disabled (set DOCKER_ACTIONS=1)")
            return getattr(self.docker, tool)(args["asset"]), None, None, None

        if tool == "update_case":
            if self.cases is None:
                return {"accepted": True, "tool": tool, "args": args}, None, None, None
            return self.cases.apply_update_case_action(request.incident_id, request.actor, args), None, None, None

        if tool == "notify":
            # Delivery is Amira's notification engine (Z6); the executor records the request.
            return {"accepted": True, "tool": tool, "args": args}, None, None, None

        raise ValueError(f"no connector for tool {tool}")
