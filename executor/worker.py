"""Action worker: queue → Guard → modes → connectors (M2 stub for Week 1–2)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from common.schemas.actions import (
    ActionRequest,
    ActionResult,
    ActionStatus,
    RejectionCode,
)
from executor.audit import AuditLog
from executor.connectors import MockHAProxyConnector, MockWebsiteConnector
from executor.modes import AutonomyController
from executor.policy_guard import PolicyGuard
from executor.queue import InMemoryActionQueue, QueuedAction


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ActionWorker:
    def __init__(
        self,
        guard: PolicyGuard | None = None,
        haproxy: MockHAProxyConnector | None = None,
        website: MockWebsiteConnector | None = None,
        autonomy: AutonomyController | None = None,
        audit: AuditLog | None = None,
        queue: InMemoryActionQueue | None = None,
    ) -> None:
        self.guard = guard or PolicyGuard()
        self.haproxy = haproxy or MockHAProxyConnector()
        self.website = website or MockWebsiteConnector()
        self.autonomy = autonomy or AutonomyController()
        self.audit = audit  # optional; demo enables it
        self.queue = queue or InMemoryActionQueue()
        self._seen: dict[str, ActionResult] = {}

    def handle(self, request: ActionRequest) -> ActionResult:
        key = request.effective_idempotency_key()
        if key in self._seen:
            prev = self._seen[key].model_copy()
            prev.rejection_code = RejectionCode.IDEMPOTENT_REPLAY
            prev.error = "idempotent replay — original result returned"
            self._audit(request, prev)
            return prev

        if self.autonomy.is_paused():
            result = ActionResult(
                action_id=request.id,
                correlation_id=request.correlation_id,
                incident_id=request.incident_id,
                tool=request.tool,
                status=ActionStatus.SKIPPED,
                rejection_code=RejectionCode.KILL_SWITCH,
                error="autonomy mode is paused",
            )
            self._seen[key] = result
            self._audit(request, result)
            return result

        decision = self.guard.evaluate(request)
        if not decision.allowed:
            result = ActionResult(
                action_id=request.id,
                correlation_id=request.correlation_id,
                incident_id=request.incident_id,
                tool=request.tool,
                status=ActionStatus.REJECTED,
                rejection_code=decision.rejection_code,
                error=decision.reason,
            )
            self._seen[key] = result
            self._audit(request, result)
            return result

        if request.dry_run or self.autonomy.is_shadow():
            result = ActionResult(
                action_id=request.id,
                correlation_id=request.correlation_id,
                incident_id=request.incident_id,
                tool=request.tool,
                status=ActionStatus.DRY_RUN,
                result={
                    "would_execute": request.tool,
                    "args": request.args,
                    "mode": self.autonomy.mode.value,
                },
            )
            self._seen[key] = result
            self._audit(request, result)
            return result

        try:
            payload, verification, expires_at, rollback = self._execute(request)
        except Exception as exc:  # noqa: BLE001 — surface as failed action
            result = ActionResult(
                action_id=request.id,
                correlation_id=request.correlation_id,
                incident_id=request.incident_id,
                tool=request.tool,
                status=ActionStatus.FAILED,
                error=str(exc),
            )
            self._seen[key] = result
            self._audit(request, result)
            return result

        if request.tool == "block_ip":
            ip = request.args["ip"]
            self.guard.register_block(ip)

        result = ActionResult(
            action_id=request.id,
            correlation_id=request.correlation_id,
            incident_id=request.incident_id,
            tool=request.tool,
            status=ActionStatus.SUCCESS,
            result=payload,
            verification=verification,
            rollback=rollback,
            expires_at=expires_at,
        )
        self._seen[key] = result
        self._audit(request, result)
        return result

    def process_queue(self, max_items: int | None = None) -> list[ActionResult]:
        """Consume queued ActionRequests (in-memory stand-in for Redis Streams)."""
        results: list[ActionResult] = []
        remaining = max_items if max_items is not None else len(self.queue)
        while remaining > 0 and len(self.queue) > 0:
            batch = self.queue.consume(1)
            if not batch:
                break
            item: QueuedAction = batch[0]
            result = self.handle(item.request)
            self.queue.ack(item.message_id)
            results.append(result)
            remaining -= 1
        return results

    def _audit(self, request: ActionRequest, result: ActionResult) -> None:
        if self.audit is not None:
            self.audit.record(request, result)

    def _execute(self, request: ActionRequest):
        tool = request.tool
        args = request.args

        if tool == "block_ip":
            ip = args["ip"]
            ttl = int(args["ttl_minutes"])
            payload = self.haproxy.add_acl(ip, ttl, reason=args.get("reason", ""))
            verification = self.haproxy.verify_block(ip)
            expires = utcnow() + timedelta(minutes=ttl)
            rollback = {"tool": "unblock_ip", "args": {"ip": ip}}
            return payload, verification, expires, rollback

        if tool == "unblock_ip":
            ip = args["ip"]
            payload = self.haproxy.del_acl(ip)
            self.guard.release_block(ip)
            return payload, self.haproxy.verify_block(ip), None, None

        if tool == "verify_block":
            ip = args["ip"]
            verification = self.haproxy.verify_block(ip)
            return verification, verification, None, None

        if tool == "lock_account":
            return self.website.lock_account(args["user"]), None, None, None

        if tool == "revoke_sessions":
            return self.website.revoke_sessions(args["user"]), None, None, None

        if tool == "add_waf_rule":
            return self.website.add_waf_rule(args["pattern"]), None, None, None

        if tool in {"notify", "update_case", "rate_limit_ip", "tarpit_ip"}:
            return {"accepted": True, "tool": tool, "args": args}, None, None, None

        raise ValueError(f"no connector for tool {tool}")
