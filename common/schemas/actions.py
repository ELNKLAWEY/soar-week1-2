"""Action contract owned by Mohamed Osama (Week 1 shared contract).

Habiba's agent produces ActionRequest items.
The executor validates them with Policy Guard and returns ActionResult.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Gate(str, Enum):
    G0 = "G0"
    G1 = "G1"
    G2 = "G2"
    G3 = "G3"


class AutonomyMode(str, Enum):
    AUTONOMOUS = "autonomous"
    SHADOW = "shadow"
    PAUSED = "paused"


class ActionStatus(str, Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    FAILED = "failed"
    DRY_RUN = "dry_run"
    SKIPPED = "skipped"  # e.g. paused / shadow with no write


class RejectionCode(str, Enum):
    ALLOWLISTED = "allowlisted"
    TTL_TOO_LONG = "ttl_too_long"
    BLAST_RADIUS = "blast_radius"
    RATE_LIMIT = "rate_limit"
    SCOPE = "scope"
    KILL_SWITCH = "kill_switch"
    UNKNOWN_TOOL = "unknown_tool"
    INVALID_ARGS = "invalid_args"
    GATE_TOO_LOW = "gate_too_low"
    IDEMPOTENT_REPLAY = "idempotent_replay"


WRITE_TOOLS = frozenset(
    {
        "block_ip",
        "unblock_ip",
        "rate_limit_ip",
        "tarpit_ip",
        "lock_account",
        "revoke_sessions",
        "add_waf_rule",
        "notify",
        "update_case",
        "verify_block",
    }
)

# Max TTL (minutes) the Policy Guard allows per confidence gate (Project Details §9.6)
MAX_TTL_MINUTES: dict[Gate, int] = {
    Gate.G0: 0,  # G0: record / enrich / notify only — no blocks
    Gate.G1: 15,
    Gate.G2: 6 * 60,
    Gate.G3: 24 * 60,
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ActionRequest(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    decision_id: str | None = None
    actor: str = "agent"  # agent | playbook:<name> | analyst
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    gate: Gate = Gate.G1
    dry_run: bool = False
    idempotency_key: str | None = None
    proposed_at: datetime = Field(default_factory=utcnow)

    def effective_idempotency_key(self) -> str:
        if self.idempotency_key:
            return self.idempotency_key
        return f"{self.incident_id}:{self.tool}:{sorted(self.args.items())}"


class ActionResult(BaseModel):
    action_id: str
    correlation_id: str
    incident_id: str
    tool: str
    status: ActionStatus
    result: dict[str, Any] = Field(default_factory=dict)
    verification: dict[str, Any] | None = None
    rollback: dict[str, Any] | None = None
    expires_at: datetime | None = None
    rejection_code: RejectionCode | None = None
    error: str | None = None
    finished_at: datetime = Field(default_factory=utcnow)
