"""Policy Guard — plain code the agent cannot override (M4)."""

from __future__ import annotations

from dataclasses import dataclass, field

from common.schemas.actions import (
    MAX_TTL_MINUTES,
    WRITE_TOOLS,
    ActionRequest,
    Gate,
    RejectionCode,
)


@dataclass
class PolicyConfig:
    allowlist: set[str] = field(
        default_factory=lambda: {
            "127.0.0.1",
            "10.0.0.1",  # lab admin
            "172.18.0.1",  # docker gateway / LB example
            "8.8.8.8",  # DNS
            "1.1.1.1",
        }
    )
    # Skyline mock inventory — only these may be acted on as *targets* for scope.
    # For block_ip, the blocked IP is the attacker (external); scope checks that
    # the protected asset (dst) is in inventory when provided.
    skyline_assets: set[str] = field(
        default_factory=lambda: {
            "skyline-web",
            "10.0.0.20",
            "172.18.0.10",
        }
    )
    max_active_blocks: int = 100
    max_blocks_per_minute: int = 20
    # tools allowed at each gate (Project Details §9.6 simplified)
    gate_tools: dict[Gate, set[str]] = field(
        default_factory=lambda: {
            Gate.G0: {"notify", "update_case", "verify_block"},
            Gate.G1: {
                "notify",
                "update_case",
                "verify_block",
                "rate_limit_ip",
                "tarpit_ip",
                "block_ip",
                "unblock_ip",
            },
            Gate.G2: {
                "notify",
                "update_case",
                "verify_block",
                "rate_limit_ip",
                "tarpit_ip",
                "block_ip",
                "unblock_ip",
                "lock_account",
                "revoke_sessions",
                "add_waf_rule",
            },
            Gate.G3: WRITE_TOOLS.copy(),
        }
    )


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""
    rejection_code: RejectionCode | None = None


class PolicyGuard:
    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()
        self._active_blocks: set[str] = set()
        self._blocks_this_minute: int = 0

    def reset_rate_window(self) -> None:
        self._blocks_this_minute = 0

    def register_block(self, ip: str) -> None:
        self._active_blocks.add(ip)
        self._blocks_this_minute += 1

    def release_block(self, ip: str) -> None:
        self._active_blocks.discard(ip)

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        tool = request.tool

        if tool not in WRITE_TOOLS:
            return PolicyDecision(
                False,
                f"unknown tool: {tool}",
                RejectionCode.UNKNOWN_TOOL,
            )

        allowed_tools = self.config.gate_tools.get(request.gate, set())
        if tool not in allowed_tools:
            return PolicyDecision(
                False,
                f"tool {tool} not allowed at gate {request.gate.value}",
                RejectionCode.GATE_TOO_LOW,
            )

        ip = request.args.get("ip")
        if tool in {"block_ip", "rate_limit_ip", "tarpit_ip", "unblock_ip"}:
            if not ip or not isinstance(ip, str):
                return PolicyDecision(
                    False,
                    "ip is required",
                    RejectionCode.INVALID_ARGS,
                )
            if ip in self.config.allowlist:
                return PolicyDecision(
                    False,
                    f"ip {ip} is allowlisted",
                    RejectionCode.ALLOWLISTED,
                )

        asset = request.args.get("asset")
        if asset and asset not in self.config.skyline_assets:
            return PolicyDecision(
                False,
                f"asset {asset} out of scope",
                RejectionCode.SCOPE,
            )

        if tool == "block_ip":
            ttl = int(request.args.get("ttl_minutes", 0))
            max_ttl = MAX_TTL_MINUTES[request.gate]
            if ttl <= 0:
                return PolicyDecision(
                    False,
                    "ttl_minutes must be > 0",
                    RejectionCode.INVALID_ARGS,
                )
            if ttl > max_ttl:
                return PolicyDecision(
                    False,
                    f"ttl {ttl}m exceeds max {max_ttl}m for {request.gate.value}",
                    RejectionCode.TTL_TOO_LONG,
                )
            if len(self._active_blocks) >= self.config.max_active_blocks:
                return PolicyDecision(
                    False,
                    "max active blocks reached",
                    RejectionCode.BLAST_RADIUS,
                )
            if self._blocks_this_minute >= self.config.max_blocks_per_minute:
                return PolicyDecision(
                    False,
                    "blocks-per-minute circuit breaker",
                    RejectionCode.RATE_LIMIT,
                )

        return PolicyDecision(True, "ok")
