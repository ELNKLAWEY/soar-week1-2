"""In-memory HAProxy ACL mock (unit tests / demo). Same interface as HAProxyRuntimeConnector."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

KINDS = ("block", "tarpit", "ratelimit")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class BlockEntry:
    ip: str
    expires_at: datetime
    reason: str = ""


@dataclass
class MockHAProxyConnector:
    acls: dict[str, dict[str, BlockEntry]] = field(
        default_factory=lambda: {k: {} for k in KINDS}
    )

    def add_acl(self, ip: str, ttl_minutes: int, reason: str = "", kind: str = "block") -> dict:
        expires = utcnow() + timedelta(minutes=ttl_minutes)
        self.acls[kind][ip] = BlockEntry(ip=ip, expires_at=expires, reason=reason)
        return {"ip": ip, "kind": kind, "expires_at": expires.isoformat(), "live": True}

    def del_acl(self, ip: str, kind: str = "block") -> dict:
        existed = self.acls[kind].pop(ip, None) is not None
        return {"ip": ip, "kind": kind, "removed": existed}

    def show_acl(self, ip: str | None = None, kind: str = "block") -> dict:
        self.expire_due()
        entries = self.acls[kind]
        if ip is not None:
            entry = entries.get(ip)
            return {
                "ip": ip,
                "kind": kind,
                "blocked": entry is not None,
                "expires_at": entry.expires_at.isoformat() if entry else None,
            }
        return {
            "kind": kind,
            "count": len(entries),
            "entries": [
                {"ip": e.ip, "expires_at": e.expires_at.isoformat(), "reason": e.reason}
                for e in sorted(entries.values(), key=lambda e: e.ip)
            ],
        }

    def verify_block(self, ip: str, kind: str = "block") -> dict:
        info = self.show_acl(ip, kind)
        return {"verified": info["blocked"], **info}

    def expire_due(self) -> list[dict]:
        now = utcnow()
        due = [(k, ip) for k, es in self.acls.items() for ip, e in es.items() if e.expires_at <= now]
        return [self.del_acl(ip, k) for k, ip in due]

    def sync_status(self) -> dict:
        return {
            k: {"file": sorted(es), "live": sorted(es), "missing_live": [], "extra_live": [], "in_sync": True}
            for k, es in self.acls.items()
        }

    def reconcile(self) -> dict:
        return self.sync_status()
