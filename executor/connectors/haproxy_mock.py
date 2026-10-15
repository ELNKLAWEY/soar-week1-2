"""In-memory HAProxy ACL mock — Week 1–2 stand-in for runtime socket."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class BlockEntry:
    ip: str
    expires_at: datetime
    reason: str = ""


@dataclass
class MockHAProxyConnector:
    blocks: dict[str, BlockEntry] = field(default_factory=dict)

    def add_acl(self, ip: str, ttl_minutes: int, reason: str = "") -> dict:
        expires = utcnow() + timedelta(minutes=ttl_minutes)
        self.blocks[ip] = BlockEntry(ip=ip, expires_at=expires, reason=reason)
        return {"ip": ip, "expires_at": expires.isoformat(), "live": True}

    def del_acl(self, ip: str) -> dict:
        existed = ip in self.blocks
        self.blocks.pop(ip, None)
        return {"ip": ip, "removed": existed}

    def show_acl(self, ip: str | None = None) -> dict:
        self._expire()
        if ip is not None:
            entry = self.blocks.get(ip)
            return {
                "ip": ip,
                "blocked": entry is not None,
                "expires_at": entry.expires_at.isoformat() if entry else None,
            }
        return {
            "count": len(self.blocks),
            "ips": sorted(self.blocks.keys()),
        }

    def verify_block(self, ip: str) -> dict:
        info = self.show_acl(ip)
        return {"verified": bool(info.get("blocked")), **info}

    def _expire(self) -> None:
        now = utcnow()
        expired = [ip for ip, e in self.blocks.items() if e.expires_at <= now]
        for ip in expired:
            del self.blocks[ip]
