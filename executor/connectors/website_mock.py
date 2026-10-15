"""In-memory website hooks mock (lock account / revoke sessions)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MockWebsiteConnector:
    locked_accounts: set[str] = field(default_factory=set)
    revoked_sessions: set[str] = field(default_factory=set)
    waf_patterns: list[str] = field(default_factory=list)

    def lock_account(self, user: str) -> dict:
        self.locked_accounts.add(user)
        return {"user": user, "locked": True}

    def revoke_sessions(self, user: str) -> dict:
        self.revoked_sessions.add(user)
        return {"user": user, "sessions_revoked": True}

    def add_waf_rule(self, pattern: str) -> dict:
        self.waf_patterns.append(pattern)
        return {"pattern": pattern, "added": True}
