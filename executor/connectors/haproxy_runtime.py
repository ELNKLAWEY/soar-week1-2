"""HAProxy Runtime API connector (M3): live ACL changes with no reload.

Each kind (block / tarpit / ratelimit) is an ACL file that haproxy.cfg loads with
`acl ... src -f <file>`. The executor:
  * sends `add acl` / `del acl` / `show acl` over the stats socket (live change),
  * rewrites the ACL file so the entry survives an HAProxy restart,
  * keeps expiry times in `<acl_dir>/state.json`; `expire_due()` removes expired entries.
The ACL directory must be mounted at the same path in the executor and HAProxy.
"""

from __future__ import annotations

import json
import socket
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

KINDS = {"block": "blocklist.acl", "tarpit": "tarpit.acl", "ratelimit": "ratelimit.acl"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class HAProxyRuntimeConnector:
    def __init__(self, socket_addr: str, acl_dir: str | Path, timeout: float = 3.0) -> None:
        """socket_addr: a unix socket path (/var/run/haproxy.sock) or host:port."""
        self.socket_addr = socket_addr
        self.acl_dir = Path(acl_dir)
        self.timeout = timeout
        self.acl_dir.mkdir(parents=True, exist_ok=True)
        self._state_path = self.acl_dir / "state.json"
        self._lock = threading.Lock()
        self._state: dict[str, dict[str, dict]] = {k: {} for k in KINDS}
        if self._state_path.exists():
            self._state.update(json.loads(self._state_path.read_text(encoding="utf-8")))
        for kind in KINDS:
            self._ref(kind).touch(exist_ok=True)

    # --- public interface (same as MockHAProxyConnector) ---

    def add_acl(self, ip: str, ttl_minutes: int, reason: str = "", kind: str = "block") -> dict:
        expires = utcnow() + timedelta(minutes=ttl_minutes)
        with self._lock:
            if ip not in self._live(kind):
                self._expect_ok(self._cmd(f"add acl {self._ref(kind)} {ip}"))
            self._state[kind][ip] = {"expires_at": expires.isoformat(), "reason": reason}
            self._save()
        return {"ip": ip, "kind": kind, "expires_at": expires.isoformat(), "live": True}

    def del_acl(self, ip: str, kind: str = "block") -> dict:
        with self._lock:
            existed = ip in self._live(kind)
            if existed:
                self._expect_ok(self._cmd(f"del acl {self._ref(kind)} {ip}"))
            existed = self._state[kind].pop(ip, None) is not None or existed
            self._save()
        return {"ip": ip, "kind": kind, "removed": existed}

    def show_acl(self, ip: str | None = None, kind: str = "block") -> dict:
        live = self._live(kind)
        if ip is not None:
            entry = self._state[kind].get(ip)
            return {
                "ip": ip,
                "kind": kind,
                "blocked": ip in live,
                "expires_at": entry["expires_at"] if entry else None,
            }
        return {
            "kind": kind,
            "count": len(live),
            "entries": [
                {"ip": i, **self._state[kind].get(i, {"expires_at": None, "reason": ""})}
                for i in sorted(live)
            ],
        }

    def verify_block(self, ip: str, kind: str = "block") -> dict:
        info = self.show_acl(ip, kind)
        return {"verified": info["blocked"], **info}

    def expire_due(self) -> list[dict]:
        """TTL scheduler tick: `del acl` every entry past its expiry."""
        now = utcnow()
        due = [
            (kind, ip)
            for kind, entries in self._state.items()
            for ip, e in entries.items()
            if datetime.fromisoformat(e["expires_at"]) <= now
        ]
        return [self.del_acl(ip, kind) for kind, ip in due]

    def sync_status(self) -> dict:
        """Compare the ACL file (what survives restart) with the live ACL."""
        out = {}
        for kind in KINDS:
            file_ips = set(self._state[kind])
            live = self._live(kind)
            out[kind] = {
                "file": sorted(file_ips),
                "live": sorted(live),
                "missing_live": sorted(file_ips - live),
                "extra_live": sorted(live - file_ips),
                "in_sync": file_ips == live,
            }
        return out

    def reconcile(self) -> dict:
        """Make the live ACL match the file/state (the executor's source of truth)."""
        with self._lock:
            for kind, status in self.sync_status().items():
                for ip in status["missing_live"]:
                    self._expect_ok(self._cmd(f"add acl {self._ref(kind)} {ip}"))
                for ip in status["extra_live"]:
                    self._expect_ok(self._cmd(f"del acl {self._ref(kind)} {ip}"))
        return self.sync_status()

    # --- internals ---

    def _ref(self, kind: str) -> Path:
        if kind not in KINDS:
            raise ValueError(f"unknown acl kind {kind}")
        return self.acl_dir / KINDS[kind]

    def _live(self, kind: str) -> set[str]:
        # `show acl` lines look like: "0x55d1c2a3b4c0 203.0.113.7"
        out = self._cmd(f"show acl {self._ref(kind)}")
        if "Unknown ACL" in out:
            raise RuntimeError(f"HAProxy does not load {self._ref(kind)}: {out.strip()}")
        return {parts[1] for line in out.splitlines() if len(parts := line.split()) == 2}

    def _save(self) -> None:
        for kind in KINDS:
            self._ref(kind).write_text(
                "".join(f"{ip}\n" for ip in sorted(self._state[kind])), encoding="utf-8"
            )
        self._state_path.write_text(json.dumps(self._state, indent=1), encoding="utf-8")

    @staticmethod
    def _expect_ok(out: str) -> None:
        # Runtime API answers an empty line on success, text on error.
        if out.strip() and "not found" not in out.lower():
            raise RuntimeError(f"HAProxy runtime API error: {out.strip()}")

    def _cmd(self, line: str) -> str:
        if "\n" in line or "\r" in line or ";" in line:
            raise ValueError("refusing multi-command runtime API input")
        if self.socket_addr.startswith("/"):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            target: str | tuple[str, int] = self.socket_addr
        else:
            host, port = self.socket_addr.rsplit(":", 1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target = (host, int(port))
        with sock:
            sock.settimeout(self.timeout)
            sock.connect(target)
            sock.sendall(line.encode() + b"\n")
            chunks = []
            while chunk := sock.recv(65536):
                chunks.append(chunk)
        return b"".join(chunks).decode(errors="replace")
