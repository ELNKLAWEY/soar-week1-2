"""Reference platform endpoints for skyline-web (M6).

The website team mounts `router` in skyline-web (mode A and mode B alike — these hooks
do not depend on MODE). Run standalone for the lab: `uvicorn website_hooks.app:app`.
State is in memory here; in skyline-web the handlers write to its user/session tables.
"""

from __future__ import annotations

import hmac
import os
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel


def require_platform_token(authorization: str = Header(default="")) -> None:
    expected = os.getenv("WEBSITE_PLATFORM_TOKEN", "")
    given = authorization.removeprefix("Bearer ")
    if not expected or not hmac.compare_digest(given, expected):
        raise HTTPException(status_code=401, detail="invalid platform token")


accounts: dict[str, dict] = {}  # user -> {"locked": bool, "sessions": set[str]}
waf_rules: list[str] = []
quarantine: list[str] = []


def _account(user: str) -> dict:
    return accounts.setdefault(user, {"locked": False, "sessions": set()})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


router = APIRouter(prefix="/platform", dependencies=[Depends(require_platform_token)])


class Pattern(BaseModel):
    pattern: str


class FilePath(BaseModel):
    path: str


@router.post("/accounts/{user}/lock")
def lock_account(user: str) -> dict:
    acc = _account(user)
    acc["locked"] = True
    return {"user": user, "locked": True, "at": _now()}


@router.post("/accounts/{user}/revoke-sessions")
def revoke_sessions(user: str) -> dict:
    acc = _account(user)
    revoked = len(acc["sessions"])
    acc["sessions"].clear()
    return {"user": user, "sessions_revoked": True, "count": revoked, "at": _now()}


@router.get("/accounts/{user}")
def account_status(user: str) -> dict:
    acc = _account(user)
    return {"user": user, "locked": acc["locked"], "active_sessions": len(acc["sessions"])}


@router.post("/waf-rules")
def add_waf_rule(body: Pattern) -> dict:
    waf_rules.append(body.pattern)
    return {"pattern": body.pattern, "added": True}


@router.post("/uploads/quarantine")
def quarantine_file(body: FilePath) -> dict:
    quarantine.append(body.path)
    return {"path": body.path, "quarantined": True}


app = FastAPI(title="skyline-web platform hooks (reference)")
app.include_router(router)


@app.post("/login/{user}")
def login(user: str) -> dict:
    """Lab-only stand-in for the real login: opens a session unless the account is locked."""
    acc = _account(user)
    if acc["locked"]:
        raise HTTPException(status_code=423, detail="account locked")
    sid = secrets.token_hex(8)
    acc["sessions"].add(sid)
    return {"user": user, "session": sid}


@app.get("/")
def home() -> dict:
    return {"site": "skyline-web (lab stand-in)"}
