"""Website connector (M6): calls the authenticated platform endpoints on skyline-web.

Endpoints are documented in website_hooks/README.md (reference implementation in
website_hooks/app.py). Auth: `Authorization: Bearer <WEBSITE_PLATFORM_TOKEN>`.
"""

from __future__ import annotations

import httpx


class WebsiteHTTPConnector:
    def __init__(self, base_url: str, token: str, timeout: float = 5.0, client: httpx.Client | None = None) -> None:
        self.client = client or httpx.Client(base_url=base_url, timeout=timeout)
        self.headers = {"Authorization": f"Bearer {token}"}

    def lock_account(self, user: str) -> dict:
        return self._post(f"/platform/accounts/{user}/lock")

    def revoke_sessions(self, user: str) -> dict:
        return self._post(f"/platform/accounts/{user}/revoke-sessions")

    def add_waf_rule(self, pattern: str) -> dict:
        return self._post("/platform/waf-rules", {"pattern": pattern})

    def quarantine_file(self, path: str) -> dict:
        return self._post("/platform/uploads/quarantine", {"path": path})

    def _post(self, url: str, body: dict | None = None) -> dict:
        resp = self.client.post(url, json=body, headers=self.headers)
        resp.raise_for_status()  # worker turns this into a `failed` ActionResult
        return resp.json()
