# skyline-web platform hooks (M6)

Authenticated endpoints the executor calls on the website. Every call needs
`Authorization: Bearer $WEBSITE_PLATFORM_TOKEN` (401 otherwise). They work the same in
website mode A (vulnerable) and mode B (hardened).

| Method | Path | Body | Effect |
|---|---|---|---|
| POST | `/platform/accounts/{user}/lock` | — | lock the account (login returns 423) |
| POST | `/platform/accounts/{user}/revoke-sessions` | — | end every active session of the user |
| GET | `/platform/accounts/{user}` | — | `{locked, active_sessions}` (verification) |
| POST | `/platform/waf-rules` | `{"pattern": "..."}` | add a request-pattern block |
| POST | `/platform/uploads/quarantine` | `{"path": "..."}` | move an uploaded file to quarantine |

`app.py` is the reference implementation (in-memory state) used by the lab stack and tests.
**Website team:** mount `router` in skyline-web and replace the in-memory dicts with the real
user / session / upload tables.
