# Mohamed Osama — review fixes (Week 3)

**Date:** 2026-11-21

| # | Review comment | Done | Evidence |
|---|---|---|---|
| 1 | Use real Redis for the action queue | `RedisActionQueue` on stream `actions`, group `executor` (XADD / XREADGROUP / XACK), re-delivery of unacked messages after a crash, dead-letter `actions:dlq`; idempotency stored in Redis so a restart never repeats an action | `executor/queue.py`, `test_connectors.py` (4 Redis tests) |
| 2 | Connect to the real HAProxy to block and unblock | `HAProxyRuntimeConnector`: `add acl` / `del acl` / `show acl` on the Runtime API, ACL file written so blocks survive a restart, TTL scheduler, verification after every change, file-vs-live sync + reconcile, tarpit and rate-limit ACLs | `executor/connectors/haproxy_runtime.py`, `deploy/haproxy/haproxy.cfg`, `test_connectors.py` (fake Runtime API socket) |
| 3 | Write 8 more playbooks | 10 playbooks from Project Details §8.3; each has a dry-run test and a live scenario test | `executor/playbooks/`, `test_playbook_library.py` (21 tests) |
| 4 | Website actions: lock an account and end its sessions | Authenticated platform endpoints + HTTP connector (also WAF rule and file quarantine) | `website_hooks/`, `executor/connectors/website_http.py`, `test_connectors.py` |
| 5 | Build case management | Auto-open for incidents above Low and uncertain verdicts, 9 states with allowed transitions, SLA timers (acknowledge / contain / resolve, breached / at-risk), notes, timeline (every action is added), closure form, REST API, `incidents` stream consumer | `executor/cases.py`, `executor/api.py`, `test_cases.py`, `test_api.py` |
| 6 | Dashboard pages: Playbook Studio and Actions Ledger | Studio: list with version / runs / success rate, YAML editor with validation, dry-run with a sample incident, run history with per-step output, versions with rollback. Ledger: every action with result, verification, expiry, rejections; Undo and Extend; active blocks; allowlist management; HAProxy sync status + reconcile | `executor/ui/`, `executor/api.py`, `test_api.py` |

## End-to-end check on the real stack (`docker compose up`)

Run on 2026-11-21 with Redis 7.4 and HAProxy 2.9:

1. Attacker container → site: **200**.
2. `block_ip` sent on the Redis `actions` stream (sent twice with the same idempotency key) → attacker gets **403**; the second message is an `idempotent_replay`, executed once; verification `verified: true`; file and live ACL in sync.
3. **Undo** from the Ledger API → `unblock_ip` → attacker gets **200** again.
4. `revoke_sessions` + `lock_account` for `alice` through the queue → login returns **423**.
5. `incidents` stream: a `high` incident opened a case, a `low` one did not.
6. 1-minute block → HAProxy restarted → still **403** (ACL file reloaded) → at expiry the TTL scheduler removed it → **200**, no HAProxy reload.

## Notes for the team

- **Mostafa:** the two pages are plain HTML + the executor API (`/api/...`, docs at `/docs`) so they can move into the dashboard framework once it is chosen. The API has no login yet — it should sit behind the dashboard auth (S2).
- **Alaa:** stream names / message fields are in `docs/contracts/action_contract.md` (Transport section). Please confirm or tell me what to rename.
- **Website team (Omar / Mostafa):** mount `website_hooks.app.router` in skyline-web and replace the in-memory state with the real user / session tables.
- **Amira:** `notify` actions are recorded by the executor; delivery is the notification engine (Z6).
- Storage for cases / playbook versions / allowlist is SQLite (`executor/db.py`) until the shared MongoDB exists.
