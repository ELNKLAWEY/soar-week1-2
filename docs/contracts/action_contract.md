# Action Contract (v2 — Week 3)

**Owner:** Mohamed Osama (SOAR / Executor)  
**Consumers:** Habiba (agent → ActionRequest), Alaa (streams / correlation), Mostafa (dashboard later)  
**Status:** Ready for team approval — schemas live in `common/schemas/actions.py`

---

## ActionRequest

| Field | Type | Notes |
|---|---|---|
| `id` | string (UUID) | Unique action id |
| `correlation_id` | string (UUID) | Ties detect → decide → act |
| `incident_id` | string | Required |
| `decision_id` | string \| null | Habiba Decision id when present |
| `actor` | string | `agent` \| `playbook:<name>` \| `analyst` |
| `tool` | string | See allowed tools |
| `args` | object | Tool-specific (e.g. `ip`, `ttl_minutes`, `user`) |
| `gate` | `G0`–`G3` | Confidence / blast gate |
| `dry_run` | bool | If true, record would-run only |
| `idempotency_key` | string \| null | Same key → execute once |
| `proposed_at` | datetime (UTC) | When proposed |

### Allowed tools and arguments

| Tool | Required args | Optional args | Lowest gate |
|---|---|---|---|
| `block_ip` | `ip`, `ttl_minutes` | `reason` | G1 (≤15 min) |
| `rate_limit_ip` / `tarpit_ip` | `ip` | `ttl_minutes` (default 15), `reason` | G1 |
| `unblock_ip` | `ip` | `kind`: `block` \| `tarpit` \| `ratelimit` | G1 |
| `verify_block` | `ip` | `kind` | G0 |
| `lock_account` / `revoke_sessions` | `user` | — | G2 |
| `add_waf_rule` | `pattern` | — | G2 |
| `quarantine_file` | `path` | — | G2 |
| `restart_service` | `asset` (must be a Skyline asset) | — | G1 |
| `isolate_container` | `asset` (must be a Skyline asset) | — | G3 |
| `notify` | — | `channel`, `message` | G0 |
| `update_case` | — | `status`, `note`, `tag` / `tags` | G0 |

`ip` must be a single IPv4/IPv6 address (no CIDR); anything else is `invalid_args`.
A step in a playbook may set `gate` in its args to run that one action at a higher gate.

### Gate TTL caps (Policy Guard)

| Gate | Max TTL (minutes) |
|---|---|
| G0 | 0 (no blocks) |
| G1 | 15 |
| G2 | 360 (6h) |
| G3 | 1440 (24h) |

---

## ActionResult

| Field | Type | Notes |
|---|---|---|
| `action_id` | string | Matches request `id` |
| `correlation_id` | string | Echo |
| `incident_id` | string | Echo |
| `tool` | string | Echo |
| `status` | enum | `success` \| `rejected` \| `failed` \| `dry_run` \| `skipped` |
| `result` | object | Connector payload or `would_execute` |
| `verification` | object \| null | e.g. block verified |
| `rollback` | object \| null | Suggested undo action |
| `expires_at` | datetime \| null | Block / control expiry |
| `rejection_code` | enum \| null | See below |
| `error` | string \| null | Human-readable |
| `finished_at` | datetime | UTC |

### Rejection codes

`allowlisted`, `ttl_too_long`, `blast_radius`, `rate_limit`, `scope`, `kill_switch`, `unknown_tool`, `invalid_args`, `gate_too_low`, `idempotent_replay`

---

## Autonomy modes (kill switch)

| Mode | Behavior |
|---|---|
| `autonomous` | Writes allowed after Policy Guard |
| `shadow` | Guard runs; result is `dry_run` (no connector write) |
| `paused` | Result is `skipped` / `kill_switch` (no write) |

---

## Transport (Redis Streams)

- Stream `actions`, consumer group `executor`. Message field `request` = the ActionRequest JSON.
- Each message is ACKed after it is handled; unacked messages are re-delivered after a restart.
- Messages that are not a valid ActionRequest go to `actions:dlq` and are ACKed.
- Idempotency results are kept in Redis hash `executor:results` (survives restarts).
- Incidents: stream `incidents`, group `cases`, field `incident` (JSON with `id`, `severity`, optional `verdict`, `src_ip`, `title`, `assets`, `techniques`).

## Verification

`verification.verified` is `true` when the live HAProxy ACL confirms the change
(entry present after a block / tarpit / rate-limit, absent after an unblock).

## Flow

```
Redis `actions` → ActionWorker → kill switch → Policy Guard
        → HAProxy Runtime API / website platform API / Docker (if autonomous + allowed)
        → ActionResult + audit JSONL + case timeline
```

---

## Approval checklist

- [ ] Habiba — Decision → ActionRequest field mapping OK  
- [ ] Alaa — stream / correlation_id usage OK  
- [ ] Mostafa — dashboard can display ActionResult later  

Please comment on this file or `common/schemas/actions.py` with requested changes.
