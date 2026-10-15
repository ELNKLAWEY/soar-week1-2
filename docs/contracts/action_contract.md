# Action Contract (Week 1–2)

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

### Allowed tools

`block_ip`, `rate_limit_ip`, `tarpit_ip`, `lock_account`, `revoke_sessions`, `add_waf_rule`, `notify`, `update_case`, `verify_block`, `unblock_ip`

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

## Flow (Week 1–2)

```
mock producer / in-memory queue
        → ActionWorker
        → Policy Guard
        → Autonomy mode check
        → MockHAProxy / MockWebsite (if autonomous + allowed)
        → ActionResult + audit JSONL
```

Week 3+: Redis Streams (`actions`), real HAProxy Runtime API, case updates (M8).

---

## Approval checklist

- [ ] Habiba — Decision → ActionRequest field mapping OK  
- [ ] Alaa — stream / correlation_id usage OK  
- [ ] Mostafa — dashboard can display ActionResult later  

Please comment on this file or `common/schemas/actions.py` with requested changes.
