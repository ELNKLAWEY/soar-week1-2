# Executor (Mohamed Osama)

Everything that **carries out** decisions safely:

| Part | File | Task |
|---|---|---|
| Policy Guard (allowlist, TTL per gate, blast radius, scope, valid IPs) | `policy_guard.py` | M4 |
| Playbook engine (YAML, conditions, templates, dry-run, validation) | `playbook_engine.py` | M1 |
| Playbook library — 10 playbooks | `playbooks/*.yaml` | M7 |
| Action worker (idempotent, audited, results on the case timeline) | `worker.py` | M2 |
| Redis Streams queue `actions` (group `executor`, DLQ `actions:dlq`) | `queue.py` | M2 |
| HAProxy Runtime API connector (add/del/show acl, ACL file, TTL, reconcile) | `connectors/haproxy_runtime.py` | M3 |
| Website hooks: lock account, end sessions, WAF rule, quarantine | `connectors/website_http.py` + `../website_hooks/` | M6 |
| Kill switch / autonomy modes | `modes.py` | M5 |
| Case management (rules, states, SLA, notes, timeline, closure) | `cases.py` | M8 |
| Playbook Studio page + API | `ui/studio.html`, `playbook_store.py`, `api.py` | M9 |
| Actions Ledger + Response page + API | `ui/ledger.html`, `api.py` | M10 |

Contract: [`docs/contracts/action_contract.md`](../docs/contracts/action_contract.md)

## Run the real stack (Redis + HAProxy + website + executor)

```bash
docker compose up -d --build
```

- Actions Ledger: http://localhost:8080/ui/ledger.html
- Playbook Studio: http://localhost:8080/ui/studio.html
- Skyline site through HAProxy: http://localhost:8081
- API docs: http://localhost:8080/docs

Send an action the way the agent does (block the `attacker` container):

```bash
ATT=$(docker inspect -f '{{(index .NetworkSettings.Networks "sentinel_lab").IPAddress}}' $(docker compose ps -q attacker))
docker compose exec redis redis-cli XADD actions '*' request "{\"incident_id\":\"inc-1\",\"tool\":\"block_ip\",\"args\":{\"ip\":\"$ATT\",\"ttl_minutes\":5},\"gate\":\"G2\"}"
docker compose exec attacker curl -s -o /dev/null -w "%{http_code}\n" http://haproxy/   # 403
```

Then press **Undo** in the Ledger: the entry is removed from HAProxy and the same curl returns 200.
Incidents written to the `incidents` stream (field `incident`, JSON) open cases automatically.

## Configuration (env)

| Variable | Effect | Default |
|---|---|---|
| `SENTINEL_ACTION_QUEUE=redis`, `REDIS_URL` | Redis Streams queue + Redis idempotency store | in-memory |
| `HAPROXY_SOCKET` | `host:port` or unix socket path of the Runtime API | mock HAProxy |
| `HAPROXY_ACL_DIR` | ACL files + `state.json`; same path in executor and HAProxy | `/acl` |
| `WEBSITE_URL`, `WEBSITE_PLATFORM_TOKEN` | skyline-web platform endpoints | mock website |
| `DOCKER_ACTIONS=1`, `DOCKER_LAB_NETWORK` | enable `isolate_container` / `restart_service` | disabled |
| `SENTINEL_DB`, `SENTINEL_AUDIT_PATH` | SQLite (cases, playbooks, allowlist) and audit JSONL | `logs/` |

## Tests

```bash
pytest -q          # 51 tests: guard, worker, Redis queue, HAProxy socket protocol, website, cases, playbooks, API
python -m executor.demo
```
