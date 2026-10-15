# Executor (Mohamed Osama)

Everything that **carries out** decisions safely:

- Policy Guard (code safety, not prompts)
- Playbook YAML engine (dry-run in Week 1–2)
- Action workers + mock HAProxy / website connectors
- In-memory action queue (Redis Streams later)
- Audit JSONL stub
- Kill switch / autonomy modes

Contract for team approval: [`docs/contracts/action_contract.md`](../docs/contracts/action_contract.md)  
Week 1–2 completion notes: [`docs/Mohamed_Week1_2_DONE.md`](../docs/Mohamed_Week1_2_DONE.md)

## Week 1–2 scope

| Done now | Later (Week 3+) |
|---|---|
| Action schemas in `common/schemas/actions.py` | Real Redis Streams consumer |
| Policy Guard v0 + tests | Real HAProxy runtime socket |
| Two sample playbook dry-runs | Full 10-playbook library (M7) |
| MockHAProxy + modes + audit | Case management APIs (M8) |
| In-memory queue + demo | Dashboard pages |

**You do not train the ML model for production.** Habiba owns that; local train is optional for playbook alignment.

## Run

```bash
cd "/Users/macbook/.cursor/graduation project"
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest executor/tests -q
python -m executor.demo
```

Demo covers: allowlist reject → queue → mock block (idempotent) → paused → shadow → playbook step history → audit lines.

## Layout

```
executor/
  policy_guard.py      # M4
  playbook_engine.py   # M1
  modes.py             # M5 stub
  queue.py             # in-memory actions queue
  audit.py             # JSONL audit stub
  connectors/          # mock HAProxy + website
  playbooks/           # YAML samples
  worker.py            # Guard → modes → connectors
  demo.py
  tests/
```

## Real HAProxy later (not Week 1–2)

Week 3+ will open the HAProxy Runtime API socket (typically `/var/run/haproxy/admin.sock`) and send:

- `add acl #<id> <ip>`
- `del acl #<id> <ip>`
- `show acl #<id>`

Until then, `MockHAProxyConnector` holds an in-memory ACL with TTL + `verify_block`.
