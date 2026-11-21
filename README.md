# Sentinel — SOAR core (Mohamed Osama)

SOAR core of the graduation project: action contract, Policy Guard, playbook engine and the
10-playbook library, executor on Redis Streams, real HAProxy blocking, website hooks, case
management, and the Playbook Studio / Actions Ledger pages. Details: [`executor/README.md`](executor/README.md).

## What's in here

| Path | What |
|---|---|
| `common/schemas/` | Shared `ActionRequest` / `ActionResult` schemas |
| `executor/` | Policy Guard, playbooks, worker, Redis queue, HAProxy + website connectors, cases, API, pages |
| `website_hooks/` | Platform endpoints for skyline-web (lock account, end sessions, WAF, quarantine) |
| `deploy/haproxy/` | HAProxy config with the runtime socket and ACL files |
| `docker-compose.yml` | Lab stack: Redis, HAProxy, website, executor, attacker container |
| `ml/` | Detection/train scripts (Habiba/Alaa area; local train helpers) |
| `docs/` | Plans, contracts, PDFs for the team |
| `docs/reports/` | Completion report, action contract PDF, ML report, handoff guide |

## Quick start

```bash
git clone https://github.com/ELNKLAWEY/soar-week1-2.git
cd soar-week1-2
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
python -m executor.demo

# real stack (Redis + HAProxy): Ledger http://localhost:8080/ui/ledger.html
docker compose up -d --build
```

## Team PDFs (share these)

- `docs/reports/Mohamed_Week1_2_Completion_Report.pdf`
- `docs/reports/Action_Contract_for_Team_Approval.pdf` ← Habiba / Alaa / Mostafa should review
- `docs/reports/ML_Local_Training_Report.pdf`
- `docs/reports/What_to_Send_Handoff_Guide.pdf`

Contract (markdown): `docs/contracts/action_contract.md`

## Not in git (on purpose)

- `data/raw/*.csv` — CIC-IDS is huge; download yourself if you need train
- `models/*.joblib` — local train artifact; see ML report PDF instead
- `.venv/`, `logs/`

## Review fixes (Week 3)

See [`docs/Mohamed_Week3_Review_Fixes.md`](docs/Mohamed_Week3_Review_Fixes.md) for each review point and its evidence.

---

Owner: **Mohamed Osama** · Sentinel Autonomous SOAR · Oct 2026
