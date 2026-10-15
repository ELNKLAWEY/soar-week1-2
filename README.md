# Sentinel — SOAR Week 1–2 (Mohamed Osama)

Week 1–2 deliverables for the graduation SOAR project: **action contract, Policy Guard, playbook engine, executor stubs**, plus local CIC-IDS training notes.

Not the full platform yet — just the SOAR-core slice so the team can agree on contracts and run a local demo.

## What's in here

| Path | What |
|---|---|
| `common/schemas/` | Shared `ActionRequest` / `ActionResult` schemas |
| `executor/` | Policy Guard, playbooks, worker, mocks, queue, audit |
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
pytest executor/tests -q
python -m executor.demo
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

## Week 3+ (not here yet)

Redis Streams, real HAProxy socket, full playbook library, cases, dashboard.

---

Owner: **Mohamed Osama** · Sentinel Autonomous SOAR · Oct 2026
