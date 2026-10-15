# Mohamed Osama — Week 1–2 Plan

**Ownership:** SOAR Core (playbooks, executor, response, cases)  
**Milestone M1 (team):** events flow + contracts agreed + mock services running  
**Your focus:** Action contract + Policy Guard (M4 start) + Playbook engine (M1 start) + mocks

**Status: COMPLETE (2026-10-16)** — see `docs/Mohamed_Week1_2_DONE.md` for evidence, open questions, and Week 3 deferrals.

---

## ML / dataset — official Task Plan vs team practice

### Official Task Plan (ownership)

| Item | Owner | What this means for you |
|---|---|---|
| ML Random Forest (train, bundle, features) | **Habiba** | Already trained once on her machine; she owns the “official” model |
| ML prediction API | Habiba (H12) | You **consume** Decisions later — you do **not** own the production API |
| Live sniffing / rules / rate layer | **Alaa** (+ Omar/Rawda for traffic) | Detection pipeline is not your deliverable |
| Your Week 1–2 “data” for SOAR | **You** | Mock ActionRequests + YAML playbooks + Policy Guard |

You build the **hands** (execute safely). Habiba builds the **brain** (decide). Alaa builds the **eyes** (detect).

### Team practice (WhatsApp) — still download + train **locally**

Habiba already trained on her laptop, but she told you to:

1. **Start the CIC dataset download ASAP** (it is large / slow).
2. **Run `train.py` on your machine** so playbooks line up with real attack families and features — even if she keeps sending model file updates.

| Goal of *your* local train | Not your job |
|---|---|
| Know **class / family labels** (`BruteForce`, `DoS`, `Web`, …) | Production ML API |
| Know **feature names** the model expects | Replacing Habiba’s official weights |
| Seed **demo incidents** that match playbook `when:` / triggers | Owning detection or cicflowmeter ops |

Scripts live under `ml/` (copy from Habiba/Alaa). Full commands: `ml/README.md`.

### Week 1–2 ML checklist (parallel to SOAR work — start download Day 1)

- [x] **Start download early** — CIC data staged under `data/raw/` (local; not committed)
- [x] Stage training **CSV** files in `data/raw/` (that is `train.py`’s default `--raw`).
- [x] `pip install -r ml/requirements.txt` (separate from root executor deps).
- [x] Run once: `python ml/train.py --raw data/raw --out models --model rf` → `models/ids_model.joblib` + report
- [x] From `models/report.txt` + joblib bundle, note **classes** and **features** for playbook mapping.
- [ ] Optional: `--export-test 500` for small demo tables — do **not** commit multi‑GB data or `*.joblib`.

```bash
cd "/Users/macbook/.cursor/graduation project"
source .venv/bin/activate
pip install -r ml/requirements.txt
# after CSVs are in data/raw/
python ml/train.py --raw data/raw --out models --model rf
```

---

## How you will learn it (practical path)

Learn by building in this order — do not binge courses first:

### Day 1–2 — Concepts (2–3 hours total)
1. What a SOAR does: detect → decide → **act** → verify → case.
2. Read your sections only in `Sentinel_SOAR_Project_Details.pdf`:
   - §8 Playbooks
   - §10 Response / Policy Guard / HAProxy
   - §11 Case Management (skim for later)
3. Skim your Task Plan section 4 (M1–M10).

### Day 2–4 — Skills you actually need
| Skill | Why you need it | Enough for Week 1–2 |
|---|---|---|
| Python + Pydantic | Schemas for ActionRequest / ActionResult | Yes — core |
| FastAPI | Executor HTTP health + later APIs | Skeleton only |
| Redis Streams (XADD / XREADGROUP / XACK) | Consume `actions` stream | Mock first, real Redis in Week 2 |
| YAML | Playbook definitions | Yes |
| HAProxy Runtime API (`add acl` / `del acl`) | Real blocking later | **Study only** in Week 1; mock connector |
| Docker Compose | Run Redis locally | One service |

**Not required Week 1–2:** LLM training, cicflowmeter, VirusTotal, React dashboard, Mongo deep modeling.

### Learning rule
Mock first (per team agreement). Until Alaa’s streams and Habiba’s decisions exist, your code talks to **fake producers** that send ActionRequests shaped like the real contract.

---

## Week 1 tasks (checklist)

### W1.1 — Repo folder you own
- [x] Create / own `executor/` (and contribute Action schemas to `common/`)
- [x] `executor/README.md` with: what it does, how to run, how to test
- [x] `Dockerfile` stub (can be minimal)

### W1.2 — Shared contract you produce (everyone depends on this)
Agree with Habiba + Mostafa + Alaa on:

- [x] `ActionRequest` fields: id, correlation_id, incident_id, decision_id, actor, tool, args, gate, dry_run, idempotency_key, proposed_at
- [x] Allowed tools: `block_ip`, `rate_limit_ip`, `tarpit_ip`, `lock_account`, `revoke_sessions`, `add_waf_rule`, `notify`, `update_case`, `verify_block`, `unblock_ip`
- [x] `ActionResult` fields: action_id, status (`success|rejected|failed|dry_run`), result, verification, rollback, expires_at, error, finished_at
- [x] Policy rejection codes: `allowlisted`, `ttl_too_long`, `blast_radius`, `rate_limit`, `scope`, `kill_switch`, `unknown_tool`, `invalid_args`
- [x] Put schemas in `common/schemas/actions.py` and document for contract approval (`docs/contracts/action_contract.md`)
- [ ] **Team approval** — Habiba + Alaa + Mostafa sign-off (integration session; not a code blocker)

### W1.3 — Policy Guard v0 (start of M4)
- [x] Allowlist never blocked (admin IPs, health checks, DNS, LB, pentest runner when authorised)
- [x] Max TTL per gate G0–G3 (use table from Project Details §9.6)
- [x] Max active blocks + max blocks/minute (circuit breaker stubs OK)
- [x] Scope check stub (asset inventory mock: only Skyline IPs)
- [x] Unit tests: allowlisted IP rejected; TTL too long rejected; valid block accepted

### W1.4 — Playbook engine v0 (start of M1)
- [x] Load one YAML playbook
- [x] Run steps sequentially in **dry-run**
- [x] Conditions (`when:`) and simple variable substitution
- [x] Store run history in memory (list of step results)
- [x] Sample playbook: `web_bruteforce_response` (from Project Details §8.1)
- [x] Second sample: `dos_flood_response` (optional, done)

### W1.5 — Team integration (Week 1 milestone)
- [x] Publish Action contract doc for Habiba + Alaa + Mostafa approval
- [x] Demo ready: dry-run playbook + Policy Guard rejecting allowlisted IP (`python -m executor.demo`)
- [ ] Consume Alaa’s Event schema once published (read-only awareness; do not redefine it) — **Week 3**

---

## Week 2 tasks (checklist)

### W2.1 — Executor worker v0 (start of M2)
- [x] In-memory action queue consumer (Redis Streams deferred to Week 3)
- [x] Idempotency: same `idempotency_key` executed once
- [x] Call Policy Guard before every write tool
- [x] Write `ActionResult` + audit record (JSONL stub under `logs/actions.jsonl`)

### W2.2 — Mock connectors
- [x] `MockHAProxyConnector`: in-memory blocklist with TTL + verify
- [x] `MockWebsiteConnector`: lock_account / revoke_sessions flags in memory
- [x] Real HAProxy socket: document how it will work; do **not** block Week 2 on Docker Desktop quirks

### W2.3 — Kill switch stub (start of M5)
- [x] Global flag `Paused` / `Shadow` / `Autonomous`
- [x] Paused → no write actions; Shadow → record what would run; Autonomous → execute (mock)

### W2.4 — Tests + demo script
- [x] `pytest` for Policy Guard + playbook dry-run + idempotency + shadow + queue/audit
- [x] One script: inject ActionRequest → rejected or “blocked” in mock → print result
- [x] Update README with demo commands

### W2.5 — Prepare for Week 3
- [x] List open questions for Alaa (stream names, consumer group for executor) — see DONE.md
- [x] List open questions for Habiba (exact Decision → Action mapping) — see DONE.md
- [x] Do **not** start Case Management UI yet (M8 is later)

---

## Definition of done (end of Week 2)

You are done with Weeks 1–2 when:

1. ~~ActionRequest / ActionResult schemas are merged and approved.~~ **Schemas + contract doc ready; human sign-off pending integration.**
2. ~~Policy Guard rejects allowlisted / over-TTL / unknown tools with tests green.~~
3. ~~At least one YAML playbook runs end-to-end in dry-run and prints step history.~~
4. ~~Executor can process a mock action once (idempotent) through Guard → MockHAProxy.~~
5. ~~Kill switch / Shadow mode prevents real (mock) writes when Paused.~~
6. ~~README + short demo ready for the integration session.~~

**Week 1–2 COMPLETE for Mohamed (code DoD).** Remaining: teammate contract sign-off; Week 3 real Redis/HAProxy/cases.

---

## What you will NOT do in Week 1–2

- Own production ML / replace Habiba’s prediction API (local train is for learning + playbook alignment only)
- Build React pages (Mostafa’s framework first)
- Full HAProxy production connector (study + mock is enough)
- Full case management API (starts after streams/incidents stabilize)
- The ten live playbooks library (M7) — only 1–2 dry-run samples now

---

## Daily rhythm (suggested)

| Day | Focus |
|---|---|
| Mon W1 | Read §§8+10; create folders; draft Action schemas |
| Tue W1 | Contract PR; Policy Guard allowlist + TTL |
| Wed W1 | Policy Guard tests; start YAML loader |
| Thu W1 | Playbook dry-run for brute_force sample |
| Fri W1 | Integration demo; fix contract feedback |
| Mon W2 | Redis/mock consumer; idempotency |
| Tue W2 | MockHAProxy + verify |
| Wed W2 | Modes: Paused / Shadow / Autonomous |
| Thu W2 | pytest suite + demo script |
| Fri W2 | Integration session; Week 3 backlog |

---

## Help from Cursor (this repo)

Starter code lives under:

- `common/schemas/actions.py` — your contract
- `executor/` — Policy Guard, playbook engine, mock connectors, worker
- `ml/` — Habiba/Alaa train + detection scripts (local copy; see `ml/README.md`)

Run (SOAR Week 1–2):

```bash
cd "/Users/macbook/.cursor/graduation project"
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest executor/tests -q
python -m executor.demo
```

ML local train (after dataset CSVs are in `data/raw/`):

```bash
pip install -r ml/requirements.txt
python ml/train.py --raw data/raw --out models --model rf
```
