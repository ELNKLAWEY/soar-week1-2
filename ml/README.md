# ML + detection scripts (team copy)

**Owners:** Habiba (ML train / model / prediction API) and Alaa (sniffer / rules / rate layer).  
**Mohamed (SOAR Core):** keep a local copy so playbooks match real attack families and features. You are **not** the production ML owner.

## What’s in this folder

| Script | Role |
|---|---|
| `train.py` | Train RF/HGB on CIC flow CSVs → `models/ids_model.joblib` |
| `detector.py` | Load model + score flow CSV rows → alerts |
| `sniffer.py` | cicflowmeter live capture → `flows.csv` |
| `rate_layer.py` | Volumetric flood heuristics (DoS/DDoS) |
| `http_rules.py` | Login brute-force / scan / SQLi HTTP rules |

## Folder layout (repo root)

```
data/
  raw/                 # ← train.py default --raw (put *.csv here)
  cicids2017/          # optional download staging
  cicids2018/          # optional download staging (scripts target 2018-style day files)
models/                # ← train.py default --out; detector loads ids_model.joblib
ml/                    # these scripts
```

`train.py` and `detector.py` resolve the project root as `ml/..`, so defaults are:

- `--raw` → `data/raw/`
- `--out` / model → `models/ids_model.joblib`

## What Mohamed needs from a local train (vs what he does NOT own)

**Needs (for playbooks):**

- Attack **family labels** from `to_family()`: `Benign`, `DDoS`, `DoS`, `Web`, `BruteForce`, `Infiltration`, `Bot`, …
- Feature column list saved in the joblib bundle (`bundle["features"]`)
- Class list (`bundle["classes"]`) so `when:` / incident_type mapping is realistic
- Optional held-out sample (`--export-test N`) for dry-run demos

**Does NOT own:**

- Production prediction API (Habiba H12)
- Keeping the “official” team model in sync (Habiba sends updates)
- Live sniffing / cicflowmeter ops (Alaa)

## Install (separate from executor Week 1–2)

```bash
cd "/Users/macbook/.cursor/graduation project"
source .venv/bin/activate   # or a dedicated venv
pip install -r ml/requirements.txt
```

Do **not** add these heavy deps to the root `requirements.txt` used by `executor/`.

## Dataset download (start early — multi‑GB)

1. CIC-IDS-2017: https://www.unb.ca/cic/datasets/ids-2017.html  
2. Team WhatsApp also said to get the **2018** set (CSE-CIC-IDS2018). `train.py` day-split defaults use 2018-style filenames (`16-02-2018`, …).

Place machine-readable **CSV** flow files under `data/raw/` (or pass `--raw` to another folder):

```bash
# after download + extract, copy/symlink CSVs into the training input dir
mkdir -p data/raw data/cicids2017 data/cicids2018 models
# e.g. cp /path/to/extracted/*.csv data/raw/
```

Do not commit the CSVs or `*.joblib` artifacts.

## Train once locally

```bash
cd "/Users/macbook/.cursor/graduation project"
source .venv/bin/activate
pip install -r ml/requirements.txt

# CSVs must already be in data/raw/
python ml/train.py --raw data/raw --out models --model rf

# optional: export a small Excel/CSV sample for playbook demos
python ml/train.py --raw data/raw --out models --model rf --export-test 500
```

Outputs: `models/ids_model.joblib`, `models/report.txt`, `models/data_audit.csv`.

## How this feeds SOAR playbooks

After training, skim `models/report.txt` and the bundle classes/features. Map families → playbook triggers (e.g. `BruteForce` → `web_bruteforce_response`). Mohamed still consumes Habiba’s **Decision** contract at runtime; local train is for understanding and demo data, not replacing her API.
