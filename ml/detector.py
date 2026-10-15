
import json
import os
import re
import time
from pathlib import Path

import joblib
import pandas as pd

from rate_layer import RateLayer

ROOT = Path(__file__).resolve().parent.parent
BUNDLE = Path(os.getenv("MODEL_PATH", ROOT / "models" / "ids_model.joblib"))
FLOWS = Path(os.getenv("FLOWS_CSV", ROOT / "flows.csv"))
ALERTS = Path(os.getenv("ALERTS_FILE", ROOT / "alerts.jsonl"))
MIN_CONF = float(os.getenv("MIN_CONF", "0.6"))

bundle = joblib.load(BUNDLE)
model = bundle["model"]
features = bundle["features"]
classes = bundle["classes"]

print(
    f"Loaded {bundle['model_type']} model, "
    f"{len(features)} features, classes={classes}",
    flush=True,
)

norm = lambda s: re.sub(r"[^a-z0-9]", "", str(s).lower())
want = {norm(f): f for f in features}

# Handle the CWR/CWE flag-count naming difference.
if "cweflagcount" in want:
    want["cwrflagcount"] = want["cweflagcount"]

_warned = False


def to_X(df):
    global _warned

    df = df.rename(
        columns={
            c: want[norm(c)]
            for c in df.columns
            if norm(c) in want
        }
    )

    missing = [f for f in features if f not in df.columns]

    if missing and not _warned:
        print(
            f"[WARN] {len(missing)} missing features (filled 0): "
            f"{missing[:5]}",
            flush=True,
        )
        _warned = True

    X = df.reindex(columns=features).apply(
        pd.to_numeric, errors="coerce"
    )

    return (
        X.replace([float("inf"), float("-inf")], float("nan"))
        .fillna(0)
        .astype("float32")
    )


def alert(row, label, conf):
    ip = next(
        (
            str(row[c])
            for c in row.index
            if norm(c) == "srcip"
        ),
        "?",
    )

    # Store the exact model input features used for this flow.
    model_input = to_X(pd.DataFrame([row]))
    feature_values = {
        str(k): float(v)
        for k, v in model_input.iloc[0].items()
    }

    rec = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "reason": str(label),
        "confidence": round(float(conf), 3),
        "features": feature_values,
        "engine": "ml",
    }

    print("[ALERT]", rec, flush=True)

    with ALERTS.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


rate = RateLayer(
    window=int(os.getenv("RATE_WINDOW", "10")),
    max_packets=int(os.getenv("RATE_MAX", "100")),
    cooldown=int(os.getenv("RATE_COOLDOWN", "1")),
)


def alert_rate(a):
    rec = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": str(a["src_ip"]),
        "reason": a["type"],
        "confidence": 1.0,
        "features": {
            "packets_in_window": int(a["packets_in_window"]),
            "window_s": int(a["window_s"]),
            "dst_port": int(a["dst_port"]),
        },
        "engine": "rate",
    }

    print("[ALERT]", rec, flush=True)

    with ALERTS.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def main():
    print(f"Watching {FLOWS} ... (Ctrl+C to stop)", flush=True)
    done = 0

    while True:
        if FLOWS.exists():
            try:
                df = pd.read_csv(FLOWS)
            except Exception:
                time.sleep(1)
                continue

            if len(df) < done:
                done = 0

            if "src_ip" not in df.columns:
                time.sleep(1)
                continue

            new = df.iloc[done:]
            done = len(df)

            if len(new):
                X = to_X(new)
                proba = model.predict_proba(X)
                cls = list(model.classes_)

                for i, p in enumerate(proba):
                    k = p.argmax()
                    label = classes[cls[k]]

                    if label != "Benign" and p[k] >= MIN_CONF:
                        alert(new.iloc[i], label, p[k])

                # Rate layer evaluates traffic volume over time.
                for r in new.itertuples():
                    a = rate.check(
                        r.src_ip,
                        r.dst_port,
                        r.timestamp,
                        int(r.tot_fwd_pkts),
                    )

                    if a:
                        alert_rate(a)

        time.sleep(2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")