from __future__ import annotations

import argparse
import warnings
import zlib
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import balanced_accuracy_score, classification_report, f1_score

warnings.filterwarnings("ignore")

SEED = 420
CHUNK = 500_000
CLASS_WEIGHT_CAP = 5.0

DROP_COLS = [
    "Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "Timestamp",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Flow Byts/s", "Flow Pkts/s",
]

DEFAULT_TEST_DAYS = ["16-02-2018", "21-02-2018", "23-02-2018", "01-03-2018"]


def to_family(label: str) -> str:
    s = label.lower()
    if s == "benign":
        return "Benign"
    if "ddos" in s:
        return "DDoS"
    if "dos" in s:
        return "DoS"
    if "web" in s or "xss" in s or "sql" in s:
        return "Web"
    if "ftp" in s or "ssh" in s or "brute" in s:
        return "BruteForce"
    if "infil" in s:
        return "Infiltration"
    if "bot" in s:
        return "Bot"
    return label


def csv_header(path: Path) -> list[str]:
    return [str(c).strip() for c in pd.read_csv(path, nrows=0).columns]


def common_features(files: list[Path]) -> list[str]:
    cols: list[str] | None = None
    for f in files:
        h = [c for c in csv_header(f) if c not in DROP_COLS and c != "Label"]
        cols = h if cols is None else [c for c in cols if c in set(h)]
    return cols or []


def count_labels(path: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    reader = pd.read_csv(
        path, usecols=lambda c: str(c).strip() == "Label",
        chunksize=CHUNK, low_memory=False,
    )
    for chunk in reader:
        lab = chunk.iloc[:, 0].astype(str).str.strip()
        for k, v in lab[lab != "Label"].value_counts().items():
            counts[k] = counts.get(k, 0) + int(v)
    return counts


def load_file(path: Path, features: list[str], keep_prob: dict[str, float],
              rng: np.random.Generator, block_rows: int) -> tuple[pd.DataFrame, dict[str, int]]:
    parts: list[pd.DataFrame] = []
    stats = {"read": 0, "invalid": 0, "sampled_out": 0, "kept": 0}
    pos = 0

    for chunk in pd.read_csv(path, chunksize=CHUNK, low_memory=False):
        chunk.columns = chunk.columns.astype(str).str.strip()
        chunk = chunk[chunk["Label"].astype(str).str.strip() != "Label"]
        stats["read"] += len(chunk)
        positions = np.arange(pos, pos + len(chunk))
        pos += len(chunk)

        labels = chunk["Label"].astype(str).str.strip()
        X = chunk.reindex(columns=features).apply(pd.to_numeric, errors="coerce")
        X = X.replace([np.inf, -np.inf], np.nan)
        valid = X.notna().all(axis=1).to_numpy()
        stats["invalid"] += int((~valid).sum())

        p = labels.map(keep_prob).fillna(1.0).to_numpy()
        pick = valid & (rng.random(len(X)) < p)
        stats["sampled_out"] += int((valid & ~pick).sum())
        stats["kept"] += int(pick.sum())

        if pick.any():
            part = X[pick].astype(np.float32)
            part["raw_label"] = labels[pick].to_numpy()
            part["weight"] = (1.0 / p[pick]).astype(np.float32)
            part["block"] = (positions[pick] // block_rows).astype(np.int32)
            parts.append(part)

    df = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()
    df["source"] = path.name
    return df, stats


def build_model(kind: str, n_jobs: int):
    if kind == "hgb":
        return HistGradientBoostingClassifier(
            max_iter=200, learning_rate=0.1, max_depth=10, random_state=SEED,
        )
    return RandomForestClassifier(
        n_estimators=100, max_depth=14, min_samples_leaf=20,
        max_features="sqrt", max_samples=0.5,
        n_jobs=n_jobs, random_state=SEED,
    )


def class_sample_weights(y: np.ndarray, n_classes: int) -> np.ndarray:
    counts = np.bincount(y, minlength=n_classes)
    w = np.sqrt(len(y) / (n_classes * np.maximum(counts, 1)))
    w = np.clip(w, 0.2, CLASS_WEIGHT_CAP)
    return w[y].astype(np.float32)


def shared_rows(train_X: pd.DataFrame, test_X: pd.DataFrame) -> float:
    h_train = pd.util.hash_pandas_object(train_X, index=False).to_numpy()
    h_test = pd.util.hash_pandas_object(test_X, index=False).to_numpy()
    return float(np.isin(h_test, h_train).mean())


def evaluate(model, X, y, w, classes, title, out):
    pred = model.predict(X)
    present = sorted(set(y) | set(pred))
    names = [classes[i] for i in present]

    benign = classes.index("Benign")
    atk_true, atk_pred = y != benign, pred != benign
    detection = w[atk_true & atk_pred].sum() / max(w[atk_true].sum(), 1e-9)
    false_alarm = w[~atk_true & atk_pred].sum() / max(w[~atk_true].sum(), 1e-9)

    out(f"\n{'=' * 78}\n{title}\n{'=' * 78}")
    out(f"Balanced accuracy : {balanced_accuracy_score(y, pred):.4f}")
    out(f"Macro F1          : {f1_score(y, pred, average='macro', zero_division=0):.4f}")
    out(f"Detection rate (any attack caught)       : {detection:.4f}")
    out(f"False-alarm rate (benign flagged, weighted): {false_alarm:.5f}")
    out("\nPer-class report (counts/precision re-weighted to real traffic):")
    out(classification_report(y, pred, labels=present, target_names=names,
                              sample_weight=w, digits=4, zero_division=0))
    return pred


def top_features(model, X: pd.DataFrame, y, n_jobs: int, k: int = 15) -> pd.Series:
    if hasattr(model, "feature_importances_"):
        imp = pd.Series(model.feature_importances_, index=X.columns)
    else:
        idx = np.random.default_rng(SEED).choice(len(X), min(20_000, len(X)), replace=False)
        r = permutation_importance(model, X.iloc[idx], y[idx], n_repeats=3,
                                   scoring="balanced_accuracy", n_jobs=n_jobs,
                                   random_state=SEED)
        imp = pd.Series(r.importances_mean, index=X.columns)
    imp = imp.clip(lower=0)
    return (imp / max(imp.sum(), 1e-12)).sort_values(ascending=False).head(k)


def export_test_sample(model, data, is_test, features, classes, n, out_dir, out):
    """Write an Excel file with N rows taken ONLY from the held-out test blocks,
    with the model's prediction next to the true label for every row."""
    test = data[is_test]
    rng = np.random.default_rng(SEED)
    avail = test["family"].value_counts()

    # 50% Benign, the rest split evenly across the attack families
    # (a rare family such as Web simply gives whatever it has).
    take = {"Benign": int(min(avail.get("Benign", 0), n // 2))}
    attacks = sorted((c for c in classes if c != "Benign"), key=lambda c: avail.get(c, 0))
    budget = n - take["Benign"]
    for i, c in enumerate(attacks):
        k = int(min(avail.get(c, 0), budget // (len(attacks) - i)))
        take[c] = k
        budget -= k

    picked = []
    for c, k in take.items():
        if k > 0:
            idx = test.index[test["family"] == c].to_numpy()
            picked.append(rng.choice(idx, k, replace=False))
    sample = test.loc[np.concatenate(picked)].sample(frac=1, random_state=SEED)

    X = sample[features]
    proba = model.predict_proba(X)
    cls_idx = list(model.classes_)
    pred = np.asarray(cls_idx)[proba.argmax(axis=1)]
    p_attack = 1.0 - proba[:, cls_idx.index(classes.index("Benign"))]

    res = pd.DataFrame({
        "source": sample["source"].to_numpy(),
        "raw_label": sample["raw_label"].to_numpy(),
        "true_label": sample["family"].to_numpy(),
        "predicted": [classes[i] for i in pred],
        "confidence": proba.max(axis=1).round(4),
        "p_attack": p_attack.round(4),
    })
    res["correct"] = res["true_label"] == res["predicted"]
    res = pd.concat([res, X.reset_index(drop=True)], axis=1)

    per_class = res.groupby("true_label")["correct"].agg(rows="size", correct="sum").reset_index()
    per_class["recall"] = (per_class["correct"] / per_class["rows"]).round(4)

    atk = res[res["true_label"] != "Benign"]
    per_pattern = (atk.groupby(["true_label", "raw_label"])["correct"]
                   .agg(rows="size", correct="sum").reset_index())
    per_pattern["recall"] = (per_pattern["correct"] / per_pattern["rows"]).round(4)

    is_atk = (res["true_label"] != "Benign").to_numpy()
    th_rows = []
    for t in (0.5, 0.7, 0.9, 0.95):
        flagged = (res["p_attack"] >= t).to_numpy()
        th_rows.append({
            "p_attack_threshold": t,
            "attacks_flagged": round(float(flagged[is_atk].mean()), 4),
            "benign_flagged (false alarm)": round(float(flagged[~is_atk].mean()), 4),
        })
    thresholds = pd.DataFrame(th_rows)
    confusion = pd.crosstab(res["true_label"], res["predicted"])

    path = out_dir / "test_sample.xlsx"
    try:
        with pd.ExcelWriter(path, engine="openpyxl") as xw:
            res.to_excel(xw, sheet_name="sample", index=False)
            per_class.to_excel(xw, sheet_name="per_class", index=False)
            per_pattern.to_excel(xw, sheet_name="per_attack_pattern", index=False)
            thresholds.to_excel(xw, sheet_name="thresholds", index=False)
            confusion.to_excel(xw, sheet_name="confusion")
    except ImportError:
        path = out_dir / "test_sample.csv"
        res.to_csv(path, index=False)
        out("openpyxl not installed -> saved CSV instead (opens in Excel)")

    out(f"\nEXPORTED {len(res):,} held-out test rows to {path}")
    out(per_class.to_string(index=False))
    out("Threshold check (balanced sample):")
    out(thresholds.to_string(index=False))


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--raw", type=Path, default=root / "data" / "raw")
    ap.add_argument("--out", type=Path, default=root / "models")
    ap.add_argument("--model", choices=["rf", "hgb"], default="rf")
    ap.add_argument("--benign-per-file", type=int, default=100_000)
    ap.add_argument("--attack-per-label", type=int, default=60_000,
                    help="max rows kept per (file, attack label)")
    ap.add_argument("--split", choices=["blocks", "days"], default="blocks",
                    help="blocks: unseen time windows of every day (known attack tools)\n"
                         "days: whole unseen days (also unseen attack tools)")
    ap.add_argument("--block-rows", type=int, default=20_000)
    ap.add_argument("--test-pct", type=int, default=30)
    ap.add_argument("--drop-features", nargs="*", default=[])
    ap.add_argument("--test-days", nargs="+", default=DEFAULT_TEST_DAYS,
                    help="date substrings of the files held out when --split days")
    ap.add_argument("--refit-all", action="store_true",
                    help="after evaluation, refit the final model on train+test days")
    ap.add_argument("--export-test", type=int, default=0,
                    help="write an Excel sample of N held-out test rows with predictions (0 = off)")
    ap.add_argument("--n-jobs", type=int, default=-1)
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    report: list[str] = []

    def out(text: str = "") -> None:
        print(text, flush=True)
        report.append(text)

    files = sorted(args.raw.glob("*.csv"))
    if not files:
        raise SystemExit(f"No CSV files found in {args.raw}")
    rng = np.random.default_rng(SEED)

    features = common_features(files)
    dropped = [c for c in features if c in set(args.drop_features)]
    features = [c for c in features if c not in set(args.drop_features)]
    out(f"{len(files)} files, {len(features)} feature columns common to all files")
    out(f"Split mode: {args.split} | extra dropped features: {dropped}")
    counts = {}
    for f in files:
        counts[f.name] = count_labels(f)
        out(f"  counted {f.name}: {sum(counts[f.name].values()):,} rows")

    frames, audit = [], []
    for f in files:
        keep = {}
        for lab, n in counts[f.name].items():
            cap = args.benign_per_file if lab.lower() == "benign" else args.attack_per_label
            keep[lab] = min(1.0, cap / n)
        out(f"  loading {f.name} ...")
        df, st = load_file(f, features, keep, rng, args.block_rows)
        st["file"] = f.name
        audit.append(st)
        frames.append(df)

    audit_df = pd.DataFrame(audit).set_index("file")
    audit_df.loc["TOTAL"] = audit_df.sum()
    audit_df.to_csv(args.out / "data_audit.csv")
    out("\nDATA AUDIT (every row of every file was read; read = invalid + sampled_out + kept)")
    out(audit_df.to_string())

    data = pd.concat(frames, ignore_index=True)
    del frames
    data["family"] = data["raw_label"].map(to_family)
    n_before = len(data)
    data = data.drop_duplicates(subset=features + ["family"]).reset_index(drop=True)
    out(f"\nDuplicates removed after sampling: {n_before - len(data):,}")

    classes = ["Benign"] + sorted(c for c in data["family"].unique() if c != "Benign")
    y_all = data["family"].map({c: i for i, c in enumerate(classes)}).to_numpy()
    w_all = data["weight"].to_numpy()
    X_all = data[features]

    if args.split == "days":
        is_test = data["source"].map(lambda s: any(d in s for d in args.test_days)).to_numpy()
    else:
        key = data["source"] + ":" + data["block"].astype(str)
        bucket = key.map(lambda s: zlib.crc32(s.encode()) % 100).to_numpy()
        is_test = bucket < args.test_pct
    if not is_test.any() or is_test.all():
        raise SystemExit("the split left the train or the test set empty")

    X_tr, y_tr = X_all[~is_test], y_all[~is_test]
    X_te, y_te, w_te = X_all[is_test], y_all[is_test], w_all[is_test]

    out("\nClass counts after sampling")
    out(pd.DataFrame({
        "train": pd.Series(y_tr).map(lambda i: classes[i]).value_counts(),
        "test": pd.Series(y_te).map(lambda i: classes[i]).value_counts(),
    }).fillna(0).astype(int).to_string())
    if args.split == "days":
        out(f"Train days: {sorted(data.loc[~is_test, 'source'].unique())}")
        out(f"Test days : {sorted(data.loc[is_test, 'source'].unique())}")
    else:
        out(f"Blocks of {args.block_rows:,} consecutive flows: {args.test_pct}% held out for testing in every file")

    model = build_model(args.model, args.n_jobs)
    out(f"\nTraining {args.model.upper()} on {len(X_tr):,} rows ...")
    model.fit(X_tr, y_tr, sample_weight=class_sample_weights(y_tr, len(classes)))

    evaluate(model, X_tr, y_tr, np.ones(len(y_tr)), classes,
             "TRAIN (diagnostic only - expected to be higher than test)", out)
    test_title = ("TEST on UNSEEN TIME BLOCKS (same attack tools, different time windows)"
                  if args.split == "blocks" else
                  "TEST on UNSEEN DAYS (also unseen attack tools)")
    pred_te = evaluate(model, X_te, y_te, w_te, classes, test_title, out)

    bal_tr = balanced_accuracy_score(y_tr, model.predict(X_tr))
    bal_te = balanced_accuracy_score(y_te, pred_te)
    out("\nOVERFITTING CHECKS")
    out(f"Balanced-accuracy gap (train - test): {bal_tr - bal_te:.4f}"
        "   (>0.10 = overfitting, ~0 with 100% test = suspect leakage)")
    out(f"Test rows that also exist in train   : {shared_rows(X_tr, X_te):.2%}")
    imp = top_features(model, X_te, y_te, args.n_jobs)
    out("Top features:\n" + imp.round(4).to_string())
    if imp.iloc[0] > 0.40:
        out(f"WARNING: '{imp.index[0]}' carries {imp.iloc[0]:.0%} of the importance - check for leakage.")

    # Must run BEFORE the refit: here `model` has never seen the test rows.
    if args.export_test > 0:
        export_test_sample(model, data, is_test, features, classes,
                           args.export_test, args.out, out)

    if args.refit_all:
        out("\nRefitting final model on ALL days ...")
        model = build_model(args.model, args.n_jobs).fit(
            X_all, y_all, sample_weight=class_sample_weights(y_all, len(classes)))

    bundle = {
        "model": model,
        "features": features,
        "classes": classes,
        "model_type": args.model,
        "refit_on_all_days": args.refit_all,
        "split_mode": args.split,
    }
    path = args.out / "ids_model.joblib"
    joblib.dump(bundle, path, compress=3)
    out(f"\nSaved {path} ({path.stat().st_size / 1e6:.1f} MB)")
    (args.out / "report.txt").write_text("\n".join(report), encoding="utf-8")


if __name__ == "__main__":
    main()