from pathlib import Path
import pandas as pd
import numpy as np

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)
from xgboost import XGBClassifier

DATA_DIR = Path("data/processed")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_PER_FILE = 30_000
RANDOM_STATE = 42
BACKWARD_COLUMN = "Total Backward Packets"
WEIGHT_MULTIPLIER = 5.0

def prepare(df):
    df = df.copy()
    df.columns = df.columns.str.strip()
    y = df["Label"].astype("string").str.strip().ne("BENIGN").astype("int8")
    X = df.drop(columns=["Label", "source_file"], errors="ignore")
    X = X.replace([np.inf, -np.inf], np.nan)
    return X, y

def build_model():
    return XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        n_jobs=-1,
        random_state=RANDOM_STATE
    )

def evaluate(model, X, y, zero_mask, fold, model_name):
    probabilities = model.predict_proba(X)[:, 1]
    predictions = (probabilities >= 0.50).astype("int8")
    tn, fp, fn, tp = confusion_matrix(y, predictions, labels=[0, 1]).ravel()

    attack_mask = y.to_numpy() == 1
    benign_mask = ~attack_mask
    zero_attack = zero_mask.to_numpy() & attack_mask
    other_attack = ~zero_mask.to_numpy() & attack_mask

    return {
        "heldout_capture": fold,
        "model": model_name,
        "test_rows": len(y),
        "accuracy": accuracy_score(y, predictions),
        "attack_precision": precision_score(y, predictions, zero_division=0),
        "attack_recall": recall_score(y, predictions, zero_division=0),
        "attack_f1": f1_score(y, predictions, zero_division=0),
        "roc_auc": roc_auc_score(y, probabilities) if y.nunique() == 2 else np.nan,
        "false_positive_rate": fp / (fp + tn) if (fp + tn) else np.nan,
        "zero_backward_attack_count": int(zero_attack.sum()),
        "zero_backward_attack_recall": (
            float((predictions[zero_attack] == 1).mean()) if zero_attack.any() else np.nan
        ),
        "has_backward_attack_count": int(other_attack.sum()),
        "has_backward_attack_recall": (
            float((predictions[other_attack] == 1).mean()) if other_attack.any() else np.nan
        ),
        "benign_zero_backward_count": int((zero_mask.to_numpy() & benign_mask).sum()),
        "benign_false_positive_count": int(
            ((predictions == 1) & benign_mask & zero_mask.to_numpy()).sum()
        ),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)
    }

print("STEP 1: Loading and sampling all eight captures...")
captures = {}
for file in sorted(DATA_DIR.glob("*.parquet")):
    df = pd.read_parquet(file)
    if len(df) > SAMPLE_PER_FILE:
        df = df.sample(n=SAMPLE_PER_FILE, random_state=RANDOM_STATE)
    captures[file.name] = df
    print(f"{file.name}: {len(df):,} rows")

print("\nSTEP 2: Running leave-one-capture-out validation...")
results = []

for heldout_name in sorted(captures):
    print(f"\n=== HELD OUT: {heldout_name} ===")
    test_df = captures[heldout_name].copy()
    train_df = pd.concat(
        [df for name, df in captures.items() if name != heldout_name],
        ignore_index=True
    )

    X_train, y_train = prepare(train_df)
    X_test, y_test = prepare(test_df)

    if list(X_train.columns) != list(X_test.columns):
        raise ValueError(f"Feature mismatch for {heldout_name}")

    train_hash = pd.util.hash_pandas_object(X_train, index=False)
    test_hash = pd.util.hash_pandas_object(X_test, index=False)

    combined = pd.DataFrame({
        "hash": pd.concat([train_hash.reset_index(drop=True), test_hash.reset_index(drop=True)], ignore_index=True),
        "label": pd.concat([y_train.reset_index(drop=True), y_test.reset_index(drop=True)], ignore_index=True)
    })
    conflicts = combined.groupby("hash")["label"].nunique()
    conflict_hashes = set(conflicts[conflicts > 1].index)

    train_keep = ~train_hash.isin(conflict_hashes)
    test_keep = ~test_hash.isin(conflict_hashes)

    X_train = X_train.loc[train_keep].copy()
    y_train = y_train.loc[train_keep].copy()
    train_hash = train_hash.loc[train_keep]

    X_test = X_test.loc[test_keep].copy()
    y_test = y_test.loc[test_keep].copy()
    test_hash = test_hash.loc[test_keep]

    overlap = test_hash.isin(set(train_hash))
    X_test = X_test.loc[~overlap].copy()
    y_test = y_test.loc[~overlap].copy()

    unique_train = ~train_hash.duplicated()
    X_train = X_train.loc[unique_train].copy()
    y_train = y_train.loc[unique_train].copy()

    if X_train.empty or X_test.empty or y_train.nunique() < 2:
        print("Skipping fold: insufficient training or test data.")
        continue

    print(f"Clean train={len(X_train):,}, test={len(X_test):,}, test attacks={int(y_test.sum()):,}")

    zero_train = (
        pd.to_numeric(X_train[BACKWARD_COLUMN], errors="coerce")
        .fillna(0).eq(0)
    )
    zero_attack_train = zero_train & y_train.eq(1)
    weights = np.ones(len(X_train), dtype=float)
    weights[zero_attack_train.to_numpy()] = WEIGHT_MULTIPLIER

    zero_test = (
        pd.to_numeric(X_test[BACKWARD_COLUMN], errors="coerce")
        .fillna(0).eq(0)
    )

    baseline = build_model()
    baseline.fit(X_train, y_train)
    results.append(evaluate(baseline, X_test, y_test, zero_test, heldout_name, "Baseline"))

    weighted = build_model()
    weighted.fit(X_train, y_train, sample_weight=weights)
    results.append(evaluate(weighted, X_test, y_test, zero_test, heldout_name, "Zero-backward attack weight x5"))

    print(f"Training zero-backward attacks: {int(zero_attack_train.sum()):,}")

results_df = pd.DataFrame(results)
out_path = REPORT_DIR / "leave_one_capture_out_weighting_results.csv"
results_df.to_csv(out_path, index=False)

print("\nSTEP 3: Results by held-out capture...")
if not results_df.empty:
    display_cols = [
        "heldout_capture", "model", "test_rows", "attack_recall",
        "zero_backward_attack_recall", "false_positive_rate",
        "attack_precision", "attack_f1", "roc_auc"
    ]
    print(results_df[display_cols].to_string(index=False))

    print("\nSTEP 4: Mean metrics across folds (descriptive; folds have different class mixes)...")
    numeric = [
        "accuracy", "attack_precision", "attack_recall", "attack_f1",
        "roc_auc", "false_positive_rate", "zero_backward_attack_recall",
        "has_backward_attack_recall"
    ]
    print(results_df.groupby("model")[numeric].mean(numeric_only=True).to_string())

print("\nSaved results:", out_path.resolve())
print("IMPORTANT: Monday is benign-only, so attack recall and ROC-AUC are undefined for that held-out fold. Interpret each capture separately; do not rely only on unweighted fold averages.")
print("LEAVE-ONE-CAPTURE-OUT VALIDATION COMPLETE.")
