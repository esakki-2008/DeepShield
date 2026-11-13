from pathlib import Path
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

DATA_DIR = Path("data/processed")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_PER_FILE = 30_000
RANDOM_STATE = 42
THRESHOLD = 0.50

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

def prepare(df):
    df = df.copy()
    df.columns = df.columns.str.strip()
    labels = df["Label"].astype("string").str.strip()
    y = labels.ne("BENIGN").astype("int8")
    X = df.drop(columns=["Label", "source_file"], errors="ignore")
    X = X.replace([np.inf, -np.inf], np.nan)
    return X, y, labels

print("STEP 1: Loading the same 30,000-row sample from each capture...")
captures = {}
for file in sorted(DATA_DIR.glob("*.parquet")):
    df = pd.read_parquet(file)
    if len(df) > SAMPLE_PER_FILE:
        df = df.sample(n=SAMPLE_PER_FILE, random_state=RANDOM_STATE)
    captures[file.name] = df
    print(f"{file.name}: {len(df):,} rows")

rows = []
print("\nSTEP 2: Training baseline models and measuring each held-out attack label...")

for heldout_name in sorted(captures):
    print(f"\nHELD OUT: {heldout_name}")
    test_df = captures[heldout_name].copy()
    train_df = pd.concat(
        [df for name, df in captures.items() if name != heldout_name],
        ignore_index=True
    )

    X_train, y_train, _ = prepare(train_df)
    X_test, y_test, original_labels = prepare(test_df)

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
    original_labels = original_labels.loc[test_keep].copy()
    test_hash = test_hash.loc[test_keep]

    overlap = test_hash.isin(set(train_hash))
    X_test = X_test.loc[~overlap].copy()
    y_test = y_test.loc[~overlap].copy()
    original_labels = original_labels.loc[~overlap].copy()

    unique_train = ~train_hash.duplicated()
    X_train = X_train.loc[unique_train].copy()
    y_train = y_train.loc[unique_train].copy()

    if X_train.empty or X_test.empty or y_train.nunique() < 2:
        print("Skipping fold: insufficient data.")
        continue

    model = build_model()
    model.fit(X_train, y_train)
    probabilities = model.predict_proba(X_test)[:, 1]
    predictions = (probabilities >= THRESHOLD).astype("int8")

    print(f"Clean train={len(X_train):,}; clean test={len(X_test):,}; attack rows={int(y_test.sum()):,}")

    for label in sorted(original_labels.unique()):
        if label == "BENIGN":
            continue
        mask = original_labels.eq(label).to_numpy()
        support = int(mask.sum())
        detected = int(predictions[mask].sum())
        rows.append({
            "heldout_capture": heldout_name,
            "attack_label": str(label),
            "support": support,
            "detected_as_attack": detected,
            "missed": support - detected,
            "attack_detection_recall": detected / support if support else np.nan,
            "mean_attack_probability": float(probabilities[mask].mean()) if support else np.nan,
            "median_attack_probability": float(np.median(probabilities[mask])) if support else np.nan
        })

    benign_mask = original_labels.eq("BENIGN").to_numpy()
    benign_count = int(benign_mask.sum())
    benign_fp = int(predictions[benign_mask].sum())
    rows.append({
        "heldout_capture": heldout_name,
        "attack_label": "BENIGN (false-positive check)",
        "support": benign_count,
        "detected_as_attack": benign_fp,
        "missed": benign_count - benign_fp,
        "attack_detection_recall": benign_fp / benign_count if benign_count else np.nan,
        "mean_attack_probability": float(probabilities[benign_mask].mean()) if benign_count else np.nan,
        "median_attack_probability": float(np.median(probabilities[benign_mask])) if benign_count else np.nan
    })

results = pd.DataFrame(rows)
out_path = REPORT_DIR / "heldout_attack_family_detection.csv"
results.to_csv(out_path, index=False)

print("\nSTEP 3: Per-label results (sorted by capture and label)...")
if not results.empty:
    print(results.to_string(index=False))

print("\nSaved:", out_path.resolve())
print("Interpretation: This is binary attack detection recall by original attack label, not multiclass family classification accuracy.")
print("Rare labels have small support in the 30,000-row-per-capture sample; interpret their rates cautiously.")
print("PER-ATTACK-LABEL GENERALIZATION ANALYSIS COMPLETE.")
