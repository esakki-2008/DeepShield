from pathlib import Path
import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)
from xgboost import XGBClassifier

DATA_DIR = Path("data/processed")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

TEST_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.parquet"
SAMPLE_PER_FILE = 30_000
RANDOM_STATE = 42
THRESHOLD = 0.50
ZERO_BACKWARD_ATTACK_WEIGHT = 5.0
BACKWARD_COLUMN = "Total Backward Packets"

def load_features(df):
    df = df.copy()
    df.columns = df.columns.str.strip()
    y = (
        df["Label"].astype("string").str.strip().ne("BENIGN")
    ).astype("int8")
    X = df.drop(columns=["Label", "source_file"], errors="ignore")
    X = X.replace([np.inf, -np.inf], np.nan)

    if list(X.select_dtypes(exclude=np.number).columns):
        raise ValueError("Non-numeric feature columns found.")

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

print("STEP 1: Loading seven training captures...")
train_frames = []

for file in sorted(DATA_DIR.glob("*.parquet")):
    if file.name == TEST_FILE:
        print("Excluded held-out benchmark:", file.name)
        continue

    df = pd.read_parquet(file)
    if len(df) > SAMPLE_PER_FILE:
        df = df.sample(n=SAMPLE_PER_FILE, random_state=RANDOM_STATE)
    train_frames.append(df)
    print(f"{file.name}: {len(df):,} sampled rows")

train_data = pd.concat(train_frames, ignore_index=True)
X_train, y_train = load_features(train_data)

print("\nSTEP 2: Loading Friday DDoS benchmark...")
test_data = pd.read_parquet(DATA_DIR / TEST_FILE)
X_test, y_test = load_features(test_data)

if list(X_train.columns) != list(X_test.columns):
    raise ValueError("Training and benchmark feature columns do not match.")

print("Raw training rows:", len(X_train))
print("Raw benchmark rows:", len(X_test))

print("\nSTEP 3: Removing conflicting feature hashes and overlap...")
train_hash = pd.util.hash_pandas_object(X_train, index=False)
test_hash = pd.util.hash_pandas_object(X_test, index=False)

combined = pd.DataFrame({
    "hash": pd.concat([train_hash, test_hash], ignore_index=True),
    "label": pd.concat([y_train.reset_index(drop=True), y_test.reset_index(drop=True)], ignore_index=True)
})
conflicts = combined.groupby("hash")["label"].nunique()
conflicting_hashes = set(conflicts[conflicts > 1].index)

train_keep = ~train_hash.isin(conflicting_hashes)
test_keep = ~test_hash.isin(conflicting_hashes)

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

print("Conflicting feature groups removed:", len(conflicting_hashes))
print("Clean training rows:", len(X_train))
print("Clean benchmark rows:", len(X_test))

if X_test.empty or y_test.nunique() < 2:
    raise ValueError("Benchmark set is insufficient.")

print("\nSTEP 4: Building zero-backward attack sample weights...")
zero_backward = (
    pd.to_numeric(X_train[BACKWARD_COLUMN], errors="coerce")
    .fillna(0)
    .eq(0)
)
zero_backward_attack = zero_backward & y_train.eq(1)

sample_weights = np.ones(len(X_train), dtype=float)
sample_weights[zero_backward_attack.to_numpy()] = ZERO_BACKWARD_ATTACK_WEIGHT

print("Zero-backward attack rows receiving extra weight:", int(zero_backward_attack.sum()))
print("Weight multiplier:", ZERO_BACKWARD_ATTACK_WEIGHT)
print("Training benign:", int((y_train == 0).sum()))
print("Training attack:", int((y_train == 1).sum()))

print("\nSTEP 5: Training baseline model...")
baseline = build_model()
baseline.fit(X_train, y_train)

print("\nSTEP 6: Training weighted model...")
weighted = build_model()
weighted.fit(X_train, y_train, sample_weight=sample_weights)

print("\nSTEP 7: Evaluating both models on the same Friday benchmark...")
results = []
prediction_frames = []

for name, model in [
    ("Baseline", baseline),
    ("Zero-backward attack weight x5", weighted)
]:
    probabilities = model.predict_proba(X_test)[:, 1]
    predictions = (probabilities >= THRESHOLD).astype("int8")

    tn, fp, fn, tp = confusion_matrix(y_test, predictions, labels=[0, 1]).ravel()

    metrics = {
        "model": name,
        "threshold": THRESHOLD,
        "accuracy": accuracy_score(y_test, predictions),
        "precision_attack": precision_score(y_test, predictions, zero_division=0),
        "recall_attack": recall_score(y_test, predictions, zero_division=0),
        "f1_attack": f1_score(y_test, predictions, zero_division=0),
        "roc_auc": roc_auc_score(y_test, probabilities),
        "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0,
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp)
    }

    zero_test = (
        pd.to_numeric(X_test[BACKWARD_COLUMN], errors="coerce")
        .fillna(0)
        .eq(0)
    )
    has_test = ~zero_test

    metrics["zero_backward_attack_recall"] = (
        recall_score(y_test.loc[zero_test], predictions[zero_test], zero_division=0)
        if zero_test.any() else np.nan
    )
    metrics["has_backward_attack_recall"] = (
        recall_score(y_test.loc[has_test], predictions[has_test], zero_division=0)
        if has_test.any() else np.nan
    )
    results.append(metrics)

    prediction_frames.append(pd.DataFrame({
        "model": name,
        "actual": y_test.to_numpy(),
        "probability": probabilities,
        "predicted": predictions,
        "backward_group": np.where(zero_test.to_numpy(), "ZERO_BACKWARD", "HAS_BACKWARD")
    }))

    print(f"\n{name}")
    for key, value in metrics.items():
        if key != "model":
            print(f"{key}: {value:.6f}" if isinstance(value, (float, np.floating)) else f"{key}: {value}")

results_df = pd.DataFrame(results)
results_path = REPORT_DIR / "zero_backward_weighting_experiment.csv"
results_df.to_csv(results_path, index=False)

predictions_path = REPORT_DIR / "zero_backward_weighting_predictions.csv"
pd.concat(prediction_frames, ignore_index=True).to_csv(predictions_path, index=False)

print("\nSaved metrics:", results_path.resolve())
print("Saved row-level predictions:", predictions_path.resolve())
print("\nIMPORTANT:")
print("- The Friday capture is an exploratory benchmark already examined in prior work.")
print("- Do not select or promote a model based only on this benchmark.")
print("- This experiment does not overwrite existing production model files.")
print("- Compare attack recall gains against false-positive rate and benign impact.")
print("\nZERO-BACKWARD WEIGHTING EXPERIMENT COMPLETE.")
