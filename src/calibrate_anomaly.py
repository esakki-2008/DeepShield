
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

from xgboost import XGBClassifier


# =====================================
# CONFIGURATION
# =====================================

DATA_DIR = Path("data/processed")
MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")

MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

CALIBRATION_FILE = "Monday-WorkingHours.pcap_ISCX.parquet"
TEST_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.parquet"

SAMPLE_PER_TRAIN_FILE = 30_000
CALIBRATION_SAMPLE = 100_000
MAX_ANOMALY_TRAIN = 100_000

RANDOM_STATE = 42
ANOMALY_PERCENTILE = 99
SUPERVISED_THRESHOLD = 0.30


# =====================================
# STEP 1: LOAD TRAINING FILES
# =====================================

print("STEP 1: Loading six training files...")

train_frames = []

for file in sorted(DATA_DIR.glob("*.parquet")):

    if file.name in [CALIBRATION_FILE, TEST_FILE]:
        continue

    df = pd.read_parquet(file)

    if len(df) > SAMPLE_PER_TRAIN_FILE:
        df = df.sample(
            n=SAMPLE_PER_TRAIN_FILE,
            random_state=RANDOM_STATE
        )

    train_frames.append(df)

    print(file.name, len(df))

train_data = pd.concat(
    train_frames,
    ignore_index=True
)


# =====================================
# STEP 2: LOAD CALIBRATION DATA
# =====================================

print("\nSTEP 2: Loading Monday calibration data...")

calibration_data = pd.read_parquet(
    DATA_DIR / CALIBRATION_FILE
)

calibration_data = calibration_data.sample(
    n=min(CALIBRATION_SAMPLE, len(calibration_data)),
    random_state=RANDOM_STATE
).reset_index(drop=True)

print("Calibration records:", len(calibration_data))


# =====================================
# STEP 3: LOAD FINAL TEST DATA
# =====================================

print("\nSTEP 3: Loading Friday DDoS test data...")

test_data = pd.read_parquet(DATA_DIR / TEST_FILE)

print("Test records:", len(test_data))


# =====================================
# STEP 4: PREPARE DATA
# =====================================

def prepare_data(df):

    df = df.copy()
    df.columns = df.columns.str.strip()

    y = (
        df["Label"]
        .astype("string")
        .str.strip()
        .ne("BENIGN")
    ).astype("int8")

    X = df.drop(
        columns=["Label", "source_file"],
        errors="ignore"
    )

    X = X.replace([np.inf, -np.inf], np.nan)

    return X, y


X_train, y_train = prepare_data(train_data)
X_cal, y_cal = prepare_data(calibration_data)
X_test, y_test = prepare_data(test_data)

if y_cal.nunique() != 1 or y_cal.iloc[0] != 0:
    raise ValueError("Calibration dataset must contain only BENIGN records.")

if list(X_train.columns) != list(X_cal.columns):
    raise ValueError("Training and calibration features do not match!")

if list(X_train.columns) != list(X_test.columns):
    raise ValueError("Training and test features do not match!")


# =====================================
# STEP 5: REMOVE DUPLICATE LEAKAGE
# =====================================

print("\nSTEP 4: Checking duplicate-feature leakage...")

train_hash = pd.util.hash_pandas_object(X_train, index=False)
cal_hash = pd.util.hash_pandas_object(X_cal, index=False)
test_hash = pd.util.hash_pandas_object(X_test, index=False)

combined = pd.DataFrame({
    "hash": pd.concat(
        [train_hash, cal_hash, test_hash],
        ignore_index=True
    ),
    "label": pd.concat(
        [y_train, y_cal, y_test],
        ignore_index=True
    )
})

conflicts = combined.groupby("hash")["label"].nunique()

conflicting_hashes = set(
    conflicts[conflicts > 1].index
)

# Remove feature patterns with conflicting labels
train_mask = ~train_hash.isin(conflicting_hashes)
cal_mask = ~cal_hash.isin(conflicting_hashes)
test_mask = ~test_hash.isin(conflicting_hashes)

X_train = X_train.loc[train_mask].copy()
y_train = y_train.loc[train_mask].copy()
train_hash = train_hash.loc[train_mask]

X_cal = X_cal.loc[cal_mask].copy()
y_cal = y_cal.loc[cal_mask].copy()
cal_hash = cal_hash.loc[cal_mask]

X_test = X_test.loc[test_mask].copy()
y_test = y_test.loc[test_mask].copy()
test_hash = test_hash.loc[test_mask]

# Remove repeated training patterns
unique_train = ~train_hash.duplicated()

X_train = X_train.loc[unique_train].copy()
y_train = y_train.loc[unique_train].copy()
train_hash = train_hash.loc[unique_train]

# Calibration must not overlap training
cal_overlap = cal_hash.isin(set(train_hash))

X_cal = X_cal.loc[~cal_overlap].copy()
y_cal = y_cal.loc[~cal_overlap].copy()
cal_hash = cal_hash.loc[~cal_overlap]

# Deduplicate calibration patterns
unique_cal = ~cal_hash.duplicated()

X_cal = X_cal.loc[unique_cal].copy()
y_cal = y_cal.loc[unique_cal].copy()
cal_hash = cal_hash.loc[unique_cal]

# Test must not overlap training or calibration
known_hashes = set(train_hash) | set(cal_hash)

test_overlap = test_hash.isin(known_hashes)

X_test = X_test.loc[~test_overlap].copy()
y_test = y_test.loc[~test_overlap].copy()

print("Conflicting patterns removed:", len(conflicting_hashes))
print("Training records:", len(X_train))
print("Calibration records:", len(X_cal))
print("Testing records:", len(X_test))

if X_train.empty or X_cal.empty or X_test.empty:
    raise ValueError("Insufficient data after leakage checks!")

if y_test.nunique() < 2:
    raise ValueError("Test data must contain BENIGN and ATTACK records.")


# =====================================
# STEP 6: TRAIN XGBOOST
# =====================================

print("\nSTEP 5: Training supervised XGBoost...")

features = list(X_train.columns)

xgb_model = XGBClassifier(
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

xgb_model.fit(X_train, y_train)

print("XGBoost training complete!")


# =====================================
# STEP 7: TRAIN ISOLATION FOREST
# =====================================

print("\nSTEP 6: Training Isolation Forest...")

X_benign = X_train.loc[y_train == 0]

if len(X_benign) > MAX_ANOMALY_TRAIN:
    X_benign = X_benign.sample(
        n=MAX_ANOMALY_TRAIN,
        random_state=RANDOM_STATE
    )

print("Benign training records:", len(X_benign))

imputer = SimpleImputer(strategy="median")
scaler = RobustScaler()

X_benign_imputed = imputer.fit_transform(X_benign)
X_benign_scaled = scaler.fit_transform(X_benign_imputed)

isolation_model = IsolationForest(
    n_estimators=300,
    max_samples=512,
    contamination="auto",
    random_state=RANDOM_STATE,
    n_jobs=-1
)

isolation_model.fit(X_benign_scaled)

print("Isolation Forest training complete!")


# =====================================
# STEP 8: CALIBRATE THRESHOLD
# =====================================

print("\nSTEP 7: Calibrating using Monday traffic...")

cal_imputed = imputer.transform(X_cal)
cal_scaled = scaler.transform(cal_imputed)

cal_scores = -isolation_model.decision_function(
    cal_scaled
)

anomaly_threshold = np.percentile(
    cal_scores,
    ANOMALY_PERCENTILE
)

cal_predictions = (
    cal_scores >= anomaly_threshold
).astype(int)

calibration_fpr = cal_predictions.mean()

print("Anomaly threshold:", anomaly_threshold)
print("Calibration false-positive rate:",
      round(calibration_fpr, 4))


# =====================================
# STEP 9: EVALUATE FRIDAY TRAFFIC
# =====================================

print("\nSTEP 8: Testing on Friday DDoS traffic...")

test_imputed = imputer.transform(X_test)
test_scaled = scaler.transform(test_imputed)

anomaly_scores = -isolation_model.decision_function(
    test_scaled
)

anomaly_predictions = (
    anomaly_scores >= anomaly_threshold
).astype(int)

supervised_probabilities = xgb_model.predict_proba(
    X_test
)[:, 1]

supervised_predictions = (
    supervised_probabilities >= SUPERVISED_THRESHOLD
).astype(int)

hybrid_predictions = (
    (supervised_predictions == 1) |
    (anomaly_predictions == 1)
).astype(int)


# =====================================
# STEP 10: METRICS
# =====================================

def evaluate(name, predictions, scores=None):

    matrix = confusion_matrix(y_test, predictions)
    tn, fp, fn, tp = matrix.ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0

    print("\n" + "=" * 50)
    print(name)
    print("=" * 50)

    print("Accuracy:", round(
        accuracy_score(y_test, predictions), 4
    ))

    print("Precision:", round(
        precision_score(y_test, predictions, zero_division=0), 4
    ))

    print("Recall:", round(
        recall_score(y_test, predictions, zero_division=0), 4
    ))

    print("F1-score:", round(
        f1_score(y_test, predictions, zero_division=0), 4
    ))

    print("False positive rate:", round(fpr, 4))

    if scores is not None:
        print("ROC-AUC:", round(
            roc_auc_score(y_test, scores), 4
        ))

    print("Confusion matrix:")
    print(matrix)

    return {
        "System": name,
        "Accuracy": accuracy_score(y_test, predictions),
        "Precision": precision_score(
            y_test, predictions, zero_division=0
        ),
        "Recall": recall_score(
            y_test, predictions, zero_division=0
        ),
        "F1 Score": f1_score(
            y_test, predictions, zero_division=0
        ),
        "False Positive Rate": fpr
    }


results = []

results.append(
    evaluate(
        "Supervised XGBoost",
        supervised_predictions,
        supervised_probabilities
    )
)

results.append(
    evaluate(
        "Calibrated Isolation Forest",
        anomaly_predictions,
        anomaly_scores
    )
)

results.append(
    evaluate(
        "Calibrated Hybrid",
        hybrid_predictions
    )
)


# =====================================
# STEP 11: SAVE MODELS AND RESULTS
# =====================================

results_df = pd.DataFrame(results)

results_df.to_csv(
    REPORT_DIR / "calibrated_anomaly_results.csv",
    index=False
)

joblib.dump(
    {
        "xgb_model": xgb_model,
        "imputer": imputer,
        "scaler": scaler,
        "isolation_model": isolation_model,
        "features": features,
        "supervised_threshold": SUPERVISED_THRESHOLD,
        "anomaly_threshold": anomaly_threshold,
        "calibration_percentile": ANOMALY_PERCENTILE
    },
    MODEL_DIR / "calibrated_hybrid_detector.joblib"
)

print("\n" + "=" * 60)
print("CALIBRATED DETECTION COMPARISON")
print("=" * 60)

print(results_df.round(4).to_string(index=False))

print("\nSaved:")
print("models/calibrated_hybrid_detector.joblib")
print("reports/calibrated_anomaly_results.csv")

print("\nANOMALY CALIBRATION COMPLETE!")
