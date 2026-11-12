
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split
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

TEST_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.parquet"

SAMPLE_PER_FILE = 30_000
RANDOM_STATE = 42

SUPERVISED_THRESHOLD = 0.30
ANOMALY_PERCENTILE = 99


# =====================================
# STEP 1: LOAD SEVEN TRAINING FILES
# =====================================

print("STEP 1: Loading training data...")

frames = []

for file in sorted(DATA_DIR.glob("*.parquet")):

    if file.name == TEST_FILE:
        continue

    df = pd.read_parquet(file)

    if len(df) > SAMPLE_PER_FILE:
        df = df.sample(
            n=SAMPLE_PER_FILE,
            random_state=RANDOM_STATE
        )

    frames.append(df)

    print(file.name, len(df))

train_data = pd.concat(frames, ignore_index=True)

print("\nSTEP 2: Loading held-out DDoS data...")

test_data = pd.read_parquet(DATA_DIR / TEST_FILE)

print("Test records:", len(test_data))


# =====================================
# STEP 3: PREPARE DATA
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
X_test, y_test = prepare_data(test_data)

if list(X_train.columns) != list(X_test.columns):
    raise ValueError("Training and testing features do not match!")


# =====================================
# STEP 4: REMOVE DUPLICATE LEAKAGE
# =====================================

print("\nSTEP 3: Removing duplicate leakage...")

train_hash = pd.util.hash_pandas_object(
    X_train, index=False
)

test_hash = pd.util.hash_pandas_object(
    X_test, index=False
)

combined = pd.DataFrame({
    "hash": pd.concat([train_hash, test_hash], ignore_index=True),
    "label": pd.concat([y_train, y_test], ignore_index=True)
})

conflicts = combined.groupby("hash")["label"].nunique()

conflicting_hashes = set(
    conflicts[conflicts > 1].index
)

train_conflicts = train_hash.isin(conflicting_hashes)
test_conflicts = test_hash.isin(conflicting_hashes)

X_train = X_train.loc[~train_conflicts].copy()
y_train = y_train.loc[~train_conflicts].copy()
train_hash = train_hash.loc[~train_conflicts]

X_test = X_test.loc[~test_conflicts].copy()
y_test = y_test.loc[~test_conflicts].copy()
test_hash = test_hash.loc[~test_conflicts]

# Remove test records already represented in training
overlap = test_hash.isin(set(train_hash))

X_test = X_test.loc[~overlap].copy()
y_test = y_test.loc[~overlap].copy()

# Deduplicate training records
unique_train = ~train_hash.duplicated()

X_train = X_train.loc[unique_train].copy()
y_train = y_train.loc[unique_train].copy()

print("Training records:", len(X_train))
print("Testing records:", len(X_test))

print("\nTraining labels:")
print(y_train.value_counts())

print("\nTesting labels:")
print(y_test.value_counts())

if X_test.empty or y_test.nunique() < 2:
    raise ValueError("Insufficient test data!")


# =====================================
# STEP 5: TRAIN SUPERVISED XGBOOST
# =====================================

print("\nSTEP 4: Training supervised XGBoost...")

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
# STEP 6: PREPARE BENIGN TRAINING DATA
# =====================================

print("\nSTEP 5: Preparing benign-only data...")

benign_indices = y_train[y_train == 0].index

fit_indices, calibration_indices = train_test_split(
    benign_indices,
    test_size=0.20,
    random_state=RANDOM_STATE
)

X_benign_fit = X_train.loc[fit_indices]

X_benign_calibration = X_train.loc[calibration_indices]

# Limit Isolation Forest training size
MAX_BENIGN_SAMPLES = 100_000

if len(X_benign_fit) > MAX_BENIGN_SAMPLES:
    X_benign_fit = X_benign_fit.sample(
        n=MAX_BENIGN_SAMPLES,
        random_state=RANDOM_STATE
    )

print("Benign records for anomaly training:", len(X_benign_fit))
print("Benign calibration records:", len(X_benign_calibration))


# =====================================
# STEP 7: TRAIN ISOLATION FOREST
# =====================================

print("\nSTEP 6: Training Isolation Forest...")

imputer = SimpleImputer(strategy="median")

scaler = RobustScaler()

X_benign_imputed = imputer.fit_transform(X_benign_fit)

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
# STEP 8: CALIBRATE ANOMALY THRESHOLD
# =====================================

print("\nSTEP 7: Calibrating anomaly threshold...")

calibration_imputed = imputer.transform(
    X_benign_calibration
)

calibration_scaled = scaler.transform(
    calibration_imputed
)

calibration_scores = -isolation_model.decision_function(
    calibration_scaled
)

anomaly_threshold = np.percentile(
    calibration_scores,
    ANOMALY_PERCENTILE
)

print("Anomaly threshold:", anomaly_threshold)
print("Calibration percentile:", ANOMALY_PERCENTILE)


# =====================================
# STEP 9: EVALUATE BOTH SYSTEMS
# =====================================

print("\nSTEP 8: Evaluating held-out traffic...")

# Supervised predictions
supervised_probabilities = xgb_model.predict_proba(
    X_test
)[:, 1]

supervised_predictions = (
    supervised_probabilities >= SUPERVISED_THRESHOLD
).astype(int)


# Anomaly predictions
test_imputed = imputer.transform(X_test)

test_scaled = scaler.transform(test_imputed)

anomaly_scores = -isolation_model.decision_function(
    test_scaled
)

anomaly_predictions = (
    anomaly_scores >= anomaly_threshold
).astype(int)


# Hybrid decision
hybrid_predictions = (
    (supervised_predictions == 1) |
    (anomaly_predictions == 1)
).astype(int)


# =====================================
# STEP 10: PRINT METRICS
# =====================================

def evaluate(name, predictions, score=None):

    accuracy = accuracy_score(y_test, predictions)

    precision = precision_score(
        y_test, predictions, zero_division=0
    )

    recall = recall_score(
        y_test, predictions, zero_division=0
    )

    f1 = f1_score(
        y_test, predictions, zero_division=0
    )

    matrix = confusion_matrix(y_test, predictions)

    tn, fp, fn, tp = matrix.ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0

    print("\n" + "=" * 50)
    print(name)
    print("=" * 50)

    print("Accuracy:", round(accuracy, 4))
    print("Precision:", round(precision, 4))
    print("Recall:", round(recall, 4))
    print("F1-score:", round(f1, 4))
    print("False positive rate:", round(fpr, 4))

    if score is not None:
        print("ROC-AUC:", round(roc_auc_score(y_test, score), 4))

    print("Confusion matrix:")
    print(matrix)

    return {
        "System": name,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1 Score": f1,
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
        "Isolation Forest",
        anomaly_predictions,
        anomaly_scores
    )
)

results.append(
    evaluate(
        "Hybrid Detection",
        hybrid_predictions
    )
)


# =====================================
# STEP 11: SAVE RESULTS AND MODELS
# =====================================

results_df = pd.DataFrame(results)

results_df.to_csv(
    REPORT_DIR / "hybrid_evaluation.csv",
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
        "anomaly_threshold": anomaly_threshold
    },
    MODEL_DIR / "hybrid_detector.joblib"
)

print("\n" + "=" * 60)
print("HYBRID MODEL COMPARISON")
print("=" * 60)

print(results_df.round(4).to_string(index=False))

print("\nSaved model: models/hybrid_detector.joblib")
print("Saved report: reports/hybrid_evaluation.csv")

print("\nDEEPSHIELD HYBRID TRAINING COMPLETE!")
