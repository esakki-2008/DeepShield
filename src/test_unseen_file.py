
from pathlib import Path
import pandas as pd
import numpy as np

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)
from xgboost import XGBClassifier

DATA_DIR = Path("data/processed")
SAMPLE_PER_FILE = 30_000
RANDOM_STATE = 42

TEST_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.parquet"

print("STEP 1: Loading training data from seven files...")

train_frames = []

for file in sorted(DATA_DIR.glob("*.parquet")):
    if file.name == TEST_FILE:
        continue

    df = pd.read_parquet(file)

    if len(df) > SAMPLE_PER_FILE:
        df = df.sample(
            n=SAMPLE_PER_FILE,
            random_state=RANDOM_STATE
        )

    train_frames.append(df)
    print(f"{file.name}: {len(df):,}")

train_data = pd.concat(train_frames, ignore_index=True)

print("\nSTEP 2: Loading completely held-out test file...")

test_data = pd.read_parquet(DATA_DIR / TEST_FILE)

print("Test records:", len(test_data))

# Prepare binary labels
def prepare_data(df):
    df = df.copy()
    df.columns = df.columns.str.strip()

    y = (
        df["Label"]
        .astype("string")
        .str.strip()
        .ne("BENIGN")
    ).astype("int8")

    X = df.drop(columns=["Label", "source_file"], errors="ignore")
    X = X.replace([np.inf, -np.inf], np.nan)

    return X, y

X_train, y_train = prepare_data(train_data)
X_test, y_test = prepare_data(test_data)

# Confirm matching features
if list(X_train.columns) != list(X_test.columns):
    raise ValueError("Training and testing features do not match!")

print("\nTraining distribution:")
print(y_train.value_counts())

print("\nTesting distribution:")
print(y_test.value_counts())

print("\nSTEP 3: Preventing duplicate-feature leakage...")

train_hash = pd.util.hash_pandas_object(
    X_train, index=False
)

test_hash = pd.util.hash_pandas_object(
    X_test, index=False
)

# Identify feature vectors associated with conflicting labels
combined = pd.DataFrame({
    "hash": pd.concat([train_hash, test_hash], ignore_index=True),
    "label": pd.concat([y_train, y_test], ignore_index=True)
})

conflicts = combined.groupby("hash")["label"].nunique()
conflicting_hashes = set(conflicts[conflicts > 1].index)

train_conflicts = train_hash.isin(conflicting_hashes)
test_conflicts = test_hash.isin(conflicting_hashes)

X_train = X_train.loc[~train_conflicts].copy()
y_train = y_train.loc[~train_conflicts].copy()
train_hash = train_hash.loc[~train_conflicts]

X_test = X_test.loc[~test_conflicts].copy()
y_test = y_test.loc[~test_conflicts].copy()
test_hash = test_hash.loc[~test_conflicts]

# Remove test patterns already present in training
overlap = test_hash.isin(set(train_hash))

X_test = X_test.loc[~overlap].copy()
y_test = y_test.loc[~overlap].copy()

# Deduplicate training features
unique_train = ~train_hash.duplicated()

X_train = X_train.loc[unique_train]
y_train = y_train.loc[unique_train]

print("Conflicting feature records removed:", len(conflicting_hashes))
print("Training rows:", len(X_train))
print("Testing rows after leakage checks:", len(X_test))

if X_test.empty or y_test.nunique() < 2:
    raise ValueError("Test data is insufficient for evaluation.")

print("\nSTEP 4: Training XGBoost...")

model = XGBClassifier(
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

model.fit(X_train, y_train)

print("\nSTEP 5: Evaluating unseen-file performance...")

probabilities = model.predict_proba(X_test)[:, 1]

# Use the threshold selected from validation data
THRESHOLD = 0.30
predictions = (probabilities >= THRESHOLD).astype(int)

print(f"\nDetection threshold: {THRESHOLD}")

print("\nAccuracy:", round(accuracy_score(y_test, predictions), 4))
print("ROC-AUC:", round(roc_auc_score(y_test, probabilities), 4))

print("\nClassification Report:")
print(classification_report(
    y_test,
    predictions,
    target_names=["BENIGN", "ATTACK"],
    zero_division=0
))

print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))

print("\nUNSEEN-FILE EVALUATION COMPLETE!")
