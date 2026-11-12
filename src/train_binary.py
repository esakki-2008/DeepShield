
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score
)
from xgboost import XGBClassifier

# Configuration
DATA_DIR = Path("data/processed")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_PER_FILE = 30_000
RANDOM_STATE = 42

# 1. Load a sample from every Parquet file
print("STEP 1: Loading dataset samples...")

frames = []

for file in sorted(DATA_DIR.glob("*.parquet")):
    df = pd.read_parquet(file)

    if len(df) > SAMPLE_PER_FILE:
        df = df.sample(
            n=SAMPLE_PER_FILE,
            random_state=RANDOM_STATE
        )

    frames.append(df)
    print(f"{file.name}: {len(df):,} rows")

data = pd.concat(frames, ignore_index=True)

# 2. Prepare binary target
print("\nSTEP 2: Preparing features and labels...")

data.columns = data.columns.str.strip()

data["target"] = (
    data["Label"].astype("string").str.strip().ne("BENIGN")
).astype("int8")

X = data.drop(columns=["Label", "target", "source_file"])
y = data["target"]

# Ensure all model features are numeric
non_numeric = X.select_dtypes(exclude=np.number).columns.tolist()

if non_numeric:
    raise ValueError(f"Non-numeric features found: {non_numeric}")

X = X.replace([np.inf, -np.inf], np.nan)

print("Total sampled rows:", len(X))
print("Benign:", int((y == 0).sum()))
print("Attack:", int((y == 1).sum()))

# 3. Prevent identical feature vectors crossing the split
print("\nSTEP 3: Checking duplicate feature vectors...")

feature_hash = pd.util.hash_pandas_object(
    X,
    index=False
)

group_info = pd.DataFrame({
    "feature_hash": feature_hash,
    "target": y.to_numpy()
})

conflicts = group_info.groupby(
    "feature_hash"
)["target"].nunique()

conflicting_hashes = conflicts[conflicts > 1].index

keep = ~feature_hash.isin(conflicting_hashes)

X = X.loc[keep].copy()
y = y.loc[keep].copy()
feature_hash = feature_hash.loc[keep]

# Keep one representative of each identical feature vector
unique = ~feature_hash.duplicated()

X = X.loc[unique].copy()
y = y.loc[unique].copy()

print("Conflicting feature groups removed:", len(conflicting_hashes))
print("Unique feature rows:", len(X))

# 4. Split into training and testing data
print("\nSTEP 4: Splitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=y
)

print("Training rows:", len(X_train))
print("Testing rows:", len(X_test))

# 5. Train XGBoost
print("\nSTEP 5: Training XGBoost model...")

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

# 6. Evaluate model
print("\nSTEP 6: Evaluating model...")

predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)[:, 1]

print("\nAccuracy:", round(accuracy_score(y_test, predictions), 4))
print("ROC-AUC:", round(roc_auc_score(y_test, probabilities), 4))

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=["BENIGN", "ATTACK"],
        zero_division=0
    )
)

print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))

# 7. Save model and feature names
model_path = MODEL_DIR / "binary_xgboost.joblib"

joblib.dump({
    "model": model,
    "features": X.columns.tolist()
}, model_path)

print("\nMODEL SAVED:", model_path)
print("BINARY INTRUSION DETECTION TRAINING COMPLETE!")
