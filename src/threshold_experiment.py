
from pathlib import Path
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score
)
from xgboost import XGBClassifier

DATA_DIR = Path("data/processed")
SAMPLE_PER_FILE = 30_000

# Load the seven training files
frames = []

for file in sorted(DATA_DIR.glob("*.parquet")):
    if file.name.startswith("Friday-WorkingHours-Afternoon-DDos"):
        continue

    df = pd.read_parquet(file)

    if len(df) > SAMPLE_PER_FILE:
        df = df.sample(n=SAMPLE_PER_FILE, random_state=42)

    frames.append(df)

data = pd.concat(frames, ignore_index=True)

# Prepare features and binary target
data.columns = data.columns.str.strip()

y = (
    data["Label"].astype("string").str.strip().ne("BENIGN")
).astype("int8")

X = data.drop(
    columns=["Label", "source_file"],
    errors="ignore"
)

X = X.replace([np.inf, -np.inf], np.nan)

# Remove conflicting feature groups
hashes = pd.util.hash_pandas_object(X, index=False)

audit = pd.DataFrame({
    "hash": hashes,
    "label": y.to_numpy()
})

conflicts = audit.groupby("hash")["label"].nunique()
bad_hashes = conflicts[conflicts > 1].index

keep = ~hashes.isin(bad_hashes)

X = X.loc[keep].copy()
y = y.loc[keep].copy()
hashes = hashes.loc[keep]

# Keep one copy of each feature vector
unique = ~hashes.duplicated()

X = X.loc[unique]
y = y.loc[unique]

# Training / validation split
X_train, X_val, y_train, y_val = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("Training XGBoost...")

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
    random_state=42
)

model.fit(X_train, y_train)

probabilities = model.predict_proba(X_val)[:, 1]

print("\nVALIDATION THRESHOLD EXPERIMENT")
print("-" * 65)
print("Threshold | Precision | Recall | F1-score")
print("-" * 65)

for threshold in [0.50, 0.40, 0.30, 0.20, 0.10]:
    predictions = (probabilities >= threshold).astype(int)

    precision = precision_score(
        y_val, predictions, zero_division=0
    )
    recall = recall_score(
        y_val, predictions, zero_division=0
    )
    f1 = f1_score(
        y_val, predictions, zero_division=0
    )

    print(
        f"{threshold:9.2f} | "
        f"{precision:9.4f} | "
        f"{recall:6.4f} | "
        f"{f1:8.4f}"
    )

print("\nVALIDATION EXPERIMENT COMPLETE")
