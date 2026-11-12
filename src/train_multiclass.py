
from pathlib import Path

import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    classification_report,
    confusion_matrix
)

from xgboost import XGBClassifier


# ==========================================
# CONFIGURATION
# ==========================================

DATA_DIR = Path("data/processed")
MODEL_DIR = Path("models")

MODEL_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_PER_LABEL = 10_000
RANDOM_STATE = 42


# ==========================================
# STEP 1: LOAD AND SAMPLE DATA
# ==========================================

print("\nSTEP 1: Loading attack categories...")

frames = []

files = sorted(DATA_DIR.glob("*.parquet"))

if not files:
    raise FileNotFoundError("No Parquet files found in data/processed")

for file in files:

    print(f"\nReading: {file.name}")

    df = pd.read_parquet(file)

    df.columns = df.columns.str.strip()

    df["Label"] = (
        df["Label"]
        .astype("string")
        .str.strip()
    )

    # Sample up to 10,000 rows per label.
    # Shuffle each group, then select its first rows.
    sampled = (
        df.groupby("Label", group_keys=False)
        .sample(
            frac=1,
            random_state=RANDOM_STATE
        )
        .groupby("Label", group_keys=False)
        .head(SAMPLE_PER_LABEL)
        .reset_index(drop=True)
    )

    frames.append(sampled)

    print(f"Sampled rows: {len(sampled):,}")


data = pd.concat(frames, ignore_index=True)

print("\nTotal sampled records:", len(data))


# ==========================================
# STEP 2: PREPARE FEATURES AND LABELS
# ==========================================

print("\nSTEP 2: Preparing features...")

y = data["Label"].copy()

X = data.drop(
    columns=["Label", "source_file"],
    errors="ignore"
)

# Replace infinite values with missing values.
X = X.replace([np.inf, -np.inf], np.nan)

# Ensure all features are numeric.
non_numeric = X.select_dtypes(
    exclude=np.number
).columns.tolist()

if non_numeric:
    raise ValueError(
        f"Non-numeric columns found: {non_numeric}"
    )

print("Feature count:", X.shape[1])
print("Label count:", y.nunique())


# ==========================================
# STEP 3: DUPLICATE FEATURE AUDIT
# ==========================================

print("\nSTEP 3: Checking duplicate features...")

hashes = pd.util.hash_pandas_object(
    X,
    index=False
)

audit = pd.DataFrame({
    "hash": hashes.to_numpy(),
    "label": y.to_numpy()
})

# Find identical feature vectors with different labels.
conflicts = (
    audit.groupby("hash")["label"]
    .nunique()
)

bad_hashes = conflicts[
    conflicts > 1
].index

keep = ~hashes.isin(bad_hashes)

X = X.loc[keep].copy()
y = y.loc[keep].copy()
hashes = hashes.loc[keep]

# Remove repeated feature vectors.
unique = ~hashes.duplicated()

X = X.loc[unique].copy()
y = y.loc[unique].copy()

print("Conflicting groups removed:", len(bad_hashes))
print("Unique records:", len(X))


# ==========================================
# STEP 4: LABEL ENCODING
# ==========================================

print("\nSTEP 4: Encoding attack labels...")

encoder = LabelEncoder()

y_encoded = encoder.fit_transform(y)

print("\nAttack categories:")

for index, label in enumerate(encoder.classes_):
    print(f"{index}: {label}")


# ==========================================
# STEP 5: TRAIN / VALIDATION SPLIT
# ==========================================

print("\nSTEP 5: Splitting dataset...")

X_train, X_val, y_train, y_val = train_test_split(
    X,
    y_encoded,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=y_encoded
)

print("Training records:", len(X_train))
print("Validation records:", len(X_val))


# ==========================================
# STEP 6: CLASS WEIGHTING
# ==========================================

print("\nSTEP 6: Calculating class weights...")

weights = compute_sample_weight(
    class_weight="balanced",
    y=y_train
)

print("Class weights calculated.")


# ==========================================
# STEP 7: TRAIN XGBOOST
# ==========================================

print("\nSTEP 7: Training multiclass XGBoost...")

model = XGBClassifier(
    objective="multi:softprob",
    num_class=len(encoder.classes_),

    n_estimators=250,
    max_depth=8,
    learning_rate=0.1,

    subsample=0.8,
    colsample_bytree=0.8,

    eval_metric="mlogloss",
    tree_method="hist",

    n_jobs=-1,
    random_state=RANDOM_STATE
)

model.fit(
    X_train,
    y_train,
    sample_weight=weights
)

print("Training completed!")


# ==========================================
# STEP 8: MODEL EVALUATION
# ==========================================

print("\nSTEP 8: Evaluating model...")

predictions = model.predict(X_val)

accuracy = accuracy_score(
    y_val,
    predictions
)

macro_f1 = f1_score(
    y_val,
    predictions,
    average="macro",
    zero_division=0
)

weighted_f1 = f1_score(
    y_val,
    predictions,
    average="weighted",
    zero_division=0
)

print("\n========== MODEL RESULTS ==========")

print(f"Accuracy:   {accuracy:.4f}")
print(f"Macro F1:   {macro_f1:.4f}")
print(f"Weighted F1: {weighted_f1:.4f}")


# ==========================================
# STEP 9: CLASSIFICATION REPORT
# ==========================================

print("\nCLASSIFICATION REPORT:\n")

print(
    classification_report(
        y_val,
        predictions,
        labels=np.arange(len(encoder.classes_)),
        target_names=encoder.classes_,
        zero_division=0
    )
)


# ==========================================
# STEP 10: CONFUSION MATRIX
# ==========================================

print("\nCONFUSION MATRIX:\n")

matrix = confusion_matrix(
    y_val,
    predictions,
    labels=np.arange(len(encoder.classes_))
)

print(matrix)


# ==========================================
# STEP 11: SAVE MODEL
# ==========================================

print("\nSTEP 11: Saving model...")

model_path = MODEL_DIR / "multiclass_xgboost.joblib"

joblib.dump(
    {
        "model": model,
        "encoder": encoder,
        "features": X.columns.tolist()
    },
    model_path
)

print(f"\nModel saved successfully: {model_path}")

print("\n===================================")
print("DEEPSHIELD MULTICLASS TRAINING DONE")
print("===================================")
