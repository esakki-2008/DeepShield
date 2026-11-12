
from pathlib import Path

import pandas as pd
import numpy as np

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

from xgboost import XGBClassifier


# --------------------------------
# CONFIGURATION
# --------------------------------

DATA_DIR = Path("data/processed")
REPORT_DIR = Path("reports")

SAMPLE_PER_FILE = 30_000
RANDOM_STATE = 42
THRESHOLD = 0.30

TEST_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.parquet"


# --------------------------------
# STEP 1: LOAD DATA
# --------------------------------

print("STEP 1: Loading seven training files...")

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

    print(f"{file.name}: {len(df):,} records")


train_data = pd.concat(
    train_frames,
    ignore_index=True
)

print("\nSTEP 2: Loading held-out DDoS file...")

test_data = pd.read_parquet(DATA_DIR / TEST_FILE)

print("Test records:", len(test_data))


# --------------------------------
# STEP 3: PREPARE FEATURES
# --------------------------------

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

    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    return X, y


X_train, y_train = prepare_data(train_data)
X_test, y_test = prepare_data(test_data)

if list(X_train.columns) != list(X_test.columns):
    raise ValueError("Feature columns do not match!")


# --------------------------------
# STEP 4: REMOVE DUPLICATE LEAKAGE
# --------------------------------

print("\nSTEP 3: Removing duplicate leakage...")

train_hash = pd.util.hash_pandas_object(
    X_train,
    index=False
)

test_hash = pd.util.hash_pandas_object(
    X_test,
    index=False
)

combined = pd.DataFrame({
    "hash": pd.concat(
        [train_hash, test_hash],
        ignore_index=True
    ),
    "label": pd.concat(
        [y_train, y_test],
        ignore_index=True
    )
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

# Remove test patterns already present in training
overlap = test_hash.isin(set(train_hash))

X_test = X_test.loc[~overlap].copy()
y_test = y_test.loc[~overlap].copy()

# Deduplicate training data
unique_train = ~train_hash.duplicated()

X_train = X_train.loc[unique_train].copy()
y_train = y_train.loc[unique_train].copy()

print("Conflicting hashes:", len(conflicting_hashes))
print("Training records:", len(X_train))
print("Testing records:", len(X_test))

if X_test.empty or y_test.nunique() < 2:
    raise ValueError("Insufficient test data!")


# --------------------------------
# STEP 5: TRAIN BASELINE
# --------------------------------

def create_model():

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


def evaluate_model(name, feature_list):

    print(f"\nTRAINING: {name}")
    print("Feature count:", len(feature_list))

    model = create_model()

    model.fit(
        X_train[feature_list],
        y_train
    )

    probabilities = model.predict_proba(
        X_test[feature_list]
    )[:, 1]

    predictions = (
        probabilities >= THRESHOLD
    ).astype(int)

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
    auc = roc_auc_score(y_test, probabilities)

    print("Accuracy:", round(accuracy, 4))
    print("Precision:", round(precision, 4))
    print("Recall:", round(recall, 4))
    print("F1-score:", round(f1, 4))
    print("ROC-AUC:", round(auc, 4))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    return {
        "Experiment": name,
        "Feature Count": len(feature_list),
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1 Score": f1,
        "ROC AUC": auc
    }, model


print("\nSTEP 4: Training baseline with all features...")

all_features = list(X_train.columns)

baseline_result, baseline_model = evaluate_model(
    "Baseline - All 78 Features",
    all_features
)


# --------------------------------
# STEP 6: FEATURE IMPORTANCE
# --------------------------------

print("\nSTEP 5: Calculating training-specific importance...")

importance_df = pd.DataFrame({
    "Feature": all_features,
    "Importance": baseline_model.feature_importances_
}).sort_values(
    by="Importance",
    ascending=False
)

print("\nTOP 20 FEATURES:")
print(importance_df.head(20).to_string(index=False))

REPORT_DIR.mkdir(parents=True, exist_ok=True)

importance_df.to_csv(
    REPORT_DIR / "ablation_feature_importance.csv",
    index=False
)

top20_features = importance_df.head(20)["Feature"].tolist()
top10_features = importance_df.head(10)["Feature"].tolist()
top4_features = importance_df.head(4)["Feature"].tolist()

without_top4 = [
    feature
    for feature in all_features
    if feature not in top4_features
]


# --------------------------------
# STEP 7: RUN EXPERIMENTS
# --------------------------------

print("\nSTEP 6: Running feature experiments...")

results = [baseline_result]

result, _ = evaluate_model(
    "Top 20 Features",
    top20_features
)
results.append(result)

result, _ = evaluate_model(
    "Top 10 Features",
    top10_features
)
results.append(result)

result, _ = evaluate_model(
    "Without Top 4 Features",
    without_top4
)
results.append(result)


# --------------------------------
# STEP 8: SAVE COMPARISON
# --------------------------------

results_df = pd.DataFrame(results)

results_df.to_csv(
    REPORT_DIR / "feature_ablation_results.csv",
    index=False
)

print("\n" + "=" * 65)
print("FEATURE ABLATION COMPARISON")
print("=" * 65)

print(
    results_df.round(4).to_string(index=False)
)

print("\nSaved:")
print("reports/ablation_feature_importance.csv")
print("reports/feature_ablation_results.csv")

print("\nFEATURE ABLATION EXPERIMENT COMPLETE!")
