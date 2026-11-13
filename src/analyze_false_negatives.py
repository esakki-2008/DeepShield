from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report, recall_score
from xgboost import XGBClassifier

DATA_DIR = Path("data/processed")
REPORT_DIR = Path("reports")
SAMPLE_PER_FILE = 30_000
RANDOM_STATE = 42
THRESHOLD = 0.50

# Keep this filename exactly aligned with the dataset on disk.
TEST_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.parquet"

def prepare_data(frame):
    frame = frame.copy()
    frame.columns = frame.columns.str.strip()

    y = (
        frame["Label"]
        .astype("string")
        .str.strip()
        .ne("BENIGN")
    ).astype("int8")

    X = frame.drop(columns=["Label", "source_file"], errors="ignore")
    X = X.replace([np.inf, -np.inf], np.nan)
    return X, y

def main():
    print("STEP 1: Loading training samples from the other seven captures...")
    train_frames = []

    for file in sorted(DATA_DIR.glob("*.parquet")):
        if file.name == TEST_FILE:
            continue

        frame = pd.read_parquet(file)
        if len(frame) > SAMPLE_PER_FILE:
            frame = frame.sample(n=SAMPLE_PER_FILE, random_state=RANDOM_STATE)

        train_frames.append(frame)
        print(f"{file.name}: {len(frame):,} rows")

    if not train_frames:
        raise FileNotFoundError(f"No training Parquet files found in {DATA_DIR}")

    train_data = pd.concat(train_frames, ignore_index=True)
    test_path = DATA_DIR / TEST_FILE
    if not test_path.exists():
        raise FileNotFoundError(
            f"Could not find held-out file: {test_path}\n"
            "Check the exact filename inside data/processed."
        )

    print("\nSTEP 2: Loading the held-out Friday DDoS capture...")
    test_data = pd.read_parquet(test_path)
    X_train, y_train = prepare_data(train_data)
    X_test, y_test = prepare_data(test_data)

    if list(X_train.columns) != list(X_test.columns):
        raise ValueError("Training and test feature columns do not match.")

    print("\nSTEP 3: Removing conflicting and overlapping feature vectors...")
    train_hash = pd.util.hash_pandas_object(X_train, index=False)
    test_hash = pd.util.hash_pandas_object(X_test, index=False)

    combined = pd.DataFrame({
        "hash": pd.concat([train_hash, test_hash], ignore_index=True),
        "label": pd.concat([y_train.reset_index(drop=True),
                            y_test.reset_index(drop=True)], ignore_index=True)
    })

    conflicting_hashes = set(
        combined.groupby("hash")["label"].nunique()
        .loc[lambda values: values > 1].index
    )

    train_conflicts = train_hash.isin(conflicting_hashes)
    test_conflicts = test_hash.isin(conflicting_hashes)

    X_train = X_train.loc[~train_conflicts].copy()
    y_train = y_train.loc[~train_conflicts].copy()
    train_hash = train_hash.loc[~train_conflicts]

    X_test = X_test.loc[~test_conflicts].copy()
    y_test = y_test.loc[~test_conflicts].copy()
    test_hash = test_hash.loc[~test_conflicts]

    overlap = test_hash.isin(set(train_hash))
    X_test = X_test.loc[~overlap].copy()
    y_test = y_test.loc[~overlap].copy()

    unique_train = ~train_hash.duplicated()
    X_train = X_train.loc[unique_train].copy()
    y_train = y_train.loc[unique_train].copy()

    print("Conflicting feature hashes removed:", len(conflicting_hashes))
    print("Training rows:", len(X_train))
    print("Held-out rows after leakage checks:", len(X_test))
    print("Held-out label counts:")
    print(y_test.value_counts().rename(index={0: "BENIGN", 1: "ATTACK"}))

    if X_test.empty or y_test.nunique() < 2:
        raise ValueError("The cleaned held-out test data is insufficient.")

    print("\nSTEP 4: Training the baseline XGBoost model...")
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

    print("\nSTEP 5: Finding false negatives at threshold", THRESHOLD)
    probabilities = model.predict_proba(X_test)[:, 1]
    predictions = (probabilities >= THRESHOLD).astype("int8")

    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])
    print("\nConfusion matrix [[TN, FP], [FN, TP]]:")
    print(matrix)
    print("\nClassification report:")
    print(classification_report(
        y_test, predictions,
        target_names=["BENIGN", "ATTACK"],
        zero_division=0
    ))
    print("Attack recall:", round(recall_score(y_test, predictions), 4))

    result = X_test.copy()
    result.insert(0, "true_label", y_test.map({0: "BENIGN", 1: "ATTACK"}))
    result["attack_probability"] = probabilities
    result["predicted_label"] = np.where(predictions == 1, "ATTACK", "BENIGN")
    result["error_type"] = np.select(
        [
            (y_test.to_numpy() == 1) & (predictions == 0),
            (y_test.to_numpy() == 0) & (predictions == 1)
        ],
        ["FALSE_NEGATIVE", "FALSE_POSITIVE"],
        default="CORRECT"
    )

    false_negatives = result[result["error_type"] == "FALSE_NEGATIVE"].copy()
    false_positives = result[result["error_type"] == "FALSE_POSITIVE"].copy()

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    fn_path = REPORT_DIR / "heldout_false_negatives.csv"
    fp_path = REPORT_DIR / "heldout_false_positives.csv"
    summary_path = REPORT_DIR / "heldout_error_summary.csv"

    false_negatives.sort_values("attack_probability").to_csv(fn_path, index=False)
    false_positives.sort_values("attack_probability", ascending=False).to_csv(fp_path, index=False)

    probability_bins = pd.cut(
        false_negatives["attack_probability"],
        bins=[0, 0.05, 0.10, 0.20, 0.30, 0.40, 0.50],
        include_lowest=True
    )
    bin_summary = (
        probability_bins.value_counts(sort=False)
        .rename_axis("Attack probability range")
        .reset_index(name="False negative records")
    )
    bin_summary.to_csv(summary_path, index=False)

    print("\nFALSE NEGATIVE COUNT:", len(false_negatives))
    print("FALSE POSITIVE COUNT:", len(false_positives))
    print("\nFalse-negative probability distribution:")
    print(bin_summary.to_string(index=False))
    print("\nSaved reports:")
    print(fn_path)
    print(fp_path)
    print(summary_path)
    print("\nFALSE NEGATIVE ANALYSIS COMPLETE.")

if __name__ == "__main__":
    main()
