from pathlib import Path

import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data" / "processed"
REPORT_DIR = BASE_DIR / "reports"
TEST_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.parquet"

FN_FILE = REPORT_DIR / "heldout_false_negatives.csv"
TP_FILE = REPORT_DIR / "heldout_true_positives.csv"

def normalize_features(frame):
    frame = frame.copy()
    frame.columns = frame.columns.str.strip()
    X = frame.drop(columns=["Label", "source_file"], errors="ignore")
    X = X.replace([np.inf, -np.inf], np.nan)
    return X

def main():
    print("STEP 1: Loading the original held-out capture...")
    source_path = DATA_DIR / TEST_FILE
    if not source_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {source_path}")

    source = pd.read_parquet(source_path)
    source_labels = source["Label"].astype("string").str.strip()
    source_features = normalize_features(source)

    print(f"Original capture rows: {len(source):,}")
    print("\nSTEP 2: Building feature-hash to attack-family mapping...")
    source_hashes = pd.util.hash_pandas_object(source_features, index=False)
    mapping = pd.DataFrame({
        "feature_hash": source_hashes.to_numpy(),
        "attack_family": source_labels.to_numpy()
    })
    mapping = mapping.drop_duplicates("feature_hash")

    print(f"Unique feature hashes mapped: {len(mapping):,}")

    print("\nSTEP 3: Matching false negatives and true positives...")
    results = []
    for label, path in [
        ("FALSE_NEGATIVE", FN_FILE),
        ("TRUE_POSITIVE", TP_FILE)
    ]:
        if not path.exists():
            raise FileNotFoundError(f"Required report not found: {path}")

        report = pd.read_csv(path)
        metadata_cols = {
            "true_label", "attack_probability", "predicted_label", "error_type"
        }
        feature_cols = [
            c for c in report.columns
            if c not in metadata_cols
        ]
        report_features = report[feature_cols].replace([np.inf, -np.inf], np.nan)

        if list(report_features.columns) != list(source_features.columns):
            raise ValueError(
                f"Feature columns in {path.name} do not match the original capture."
            )

        hashes = pd.util.hash_pandas_object(report_features, index=False)
        matched = pd.DataFrame({"feature_hash": hashes.to_numpy()})
        matched = matched.merge(mapping, on="feature_hash", how="left")

        unmatched = matched["attack_family"].isna().sum()
        if unmatched:
            print(f"WARNING: {unmatched:,} rows in {label} did not match the source capture.")

        matched["group"] = label
        results.append(matched)

        print(f"{label}: {len(matched):,} rows; unmatched: {unmatched:,}")

    combined = pd.concat(results, ignore_index=True)
    combined = combined.dropna(subset=["attack_family"])

    print("\nSTEP 4: Attack-family distribution by prediction outcome...")
    counts = pd.crosstab(
        combined["attack_family"],
        combined["group"]
    )

    for col in ["FALSE_NEGATIVE", "TRUE_POSITIVE"]:
        if col not in counts.columns:
            counts[col] = 0
    counts = counts[["FALSE_NEGATIVE", "TRUE_POSITIVE"]]
    counts["TOTAL_ATTACKS_IN_ANALYZED_GROUPS"] = (
        counts["FALSE_NEGATIVE"] + counts["TRUE_POSITIVE"]
    )
    counts["FN_RATE_WITHIN_ANALYZED_GROUP_%"] = (
        counts["FALSE_NEGATIVE"]
        / counts["TOTAL_ATTACKS_IN_ANALYZED_GROUPS"].replace(0, np.nan)
        * 100
    ).round(2)

    counts = counts.sort_values(
        "FALSE_NEGATIVE", ascending=False
    )

    print(counts.to_string())
    output = REPORT_DIR / "false_negative_attack_family_distribution.csv"
    counts.to_csv(output)
    print(f"\nSaved report: {output}")
    print(
        "\nNOTE: FN rate here is calculated only among the false-negative "
        "and true-positive records included in these reports. It excludes "
        "other records and is not a full per-class recall calculation."
    )
    print("ATTACK-FAMILY ANALYSIS COMPLETE.")

if __name__ == "__main__":
    main()
