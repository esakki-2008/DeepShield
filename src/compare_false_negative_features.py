
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp

REPORT_DIR = Path("reports")
FN_FILE = REPORT_DIR / "heldout_false_negatives.csv"
TP_FILE = REPORT_DIR / "heldout_true_positives.csv"
OUTPUT_FILE = REPORT_DIR / "false_negative_feature_comparison.csv"
SAMPLE_SIZE = 20_000
RANDOM_STATE = 42

METADATA_COLUMNS = {
    "true_label", "predicted_label", "attack_probability",
    "error_type", "risk_score", "severity", "anomaly_score",
    "anomaly_detected", "row_number"
}


def main():
    print("STEP 1: Loading false-negative and true-positive reports...")
    if not FN_FILE.exists() or not TP_FILE.exists():
        raise FileNotFoundError(
            "Required reports are missing. Run src/analyze_false_negatives.py first."
        )

    fn = pd.read_csv(FN_FILE)
    tp = pd.read_csv(TP_FILE)

    print(f"False negatives: {len(fn):,}")
    print(f"True positives:  {len(tp):,}")

    feature_columns = [
        col for col in fn.columns
        if col in tp.columns and col not in METADATA_COLUMNS
    ]

    fn_features = fn[feature_columns].apply(pd.to_numeric, errors="coerce")
    tp_features = tp[feature_columns].apply(pd.to_numeric, errors="coerce")

    # Exclude constant or entirely missing columns from statistical comparison.
    feature_columns = [
        col for col in feature_columns
        if fn_features[col].notna().any()
        and tp_features[col].notna().any()
        and (fn_features[col].nunique(dropna=True) > 1
             or tp_features[col].nunique(dropna=True) > 1)
    ]

    print(f"Numeric candidate features: {len(feature_columns)}")

    print("\nSTEP 2: Sampling records for efficient distribution testing...")
    fn_sample = fn_features[feature_columns].sample(
        n=min(SAMPLE_SIZE, len(fn_features)),
        random_state=RANDOM_STATE
    )
    tp_sample = tp_features[feature_columns].sample(
        n=min(SAMPLE_SIZE, len(tp_features)),
        random_state=RANDOM_STATE
    )

    print(f"Sampled FN rows: {len(fn_sample):,}")
    print(f"Sampled TP rows: {len(tp_sample):,}")

    print("\nSTEP 3: Comparing feature distributions...")
    rows = []

    for feature in feature_columns:
        a = fn_sample[feature].replace([np.inf, -np.inf], np.nan).dropna()
        b = tp_sample[feature].replace([np.inf, -np.inf], np.nan).dropna()

        if len(a) < 2 or len(b) < 2:
            continue

        mean_fn = a.mean()
        mean_tp = b.mean()
        std_fn = a.std()
        std_tp = b.std()
        pooled_std = np.sqrt((std_fn ** 2 + std_tp ** 2) / 2)

        smd = (mean_fn - mean_tp) / pooled_std if pooled_std > 0 else 0.0
        ks_stat, ks_p = ks_2samp(a, b, alternative="two-sided", method="auto")

        rows.append({
            "Feature": feature,
            "FN_Mean": mean_fn,
            "TP_Mean": mean_tp,
            "FN_Median": a.median(),
            "TP_Median": b.median(),
            "FN_Std": std_fn,
            "TP_Std": std_tp,
            "Standardized_Mean_Difference": smd,
            "Absolute_SMD": abs(smd),
            "KS_Statistic": ks_stat,
            "KS_P_Value": ks_p,
            "FN_Missing_Pct": fn_features[feature].isna().mean() * 100,
            "TP_Missing_Pct": tp_features[feature].isna().mean() * 100,
            "FN_Sample_Count": len(a),
            "TP_Sample_Count": len(b)
        })

    comparison = pd.DataFrame(rows).sort_values(
        "Absolute_SMD", ascending=False
    )
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    comparison.to_csv(OUTPUT_FILE, index=False)

    print("\nSTEP 4: Top 20 features with largest standardized differences")
    display_columns = [
        "Feature", "FN_Median", "TP_Median",
        "Standardized_Mean_Difference", "KS_Statistic"
    ]
    print(comparison[display_columns].head(20).to_string(index=False))

    print("\nImportant interpretation:")
    print("- Positive SMD: feature mean is higher in missed attacks (FN).")
    print("- Negative SMD: feature mean is lower in missed attacks (FN).")
    print("- Large absolute SMD indicates a stronger difference in these samples.")
    print("- KS statistics compare distributions, not causation.")
    print("- These are exploratory comparisons on the held-out capture,")
    print("  not a new independent test or proof that a feature causes errors.")

    print(f"\nSaved comparison: {OUTPUT_FILE}")
    print("FEATURE COMPARISON COMPLETE.")


if __name__ == "__main__":
    main()
