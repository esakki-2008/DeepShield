from pathlib import Path

import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
REPORT_DIR = BASE_DIR / "reports"

FN_FILE = REPORT_DIR / "heldout_false_negatives.csv"
TP_FILE = REPORT_DIR / "heldout_true_positives.csv"
FEATURE = "Total Backward Packets"

def load_report(path: Path, outcome: str) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Required report not found: {path}")
    df = pd.read_csv(path)
    required = {FEATURE, "attack_probability"}
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(f"{path.name} is missing columns: {sorted(missing)}")
    df[FEATURE] = pd.to_numeric(df[FEATURE], errors="coerce")
    df["attack_probability"] = pd.to_numeric(
        df["attack_probability"], errors="coerce"
    )
    df["outcome"] = outcome
    return df

def main():
    print("STEP 1: Loading held-out DDoS prediction reports...")
    fn = load_report(FN_FILE, "FALSE_NEGATIVE")
    tp = load_report(TP_FILE, "TRUE_POSITIVE")
    combined = pd.concat([fn, tp], ignore_index=True)
    combined = combined.dropna(subset=[FEATURE])

    print(f"False negatives loaded: {len(fn):,}")
    print(f"True positives loaded:  {len(tp):,}")

    print("\nSTEP 2: Grouping records by backward packet count...")
    combined["backward_traffic_group"] = np.where(
        combined[FEATURE] == 0,
        "Zero backward packets",
        "At least one backward packet"
    )

    print("\nSTEP 3: Calculating detection performance per group...")
    rows = []
    for group_name, group in combined.groupby("backward_traffic_group", sort=False):
        fn_count = int((group["outcome"] == "FALSE_NEGATIVE").sum())
        tp_count = int((group["outcome"] == "TRUE_POSITIVE").sum())
        total = fn_count + tp_count
        rows.append({
            "Backward traffic group": group_name,
            "Total DDoS records": total,
            "False negatives": fn_count,
            "True positives": tp_count,
            "False negative rate (%)": round(fn_count / total * 100, 2) if total else np.nan,
            "Recall (%)": round(tp_count / total * 100, 2) if total else np.nan,
            "Median attack probability": round(group["attack_probability"].median(), 6),
            "Mean attack probability": round(group["attack_probability"].mean(), 6),
        })

    summary = pd.DataFrame(rows)
    print(summary.to_string(index=False))

    print("\nSTEP 4: Checking packet-count distribution...")
    distribution = (
        combined.groupby(["backward_traffic_group", "outcome"])
        .size()
        .unstack(fill_value=0)
        .reset_index()
    )
    print(distribution.to_string(index=False))

    output = REPORT_DIR / "backward_traffic_detection_performance.csv"
    summary.to_csv(output, index=False)
    print(f"\nSaved report: {output}")
    print(
        "\nNOTE: These rates describe only the held-out DDoS records in the "
        "false-negative and true-positive reports. They are diagnostic "
        "subgroup results, not independent validation or proof of causation."
    )
    print("BACKWARD-TRAFFIC PERFORMANCE ANALYSIS COMPLETE.")

if __name__ == "__main__":
    main()
