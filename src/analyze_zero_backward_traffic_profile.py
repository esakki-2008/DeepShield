from pathlib import Path

import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
REPORT_DIR = BASE_DIR / "reports"
FN_FILE = REPORT_DIR / "heldout_false_negatives.csv"
TP_FILE = REPORT_DIR / "heldout_true_positives.csv"

GROUP_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Total Backward Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd IAT Total",
    "Bwd IAT Total",
    "Fwd Header Length",
    "Bwd Header Length",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
]

def load_group(path: Path, outcome: str) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Missing report: {path}")
    df = pd.read_csv(path)
    required = {"Total Backward Packets", "attack_probability"}
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(f"{path.name} is missing required columns: {sorted(missing)}")
    for col in df.columns:
        if col not in {"true_label", "predicted_label", "error_type"}:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    df["outcome"] = outcome
    return df

def main():
    print("STEP 1: Loading DDoS false-negative and true-positive records...")
    fn = load_group(FN_FILE, "FALSE_NEGATIVE")
    tp = load_group(TP_FILE, "TRUE_POSITIVE")
    data = pd.concat([fn, tp], ignore_index=True)
    data = data.dropna(subset=["Total Backward Packets"])
    data["traffic_group"] = np.where(
        data["Total Backward Packets"] == 0,
        "ZERO_BACKWARD",
        "HAS_BACKWARD"
    )
    print(f"Records analyzed: {len(data):,}")

    print("\nSTEP 2: Summarizing feature consistency by backward-traffic group...")
    features = [c for c in GROUP_FEATURES if c in data.columns]
    rows = []
    for group_name, group in data.groupby("traffic_group", sort=False):
        row = {"Traffic group": group_name, "Records": len(group)}
        for col in features:
            values = group[col].replace([np.inf, -np.inf], np.nan).dropna()
            row[f"{col} median"] = values.median() if len(values) else np.nan
            row[f"{col} zero %"] = (values.eq(0).mean() * 100) if len(values) else np.nan
        rows.append(row)

    summary = pd.DataFrame(rows)
    pd.set_option("display.max_columns", None)
    pd.set_option("display.width", 260)
    print(summary.to_string(index=False))

    print("\nSTEP 3: Checking backward-feature consistency for zero-backward records...")
    zero = data[data["traffic_group"] == "ZERO_BACKWARD"].copy()
    checks = [
        ("Total Length of Bwd Packets", "backward bytes"),
        ("Subflow Bwd Packets", "subflow backward packets"),
        ("Subflow Bwd Bytes", "subflow backward bytes"),
        ("Bwd Header Length", "backward header length"),
        ("Bwd Packet Length Max", "maximum backward packet length"),
        ("Bwd Packet Length Min", "minimum backward packet length"),
        ("Bwd Packet Length Mean", "mean backward packet length"),
        ("Bwd Packet Length Std", "backward packet length standard deviation"),
    ]
    for col, description in checks:
        if col not in zero.columns:
            continue
        values = zero[col].replace([np.inf, -np.inf], np.nan).dropna()
        if len(values):
            nonzero = int((values != 0).sum())
            print(f"{description}: nonzero={nonzero:,}/{len(values):,}; min={values.min()}; max={values.max()}")

    print("\nSTEP 4: Missing and infinite values in selected features...")
    missing_rows = []
    for col in features:
        values = data[col]
        missing_rows.append({
            "Feature": col,
            "Missing": int(values.isna().sum()),
            "Infinite": int(np.isinf(values.dropna()).sum()),
        })
    missing_df = pd.DataFrame(missing_rows)
    print(missing_df[missing_df["Missing"].gt(0) | missing_df["Infinite"].gt(0)].to_string(index=False))

    summary_path = REPORT_DIR / "zero_backward_traffic_profile.csv"
    missing_path = REPORT_DIR / "zero_backward_feature_quality.csv"
    summary.to_csv(summary_path, index=False)
    missing_df.to_csv(missing_path, index=False)
    print(f"\nSaved profile: {summary_path}")
    print(f"Saved quality report: {missing_path}")
    print(
        "\nNOTE: These are descriptive diagnostics on the already evaluated "
        "held-out capture. They do not establish causation or independent model performance."
    )
    print("ZERO-BACKWARD TRAFFIC PROFILE COMPLETE.")

if __name__ == "__main__":
    main()
