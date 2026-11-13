from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
REPORT_DIR = BASE_DIR / "reports"

FN_FILE = REPORT_DIR / "heldout_false_negatives.csv"
TP_FILE = REPORT_DIR / "heldout_true_positives.csv"

FEATURES = [
    "Total Backward Packets",
    "Total Length of Bwd Packets",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
]

def load_group(path: Path, group_name: str) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Missing report: {path}")
    df = pd.read_csv(path)
    available = [c for c in FEATURES if c in df.columns]
    if not available:
        raise ValueError(f"No expected traffic features found in {path.name}")
    for col in available:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df["Group"] = group_name
    return df

def main():
    print("STEP 1: Loading held-out false negatives and true positives...")
    fn = load_group(FN_FILE, "False Negatives")
    tp = load_group(TP_FILE, "True Positives")
    print(f"False negatives: {len(fn):,}")
    print(f"True positives:  {len(tp):,}")

    common = [c for c in FEATURES if c in fn.columns and c in tp.columns]
    combined = pd.concat([fn, tp], ignore_index=True)

    print("\nSTEP 2: Measuring zero and low backward-traffic rates...")
    rows = []
    for group_name, group in combined.groupby("Group", sort=False):
        row = {"Group": group_name, "Records": len(group)}
        for col in common:
            values = group[col]
            valid = values.notna()
            row[f"{col} - zero %"] = round((values[valid] == 0).mean() * 100, 2) if valid.any() else None
            row[f"{col} - median"] = values.median()
        rows.append(row)

    summary = pd.DataFrame(rows)
    pd.set_option("display.max_columns", None)
    pd.set_option("display.width", 220)
    print(summary.to_string(index=False))

    print("\nSTEP 3: Backward packet count distribution...")
    backward_col = "Total Backward Packets"
    if backward_col in common:
        for group_name, group in combined.groupby("Group", sort=False):
            values = group[backward_col].dropna()
            print(f"\n{group_name}:")
            print(f"  Exactly zero: {(values == 0).sum():,} ({(values == 0).mean() * 100:.2f}%)")
            print(f"  At most 1:    {(values <= 1).sum():,} ({(values <= 1).mean() * 100:.2f}%)")
            print(f"  At most 5:    {(values <= 5).sum():,} ({(values <= 5).mean() * 100:.2f}%)")
            print(f"  Median:       {values.median():.2f}")
            print(f"  90th pct:     {values.quantile(0.90):.2f}")

    output = REPORT_DIR / "backward_traffic_comparison.csv"
    summary.to_csv(output, index=False)
    print(f"\nSaved summary: {output}")
    print("BACKWARD TRAFFIC ANALYSIS COMPLETE.")

if __name__ == "__main__":
    main()
