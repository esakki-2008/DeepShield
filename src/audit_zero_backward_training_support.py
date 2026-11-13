from pathlib import Path

import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data" / "processed"
REPORT_DIR = BASE_DIR / "reports"

TEST_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.parquet"
BACKWARD_FEATURE = "Total Backward Packets"
LABEL_FEATURE = "Label"

def summarize_file(path: Path) -> pd.DataFrame:
    print(f"Reading {path.name} ...")
    frame = pd.read_parquet(path, columns=[LABEL_FEATURE, BACKWARD_FEATURE])
    frame[LABEL_FEATURE] = frame[LABEL_FEATURE].astype("string").str.strip()
    frame[BACKWARD_FEATURE] = pd.to_numeric(
        frame[BACKWARD_FEATURE], errors="coerce"
    )
    frame["backward_group"] = np.where(
        frame[BACKWARD_FEATURE].eq(0),
        "ZERO_BACKWARD",
        "HAS_BACKWARD"
    )
    summary = (
        frame.groupby([LABEL_FEATURE, "backward_group"], dropna=False)
        .size()
        .rename("records")
        .reset_index()
    )
    summary["source_file"] = path.name
    return summary

def main():
    files = sorted(DATA_DIR.glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No Parquet files found in {DATA_DIR}")

    print("STEP 1: Scanning all CIC-IDS2017 capture files...")
    summaries = []
    for path in files:
        summaries.append(summarize_file(path))

    detail = pd.concat(summaries, ignore_index=True)

    print("\nSTEP 2: Calculating zero-backward percentages by capture and label...")
    totals = (
        detail.groupby(["source_file", LABEL_FEATURE])["records"]
        .sum()
        .rename("label_total")
        .reset_index()
    )
    detail = detail.merge(
        totals, on=["source_file", LABEL_FEATURE], how="left"
    )
    detail["percentage_within_label"] = (
        detail["records"] / detail["label_total"] * 100
    ).round(2)

    pivot = detail.pivot_table(
        index=["source_file", LABEL_FEATURE],
        columns="backward_group",
        values="records",
        aggfunc="sum",
        fill_value=0
    ).reset_index()

    for col in ["ZERO_BACKWARD", "HAS_BACKWARD"]:
        if col not in pivot.columns:
            pivot[col] = 0

    pivot["total_records"] = pivot["ZERO_BACKWARD"] + pivot["HAS_BACKWARD"]
    pivot["zero_backward_pct"] = (
        pivot["ZERO_BACKWARD"] / pivot["total_records"] * 100
    ).round(2)

    pd.set_option("display.max_rows", 200)
    pd.set_option("display.width", 220)
    print(pivot.to_string(index=False))

    print("\nSTEP 3: Summarizing attack-family support in training captures...")
    training = pivot[pivot["source_file"].ne(TEST_FILE)].copy()
    attack_training = training[training[LABEL_FEATURE].ne("BENIGN")]
    if attack_training.empty:
        print("No attack labels found in the seven training captures.")
    else:
        print(
            attack_training[
                [LABEL_FEATURE, "total_records", "ZERO_BACKWARD", "zero_backward_pct"]
            ]
            .groupby(LABEL_FEATURE, as_index=False)
            .sum(numeric_only=True)
            .to_string(index=False)
        )

    print("\nSTEP 4: Comparing held-out Friday DDoS with training support...")
    heldout = pivot[
        pivot["source_file"].eq(TEST_FILE)
        & pivot[LABEL_FEATURE].eq("DDoS")
    ]
    if not heldout.empty:
        print(heldout.to_string(index=False))
    else:
        print("Expected DDoS label not found in the held-out capture.")

    out_detail = REPORT_DIR / "backward_traffic_by_capture_and_label.csv"
    out_pivot = REPORT_DIR / "backward_traffic_training_support.csv"
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    detail.to_csv(out_detail, index=False)
    pivot.to_csv(out_pivot, index=False)

    print(f"\nSaved detailed report: {out_detail}")
    print(f"Saved summary report:  {out_pivot}")
    print(
        "\nNOTE: This is a dataset-support audit. It measures how often "
        "zero-backward flows occur in each capture and label; it does not "
        "evaluate a newly trained model."
    )
    print("TRAINING SUPPORT AUDIT COMPLETE.")

if __name__ == "__main__":
    main()
