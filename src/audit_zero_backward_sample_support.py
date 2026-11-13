from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

DATA_DIR = Path("data/processed")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_PER_FILE = 30_000
RANDOM_STATE = 42
BACKWARD_COLUMN = "Total Backward Packets"

print("STEP 1: Reproducing the exact per-file sampling used by train_binary.py...")
frames = []

for file in sorted(DATA_DIR.glob("*.parquet")):
    df = pd.read_parquet(file)

    if BACKWARD_COLUMN not in df.columns:
        raise ValueError(f"Missing required column: {BACKWARD_COLUMN}")

    if len(df) > SAMPLE_PER_FILE:
        df = df.sample(n=SAMPLE_PER_FILE, random_state=RANDOM_STATE)

    df = df.copy()
    df["source_file"] = file.name
    frames.append(df)
    print(f"{file.name}: {len(df):,} sampled rows")

data = pd.concat(frames, ignore_index=True)
data.columns = data.columns.str.strip()

data["Label"] = data["Label"].astype("string").str.strip()
data["target"] = data["Label"].ne("BENIGN").astype("int8")
data["backward_group"] = np.where(
    pd.to_numeric(data[BACKWARD_COLUMN], errors="coerce").fillna(0).eq(0),
    "ZERO_BACKWARD",
    "HAS_BACKWARD"
)

def summarize(frame, stage):
    result = (
        frame.groupby(["source_file", "Label", "target", "backward_group"], dropna=False)
        .size()
        .rename("records")
        .reset_index()
    )
    result["stage"] = stage
    return result

reports = [summarize(data, "sampled_before_cleaning")]
print("\nSampled records:", len(data))
print("Sampled BENIGN:", int((data["target"] == 0).sum()))
print("Sampled ATTACK:", int((data["target"] == 1).sum()))

print("\nSTEP 2: Applying the same conflicting-hash removal...")
feature_columns = [
    c for c in data.columns
    if c not in ["Label", "target", "source_file", "backward_group"]
]
X = data[feature_columns].replace([np.inf, -np.inf], np.nan)
y = data["target"]
feature_hash = pd.util.hash_pandas_object(X, index=False)

group_info = pd.DataFrame({
    "feature_hash": feature_hash.to_numpy(),
    "target": y.to_numpy()
})
conflicts = group_info.groupby("feature_hash")["target"].nunique()
conflicting_hashes = conflicts[conflicts > 1].index
keep = ~feature_hash.isin(conflicting_hashes)

clean = data.loc[keep].copy()
clean_hash = feature_hash.loc[keep]
print("Conflicting feature groups removed:", len(conflicting_hashes))
reports.append(summarize(clean, "after_conflict_removal"))

print("\nSTEP 3: Applying the same duplicate-feature removal...")
unique = ~clean_hash.duplicated()
clean = clean.loc[unique].copy()
print("Unique rows after cleaning:", len(clean))
reports.append(summarize(clean, "after_deduplication"))

print("\nSTEP 4: Reproducing the same stratified 80/20 train-test split...")
train, test = train_test_split(
    clean,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=clean["target"]
)

print("Training rows:", len(train))
print("Testing rows:", len(test))
reports.append(summarize(train, "actual_training_split"))
reports.append(summarize(test, "random_test_split"))

combined = pd.concat(reports, ignore_index=True)
combined_path = REPORT_DIR / "zero_backward_sample_support_detail.csv"
combined.to_csv(combined_path, index=False)

summary = (
    combined.groupby(["stage", "target", "Label", "backward_group"], dropna=False)["records"]
    .sum()
    .reset_index()
)
summary["class_name"] = summary["target"].map({0: "BENIGN", 1: "ATTACK"})
summary_path = REPORT_DIR / "zero_backward_sample_support_summary.csv"
summary.to_csv(summary_path, index=False)

print("\nSTEP 5: Actual model training sample support...")
training_summary = summary[summary["stage"] == "actual_training_split"]
print(training_summary.to_string(index=False))

print("\nSaved detailed report:", combined_path.resolve())
print("Saved summary report:", summary_path.resolve())
print("\nIMPORTANT: This reproduces the sampling, conflict removal, deduplication, and split logic. It does not train or modify any model.")
print("SAMPLE-LEVEL SUPPORT AUDIT COMPLETE.")
