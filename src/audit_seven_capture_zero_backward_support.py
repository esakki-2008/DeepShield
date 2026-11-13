from pathlib import Path
import pandas as pd
import numpy as np

DATA_DIR = Path("data/processed")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_PER_FILE = 30_000
RANDOM_STATE = 42
HELDOUT_FILE_KEY = "Friday-WorkingHours-Afternoon-DDos"
BACKWARD_COLUMN = "Total Backward Packets"

print("STEP 1: Sampling only the seven training captures...")
frames = []

for file in sorted(DATA_DIR.glob("*.parquet")):
    if HELDOUT_FILE_KEY.lower() in file.name.lower():
        print(f"EXCLUDED HELD-OUT CAPTURE: {file.name}")
        continue

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

print("\nSampled rows:", len(data))
print("BENIGN:", int((data["target"] == 0).sum()))
print("ATTACK:", int((data["target"] == 1).sum()))

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

print("\nSTEP 3: Removing duplicate feature vectors...")
unique = ~clean_hash.duplicated()
clean = clean.loc[unique].copy()
print("Unique training rows:", len(clean))

print("\nSTEP 4: Zero-backward support by attack family in the seven-capture training data...")
summary = (
    clean.groupby(["Label", "target", "backward_group"])
    .size()
    .rename("records")
    .reset_index()
)
pivot = summary.pivot_table(
    index=["Label", "target"],
    columns="backward_group",
    values="records",
    fill_value=0
).reset_index()

for col in ["ZERO_BACKWARD", "HAS_BACKWARD"]:
    if col not in pivot.columns:
        pivot[col] = 0

pivot["total_records"] = pivot["ZERO_BACKWARD"] + pivot["HAS_BACKWARD"]
pivot["zero_backward_pct"] = (
    pivot["ZERO_BACKWARD"] / pivot["total_records"] * 100
).round(2)
pivot["class_name"] = pivot["target"].map({0: "BENIGN", 1: "ATTACK"})
pivot = pivot.sort_values(["target", "Label"])

print(pivot.to_string(index=False))

out_path = REPORT_DIR / "seven_capture_zero_backward_support.csv"
pivot.to_csv(out_path, index=False)

print("\nSaved report:", out_path.resolve())
print("NOTE: This audits seven-capture sampled training support only. It does not train a model or use the held-out Friday DDoS capture for training.")
print("SEVEN-CAPTURE TRAINING SUPPORT AUDIT COMPLETE.")
