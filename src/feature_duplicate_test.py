
import pandas as pd
import numpy as np

file = "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

print("Loading 50,000 records...")

df = pd.read_csv(file, nrows=50000)
df.columns = df.columns.str.strip()

# Separate features and labels
X = df.drop(columns=["Label"])
y = df["Label"].astype("string").str.strip()

# Replace infinite values
X = X.replace([np.inf, -np.inf], np.nan)

# Hash features WITHOUT the label
feature_hashes = pd.util.hash_pandas_object(
    X,
    index=False
)

# Check repeated feature vectors
duplicate_features = feature_hashes.duplicated()

# Check whether identical features have different labels
audit = pd.DataFrame({
    "feature_hash": feature_hashes,
    "label": y
})

label_counts = audit.groupby(
    "feature_hash"
)["label"].nunique()

conflicting_hashes = label_counts[label_counts > 1]

print("\nFEATURE DUPLICATE AUDIT")
print("Total records:", len(df))
print("Repeated feature rows:", duplicate_features.sum())
print("Feature groups with conflicting labels:", len(conflicting_hashes))

print("\nAttack label distribution:")
print(y.value_counts())
