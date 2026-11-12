
import pandas as pd
import numpy as np


def clean_features(df):
    """Clean network traffic feature values."""

    df = df.copy()

    # Remove extra spaces from column names
    df.columns = df.columns.str.strip()

    # Convert infinite values into missing values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Normalize attack labels
    if "Label" in df.columns:
        df["Label"] = df["Label"].astype("string").str.strip()

        label_mapping = {
            "Web Attack � Brute Force": "Web Attack - Brute Force",
            "Web Attack � XSS": "Web Attack - XSS",
            "Web Attack � Sql Injection": "Web Attack - Sql Injection",
        }

        df["Label"] = df["Label"].replace(label_mapping)

    return df


# Test the cleaning function
sample = pd.DataFrame({
    " Flow Bytes/s ": [100.0, np.inf, 300.0],
    " Total Fwd Packets ": [10, 20, 30],
    " Label ": ["BENIGN", "DDoS", "Web Attack � XSS"]
})

cleaned = clean_features(sample)

print("Before cleaning:")
print(sample)

print("\nAfter cleaning:")
print(cleaned)

print("\nRemaining infinite values:")
print(np.isinf(
    cleaned.select_dtypes(include="number")
).sum().sum())

print("\nMissing values:")
print(cleaned.isnull().sum())
