
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

        df["Label"] = (
            df["Label"]
            .str.replace("\ufffd", "-", regex=False)
            .str.replace("\u00ef\u00bf\xbd", "-", regex=False)
        )

        label_mapping = {
            "Web Attack - Brute Force": "Web Attack - Brute Force",
            "Web Attack - XSS": "Web Attack - XSS",
            "Web Attack - Sql Injection": "Web Attack - Sql Injection",
        }

        df["Label"] = df["Label"].replace(label_mapping)

    return df
