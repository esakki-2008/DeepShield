
import pandas as pd
import numpy as np
from pathlib import Path

DATA_PATH = Path("data/raw")
CHUNK_SIZE = 100_000

csv_files = list(DATA_PATH.glob("*.csv"))

print("=" * 60)
print("       DEEPSHIELD - DATASET ANALYSIS")
print("=" * 60)

for file in csv_files:

    print(f"\nAnalyzing: {file.name}")

    total_rows = 0
    label_counts = {}
    missing_values = {}
    infinite_values = {}

    # Read large files in smaller chunks
    for chunk in pd.read_csv(file, chunksize=CHUNK_SIZE):

        # Remove extra spaces from column names
        chunk.columns = chunk.columns.str.strip()

        total_rows += len(chunk)

        # Count attack labels
        if "Label" in chunk.columns:
            counts = chunk["Label"].astype(str).str.strip().value_counts()

            for label, count in counts.items():
                label_counts[label] = (
                    label_counts.get(label, 0) + count
                )

        # Count missing values
        missing = chunk.isna().sum()

        for column, count in missing.items():
            missing_values[column] = (
                missing_values.get(column, 0) + count
            )

        # Count infinite numeric values
        numeric = chunk.select_dtypes(include=np.number)

        infinite = np.isinf(numeric).sum()

        for column, count in infinite.items():
            infinite_values[column] = (
                infinite_values.get(column, 0) + count
            )

    print("\nTotal records:", f"{total_rows:,}")

    print("\nAttack distribution:")
    for label, count in sorted(label_counts.items()):
        print(f"{label}: {count:,}")

    print("\nColumns with missing values:")
    print({
        col: count
        for col, count in missing_values.items()
        if count > 0
    })

    print("\nColumns with infinite values:")
    print({
        col: count
        for col, count in infinite_values.items()
        if count > 0
    })

print("\nEDA completed!")
