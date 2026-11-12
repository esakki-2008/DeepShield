
import pandas as pd
import numpy as np
from pathlib import Path

DATA_PATH = Path("data/raw")
CHUNK_SIZE = 100_000

total_rows = 0
total_missing = 0
total_infinite = 0

for file in DATA_PATH.glob("*.csv"):
    print(f"\nChecking: {file.name}")

    file_rows = 0
    missing_count = 0
    infinite_count = 0

    for chunk in pd.read_csv(file, chunksize=CHUNK_SIZE):
        chunk.columns = chunk.columns.str.strip()

        file_rows += len(chunk)

        numeric = chunk.select_dtypes(include="number")

        missing_count += chunk.isnull().sum().sum()

        infinite_count += np.isinf(numeric).sum().sum()

    total_rows += file_rows
    total_missing += missing_count
    total_infinite += infinite_count

    print("Rows:", f"{file_rows:,}")
    print("Missing values:", f"{missing_count:,}")
    print("Infinite values:", f"{infinite_count:,}")

print("\n" + "=" * 45)
print("COMPLETE DATASET QUALITY SUMMARY")
print("=" * 45)

print("Total rows:", f"{total_rows:,}")
print("Total missing values:", f"{total_missing:,}")
print("Total infinite values:", f"{total_infinite:,}")
