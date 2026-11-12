
from pathlib import Path
import pandas as pd
import pyarrow.parquet as pq

folder = Path("data/processed")
files = sorted(folder.glob("*.parquet"))

total_rows = 0
all_labels = {}

print("DEEPSHIELD PARQUET VERIFICATION\n")

for file in files:
    metadata = pq.ParquetFile(file).metadata
    rows = metadata.num_rows
    total_rows += rows

    labels = pd.read_parquet(file, columns=["Label"])["Label"]
    counts = labels.value_counts()

    for label, count in counts.items():
        all_labels[label] = all_labels.get(label, 0) + int(count)

    print(f"{file.name}")
    print(f"Rows: {rows:,}\n")

print("=" * 40)
print(f"Total files: {len(files)}")
print(f"Total records: {total_rows:,}")

print("\nLABEL DISTRIBUTION")
for label, count in sorted(all_labels.items()):
    print(f"{label}: {count:,}")

print("\nVERIFICATION COMPLETE")
