
import pandas as pd
from pathlib import Path
from collections import Counter

DATA_PATH = Path("data/raw")
CHUNK_SIZE = 100_000

seen_hashes = set()
duplicate_by_label = Counter()
total_rows = 0
duplicate_count = 0

for file in DATA_PATH.glob("*.csv"):

    print(f"\nAnalyzing: {file.name}")

    for chunk in pd.read_csv(
        file,
        chunksize=CHUNK_SIZE,
        dtype="string",
        keep_default_na=False
    ):

        chunk.columns = chunk.columns.str.strip()

        labels = chunk["Label"].str.strip()

        # Generate hashes for complete records
        hashes = pd.util.hash_pandas_object(
            chunk,
            index=False
        )

        # Count repeated records by attack category
        for row_hash, label in zip(hashes, labels):

            if row_hash in seen_hashes:
                duplicate_by_label[label] += 1
                duplicate_count += 1
            else:
                seen_hashes.add(row_hash)

        total_rows += len(chunk)

    print("Total records processed:", f"{total_rows:,}")

print("\n" + "=" * 55)
print("DEEPSHIELD - DUPLICATE ANALYSIS BY ATTACK")
print("=" * 55)

for label, count in duplicate_by_label.most_common():
    print(f"{label}: {count:,}")

print("\nTotal records:", f"{total_rows:,}")
print("Total duplicates:", f"{duplicate_count:,}")
print("Unique records:", f"{len(seen_hashes):,}")
