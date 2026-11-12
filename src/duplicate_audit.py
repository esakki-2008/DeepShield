
import pandas as pd
from pathlib import Path

DATA_PATH = Path("data/raw")
CHUNK_SIZE = 100_000

seen_hashes = set()
total_rows = 0
duplicate_count = 0

for file in DATA_PATH.glob("*.csv"):

    print(f"\nChecking: {file.name}")

    for chunk in pd.read_csv(
        file,
        chunksize=CHUNK_SIZE,
        dtype="string",
        keep_default_na=False
    ):

        chunk.columns = chunk.columns.str.strip()

        # Generate a hash for every complete row
        hashes = pd.util.hash_pandas_object(
            chunk,
            index=False
        )

        for value in hashes:
            if value in seen_hashes:
                duplicate_count += 1
            else:
                seen_hashes.add(value)

        total_rows += len(chunk)

    print("Rows processed:", f"{total_rows:,}")
    print("Duplicates found so far:", f"{duplicate_count:,}")

print("\n" + "=" * 45)
print("DEEPSHIELD DUPLICATE AUDIT")
print("=" * 45)

print("Total records:", f"{total_rows:,}")
print("Duplicate records:", f"{duplicate_count:,}")
print("Unique row hashes:", f"{len(seen_hashes):,}")
