
import pandas as pd
from pathlib import Path
from collections import defaultdict

DATA_PATH = Path("data/raw")
CHUNK_SIZE = 100_000

seen = {}
cross_file_duplicates = defaultdict(int)

for file in DATA_PATH.glob("*.csv"):

    print(f"\nChecking: {file.name}")

    for chunk in pd.read_csv(
        file,
        chunksize=CHUNK_SIZE,
        dtype="string",
        keep_default_na=False
    ):

        chunk.columns = chunk.columns.str.strip()

        hashes = pd.util.hash_pandas_object(
            chunk,
            index=False
        )

        for row_hash in hashes:

            if row_hash in seen:
                previous_file = seen[row_hash]

                if previous_file != file.name:
                    cross_file_duplicates[
                        (previous_file, file.name)
                    ] += 1

            else:
                seen[row_hash] = file.name

print("\nCROSS-FILE DUPLICATES")
print("=" * 55)

for files, count in sorted(
    cross_file_duplicates.items(),
    key=lambda x: x[1],
    reverse=True
):
    print(f"{files[0]} <-> {files[1]}: {count:,}")

print("\nTotal cross-file duplicate pairs:",
      f"{sum(cross_file_duplicates.values()):,}")
