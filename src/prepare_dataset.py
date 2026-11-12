
from pathlib import Path
import pandas as pd
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

RAW_DIR = Path("data/raw")
OUTPUT_DIR = Path("data/processed")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 100_000

label_mapping = {
    "Web Attack � Brute Force": "Web Attack - Brute Force",
    "Web Attack � XSS": "Web Attack - XSS",
    "Web Attack � Sql Injection": "Web Attack - Sql Injection",
}

total_rows = 0

for csv_file in sorted(RAW_DIR.glob("*.csv")):
    output_file = OUTPUT_DIR / f"{csv_file.stem}.parquet"

    print(f"\nProcessing: {csv_file.name}")

    writer = None
    file_rows = 0

    try:
        for chunk in pd.read_csv(csv_file, chunksize=CHUNK_SIZE):
            chunk.columns = chunk.columns.str.strip()

            chunk["Label"] = (
                chunk["Label"]
                .astype("string")
                .str.strip()
                .replace(label_mapping)
            )

            chunk = chunk.replace([np.inf, -np.inf], np.nan)
            chunk["source_file"] = csv_file.name

            table = pa.Table.from_pandas(
                chunk,
                preserve_index=False
            )

            if writer is None:
                writer = pq.ParquetWriter(output_file, table.schema)

            writer.write_table(table)

            file_rows += len(chunk)
            total_rows += len(chunk)

        print(f"Rows saved: {file_rows:,}")

    finally:
        if writer is not None:
            writer.close()

print("\nDATASET PREPARATION COMPLETE")
print(f"Total rows: {total_rows:,}")
print(f"Parquet folder: {OUTPUT_DIR}")
