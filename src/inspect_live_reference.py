
from pathlib import Path
import pandas as pd
import numpy as np

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data" / "processed"

files = sorted(DATA_DIR.glob("*.parquet"))

checks = [
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Min",
    "Fwd IAT Min",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward"
]

print("DEEPSHIELD - DATASET FEATURE AUDIT")
print("=" * 90)

for file in files:
    df = pd.read_parquet(file, columns=checks)

    print(f"\nFILE: {file.name}")
    print("Rows:", len(df))

    for col in checks:
        series = df[col]

        print(
            f"{col:30} "
            f"missing={series.isna().sum():8} "
            f"negative={(series < 0).sum():8} "
            f"infinite={np.isinf(series).sum():8}"
        )

print("\nAudit completed.")
