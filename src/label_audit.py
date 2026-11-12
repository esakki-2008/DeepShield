
import pandas as pd
from pathlib import Path
from collections import Counter

DATA_PATH = Path("data/raw")
label_counts = Counter()

for file in DATA_PATH.glob("*.csv"):
    print(f"\nReading: {file.name}")

    for chunk in pd.read_csv(
        file,
        usecols=lambda col: col.strip() == "Label",
        chunksize=100_000
    ):
        labels = chunk.iloc[:, 0].astype("string").str.strip()
        label_counts.update(labels.value_counts().to_dict())

print("\n" + "=" * 50)
print("DEEPSHIELD - COMPLETE ATTACK LABEL SUMMARY")
print("=" * 50)

for label, count in label_counts.most_common():
    print(f"{repr(label)} : {count:,}")

print("\nTotal records:", f"{sum(label_counts.values()):,}")
