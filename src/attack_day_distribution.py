
import pandas as pd
from pathlib import Path

DATA_PATH = Path("data/raw")

for file in sorted(DATA_PATH.glob("*.csv")):

    labels = pd.read_csv(
        file,
        usecols=lambda col: col.strip() == "Label",
        dtype="string"
    )

    labels.columns = labels.columns.str.strip()
    labels["Label"] = labels["Label"].str.strip()

    print("\n" + "=" * 55)
    print(file.name)
    print("=" * 55)

    print(labels["Label"].value_counts().to_string())
