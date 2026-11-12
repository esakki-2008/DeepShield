
import pandas as pd
from pathlib import Path

# Dataset folder
data_path = Path("data/raw")

# Find all CSV files
csv_files = list(data_path.glob("*.csv"))

print("Total CSV files:", len(csv_files))

# Inspect each CSV
for file in csv_files:
    print("\n" + "=" * 60)
    print("File:", file.name)

    # Read only 5 rows initially
    df = pd.read_csv(file, nrows=5)

    print("Columns:", len(df.columns))
    print("Column names:")
    print(df.columns.tolist())

    # Find the label column
    label_col = next(
        (col for col in df.columns if col.strip().lower() == "label"),
        None
    )

    if label_col:
        print("Sample labels:")
        print(df[label_col].unique())
