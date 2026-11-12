
import pandas as pd
from pathlib import Path

file = Path(
    "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

df = pd.read_csv(file, nrows=10000)

df.columns = df.columns.str.strip()

print("Dataset shape:", df.shape)

print("\nMissing values:")
print(df.isnull().sum().sort_values(ascending=False).head(10))

print("\nDuplicate rows:", df.duplicated().sum())

print("\nInfinite values:")
numeric_df = df.select_dtypes(include="number")
print(numeric_df.isin([float("inf"), float("-inf")]).sum().sum())

print("\nData types:")
print(df.dtypes.value_counts())
