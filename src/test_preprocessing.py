
import pandas as pd
from pathlib import Path

from preprocessing import clean_features

file = Path(
    "data/raw/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
)

print("Loading dataset...")

df = pd.read_csv(file, nrows=20000)

print("\nOriginal shape:", df.shape)

cleaned = clean_features(df)

print("Cleaned shape:", cleaned.shape)

print("\nColumn names:")
print(cleaned.columns.tolist()[:5])

print("\nAttack label counts:")
print(cleaned["Label"].value_counts())

print("\nMissing values:", cleaned.isnull().sum().sum())

print(
    "\nInfinite values:",
    cleaned.select_dtypes(include="number")
    .isin([float("inf"), float("-inf")]).sum().sum()
)

print("\nPreprocessing test completed!")
