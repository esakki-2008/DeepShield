
from pathlib import Path
import pandas as pd

path = Path("reports/heldout_false_negatives.csv")
df = pd.read_csv(path)

print("\n========== FALSE NEGATIVE INVESTIGATION ==========")

print("\n1. Probability statistics")
print(df["attack_probability"].describe(
    percentiles=[0.25, 0.50, 0.75, 0.90, 0.95, 0.99]
))

print("\n2. Lowest probability examples")
print(
    df[["true_label", "attack_probability", "predicted_label"]]
    .head(10)
    .to_string(index=False)
)

print("\n3. Features with most missing values")
missing = df.isna().sum().sort_values(ascending=False)
print(missing.head(15).to_string())

print("\n4. Features with highest standard deviation")
numeric = df.select_dtypes(include="number")
variation = numeric.std().sort_values(ascending=False)
print(variation.head(20).to_string())

print("\n5. Attack probability distribution")
print(
    pd.cut(
        df["attack_probability"],
        bins=[0, 0.01, 0.05, 0.10, 0.20, 0.30, 0.40, 0.50]
    ).value_counts(sort=False).to_string()
)

print("\nINVESTIGATION COMPLETE")
