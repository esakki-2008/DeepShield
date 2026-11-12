
import json
import pandas as pd
from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

csv_path = Path("data/processed/api_test_ddos_5000.csv")
json_path = Path("data/processed/api_response.json")

df = pd.read_csv(csv_path, low_memory=False)

# Find the actual label column, even if it has extra spaces.
label_col = next(
    (c for c in df.columns if c.strip().lower() == "label"),
    None
)

if label_col is None:
    raise ValueError("Label column not found in CSV.")

with open(json_path, encoding="utf-8") as f:
    result = json.load(f)

predictions = result["predictions"]

if len(df) != len(predictions):
    raise ValueError("CSV and API prediction counts do not match.")

actual = (
    df[label_col]
    .astype(str)
    .str.strip()
    .str.upper()
    .ne("BENIGN")
    .astype(int)
)

predicted = pd.Series([
    1 if row["prediction"] == "ATTACK" else 0
    for row in predictions
])

print("\n===== DEEPSHIELD API EVALUATION =====")
print("Total records:", len(df))
print("Accuracy:", round(accuracy_score(actual, predicted), 4))
print("Precision:", round(precision_score(actual, predicted, zero_division=0), 4))
print("Recall:", round(recall_score(actual, predicted, zero_division=0), 4))
print("F1 Score:", round(f1_score(actual, predicted, zero_division=0), 4))

print("\nConfusion Matrix:")
print(confusion_matrix(actual, predicted))

print("\nClassification Report:")
print(classification_report(
    actual,
    predicted,
    target_names=["BENIGN", "ATTACK"],
    zero_division=0
))
