from pathlib import Path
import joblib
import pandas as pd

MODEL_PATH = Path("models/binary_xgboost.joblib")

print("Loading binary model...")

saved = joblib.load(MODEL_PATH)

model = saved["model"]
features = saved["features"]

print("\nMODEL INFORMATION")
print("-----------------")
print("Model:", type(model).__name__)
print("Total features:", len(features))

# Get feature importance
importance = model.feature_importances_

importance_df = pd.DataFrame({
    "Feature": features,
    "Importance": importance
})

importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
)

print("\nTOP 20 IMPORTANT FEATURES")
print("-------------------------")
print(importance_df.head(20).to_string(index=False))

# Save results
output_path = Path("reports/binary_feature_importance.csv")
output_path.parent.mkdir(parents=True, exist_ok=True)

importance_df.to_csv(output_path, index=False)

print("\nFeature importance saved:", output_path)
print("\nMODEL INSPECTION COMPLETE!")