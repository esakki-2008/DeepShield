
from pathlib import Path

import joblib
import pandas as pd
import matplotlib.pyplot as plt
import shap

# Paths
MODEL_PATH = Path("models/multiclass_xgboost.joblib")
DATA_DIR = Path("data/processed")
OUTPUT_DIR = Path("reports/figures")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("STEP 1: Loading trained model...")

saved = joblib.load(MODEL_PATH)

model = saved["model"]
encoder = saved["encoder"]
features = saved["features"]

print("Model loaded successfully!")

# Load a small sample for explanation
print("\nSTEP 2: Loading network traffic sample...")

data = pd.read_parquet(
    DATA_DIR / "Wednesday-workingHours.pcap_ISCX.parquet"
)

data.columns = data.columns.str.strip()

X = data[features].sample(
    n=min(200, len(data)),
    random_state=42
)

X = X.replace([float("inf"), float("-inf")], float("nan"))

print("Explanation records:", len(X))

# Explain predictions for the selected sample
print("\nSTEP 3: Calculating SHAP values...")

explainer = shap.TreeExplainer(model)

shap_values = explainer(X)

print("SHAP calculation complete!")

# Explain the DDoS class
class_name = "DDoS"
class_index = int(encoder.transform([class_name])[0])

print(f"\nSTEP 4: Explaining {class_name} predictions...")

class_shap = shap_values[:, :, class_index]

plt.figure()

shap.plots.bar(
    class_shap,
    max_display=15,
    show=False
)

plt.title(f"Top Features Influencing {class_name} Detection")
plt.tight_layout()

output_file = OUTPUT_DIR / "shap_ddos_explanation.png"

plt.savefig(
    output_file,
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print("\nSHAP explanation saved:")
print(output_file)

print("\nDEEPSHIELD EXPLAINABILITY COMPLETE!")
