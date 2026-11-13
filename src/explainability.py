from pathlib import Path

import joblib
import pandas as pd
import matplotlib.pyplot as plt
import shap

MODEL_PATH = Path("models/multiclass_xgboost.joblib")
DATA_DIR = Path("data/processed")
DATA_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.parquet"
OUTPUT_DIR = Path("reports/figures")
SAMPLE_SIZE = 200
RANDOM_STATE = 42

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("STEP 1: Loading trained multiclass model...")
saved = joblib.load(MODEL_PATH)
model = saved["model"]
encoder = saved["encoder"]
features = saved["features"]
print("Model loaded successfully.")

print("\nSTEP 2: Loading actual labelled DDoS records...")
data = pd.read_parquet(DATA_DIR / DATA_FILE)
data.columns = data.columns.str.strip()

ddos_data = data.loc[data["Label"].astype("string").str.strip() == "DDoS"].copy()
if ddos_data.empty:
    raise ValueError("No rows labelled DDoS were found in the selected capture.")

sample = ddos_data.sample(
    n=min(SAMPLE_SIZE, len(ddos_data)),
    random_state=RANDOM_STATE
)
X = sample[features].copy()
X = X.replace([float("inf"), float("-inf")], float("nan"))

print(f"Total labelled DDoS records in capture: {len(ddos_data):,}")
print(f"Records selected for explanation: {len(X):,}")

print("\nSTEP 3: Checking model predictions on these DDoS records...")
predicted_ids = model.predict(X).astype(int)
predicted_labels = encoder.inverse_transform(predicted_ids)
ddos_predictions = int((predicted_labels == "DDoS").sum())
print(f"Predicted as DDoS: {ddos_predictions:,}/{len(X):,} ({ddos_predictions / len(X):.2%})")

class_name = "DDoS"
class_index = int(encoder.transform([class_name])[0])

print("\nSTEP 4: Calculating SHAP values for the DDoS output...")
explainer = shap.TreeExplainer(model)
shap_values = explainer(X)
class_shap = shap_values[:, :, class_index]
print("SHAP calculation complete.")

print("\nSTEP 5: Saving feature-importance explanation...")
bar_path = OUTPUT_DIR / "shap_ddos_explanation.png"
shap.plots.bar(class_shap, max_display=15, show=False)
plt.title("Top Features Influencing DDoS Class Output")
plt.tight_layout()
plt.savefig(bar_path, dpi=300, bbox_inches="tight")
plt.close()

print("\nSTEP 6: Saving per-record SHAP distribution...")
beeswarm_path = OUTPUT_DIR / "shap_ddos_beeswarm.png"
shap.plots.beeswarm(class_shap, max_display=15, show=False)
plt.title("SHAP Distribution for Actual DDoS Records")
plt.tight_layout()
plt.savefig(beeswarm_path, dpi=300, bbox_inches="tight")
plt.close()

print("\nSaved explanations:")
print(bar_path)
print(beeswarm_path)
print("\nNote: SHAP explains the model's DDoS-class output for labelled DDoS records. It does not establish causation or prove real-world attack detection.")
print("\nDEEPSHIELD DDoS EXPLAINABILITY COMPLETE!")
