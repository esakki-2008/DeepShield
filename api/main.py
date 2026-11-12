
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from fastapi import FastAPI, File, HTTPException, UploadFile


# --------------------------------------------------
# PATHS AND MODEL LOADING
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_DIR = BASE_DIR / "models"

binary_bundle = joblib.load(MODEL_DIR / "binary_xgboost.joblib")
multiclass_bundle = joblib.load(MODEL_DIR / "multiclass_xgboost.joblib")
anomaly_bundle = joblib.load(MODEL_DIR / "calibrated_hybrid_detector.joblib")

binary_model = binary_bundle["model"]
multiclass_model = multiclass_bundle["model"]
label_encoder = multiclass_bundle["encoder"]

anomaly_imputer = anomaly_bundle["imputer"]
anomaly_scaler = anomaly_bundle["scaler"]
isolation_model = anomaly_bundle["isolation_model"]

FEATURES = binary_bundle["features"]
MULTICLASS_FEATURES = multiclass_bundle["features"]
ANOMALY_FEATURES = anomaly_bundle["features"]

SUPERVISED_THRESHOLD = 0.50
ANOMALY_THRESHOLD = float(anomaly_bundle["anomaly_threshold"])

if FEATURES != MULTICLASS_FEATURES or FEATURES != ANOMALY_FEATURES:
    raise RuntimeError("The three models do not have matching feature orders.")


# --------------------------------------------------
# FASTAPI APPLICATION
# --------------------------------------------------

app = FastAPI(
    title="DeepShield API",
    description="AI-powered network intrusion detection and threat analytics",
    version="1.0.0"
)


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "project": "DeepShield",
        "status": "running",
        "message": "Network Intrusion Detection API is ready"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "binary_model": "loaded",
        "multiclass_model": "loaded",
        "anomaly_model": "loaded",
        "features_required": len(FEATURES)
    }


# --------------------------------------------------
# CSV PREDICTION
# --------------------------------------------------

@app.post("/predict")
async def predict(file: UploadFile = File(...)):

    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a CSV file."
        )

    try:
        df = pd.read_csv(file.file)
    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Could not read CSV: {str(error)}"
        )

    if df.empty:
        raise HTTPException(
            status_code=400,
            detail="The uploaded CSV is empty."
        )

    if len(df) > 50000:
        raise HTTPException(
            status_code=413,
            detail="Maximum upload size is 50,000 rows per request."
        )

    # Clean column names
    df.columns = df.columns.astype(str).str.strip()

    if df.columns.duplicated().any():
        raise HTTPException(
            status_code=400,
            detail="CSV contains duplicate column names."
        )

    # Check required model features
    missing_features = [
        feature for feature in FEATURES
        if feature not in df.columns
    ]

    if missing_features:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Required network-flow features are missing.",
                "missing_features": missing_features,
                "required_feature_count": len(FEATURES)
            }
        )

    # Keep features in the exact training order
    X = df[FEATURES].copy()

    # Convert values to numeric
    for column in FEATURES:
        X[column] = pd.to_numeric(X[column], errors="coerce")

    # Replace infinity with missing values
    X = X.replace([np.inf, -np.inf], np.nan)

    # --------------------------------------------------
    # 1. BINARY CLASSIFICATION
    # --------------------------------------------------

    binary_probabilities = binary_model.predict_proba(X)

    attack_class_index = list(binary_model.classes_).index(1)
    attack_probabilities = binary_probabilities[:, attack_class_index]

    predictions = (
        attack_probabilities >= SUPERVISED_THRESHOLD
    ).astype(int)

    # --------------------------------------------------
    # 2. MULTICLASS CLASSIFICATION
    # --------------------------------------------------

    attack_indices = np.where(predictions == 1)[0]

    attack_families = np.full(
        len(X),
        "BENIGN",
        dtype=object
    )

    if len(attack_indices) > 0:
        attack_X = X.iloc[attack_indices]

        multiclass_predictions = multiclass_model.predict(attack_X)

        predicted_labels = label_encoder.inverse_transform(
            multiclass_predictions.astype(int)
        )

        attack_families[attack_indices] = predicted_labels

    # --------------------------------------------------
    # 3. ISOLATION FOREST ANOMALY DETECTION
    # --------------------------------------------------

    anomaly_X = X[ANOMALY_FEATURES]

    imputed_X = anomaly_imputer.transform(anomaly_X)
    scaled_X = anomaly_scaler.transform(imputed_X)

    # Higher score means more anomalous
    anomaly_scores = -isolation_model.decision_function(scaled_X)

    anomaly_flags = anomaly_scores > ANOMALY_THRESHOLD

    # --------------------------------------------------
    # 4. BUILD RESULTS
    # --------------------------------------------------

    results = []

    for i in range(len(X)):

        is_attack = bool(predictions[i])

        results.append({
            "row_number": i + 1,
            "prediction": "ATTACK" if is_attack else "BENIGN",
            "attack_probability": round(
                float(attack_probabilities[i]), 4
            ),
            "attack_family": str(attack_families[i]),
            "anomaly_score": round(
                float(anomaly_scores[i]), 6
            ),
            "anomaly_detected": bool(anomaly_flags[i])
        })

    # --------------------------------------------------
    # 5. SUMMARY
    # --------------------------------------------------

    attack_count = int(np.sum(predictions))
    benign_count = int(len(predictions) - attack_count)
    anomaly_count = int(np.sum(anomaly_flags))

    family_counts = {}

    for family in attack_families:
        if family != "BENIGN":
            family_counts[family] = (
                family_counts.get(family, 0) + 1
            )

    return {
        "project": "DeepShield",
        "total_records": len(X),
        "summary": {
            "benign_records": benign_count,
            "attack_records": attack_count,
            "anomalous_records": anomaly_count,
            "attack_families": family_counts
        },
        "thresholds": {
            "supervised_threshold": SUPERVISED_THRESHOLD,
            "anomaly_threshold": ANOMALY_THRESHOLD
        },
        "predictions": results,
        "note": (
            "Anomaly detection is a separate signal. "
            "It does not automatically change the supervised prediction. "
            "Attack probability is a model output, not a calibrated "
            "real-world risk score."
        )
    }
