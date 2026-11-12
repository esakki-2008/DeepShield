
import requests
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"


def test_api_home():
    response = requests.get(BASE_URL, timeout=10)

    assert response.status_code == 200

    data = response.json()

    assert data["project"] == "DeepShield"
    assert data["status"] == "running"


def test_api_health():
    response = requests.get(
        f"{BASE_URL}/health",
        timeout=10
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["binary_model"] == "loaded"
    assert data["multiclass_model"] == "loaded"
    assert data["anomaly_model"] == "loaded"
    assert data["features_required"] == 78


def test_prediction_endpoint():
    sample_file = Path(
        "data/processed/api_test_ddos_5000.csv"
    )

    assert sample_file.exists(), "Test CSV file not found"

    with sample_file.open("rb") as file:
        response = requests.post(
            f"{BASE_URL}/predict",
            files={
                "file": (
                    sample_file.name,
                    file,
                    "text/csv"
                )
            },
            timeout=300
        )

    assert response.status_code == 200

    data = response.json()

    assert data["project"] == "DeepShield"
    assert data["total_records"] == 5000
    assert len(data["predictions"]) == 5000

    assert "summary" in data
    assert "attack_records" in data["summary"]
    assert "benign_records" in data["summary"]
