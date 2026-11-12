
import csv
import json
import uuid

from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALERT_DIR = PROJECT_ROOT / "reports" / "live_alerts"

JSON_ALERT_FILE = ALERT_DIR / "alerts.jsonl"
CSV_ALERT_FILE = ALERT_DIR / "alerts.csv"


class AlertManager:

    def __init__(self):
        ALERT_DIR.mkdir(parents=True, exist_ok=True)

        self.alert_count = 0

        print("Alert Manager initialized.")
        print("Alert directory:", ALERT_DIR)

    def get_severity(self, probability):

        if probability >= 0.90:
            return "CRITICAL"
        elif probability >= 0.75:
            return "HIGH"
        elif probability >= 0.50:
            return "MEDIUM"

        return "LOW"

    def create_alert(self, result):

        if result.get("prediction") != "ATTACK":
            return None

        probability = float(result["attack_probability"])

        alert = {
            "alert_id": str(uuid.uuid4())[:8],
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "severity": self.get_severity(probability),
            "attack_probability": probability,
            "source_ip": result.get("source_ip", "Unknown"),
            "destination_ip": result.get("destination_ip", "Unknown"),
            "destination_port": result.get("destination_port", 0),
            "protocol": result.get("protocol", "Unknown"),
            "total_packets": result.get("total_packets", 0),
            "classification": "ATTACK"
        }

        self.save_json(alert)
        self.save_csv(alert)

        self.alert_count += 1

        print("\n!!! SECURITY ALERT CREATED !!!")
        print("Alert ID:", alert["alert_id"])
        print("Severity:", alert["severity"])
        print("Attack Probability:", probability)
        print("Saved to:", JSON_ALERT_FILE)

        return alert

    def save_json(self, alert):

        with open(JSON_ALERT_FILE, "a", encoding="utf-8") as file:
            file.write(json.dumps(alert) + "\n")

    def save_csv(self, alert):

        file_exists = CSV_ALERT_FILE.exists()

        with open(
            CSV_ALERT_FILE,
            "a",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=alert.keys()
            )

            if not file_exists:
                writer.writeheader()

            writer.writerow(alert)


if __name__ == "__main__":

    manager = AlertManager()

    test_result = {
        "prediction": "ATTACK",
        "attack_probability": 0.96,
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "destination_port": 443,
        "protocol": "TCP",
        "total_packets": 25
    }

    manager.create_alert(test_result)

    print("\nAlert manager test completed.")
