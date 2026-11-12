
import json
import threading
import uuid

from pathlib import Path
from datetime import datetime, timezone
from collections import deque


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVENT_DIR = PROJECT_ROOT / "reports" / "live_events"
EVENT_FILE = EVENT_DIR / "predictions.jsonl"


class EventStore:

    def __init__(self):

        EVENT_DIR.mkdir(parents=True, exist_ok=True)

        self.event_file = EVENT_FILE
        self.lock = threading.Lock()

        print("Live Event Store initialized.")
        print("Event file:", self.event_file)

    def append_prediction(self, result):

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "prediction",
            "prediction_stage": result.get(
                "prediction_stage", "UNKNOWN"
            ),
            "classification": result.get("prediction", "UNKNOWN"),
            "attack_probability": float(
                result.get("attack_probability", 0)
            ),
            "benign_probability": float(
                result.get("benign_probability", 0)
            ),
            "source_ip": result.get("source_ip"),
            "destination_ip": result.get("destination_ip"),
            "destination_port": result.get("destination_port"),
            "protocol": result.get("protocol"),
            "total_packets": int(result.get("total_packets", 0))
        }

        with self.lock:

            with self.event_file.open(
                "a",
                encoding="utf-8"
            ) as file:

                file.write(
                    json.dumps(event, allow_nan=False) + "\n"
                )

                file.flush()

        return event

    def read_recent(self, limit=500):

        if not self.event_file.exists():
            return []

        with self.event_file.open(
            "r",
            encoding="utf-8"
        ) as file:

            recent_lines = deque(file, maxlen=limit)

        events = []

        for line in recent_lines:

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return events


if __name__ == "__main__":

    store = EventStore()

    test_result = {
        "prediction": "BENIGN",
        "prediction_stage": "PROVISIONAL",
        "attack_probability": 0.0001,
        "benign_probability": 0.9999,
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "destination_port": 443,
        "protocol": "TCP",
        "total_packets": 10
    }

    saved_event = store.append_prediction(test_result)

    print("\nTEST EVENT SAVED")
    print(json.dumps(saved_event, indent=4))

    recent_events = store.read_recent(limit=5)

    print("\nRecent events:", len(recent_events))
    print("\nEvent Store test completed.")
