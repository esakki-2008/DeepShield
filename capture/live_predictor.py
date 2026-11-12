
import joblib
import pandas as pd
from pathlib import Path

try:
    from .feature_extractor import extract_features
except ImportError:
    from feature_extractor import extract_features


PROJECT_ROOT = Path(__file__).resolve().parent.parent

BINARY_MODEL_PATH = PROJECT_ROOT / "models" / "binary_xgboost.joblib"


class LivePredictor:

    def __init__(self):
        print("Loading DeepShield binary model...")

        bundle = joblib.load(BINARY_MODEL_PATH)

        self.model = bundle["model"]
        self.feature_names = bundle["features"]

        self.threshold = 0.50

        print("Binary model loaded.")
        print("Expected features:", len(self.feature_names))

    def predict_flow(self, flow):

        # Step 1: Convert network flow into 78 features.
        features = extract_features(
            flow,
            self.feature_names
        )

        # Step 2: Arrange features in the exact training order.
        input_data = pd.DataFrame(
            [features],
            columns=self.feature_names
        )

        # Step 3: Get model probabilities.
        probabilities = self.model.predict_proba(input_data)[0]

        # Binary model encoding:
        # 0 = BENIGN
        # 1 = ATTACK
        attack_probability = float(probabilities[1])

        # Step 4: Apply the provisional threshold.
        prediction = (
            "ATTACK"
            if attack_probability >= self.threshold
            else "BENIGN"
        )

        return {
            "prediction": prediction,
            "attack_probability": round(attack_probability, 4),
            "benign_probability": round(
                float(probabilities[0]), 4
            ),
            "threshold": self.threshold,
            "destination_ip": flow.get(
                "destination_ip", "Unknown"
            ),
            "source_ip": flow.get(
                "source_ip", "Unknown"
            ),
            "destination_port": flow.get(
                "destination_port", 0
            ),
            "protocol": flow.get(
                "protocol", "Unknown"
            ),
            "total_packets": (
                len(flow.get("forward_packet_lengths", []))
                + len(flow.get("backward_packet_lengths", []))
            )
        }


if __name__ == "__main__":

    predictor = LivePredictor()

    # Synthetic test flow.
    test_flow = {
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "destination_port": 443,
        "protocol": "TCP",

        "forward_packet_lengths": [100, 200, 300],
        "backward_packet_lengths": [150, 250],

        "forward_times": [1.0, 1.001, 1.003],
        "backward_times": [1.002, 1.004],
        "packet_times": [
            1.0, 1.001, 1.002, 1.003, 1.004
        ],

        "forward_header_lengths": [40, 40, 40],
        "backward_header_lengths": [40, 40],

        "tcp_flags": {
            "FIN": 0,
            "SYN": 1,
            "RST": 0,
            "PSH": 2,
            "ACK": 5,
            "URG": 0,
            "ECE": 0,
            "CWE": 0
        },

        "init_window_forward": 65535,
        "init_window_backward": 65535,

        "forward_data_packets": 3,
        "min_segment_size_forward": 40,

        "forward_psh_flags": 1,
        "backward_psh_flags": 1,
        "forward_urg_flags": 0,
        "backward_urg_flags": 0
    }

    result = predictor.predict_flow(test_flow)

    print("\nDEEPSHIELD LIVE PREDICTION")
    print("-" * 40)

    for key, value in result.items():
        print(f"{key}: {value}")

    print("\nPrediction pipeline test completed.")
