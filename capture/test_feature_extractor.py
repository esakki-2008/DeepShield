
import math
import joblib
from pathlib import Path

from feature_extractor import extract_features


MODEL_PATH = Path("models/binary_xgboost.joblib")


def main():
    bundle = joblib.load(MODEL_PATH)
    feature_names = bundle["features"]

    # A small artificial flow for testing calculations.
    test_flow = {
        "destination_port": 443,

        "forward_packet_lengths": [100, 200, 300],
        "backward_packet_lengths": [150, 250],

        "forward_times": [1.0, 1.001, 1.003],
        "backward_times": [1.002, 1.004],
        "packet_times": [1.0, 1.001, 1.002, 1.003, 1.004],

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
            "CWE": 0,
        },

        "init_window_forward": 65535,
        "init_window_backward": 65535,

        "forward_data_packets": 3,
        "min_segment_size_forward": 40,

        "forward_psh_flags": 1,
        "backward_psh_flags": 1,
        "forward_urg_flags": 0,
        "backward_urg_flags": 0,
    }

    result = extract_features(test_flow, feature_names)

    print("\nDEEPSHIELD FEATURE VALIDATION")
    print("-" * 40)

    # Check 1: Feature count
    print("Feature count:", len(result))
    assert len(result) == 78

    # Check 2: Exact feature order
    assert list(result.keys()) == feature_names
    print("Feature order: PASS")

    # Check 3: Numeric values and no infinity
    for name, value in result.items():
        assert isinstance(value, (int, float)), (
            f"Non-numeric feature: {name}"
        )
        assert not math.isinf(float(value)), (
            f"Infinite value: {name}"
        )

    print("Numeric validation: PASS")
    print("Infinity validation: PASS")

    # Check 4: Basic calculation results
    assert result["Destination Port"] == 443
    assert result["Total Fwd Packets"] == 3
    assert result["Total Backward Packets"] == 2
    assert result["Total Length of Fwd Packets"] == 600
    assert result["Total Length of Bwd Packets"] == 400
    assert math.isclose(
    result["Flow Duration"],
    4000,
    rel_tol=1e-9,
    abs_tol=1e-6
)

    print("Basic calculations: PASS")

    print("\nSelected feature values:")
    for name in [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
    ]:
        print(f"{name}: {result[name]}")

    print("\nALL VALIDATION CHECKS PASSED")


if __name__ == "__main__":
    main()
