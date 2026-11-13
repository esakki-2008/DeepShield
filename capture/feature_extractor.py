
import math
import joblib
import numpy as np
from pathlib import Path


MODEL_PATH = Path("models/binary_xgboost.joblib")

# CICFlowMeter-style active/idle threshold (microseconds)
ACTIVE_IDLE_THRESHOLD = 5_000_000


def safe_mean(values):
    return float(np.mean(values)) if values else 0.0


def safe_std(values):
    return float(np.std(values, ddof=1)) if len(values) > 1 else 0.0


def safe_min(values):
    return float(min(values)) if values else 0.0


def safe_max(values):
    return float(max(values)) if values else 0.0


def safe_variance(values):
    return float(np.var(values, ddof=1)) if len(values) > 1 else 0.0


def calculate_iat(times):
    ordered = sorted(times)

    if len(ordered) < 2:
        return []

    return [
        max(0.0, (ordered[i] - ordered[i - 1]) * 1_000_000)
        for i in range(1, len(ordered))
    ]


def calculate_active_idle(times):
    ordered = sorted(times)

    if len(ordered) < 2:
        return [], []

    active_periods = []
    idle_periods = []
    active_start = ordered[0]
    previous = ordered[0]

    for current in ordered[1:]:
        gap = (current - previous) * 1_000_000

        if gap > ACTIVE_IDLE_THRESHOLD:
            active_duration = (previous - active_start) * 1_000_000
            active_periods.append(max(0.0, active_duration))
            idle_periods.append(gap)
            active_start = current

        previous = current

    final_active = (previous - active_start) * 1_000_000
    active_periods.append(max(0.0, final_active))

    return active_periods, idle_periods


def extract_features(flow, feature_names):
    fwd = flow.get("forward_packet_lengths", [])
    bwd = flow.get("backward_packet_lengths", [])

    fwd_times = flow.get("forward_times", [])
    bwd_times = flow.get("backward_times", [])
    all_times = sorted(flow.get("packet_times", []))

    fwd_headers = flow.get("forward_header_lengths", [])
    bwd_headers = flow.get("backward_header_lengths", [])

    fwd_packets = len(fwd)
    bwd_packets = len(bwd)
    total_packets = fwd_packets + bwd_packets

    fwd_bytes = sum(fwd)
    bwd_bytes = sum(bwd)
    total_bytes = fwd_bytes + bwd_bytes

    duration = (
        max(0.0, (all_times[-1] - all_times[0]) * 1_000_000)
        if len(all_times) > 1 else 0.0
    )

    duration_seconds = duration / 1_000_000

    flow_iat = calculate_iat(all_times)
    fwd_iat = calculate_iat(fwd_times)
    bwd_iat = calculate_iat(bwd_times)

    active, idle = calculate_active_idle(all_times)

    all_lengths = fwd + bwd
    tcp_flags = flow.get("tcp_flags", {})

    features = {
        "Destination Port": flow.get("destination_port", 0),
        "Flow Duration": duration,

        "Total Fwd Packets": fwd_packets,
        "Total Backward Packets": bwd_packets,
        "Total Length of Fwd Packets": fwd_bytes,
        "Total Length of Bwd Packets": bwd_bytes,

        "Fwd Packet Length Max": safe_max(fwd),
        "Fwd Packet Length Min": safe_min(fwd),
        "Fwd Packet Length Mean": safe_mean(fwd),
        "Fwd Packet Length Std": safe_std(fwd),

        "Bwd Packet Length Max": safe_max(bwd),
        "Bwd Packet Length Min": safe_min(bwd),
        "Bwd Packet Length Mean": safe_mean(bwd),
        "Bwd Packet Length Std": safe_std(bwd),

        "Flow Bytes/s": total_bytes / duration_seconds if duration_seconds > 0 else np.nan,
        "Flow Packets/s": total_packets / duration_seconds if duration_seconds > 0 else np.nan,

        "Flow IAT Mean": safe_mean(flow_iat),
        "Flow IAT Std": safe_std(flow_iat),
        "Flow IAT Max": safe_max(flow_iat),
        "Flow IAT Min": safe_min(flow_iat),

        "Fwd IAT Total": sum(fwd_iat),
        "Fwd IAT Mean": safe_mean(fwd_iat),
        "Fwd IAT Std": safe_std(fwd_iat),
        "Fwd IAT Max": safe_max(fwd_iat),
        "Fwd IAT Min": safe_min(fwd_iat),

        "Bwd IAT Total": sum(bwd_iat),
        "Bwd IAT Mean": safe_mean(bwd_iat),
        "Bwd IAT Std": safe_std(bwd_iat),
        "Bwd IAT Max": safe_max(bwd_iat),
        "Bwd IAT Min": safe_min(bwd_iat),

        "Fwd PSH Flags": flow.get("forward_psh_flags", 0),
        "Bwd PSH Flags": flow.get("backward_psh_flags", 0),
        "Fwd URG Flags": flow.get("forward_urg_flags", 0),
        "Bwd URG Flags": flow.get("backward_urg_flags", 0),

        "Fwd Header Length": sum(fwd_headers),
        "Bwd Header Length": sum(bwd_headers),

        "Fwd Packets/s": fwd_packets / duration_seconds if duration_seconds > 0 else np.nan,
        "Bwd Packets/s": bwd_packets / duration_seconds if duration_seconds > 0 else np.nan,

        "Min Packet Length": safe_min(all_lengths),
        "Max Packet Length": safe_max(all_lengths),
        "Packet Length Mean": safe_mean(all_lengths),
        "Packet Length Std": safe_std(all_lengths),
        "Packet Length Variance": safe_variance(all_lengths),

        "FIN Flag Count": tcp_flags.get("FIN", 0),
        "SYN Flag Count": tcp_flags.get("SYN", 0),
        "RST Flag Count": tcp_flags.get("RST", 0),
        "PSH Flag Count": tcp_flags.get("PSH", 0),
        "ACK Flag Count": tcp_flags.get("ACK", 0),
        "URG Flag Count": tcp_flags.get("URG", 0),
        "CWE Flag Count": tcp_flags.get("CWE", 0),
        "ECE Flag Count": tcp_flags.get("ECE", 0),

        "Down/Up Ratio": bwd_packets / fwd_packets if fwd_packets else 0.0,
        "Average Packet Size": safe_mean(all_lengths),
        "Avg Fwd Segment Size": safe_mean(fwd),
        "Avg Bwd Segment Size": safe_mean(bwd),

        "Fwd Header Length.1": sum(fwd_headers),

        # Bulk features are not yet calculated by our flow generator.
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,

        # Preliminary single-subflow approximation.
        "Subflow Fwd Packets": fwd_packets,
        "Subflow Fwd Bytes": fwd_bytes,
        "Subflow Bwd Packets": bwd_packets,
        "Subflow Bwd Bytes": bwd_bytes,

        "Init_Win_bytes_forward": flow.get("init_window_forward", -1),
        "Init_Win_bytes_backward": flow.get("init_window_backward", -1),

        "act_data_pkt_fwd": flow.get("forward_data_packets", 0),
        "min_seg_size_forward": flow.get("min_segment_size_forward", 0),

        "Active Mean": safe_mean(active),
        "Active Std": safe_std(active),
        "Active Max": safe_max(active),
        "Active Min": safe_min(active),

        "Idle Mean": safe_mean(idle),
        "Idle Std": safe_std(idle),
        "Idle Max": safe_max(idle),
        "Idle Min": safe_min(idle),
    }

    # Fail loudly if the model asks for a feature we do not calculate.
    # Silently substituting zero can create misleading live predictions.
    missing_features = [name for name in feature_names if name not in features]
    if missing_features:
        raise ValueError(
            "Feature extractor does not calculate required model features: "
            + ", ".join(missing_features)
        )

    if len(set(feature_names)) != len(feature_names):
        raise ValueError("Model feature list contains duplicate feature names.")

    # Preserve the trained model's exact feature order.
    ordered = {}
    for name in feature_names:
        value = features[name]

        if isinstance(value, (int, float, np.number)):
            value = float(value)
            if math.isinf(value):
                value = np.nan

        ordered[name] = value

    return ordered


def load_model_features():
    bundle = joblib.load(MODEL_PATH)
    return bundle["features"]


if __name__ == "__main__":
    names = load_model_features()

    print("DEEPSHIELD FEATURE EXTRACTOR")
    print("Expected model features:", len(names))
    print("Feature order loaded successfully.")

    for index, name in enumerate(names, start=1):
        print(f"{index:02}. {name}")
