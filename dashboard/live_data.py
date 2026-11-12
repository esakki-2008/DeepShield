
import json
from pathlib import Path

import pandas as pd


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parents[1]

EVENT_FILE = (
    PROJECT_ROOT
    / "reports"
    / "live_events"
    / "predictions.jsonl"
)


def load_live_events(limit=500):

    """
    Load the latest live prediction events
    from the DeepShield EventStore.
    """

    if not EVENT_FILE.exists():
        return pd.DataFrame()

    events = []

    try:

        with EVENT_FILE.open("r", encoding="utf-8") as file:

            # Read only the most recent records.
            lines = file.readlines()[-limit:]

        for line in lines:

            try:

                event = json.loads(line)

                events.append(event)

            except json.JSONDecodeError:

                continue

    except OSError:

        return pd.DataFrame()

    if not events:
        return pd.DataFrame()

    df = pd.DataFrame(events)

    # Normalize timestamp.
    if "timestamp" in df.columns:

        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            errors="coerce",
            utc=True
        )

    # Normalize probabilities.
    for column in [
        "attack_probability",
        "benign_probability"
    ]:

        if column in df.columns:

            df[column] = pd.to_numeric(
                df[column],
                errors="coerce"
            ).fillna(0)

    # Normalize packet counts.
    if "total_packets" in df.columns:

        df["total_packets"] = pd.to_numeric(
            df["total_packets"],
            errors="coerce"
        ).fillna(0).astype(int)

    return df


def get_live_statistics(df):

    """
    Calculate summary statistics
    from the loaded prediction events.
    """

    if df.empty:

        return {
            "total_predictions": 0,
            "benign_predictions": 0,
            "attack_predictions": 0,
            "attack_percentage": 0.0,
            "average_attack_probability": 0.0
        }

    total = len(df)

    benign = int(
        (df["classification"] == "BENIGN").sum()
    )

    attacks = int(
        (df["classification"] == "ATTACK").sum()
    )

    return {
        "total_predictions": total,
        "benign_predictions": benign,
        "attack_predictions": attacks,
        "attack_percentage": round(
            attacks / total * 100, 2
        ) if total else 0.0,
        "average_attack_probability": round(
            float(df["attack_probability"].mean()),
            4
        )
    }


if __name__ == "__main__":

    events_df = load_live_events()

    print("\nDeepShield Live Data Test")
    print("=" * 45)

    print("Event file:", EVENT_FILE)
    print("Loaded events:", len(events_df))

    if not events_df.empty:

        print("\nStatistics:")

        statistics = get_live_statistics(events_df)

        for key, value in statistics.items():

            print(f"{key}: {value}")

        print("\nLatest events:")

        print(
            events_df.tail(5).to_string(index=False)
        )

    else:

        print("\nNo live prediction events found.")
