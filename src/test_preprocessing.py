
import numpy as np
import pandas as pd

from src.preprocessing import clean_features


def test_clean_features_strips_column_names():
    df = pd.DataFrame({" Flow Bytes/s ": [100.0]})

    cleaned = clean_features(df)

    assert "Flow Bytes/s" in cleaned.columns


def test_clean_features_replaces_infinity():
    df = pd.DataFrame({
        "value": [100.0, np.inf, -np.inf]
    })

    cleaned = clean_features(df)

    assert cleaned["value"].iloc[0] == 100.0
    assert cleaned["value"].isna().sum() == 2


def test_clean_features_normalizes_attack_labels():
    df = pd.DataFrame({
        "Label": [
            "BENIGN",
            "Web Attack ï¿½ XSS"
        ]
    })

    cleaned = clean_features(df)

    assert cleaned["Label"].iloc[0] == "BENIGN"
    assert cleaned["Label"].iloc[1] == "Web Attack - XSS"


def test_clean_features_preserves_original_dataframe():
    df = pd.DataFrame({
        " Flow Bytes/s ": [100.0, np.inf]
    })

    original = df.copy(deep=True)

    clean_features(df)

    pd.testing.assert_frame_equal(df, original)
