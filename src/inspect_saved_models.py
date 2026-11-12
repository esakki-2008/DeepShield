
import joblib
from pathlib import Path

files = [
    "models/binary_xgboost.joblib",
    "models/multiclass_xgboost.joblib",
    "models/calibrated_hybrid_detector.joblib"
]

for file in files:
    print("\n" + "=" * 55)
    print("MODEL:", file)
    print("=" * 55)

    path = Path(file)

    if not path.exists():
        print("FILE NOT FOUND")
        continue

    try:
        obj = joblib.load(path)

        print("Type:", type(obj).__name__)

        if isinstance(obj, dict):
            print("Keys:", list(obj.keys()))

            for key, value in obj.items():
                print(f"\n{key}: {type(value).__name__}")

                if hasattr(value, "n_features_in_"):
                    print("Features:", value.n_features_in_)

                if hasattr(value, "classes_"):
                    print("Classes:", value.classes_)

        else:
            if hasattr(obj, "n_features_in_"):
                print("Features:", obj.n_features_in_)

            if hasattr(obj, "classes_"):
                print("Classes:", obj.classes_)

    except Exception as error:
        print("ERROR:", error)
