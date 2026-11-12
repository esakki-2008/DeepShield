
import pandas as pd
from pathlib import Path

input_file = Path(
    "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

output_file = Path(
    "data/processed/api_test_ddos_5000.csv"
)

if not input_file.exists():
    raise FileNotFoundError(f"Dataset not found: {input_file}")

print("Loading Friday DDoS dataset...")

df = pd.read_csv(input_file, low_memory=False)

print("Original records:", len(df))

sample = df.sample(
    n=min(5000, len(df)),
    random_state=42
)

output_file.parent.mkdir(parents=True, exist_ok=True)

sample.to_csv(output_file, index=False)

print("\nTest dataset created successfully!")
print("Records:", len(sample))
print("Saved to:", output_file)
