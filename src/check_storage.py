
import pandas as pd
import shutil
from pathlib import Path

print("Pandas version:", pd.__version__)

# Check Parquet support
try:
    import pyarrow
    print("PyArrow version:", pyarrow.__version__)
    print("Parquet support: AVAILABLE")
except ImportError:
    print("Parquet support: NOT AVAILABLE")

# Check project disk space
disk = shutil.disk_usage(Path.cwd())

print("\nDisk information:")
print(f"Total space: {disk.total / (1024**3):.2f} GB")
print(f"Free space: {disk.free / (1024**3):.2f} GB")

# Check raw dataset size
raw_path = Path("data/raw")

total_size = sum(
    file.stat().st_size
    for file in raw_path.glob("*.csv")
)

print("\nRaw dataset size:")
print(f"{total_size / (1024**3):.2f} GB")
