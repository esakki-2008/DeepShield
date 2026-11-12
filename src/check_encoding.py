
from pathlib import Path

file = Path(
    "data/raw/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
)

with open(file, "rb") as f:
    for line_number, line in enumerate(f):
        if b"Web Attack" in line:
            print("Line:", line_number + 1)
            print("Raw bytes:", repr(line[-100:]))
            break
