import json
import glob
import random
from pathlib import Path

# Folder containing your JSONL files
input_folder = Path("filled_templates")

# Output files inside the same folder
combined_file = input_folder / "combined_IFT.jsonl"
shuffled_file = input_folder / "combined_IFT_shuffled.jsonl"

all_data = []

# Read only JSONL files starting with "IFT"
for jsonl_file in sorted(input_folder.glob("filled*.jsonl")):
    with open(jsonl_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():  # Skip empty lines
                all_data.append(json.loads(line))

# Write combined JSONL
with open(combined_file, "w", encoding="utf-8") as f:
    for item in all_data:
        f.write(json.dumps(item) + "\n")

# Set seed for reproducibility
random.seed(42)
random.shuffle(all_data)

# Write shuffled JSONL
with open(shuffled_file, "w", encoding="utf-8") as f:
    for item in all_data:
        f.write(json.dumps(item) + "\n")

print(f"Combined JSONL saved to {combined_file}")
print(f"Shuffled JSONL saved to {shuffled_file}")
