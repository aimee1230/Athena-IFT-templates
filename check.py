import json
from pathlib import Path

path = Path("filled_templates/filled_cve_templates_400.jsonl")

empty_attack_vectors = []
total = 0

with path.open("r", encoding="utf-8") as fh:
    for line in fh:
        if not line.strip():
            continue
        total += 1
        entry = json.loads(line)
        inp = entry.get("input", "")
        out = entry.get("output", "")
        # check if vector string like "CVSS:" or "/AV:" appears
        if "CVSS" not in inp and "CVSS" not in out and "/AV:" not in inp and "/AV:" not in out:
            empty_attack_vectors.append(entry)

print(f"Total entries checked: {total}")
print(f"Entries missing CVSS v3.1 vector: {len(empty_attack_vectors)}")

if empty_attack_vectors:
    print("\nExamples of missing attack vectors:")
    for e in empty_attack_vectors[:3]:
        print(json.dumps(e, indent=2)[:400], "\n---")
