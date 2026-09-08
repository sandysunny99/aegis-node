import json
from pathlib import Path

# Paths
base_dir = Path("research/benchmark")
gt_path = base_dir / "ground_truth" / "ground_truth.json"
gt_v2_path = base_dir / "ground_truth_v2" / "ground_truth.json"

# Load original
with open(gt_path, "r", encoding="utf-8") as f:
    gt_data = json.load(f)

# Add new cases
new_cases = [
    {
        "case_id": "N01",
        "file_name": "N01_encoded_suspicious.csv",
        "format": "csv",
        "category": "ENCODED_SUSPICIOUS",
        "expected_class": "SUSPICIOUS",
        "expected_properties": {"encoded_content": True, "script_injection": True},
        "description": "URL and Base64 encoded XSS payload. Variant B misses, C detects.",
        "safe_for_execution": True,
        "source_type": "synthetic",
        "notes": "Testing URL and B64 decoding."
    },
    {
        "case_id": "N02",
        "file_name": "N02_encoded_benign.csv",
        "format": "csv",
        "category": "ENCODED_BENIGN",
        "expected_class": "CLEAN",
        "expected_properties": {"encoded_content": True},
        "description": "URL and Base64 encoded benign text 'Hello World'.",
        "safe_for_execution": True,
        "source_type": "synthetic",
        "notes": "Ensures normalization does not cause false positives."
    },
    {
        "case_id": "N03",
        "file_name": "N03_escaped_suspicious.csv",
        "format": "csv",
        "category": "ENCODED_SUSPICIOUS",
        "expected_class": "SUSPICIOUS",
        "expected_properties": {"encoded_content": True, "script_injection": True},
        "description": "Hex escaped <script> tags.",
        "safe_for_execution": True,
        "source_type": "synthetic",
        "notes": "Testing hex unescaping."
    }
]

# Note: F01_encoded_payloads.csv is already in the dataset and in V1 we saw B miss it and C detect it!
# Wait, actually in my previous V1 test, F01 was flagged as MALICIOUS by Variant A and B because normalization was ON.
# Since we patched normalize to OFF in Variant A and B, now F01 should be missed by A/B and caught by C!

# Let's save V2 ground truth
gt_data.extend(new_cases)
with open(gt_v2_path, "w", encoding="utf-8") as f:
    json.dump(gt_data, f, indent=2)

print(f"Created ground_truth_v2 with {len(gt_data)} cases.")
