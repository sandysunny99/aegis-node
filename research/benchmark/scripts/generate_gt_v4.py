import json
from pathlib import Path

base_dir = Path("research/benchmark")
gt_v3 = base_dir / "ground_truth_v3" / "ground_truth.json"
gt_v4 = base_dir / "ground_truth_v4" / "ground_truth.json"

with open(gt_v3, "r", encoding="utf-8") as f:
    gt_data = json.load(f)

new_cases = [
    {
        "case_id": "T01",
        "file_name": "T01_known_malicious.csv",
        "format": "csv",
        "category": "threat_intel",
        "expected_class": "SUSPICIOUS",
        "expected_properties": {"threat_intel": True},
        "description": "Contains known malicious IPs, domains, and hashes.",
        "safe_for_execution": True,
        "source_type": "synthetic",
        "notes": "Variant D should miss this (CLEAN), E should catch (SUSPICIOUS)."
    },
    {
        "case_id": "T02",
        "file_name": "T02_known_clean.csv",
        "format": "csv",
        "category": "threat_intel",
        "expected_class": "CLEAN",
        "expected_properties": {"threat_intel": False},
        "description": "Contains strictly known clean indicators (8.8.8.8, google.com).",
        "safe_for_execution": True,
        "source_type": "synthetic",
        "notes": "Both D and E should remain CLEAN."
    },
    {
        "case_id": "T03",
        "file_name": "T03_unknown.csv",
        "format": "csv",
        "category": "threat_intel",
        "expected_class": "CLEAN",
        "expected_properties": {"threat_intel": False},
        "description": "Indicators not in database. Should default to CLEAN (enrichment only).",
        "safe_for_execution": True,
        "source_type": "synthetic",
        "notes": "Unknown TI should not escalate to SUSPICIOUS."
    },
    {
        "case_id": "T04",
        "file_name": "T04_api_failures.csv",
        "format": "csv",
        "category": "threat_intel",
        "expected_class": "CLEAN",
        "expected_properties": {"threat_intel": False},
        "description": "Simulates API timeout, unavailability, and rate limits.",
        "safe_for_execution": True,
        "source_type": "synthetic",
        "notes": "Failure must not trigger an alert; should gracefully fallback to CLEAN."
    },
    {
        "case_id": "T05",
        "file_name": "T05_conflicting.csv",
        "format": "csv",
        "category": "threat_intel",
        "expected_class": "SUSPICIOUS",
        "expected_properties": {"threat_intel": True},
        "description": "Conflicting intelligence. Errs on the side of caution.",
        "safe_for_execution": True,
        "source_type": "synthetic",
        "notes": "If one source says malicious, flag as SUSPICIOUS."
    },
    {
        "case_id": "T06",
        "file_name": "T06_benign_research.csv",
        "format": "csv",
        "category": "threat_intel",
        "expected_class": "CLEAN",
        "expected_properties": {"threat_intel": False},
        "description": "Benign security domain (eicar.org).",
        "safe_for_execution": True,
        "source_type": "synthetic",
        "notes": "The domain itself is clean, even though files from it might be bad."
    }
]

gt_data.extend(new_cases)

with open(gt_v4, "w", encoding="utf-8") as f:
    json.dump(gt_data, f, indent=2)

print(f"Created ground_truth_v4 with {len(gt_data)} cases.")
print(f"  v3 cases: {len(gt_data) - len(new_cases)}")
print(f"  New T-cases: {len(new_cases)}")
