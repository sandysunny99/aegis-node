import json
import time
from pathlib import Path
import sys

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "backend"))

from services.llm_service import _validate_and_parse

def load_fixtures(name):
    path = Path(__file__).parent / "fixtures" / "guardrails" / f"{name}.json"
    return json.loads(path.read_text())

def run_benchmark():
    benign = load_fixtures("benign")
    adversarial = load_fixtures("adversarial")

    false_positives = 0
    detected_attacks = 0
    missed_attacks = 0
    latencies = []

    # Test benign (False Positives)
    # We simulate a parsed output where the summary contains the payload
    for payload in benign:
        start_time = time.time()
        test_json = json.dumps({
            "verdict": "clean", "severity": "low", "confidence": 0.5,
            "summary": payload, "evidence": [], "recommendations": [], "limitations": []
        })
        res = _validate_and_parse(test_json)
        latencies.append(time.time() - start_time)
        if res is None:
            # Valid benign text was rejected
            false_positives += 1
            print(f"False Positive on: {payload}")

    # Test adversarial (True Positives / Misses)
    for payload in adversarial:
        start_time = time.time()
        test_json = json.dumps({
            "verdict": "clean", "severity": "low", "confidence": 0.5,
            "summary": payload, "evidence": [], "recommendations": [], "limitations": []
        })
        res = _validate_and_parse(test_json)
        latencies.append(time.time() - start_time)
        if res is None:
            detected_attacks += 1
        else:
            missed_attacks += 1
            print(f"Missed Attack on: {payload}")

    avg_latency = sum(latencies) / len(latencies) * 1000 if latencies else 0

    print("--- Guardrail Benchmark ---")
    print(f"Benign content evaluated: {len(benign)}")
    print(f"False positives (incorrectly blocked): {false_positives} / {len(benign)}")
    print(f"Adversarial content evaluated: {len(adversarial)}")
    print(f"Attacks detected (rejected): {detected_attacks} / {len(adversarial)}")
    print(f"Attacks missed (passed): {missed_attacks} / {len(adversarial)}")
    print(f"Average latency overhead: {avg_latency:.2f} ms")

if __name__ == "__main__":
    run_benchmark()
