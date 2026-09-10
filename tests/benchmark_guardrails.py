import json
import time
from pathlib import Path
import sys

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "backend"))

from services.guardrails import evaluate_input_guardrail

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
    
    allow_count = 0
    restrict_count = 0
    block_count = 0

    # Test benign (False Positives)
    for payload in benign:
        start_time = time.time()
        status, score, signals = evaluate_input_guardrail(payload)
        latencies.append(time.time() - start_time)
        if status in ("RESTRICT", "BLOCK"):
            false_positives += 1
            print(f"[FP] Status: {status}, Score: {score}, Signals: {signals} -> {payload}")
        
        if status == "ALLOW": allow_count += 1
        elif status == "RESTRICT": restrict_count += 1
        elif status == "BLOCK": block_count += 1

    # Test adversarial (True Positives / Misses)
    for payload in adversarial:
        start_time = time.time()
        status, score, signals = evaluate_input_guardrail(payload)
        latencies.append(time.time() - start_time)
        if status in ("RESTRICT", "BLOCK"):
            detected_attacks += 1
        else:
            missed_attacks += 1
            print(f"[MISS] Status: {status}, Score: {score}, Signals: {signals} -> {payload}")

        if status == "ALLOW": allow_count += 1
        elif status == "RESTRICT": restrict_count += 1
        elif status == "BLOCK": block_count += 1

    avg_latency = sum(latencies) / len(latencies) * 1000 if latencies else 0

    print("--- Guardrail Benchmark ---")
    print(f"Benign content evaluated: {len(benign)}")
    print(f"False positives (incorrectly restricted/blocked): {false_positives} / {len(benign)} ({false_positives/len(benign)*100:.1f}%)")
    print(f"Adversarial content evaluated: {len(adversarial)}")
    print(f"Attacks detected (restricted/blocked): {detected_attacks} / {len(adversarial)} ({detected_attacks/len(adversarial)*100:.1f}%)")
    print(f"Attacks missed (passed as ALLOW): {missed_attacks} / {len(adversarial)}")
    print(f"Average latency overhead: {avg_latency:.2f} ms")
    print(f"ALLOW: {allow_count}, RESTRICT: {restrict_count}, BLOCK: {block_count}")

if __name__ == "__main__":
    run_benchmark()
