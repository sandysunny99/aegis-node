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
    benign = load_fixtures("holdout_benign")
    adversarial = load_fixtures("holdout_adversarial")

    false_positives = 0
    detected_attacks = 0
    missed_attacks = 0
    
    for payload in benign:
        status, score, signals = evaluate_input_guardrail(payload)
        if status in ("RESTRICT", "BLOCK"):
            false_positives += 1
            print(f"[FP] Status: {status}, Score: {score}, Signals: {signals} -> {payload}")
        
    for payload in adversarial:
        status, score, signals = evaluate_input_guardrail(payload)
        if status in ("RESTRICT", "BLOCK"):
            detected_attacks += 1
        else:
            missed_attacks += 1
            print(f"[MISS] Status: {status}, Score: {score}, Signals: {signals} -> {payload}")

    print("--- Holdout Benchmark ---")
    print(f"False positives: {false_positives} / {len(benign)} ({false_positives/len(benign)*100:.1f}%)")
    print(f"Attacks detected: {detected_attacks} / {len(adversarial)} ({detected_attacks/len(adversarial)*100:.1f}%)")

if __name__ == "__main__":
    run_benchmark()
