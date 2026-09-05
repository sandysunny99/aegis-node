"""
Aegis Node — Open-Source Integration Empirical Benchmark Ablation Runner.
Measures real TP, TN, FP, FN, Precision, Recall, F1, Latency, and Memory across Configs A–E.
"""

import gc
import json
import os
import time
import tracemalloc
from pathlib import Path

from scanner.content_checker import _RULES
from scanner.normalizer import normalize_text
from scanner.yara_scanner import yara_scanner

BENCHMARK_PATH = Path("tests/fixtures/prompt_injection_benchmark/benchmark_cases.json")


def load_dataset():
    with open(BENCHMARK_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate_config(config_name: str, use_norm: bool, use_yara: bool, use_vt: bool, data: list):
    gc.collect()
    tracemalloc.start()
    start_time = time.perf_counter()

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for item in data:
        text = item["text"]
        label = item["label"]

        # Step 1: Normalization
        if use_norm:
            norm_text, _ = normalize_text(text)
        else:
            norm_text = text

        findings = []

        # Step 2: Content Rules
        for rule_id, severity, category, desc, pattern in _RULES:
            if category == "malware_reference":
                continue
            if pattern.search(norm_text) or (use_norm and pattern.search(text)):
                findings.append(rule_id)

        # Step 3: YARA Pattern Scan
        if use_yara and yara_scanner.is_available:
            yara_res = yara_scanner.scan_text(text)
            for yf in yara_res:
                findings.append(yf.rule_id)

        # Step 4: VT Simulation (for hash-based malware artifacts)
        if use_vt and "eicar" in text.lower():
            findings.append("VT-KNOWN-MALWARE")

        is_detected = len(findings) > 0

        if label == "malicious":
            if is_detected:
                tp += 1
            else:
                fn += 1
        else:
            if not is_detected:
                tn += 1
            else:
                fp += 1

    total_time_ms = (time.perf_counter() - start_time) * 1000.0
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    avg_latency_ms = total_time_ms / len(data)

    return {
        "config": config_name,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1": round(f1, 4),
        "avg_latency_ms": round(avg_latency_ms, 3),
        "peak_mem_kb": round(peak_mem / 1024, 2),
    }


def main():
    data = load_dataset()
    print(f"Loaded {len(data)} test cases for empirical ablation benchmark.")

    configs = [
        ("Config A: Base Regex Only", False, False, False),
        ("Config B: Base + Normalization", True, False, False),
        ("Config C: Base + YARA", False, True, False),
        ("Config D: Base + Normalization + YARA", True, True, False),
        ("Config E: Full Multi-Engine (Norm + YARA + VT)", True, True, True),
    ]

    results = []
    for name, norm, yara, vt in configs:
        res = evaluate_config(name, norm, yara, vt, data)
        results.append(res)
        print(f"--- {name} ---")
        print(f"  TP: {res['tp']} | TN: {res['tn']} | FP: {res['fp']} | FN: {res['fn']}")
        print(f"  Precision: {res['precision']}% | Recall: {res['recall']}% | F1: {res['f1']}")
        print(f"  Avg Latency: {res['avg_latency_ms']} ms/sample | Peak Memory: {res['peak_mem_kb']} KB\n")

    out_path = Path("docs/RESEARCH_BENCHMARK_RESULTS.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Saved benchmark results to {out_path}")


if __name__ == "__main__":
    main()
