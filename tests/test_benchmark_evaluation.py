"""
Aegis Node — Benchmark Evaluation Suite for Prompt Injection & Hard Negatives.
Evaluates detector accuracy on held-out dataset (tests/fixtures/prompt_injection_benchmark/benchmark_cases.json).
"""

import json
from pathlib import Path
import pytest
from scanner.content_checker import _check_string_value


@pytest.fixture
def benchmark_data():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "prompt_injection_benchmark" / "benchmark_cases.json"
    )
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_prompt_injection_benchmark_metrics(benchmark_data):
    """
    Run empirical evaluation across all 50 test samples.
    Calculates TP, TN, FP, FN, Precision, Recall, and observed False Positive Rate.
    """
    tp = 0  # Malicious correctly flagged
    tn = 0  # Benign correctly passed
    fp = 0  # Benign incorrectly flagged as malicious
    fn = 0  # Malicious missed

    for case in benchmark_data:
        text = case["text"]
        expected_label = case["label"]
        case_id = case["id"]

        findings = _check_string_value(text, column="test_field", row_idx="0")
        actionable_findings = [f for f in findings if f.category != "malware_reference"]
        is_detected = len(actionable_findings) > 0

        if expected_label == "malicious":
            if is_detected:
                tp += 1
            else:
                fn += 1
        elif expected_label == "benign":
            if not is_detected:
                tn += 1
            else:
                fp += 1

    total_samples = len(benchmark_data)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(
        f"\n[BENCHMARK EVALUATION RESULTS]\n"
        f"Total Samples: {total_samples}\n"
        f"TP: {tp} | TN: {tn} | FP: {fp} | FN: {fn}\n"
        f"Precision: {precision * 100:.2f}%\n"
        f"Recall: {recall * 100:.2f}%\n"
        f"F1-Score: {f1:.4f}\n"
        f"Observed False Positive Rate: {fpr * 100:.2f}%\n"
    )

    # Verification assertions
    assert fp == 0, f"Expected 0 false positives on benign hard negatives, got {fp}"
    assert tp >= 20, f"Expected high recall on adversarial attacks, detected {tp}/25"
    assert precision == 1.0, f"Expected 100% precision, got {precision:.4f}"
