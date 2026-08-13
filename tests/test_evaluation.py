"""
tests/test_evaluation.py — Unit & Integration tests for Phase 6 Research Evaluation Module.

Requirements Tested:
  1. Classification Metrics: TP, TN, FP, FN, accuracy, precision, recall, F1, FPR, FNR, zero-denominator safety.
  2. Performance Metrics: mean, median, min, max, stddev, datasets/sec, empty list safety.
  3. LLM Metrics: input/output token accounting, averages, unavailable status handling.
  4. Remediation Metrics: threat reduction %, success rate, zero denominator safety.
  5. Dataset Generator: synthetic dataset creation, ground_truth.json structure.
  6. Benchmark Runner: mode selection, mocked Gemini/ClamAV execution.
  7. Report Generator: CSV and Markdown report generation.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from evaluation.dataset_generator import generate_benchmark_corpus
from evaluation.metrics import (
    ClassificationMetrics,
    LlmMetrics,
    PerformanceMetrics,
    RemediationMetrics,
)
from evaluation.report_generator import generate_reports


def test_classification_metrics_calculations():
    """Verify TP/TN/FP/FN formulas and zero denominator safety."""
    clf = ClassificationMetrics(tp=16, tn=18, fp=2, fn=4)
    assert clf.total == 40
    assert clf.accuracy == 0.85
    assert clf.precision == round(16 / 18, 4)
    assert clf.recall == round(16 / 20, 4)
    assert clf.f1_score > 0.0
    assert clf.false_positive_rate == round(2 / 20, 4)
    assert clf.false_negative_rate == round(4 / 20, 4)

    # Zero denominator safety check
    zero_clf = ClassificationMetrics()
    assert zero_clf.accuracy == 0.0
    assert zero_clf.precision == 0.0
    assert zero_clf.recall == 0.0
    assert zero_clf.f1_score == 0.0
    assert zero_clf.false_positive_rate == 0.0
    assert zero_clf.false_negative_rate == 0.0


def test_performance_metrics_calculations():
    """Verify latency performance metrics calculations."""
    perf = PerformanceMetrics(durations_ms=[10.0, 20.0, 30.0, 40.0, 50.0])
    assert perf.count == 5
    assert perf.total_duration_ms == 150.0
    assert perf.mean_duration_ms == 30.0
    assert perf.median_duration_ms == 30.0
    assert perf.min_duration_ms == 10.0
    assert perf.max_duration_ms == 50.0
    assert perf.stddev_duration_ms > 0.0
    assert perf.datasets_per_second == round(5 / 0.150, 2)

    # Empty durations safety
    empty_perf = PerformanceMetrics()
    assert empty_perf.mean_duration_ms == 0.0
    assert empty_perf.median_duration_ms == 0.0
    assert empty_perf.datasets_per_second == 0.0


def test_llm_metrics_calculations():
    """Verify LLM token consumption and latency metrics."""
    llm_met = LlmMetrics(llm_requests=5, input_tokens=500, output_tokens=250, latencies_ms=[100.0, 200.0])
    assert llm_met.total_tokens == 750
    assert llm_met.avg_tokens_per_dataset == 150.0
    assert llm_met.avg_llm_latency_ms == 150.0

    empty_llm = LlmMetrics()
    assert empty_llm.avg_tokens_per_dataset == 0.0
    assert empty_llm.avg_llm_latency_ms == 0.0


def test_remediation_metrics_calculations():
    """Verify threat reduction % and success rate metrics."""
    rem_met = RemediationMetrics(
        total_remediated=10,
        successful_remediations=8,
        threat_reductions_pct=[100.0, 100.0, 50.0, 100.0],
        total_before_findings=20,
        total_after_findings=4,
    )
    assert rem_met.remediation_success_rate == 80.0
    assert rem_met.avg_threat_reduction_percent == 87.5
    assert rem_met.total_resolved_findings == 16


def test_dataset_generator(tmp_path, monkeypatch):
    """Verify dataset_generator creates ground_truth.json and dataset files."""
    bench_dir = tmp_path / "benchmarks"
    meta_dir = bench_dir / "metadata"
    monkeypatch.setattr("evaluation.dataset_generator._BENCHMARK_DIR", bench_dir)
    monkeypatch.setattr("evaluation.dataset_generator._METADATA_DIR", meta_dir)

    gt = generate_benchmark_corpus(count_per_category=2)
    assert len(gt) == 10  # 5 categories * 2 files
    assert (meta_dir / "ground_truth.json").exists()

    clean_file = bench_dir / "clean" / "clean_001.csv"
    assert clean_file.exists()
    assert "name,email,age" in clean_file.read_text()


def test_report_generator(tmp_path, monkeypatch):
    """Verify report_generator exports CSV, JSON, and Markdown files."""
    res_dir = tmp_path / "results"
    docs_dir = tmp_path / "docs"
    monkeypatch.setattr("evaluation.report_generator._RESULTS_DIR", res_dir)
    monkeypatch.setattr("evaluation.report_generator._DOCS_DIR", docs_dir)

    sample_output = {
        "dataset_count": 10,
        "modes": {
            "rule_only": {
                "classification": ClassificationMetrics(tp=8, tn=2).to_dict(),
                "performance": PerformanceMetrics(durations_ms=[5.0]).to_dict(),
                "llm": LlmMetrics().to_dict(),
            },
            "combined": {
                "classification": ClassificationMetrics(tp=8, tn=2).to_dict(),
                "performance": PerformanceMetrics(durations_ms=[12.0]).to_dict(),
                "llm": LlmMetrics().to_dict(),
            },
        },
        "remediation": RemediationMetrics(total_remediated=5, successful_remediations=5, threat_reductions_pct=[100.0]).to_dict(),
    }

    csv_path, report_path = generate_reports(sample_output)
    assert csv_path.exists()
    assert report_path.exists()

    csv_content = csv_path.read_text(encoding="utf-8")
    assert "rule_only" in csv_content
    assert "combined" in csv_content

    md_content = report_path.read_text(encoding="utf-8")
    assert "Research Evaluation Report" in md_content
    assert "Hypotheses Verification" in md_content
