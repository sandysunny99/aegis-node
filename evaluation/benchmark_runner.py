"""
Aegis Node — Benchmark Execution Engine.
Runs comparative evaluations across 4 detection modes and remediation engine.

Modes Evaluated:
  1. rule_only       — Deterministic content rules only
  2. clamav_only     — ClamAV TCP daemon scan only
  3. combined        — Rule-based + ClamAV combined
  4. combined_llm    — Combined scanner + Gemini LLM contextual reasoning

Remediation Benchmark:
  Runs initial scan → sanitizer → verification re-scan on all threat datasets.
"""

import json
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_BACKEND_DIR = _ROOT / "backend"
_SCANNER_DIR = _ROOT / "scanner"

for p in (_ROOT, _BACKEND_DIR, _SCANNER_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from services.llm_service import analyse  # noqa: E402

from evaluation.dataset_generator import generate_benchmark_corpus  # noqa: E402
from evaluation.metrics import (  # noqa: E402
    ClassificationMetrics,
    LlmMetrics,
    PerformanceMetrics,
    RemediationMetrics,
)

# Reuse existing application scanner modules
from evaluation.report_generator import generate_reports  # noqa: E402
from scanner.clamd_client import scan_file as clamav_scan_file  # noqa: E402
from scanner.content_checker import check_file  # noqa: E402
from scanner.engine import run_scan  # noqa: E402
from scanner.sanitizer import sanitize_file  # noqa: E402

logger = logging.getLogger(__name__)

_BENCHMARK_DIR = _ROOT / "data" / "benchmarks"
_RESULTS_DIR = _BENCHMARK_DIR / "results"


@dataclass
class ModeEvaluationResult:
    mode: str
    classification: ClassificationMetrics
    performance: PerformanceMetrics
    llm: LlmMetrics
    clamav_available: bool = True


def evaluate_dataset_mode(file_path: Path, expected_threat: bool, mode: str) -> tuple[bool, float, dict]:
    """
    Evaluate a single dataset under a specific detection mode.
    Returns (detected_threat_bool, scan_duration_ms, extra_info_dict).
    """
    t0 = time.perf_counter()

    if mode == "rule_only":
        res = check_file(str(file_path))
        t1 = time.perf_counter()
        dur_ms = (t1 - t0) * 1000.0
        detected = res.threat_count > 0
        return detected, dur_ms, {"findings_count": res.threat_count, "risk_score": res.risk_score}

    elif mode == "clamav_only":
        clam_res = clamav_scan_file(str(file_path))
        t1 = time.perf_counter()
        dur_ms = (t1 - t0) * 1000.0
        if not clam_res.available:
            return False, dur_ms, {"clamav_available": False}
        detected = clam_res.infected
        return detected, dur_ms, {"clamav_status": "infected" if clam_res.infected else "clean", "virus_name": clam_res.virus_name}

    elif mode == "combined":
        scan_res = run_scan(str(file_path))
        t1 = time.perf_counter()
        dur_ms = (t1 - t0) * 1000.0
        detected = scan_res.threats_found_count > 0 or scan_res.clamav_status == "infected"
        return detected, dur_ms, {
            "findings_count": scan_res.threats_found_count,
            "risk_score": scan_res.risk_score,
            "clamav_status": scan_res.clamav_status,
        }

    elif mode == "combined_llm":
        scan_res = run_scan(str(file_path))
        detected = scan_res.threats_found_count > 0 or scan_res.clamav_status == "infected"

        # Downstream LLM call
        t_llm0 = time.perf_counter()
        findings_dicts = [
            {"rule_id": f.rule_id, "severity": f.severity, "category": f.category, "description": f.description, "location": f.location}
            for f in scan_res.content_findings
        ]
        llm_res = analyse(
            dataset_id=999,
            file_format=file_path.suffix.lstrip("."),
            file_size_bytes=file_path.stat().st_size,
            clamav_status=scan_res.clamav_status,
            risk_score=scan_res.risk_score,
            findings=findings_dicts,
        )
        t1 = time.perf_counter()
        dur_ms = (t1 - t0) * 1000.0
        llm_dur_ms = (t1 - t_llm0) * 1000.0

        return detected, dur_ms, {
            "findings_count": scan_res.threats_found_count,
            "risk_score": scan_res.risk_score,
            "llm_res": llm_res,
            "llm_dur_ms": llm_dur_ms,
        }

    else:
        raise ValueError(f"Unknown benchmark mode: {mode}")


def run_benchmark_for_mode(ground_truth: dict, mode: str, max_datasets: int | None = None) -> ModeEvaluationResult:
    """Run full benchmark suite across all datasets for a single mode."""
    clf = ClassificationMetrics()
    perf = PerformanceMetrics()
    llm_met = LlmMetrics()
    clam_avail = True

    items = list(ground_truth.values())
    if max_datasets:
        items = items[:max_datasets]

    for item in items:
        rel_path = item["relative_path"]
        file_path = _BENCHMARK_DIR / rel_path
        if not file_path.exists():
            continue

        expected_threat = item["expected_threat"]
        detected, dur_ms, extra = evaluate_dataset_mode(file_path, expected_threat, mode)

        perf.durations_ms.append(dur_ms)

        if mode == "clamav_only" and extra.get("clamav_available") is False:
            clam_avail = False

        if mode == "combined_llm":
            llm_res = extra.get("llm_res")
            if llm_res and llm_res.status == "completed":
                llm_met.llm_requests += 1
                llm_met.input_tokens += llm_res.prompt_tokens
                llm_met.output_tokens += llm_res.completion_tokens
                llm_met.latencies_ms.append(extra.get("llm_dur_ms", 0.0))
            elif llm_res and llm_res.status == "unavailable":
                llm_met.available = False

        # Confusion matrix accumulation
        if expected_threat and detected:
            clf.tp += 1
        elif expected_threat and not detected:
            clf.fn += 1
        elif not expected_threat and detected:
            clf.fp += 1
        else:
            clf.tn += 1

    return ModeEvaluationResult(
        mode=mode,
        classification=clf,
        performance=perf,
        llm=llm_met,
        clamav_available=clam_avail,
    )


def run_remediation_benchmark(ground_truth: dict, max_datasets: int | None = None) -> RemediationMetrics:
    """Run dataset remediation & re-scan verification across all threat datasets."""
    rem_met = RemediationMetrics()

    items = [item for item in ground_truth.values() if item["expected_threat"]]
    if max_datasets:
        items = items[:max_datasets]

    for item in items:
        file_path = _BENCHMARK_DIR / item["relative_path"]
        if not file_path.exists():
            continue

        t0 = time.perf_counter()

        # 1. Initial Scan
        scan_before = run_scan(str(file_path))
        orig_risk = scan_before.risk_score
        orig_findings = scan_before.threats_found_count

        # 2. Sanitizer
        fmt = file_path.suffix.lstrip(".").lower()
        san_res = sanitize_file(str(file_path), fmt)

        if san_res.error or not san_res.sanitized_bytes:
            continue

        # 3. Write temp sanitized file for re-scan
        temp_san_path = file_path.parent / f"_temp_san_{file_path.name}"
        temp_san_path.write_bytes(san_res.sanitized_bytes)

        try:
            # 4. Verification Re-scan
            scan_after = run_scan(str(temp_san_path))
            t1 = time.perf_counter()
            rem_dur_ms = (t1 - t0) * 1000.0

            san_risk = scan_after.risk_score
            remaining_findings = scan_after.threats_found_count

            if orig_risk > 0:
                reduction = round(max(0.0, min(100.0, ((orig_risk - san_risk) / orig_risk) * 100.0)), 1)
            else:
                reduction = 100.0 if remaining_findings == 0 else 0.0

            rem_met.total_remediated += 1
            if remaining_findings == 0:
                rem_met.successful_remediations += 1

            rem_met.threat_reductions_pct.append(reduction)
            rem_met.total_before_findings += orig_findings
            rem_met.total_after_findings += remaining_findings
            rem_met.durations_ms.append(rem_dur_ms)

        finally:
            if temp_san_path.exists():
                temp_san_path.unlink()

    return rem_met


def run_full_benchmark(limit: int | None = None) -> dict:
    """Execute complete Phase 6 benchmark suite, generate reports, and return results dictionary."""
    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=== Aegis Node Phase 6 Benchmark Execution ===")

    # 1. Ensure ground truth dataset corpus exists
    gt_file = _BENCHMARK_DIR / "metadata" / "ground_truth.json"
    if not gt_file.exists():
        print("Generating 100 synthetic benchmark datasets...")
        ground_truth = generate_benchmark_corpus(20)
    else:
        ground_truth = json.loads(gt_file.read_text(encoding="utf-8"))

    modes = ["rule_only", "clamav_only", "combined", "combined_llm"]
    mode_results = {}

    for mode in modes:
        print(f"Running detection benchmark mode: {mode}...")
        res = run_benchmark_for_mode(ground_truth, mode, max_datasets=limit)
        mode_results[mode] = {
            "mode": mode,
            "classification": res.classification.to_dict(),
            "performance": res.performance.to_dict(),
            "llm": res.llm.to_dict(),
            "clamav_available": res.clamav_available,
        }

    print("Running dataset remediation benchmark...")
    rem_results = run_remediation_benchmark(ground_truth, max_datasets=limit)

    full_output = {
        "dataset_count": len(ground_truth if not limit else list(ground_truth.keys())[:limit]),
        "modes": mode_results,
        "remediation": rem_results.to_dict(),
    }

    # Save machine readable json
    out_json = _RESULTS_DIR / "benchmark_results.json"
    out_json.write_text(json.dumps(full_output, indent=2), encoding="utf-8")
    print(f"Benchmark results saved to {out_json}")

    # Generate CSV and Markdown report
    csv_p, md_p = generate_reports(full_output)
    print(f"Summary CSV exported to {csv_p}")
    print(f"Research evaluation report generated at {md_p}")

    return full_output


if __name__ == "__main__":
    run_full_benchmark()
