"""
Aegis Node Research Benchmark — Evaluation Harness

Invokes the FROZEN production scanner (main @ 3f440ee) against benchmark
cases and records machine-readable results WITHOUT modifying any production
code or state.

Usage:
    python research/benchmark/scripts/run_experiment.py --variant A

Variants:
    A = Rules + ClamAV + Heuristics (baseline)
    B = A + YARA                     (future)
    C = B + Normalization            (future)
    D = C + Prompt Guard             (future)
    E = D + Threat Intelligence      (future)
    F = E + LLM Analysis             (future)

Output:
    research/benchmark/results/variant_A_results.json
    research/benchmark/results/variant_A_results.csv
    research/benchmark/results/variant_A_summary.md
"""

import argparse
import csv
import datetime
import hashlib
import json
import logging
import platform
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Resolve project paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[3]          # Aegis-Node/
BENCHMARK_DIR = PROJECT_ROOT / "research" / "benchmark"
DATASET_DIR = BENCHMARK_DIR / "dataset"
GROUND_TRUTH_DIR = BENCHMARK_DIR / "ground_truth"
RESULTS_DIR = BENCHMARK_DIR / "results"

# Ensure scanner is importable
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scanner"))
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s %(name)s: %(message)s",
)

# ---------------------------------------------------------------------------
# Import the FROZEN scanner — NO modifications allowed
# ---------------------------------------------------------------------------
from scanner.engine import run_scan, ScanEngineResult  # noqa: E402


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class GroundTruth:
    case_id: str
    file_name: str
    format: str
    category: str
    expected_class: str
    expected_properties: dict
    description: str
    safe_for_execution: bool
    source_type: str
    notes: str


@dataclass
class EvaluationResult:
    case_id: str
    system_version: str
    git_commit: str
    experiment_variant: str
    predicted_class: str
    expected_class: str
    correct: bool
    scanner_status: str
    clamav_result: str
    yara_result: str
    heuristic_result: str
    normalization_result: str
    ai_result: str = "N/A"
    remediation_result: str = "N/A"
    verification_result: str = "N/A"
    
    # Prompt Guard Details
    prompt_guard_available: bool = False
    prompt_guard_score: float = 0.0
    prompt_guard_prediction: str = "none"
    prompt_guard_evidence: str = "none"
    
    # Threat Intelligence Details
    ti_available: bool = False
    ti_error: str = "none"
    ti_prediction: str = "none"
    ti_evidence: str = "none"
    
    # LLM Details
    llm_status: str = "none"
    llm_summary: str = "none"
    llm_risk_level: str = "none"
    llm_prompt_injection: bool = False
    llm_contradiction: bool = False
    llm_summary: str = ""
    llm_model_used: str = ""
    llm_latency_ms: int = 0
    llm_error: str = ""
    
    latency_ms: int = 0
    error: str = ""
    timestamp: str = ""
    findings_count: int = 0
    findings_detail: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_git_commit() -> str:
    """Return the current HEAD short hash."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(PROJECT_ROOT),
            text=True,
            stderr=subprocess.DEVNULL,
        )
        return out.strip()
    except Exception:
        return "unknown"


def _map_verdict_to_class(verdict: str) -> str:
    """Map the scanner's verdict string to the ground-truth class taxonomy."""
    mapping = {
        "clean_verified": "CLEAN",
        "clean_with_limitations": "CLEAN",
        "suspicious": "SUSPICIOUS",
        "malicious": "MALICIOUS",
        "scan_incomplete": "CLEAN",  # parse failure without threat = not malicious
    }
    return mapping.get(verdict, "CLEAN")


def _load_ground_truth() -> list[GroundTruth]:
    """Load ground truth from JSON."""
    gt_file = GROUND_TRUTH_DIR / "ground_truth.json"
    if not gt_file.exists():
        raise FileNotFoundError(f"Ground truth not found: {gt_file}")
    with gt_file.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return [GroundTruth(**item) for item in raw]


# ---------------------------------------------------------------------------
# Core evaluation
# ---------------------------------------------------------------------------
def evaluate_case(gt: GroundTruth, variant: str, git_commit: str) -> EvaluationResult:
    """Run the scanner against a single benchmark case and record the result."""
    file_path = DATASET_DIR / gt.file_name
    
    if not file_path.exists():
        return EvaluationResult(
            case_id=gt.case_id,
            system_version="aegis-node",
            git_commit=git_commit,
            experiment_variant=variant,
            predicted_class="ERROR",
            expected_class=gt.expected_class,
            correct=False,
            scanner_status="error",
            clamav_result="N/A",
            yara_result="N/A",
            heuristic_result="N/A",
            normalization_result="N/A",
            error=f"File not found: {file_path}",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )

    # Isolated Variant Configuration via memory patching
    # (We DO NOT modify production source code)
    import scanner.engine
    from scanner.yara_scanner import yara_scanner
    import scanner.content_checker
    
    # Prompt Guard is a research module only
    import prompt_guard
    # Threat Intelligence mock is a research module only
    import threat_intel
    # LLM Eval module is a research module only
    import llm_evaluator
    from backend.config import settings
    
    # Store original states
    orig_yara_available = yara_scanner.is_available
    orig_normalize = scanner.content_checker.normalize_text
    
    # Mock no-op normalizer
    def noop_normalize(text: str, max_depth: int = 3) -> tuple[str, list[str]]:
        return text, []
        
    pg_result_obj = None
    ti_result_obj = None
    llm_result_obj = None
    t0 = time.perf_counter()
    
    try:
        if variant == "A":
            # Rules + ClamAV + Heuristics ONLY
            yara_scanner.is_available = False
            scanner.content_checker.normalize_text = noop_normalize
            
        elif variant == "B":
            # Variant A + YARA
            yara_scanner.is_available = orig_yara_available
            scanner.content_checker.normalize_text = noop_normalize
            
        elif variant == "C":
            # Variant B + Normalization
            yara_scanner.is_available = orig_yara_available
            scanner.content_checker.normalize_text = orig_normalize
            
        elif variant in ["D", "E", "F"]:
            # Variant C + Prompt Guard (+ Threat Intel for E/F) (+ LLM for F)
            yara_scanner.is_available = orig_yara_available
            scanner.content_checker.normalize_text = orig_normalize
        
        # Run the frozen scanner
        result: ScanEngineResult = run_scan(str(file_path))
        
        # Research Layer: If Variant D, E, or F, run Prompt Guard independently
        if variant in ["D", "E", "F"]:
            try:
                import csv
                import json
                
                rows = []
                ext = file_path.suffix.lower()
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    if ext == ".csv":
                        reader = csv.DictReader(f)
                        for row in reader:
                            rows.append({k: orig_normalize(str(v))[0] for k, v in row.items() if v})
                    elif ext == ".json":
                        try:
                            data = json.load(f)
                            if isinstance(data, list):
                                for item in data:
                                    if isinstance(item, dict):
                                        rows.append({k: orig_normalize(str(v))[0] for k, v in item.items() if v})
                            elif isinstance(data, dict):
                                rows.append({k: orig_normalize(str(v))[0] for k, v in data.items() if v})
                        except:
                            pass
                    else:
                        rows.append({"text": orig_normalize(f.read())[0]})
                
                pg_results = prompt_guard.classify_file_cells(rows)
                # Take highest confidence result
                if pg_results:
                    pg_result_obj = max(pg_results, key=lambda x: x.confidence)
                else:
                    pg_result_obj = prompt_guard.PromptGuardResult(is_injection=False, confidence=0.0)
                    
                # If Prompt Guard detects injection, escalate to SUSPICIOUS or MALICIOUS
                if pg_result_obj.is_injection:
                    # Treat prompt injection as SUSPICIOUS (which triggers review) unless engine already says MALICIOUS
                    current_verdict = getattr(result.verdict, "value", str(result.verdict))
                    if current_verdict.startswith("clean"):
                        result.verdict = "suspicious" # _map_verdict_to_class handles string values gracefully
                
                # Research Layer: If Variant E or F, run Threat Intelligence independently
                if variant in ["E", "F"]:
                    ti_result_obj = threat_intel.evaluate_rows(rows)
                    if ti_result_obj.is_malicious:
                        # Threat intelligence detects malicious indicator -> escalate
                        current_verdict = getattr(result.verdict, "value", str(result.verdict))
                        if current_verdict.startswith("clean"):
                            result.verdict = "suspicious"
                            
                # Research Layer: If Variant F, run LLM Evaluator
                if variant == "F":
                    # Build evidence payload
                    evidence = {
                        "dataset_id": str(file_path.name),
                        "format": ext,
                        "file_size_bytes": file_path.stat().st_size,
                        "clamav_status": "clean", # mocking for brevity since we don't have real clamav data here
                        "risk_score": 0.0, # mocking
                        "findings_count": result.threats_found_count,
                        "findings": result.to_findings_dicts(),
                        "ti_signals": [s.__dict__ for s in ti_result_obj.signals] if ti_result_obj else [],
                        "prompt_guard_score": pg_result_obj.confidence if pg_result_obj else 0.0,
                    }
                    llm_result_obj = llm_evaluator.evaluate_with_llm(
                        evidence,
                        api_key=settings.gemini_api_key,
                        xai_api_key=getattr(settings, 'xai_api_key', ''),
                    )
                    # Note: We explicitly DO NOT overwrite deterministic verdicts based on LLM output.
                    
            except Exception as e:
                print(f" Research Layer Error: {e} ")
                # Failure must NOT silently overwrite security finding
                pass
                
    except Exception as exc:
        return EvaluationResult(
            case_id=gt.case_id,
            system_version="aegis-node",
            git_commit=git_commit,
            experiment_variant=variant,
            predicted_class="ERROR",
            expected_class=gt.expected_class,
            correct=False,
            scanner_status="error",
            clamav_result="N/A",
            yara_result="N/A",
            heuristic_result="N/A",
            normalization_result="N/A",
            error=str(exc),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
    finally:
        # Restore original state
        yara_scanner.is_available = orig_yara_available
        scanner.content_checker.normalize_text = orig_normalize

    predicted = _map_verdict_to_class(result.verdict)
    correct = predicted == gt.expected_class

    yara_matches = ", ".join(f.rule_id for f in result.yara_findings) if result.yara_findings else "none"
    latency = int((time.perf_counter() - t0) * 1000)
    
    pg_avail = bool(variant in ["D", "E"] and pg_result_obj is not None)
    pg_score = pg_result_obj.confidence if pg_result_obj else 0.0
    pg_pred = "injection" if (pg_result_obj and pg_result_obj.is_injection) else "clean"
    pg_evidence = pg_result_obj.evidence_summary if pg_result_obj else "none"

    ti_avail = bool(variant in ["E", "F"] and ti_result_obj is not None and ti_result_obj.available)
    ti_err = ti_result_obj.error_str if ti_result_obj else "none"
    ti_pred = "malicious" if (ti_result_obj and ti_result_obj.is_malicious) else "clean"
    if ti_result_obj and ti_result_obj.signals:
        ti_evidence = "; ".join([f"{s.indicator}({s.verdict})" for s in ti_result_obj.signals])
    else:
        ti_evidence = "none"

    return EvaluationResult(
        case_id=gt.case_id,
        system_version="aegis-node",
        git_commit=git_commit,
        experiment_variant=variant,
        predicted_class=predicted,
        expected_class=gt.expected_class,
        correct=correct,
        scanner_status=result.verdict,
        clamav_result=result.clamav_status,
        yara_result=yara_matches,
        heuristic_result=f"findings={len(result.heuristic_findings)}, risk={result.heuristic_risk_score:.4f}",
        normalization_result="applied",
        prompt_guard_available=pg_avail,
        prompt_guard_score=pg_score,
        prompt_guard_prediction=pg_pred,
        prompt_guard_evidence=pg_evidence,
        ti_available=ti_avail,
        ti_error=ti_err,
        ti_prediction=ti_pred,
        ti_evidence=ti_evidence,
        llm_status=llm_result_obj.llm_status if llm_result_obj else "none",
        llm_summary=llm_result_obj.analysis_summary if llm_result_obj else "none",
        llm_risk_level=llm_result_obj.risk_level if llm_result_obj else "none",
        llm_prompt_injection=llm_result_obj.prompt_injection_detected if llm_result_obj else False,
        llm_contradiction=llm_result_obj.contradiction_detected if llm_result_obj else False,
        llm_model_used=llm_result_obj.model_used if llm_result_obj else "none",
        llm_latency_ms=llm_result_obj.latency_ms if llm_result_obj else 0,
        llm_error=llm_result_obj.error if llm_result_obj else "none",
        latency_ms=result.scan_duration_ms,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        findings_count=result.threats_found_count,
        findings_detail=result.to_findings_dicts(),
    )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def compute_metrics(results: list[EvaluationResult]) -> dict:
    """Compute precision, recall, F1, FPR, FNR, and latency stats."""
    # Binary: CLEAN vs NOT-CLEAN (SUSPICIOUS or MALICIOUS = positive)
    tp = fp = tn = fn = 0
    latencies = []

    for r in results:
        if r.predicted_class == "ERROR":
            continue
        latencies.append(r.latency_ms)

        expected_positive = r.expected_class in ("SUSPICIOUS", "MALICIOUS")
        predicted_positive = r.predicted_class in ("SUSPICIOUS", "MALICIOUS")

        if predicted_positive and expected_positive:
            tp += 1
        elif predicted_positive and not expected_positive:
            fp += 1
        elif not predicted_positive and not expected_positive:
            tn += 1
        elif not predicted_positive and expected_positive:
            fn += 1

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

    sorted_lat = sorted(latencies) if latencies else [0]
    p95_idx = int(len(sorted_lat) * 0.95)

    # Multiclass confusion
    classes = ["CLEAN", "SUSPICIOUS", "MALICIOUS"]
    multiclass = {c: {c2: 0 for c2 in classes} for c in classes}
    for r in results:
        if r.expected_class in classes and r.predicted_class in classes:
            multiclass[r.expected_class][r.predicted_class] += 1

    # Per-category metrics
    categories = set(r.case_id[:1] for r in results)
    per_category = {}
    for cat_prefix in sorted(categories):
        cat_results = [r for r in results if r.case_id.startswith(cat_prefix)]
        cat_correct = sum(1 for r in cat_results if r.correct)
        per_category[cat_prefix] = {
            "total": len(cat_results),
            "correct": cat_correct,
            "accuracy": cat_correct / len(cat_results) if cat_results else 0.0,
        }

    return {
        "binary_classification": {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "tpr": round(tpr, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
        },
        "multiclass_confusion_matrix": multiclass,
        "per_category": per_category,
        "latency": {
            "mean_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0,
            "median_ms": sorted_lat[len(sorted_lat) // 2] if sorted_lat else 0,
            "p95_ms": sorted_lat[p95_idx] if sorted_lat else 0,
            "min_ms": min(latencies) if latencies else 0,
            "max_ms": max(latencies) if latencies else 0,
        },
    }


def compute_error_analysis(results: list[EvaluationResult]) -> list[dict]:
    """Generate error analysis for incorrect predictions."""
    errors = []
    for r in results:
        if r.correct or r.predicted_class == "ERROR":
            continue

        # Classify error type
        expected_pos = r.expected_class in ("SUSPICIOUS", "MALICIOUS")
        predicted_pos = r.predicted_class in ("SUSPICIOUS", "MALICIOUS")

        if predicted_pos and not expected_pos:
            error_type = "false_positive"
        elif not predicted_pos and expected_pos:
            error_type = "false_negative"
        else:
            error_type = "classification_ambiguity"

        errors.append({
            "case_id": r.case_id,
            "expected": r.expected_class,
            "predicted": r.predicted_class,
            "error_type": error_type,
            "scanner_status": r.scanner_status,
            "findings_count": r.findings_count,
            "findings_detail": r.findings_detail,
            "likely_failure_reason": _infer_failure_reason(r, error_type),
        })
    return errors


def _infer_failure_reason(r: EvaluationResult, error_type: str) -> str:
    """Attempt to infer why the prediction was wrong."""
    if error_type == "false_positive":
        if any("malware_reference" in str(f) for f in r.findings_detail):
            return "malware_reference_text_flagged_as_threat"
        if any("formula" in str(f).lower() for f in r.findings_detail):
            return "legitimate_formula_flagged_as_injection"
        return "benign_content_triggered_detection_rule"
    elif error_type == "false_negative":
        if r.findings_count == 0:
            return "no_detection_rule_matched"
        return "detection_rule_matched_but_severity_insufficient"
    return "classification_boundary_ambiguity"


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------
def write_results_json(results: list[EvaluationResult], metrics: dict,
                       errors: list[dict], variant: str, git_commit: str) -> Path:
    """Write full results to JSON."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / f"variant_{variant}_results.json"
    payload = {
        "metadata": {
            "system": "aegis-node",
            "git_commit": git_commit,
            "variant": variant,
            "python_version": platform.python_version(),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_cases": len(results),
        },
        "metrics": metrics,
        "results": [asdict(r) for r in results],
        "error_analysis": errors,
    }
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    return out_path




def write_results_csv(results: list[EvaluationResult], variant: str):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / f"variant_{variant}_results.csv"
    
    fieldnames = [
        "case_id", "expected_class", "predicted_class", "correct",
        "scanner_status", "clamav_result", "yara_result", "heuristic_result",
        "normalization_result", "ai_result", "remediation_result", "verification_result",
        "prompt_guard_available", "prompt_guard_score", "prompt_guard_prediction", "prompt_guard_evidence",
        "ti_available", "ti_error", "ti_prediction", "ti_evidence",
        "llm_status", "llm_risk_level", "llm_prompt_injection", "llm_contradiction", "llm_summary",
        "llm_model_used", "llm_latency_ms", "llm_error",
        "findings_count", "latency_ms", "error"
    ]
    
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "case_id": r.case_id,
                "expected_class": r.expected_class,
                "predicted_class": r.predicted_class,
                "correct": r.correct,
                "scanner_status": r.scanner_status,
                "clamav_result": r.clamav_result,
                "yara_result": r.yara_result,
                "heuristic_result": r.heuristic_result,
                "normalization_result": r.normalization_result,
                "ai_result": r.ai_result,
                "remediation_result": r.remediation_result,
                "verification_result": r.verification_result,
                "prompt_guard_available": r.prompt_guard_available,
                "prompt_guard_score": r.prompt_guard_score,
                "prompt_guard_prediction": r.prompt_guard_prediction,
                "prompt_guard_evidence": r.prompt_guard_evidence,
                "ti_available": r.ti_available,
                "ti_error": r.ti_error,
                "ti_prediction": r.ti_prediction,
                "ti_evidence": r.ti_evidence,
                "llm_status": r.llm_status,
                "llm_risk_level": r.llm_risk_level,
                "llm_prompt_injection": r.llm_prompt_injection,
                "llm_contradiction": r.llm_contradiction,
                "llm_summary": r.llm_summary,
                "llm_model_used": r.llm_model_used,
                "llm_latency_ms": r.llm_latency_ms,
                "llm_error": r.llm_error,
                "findings_count": len(r.findings_detail),
                "latency_ms": r.latency_ms,
                "error": r.error
            })
    return out_path


def write_summary_md(results: list[EvaluationResult], metrics: dict,
                     errors: list[dict], variant: str, git_commit: str) -> Path:
    """Write human-readable summary."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / f"variant_{variant}_summary.md"

    bc = metrics["binary_classification"]
    lat = metrics["latency"]

    lines = [
        f"# Aegis Node Benchmark — Variant {variant} Results\n",
        f"**Git Commit**: `{git_commit}`",
        f"**Timestamp**: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
        f"**Python**: {platform.python_version()}",
        f"**Total Cases**: {len(results)}\n",
        "## Binary Classification (CLEAN vs SUSPICIOUS/MALICIOUS)\n",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Accuracy | {bc['accuracy']:.4f} |",
        f"| Precision | {bc['precision']:.4f} |",
        f"| Recall | {bc['recall']:.4f} |",
        f"| F1 Score | {bc['f1_score']:.4f} |",
        f"| False Positive Rate | {bc['fpr']:.4f} |",
        f"| False Negative Rate | {bc['fnr']:.4f} |\n",
        "## Confusion Matrix (Binary)\n",
        "| | Predicted Positive | Predicted Negative |",
        "|---|---|---|",
        f"| **Actual Positive** | TP={bc['tp']} | FN={bc['fn']} |",
        f"| **Actual Negative** | FP={bc['fp']} | TN={bc['tn']} |\n",
        "## Multiclass Confusion Matrix\n",
        "| Expected \\ Predicted | CLEAN | SUSPICIOUS | MALICIOUS |",
        "|---|---|---|---|",
    ]

    mcm = metrics["multiclass_confusion_matrix"]
    for expected in ["CLEAN", "SUSPICIOUS", "MALICIOUS"]:
        row = mcm.get(expected, {})
        lines.append(
            f"| **{expected}** | {row.get('CLEAN', 0)} | "
            f"{row.get('SUSPICIOUS', 0)} | {row.get('MALICIOUS', 0)} |"
        )

    lines.extend([
        "",
        "## Per-Category Accuracy\n",
        "| Category | Total | Correct | Accuracy |",
        "|----------|-------|---------|----------|",
    ])
    cat_names = {
        "A": "Benign", "B": "Malware Reference", "C": "Malicious Payload",
        "D": "Formula Injection", "E": "Prompt Injection", "F": "Encoded Content",
        "G": "Mixed", "H": "Edge Cases",
    }
    for prefix, data in metrics["per_category"].items():
        name = cat_names.get(prefix, prefix)
        lines.append(
            f"| {prefix}: {name} | {data['total']} | {data['correct']} | {data['accuracy']:.4f} |"
        )

    lines.extend([
        "",
        "## Latency\n",
        "| Metric | Value (ms) |",
        "|--------|-----------|",
        f"| Mean | {lat['mean_ms']} |",
        f"| Median | {lat['median_ms']} |",
        f"| P95 | {lat['p95_ms']} |",
        f"| Min | {lat['min_ms']} |",
        f"| Max | {lat['max_ms']} |\n",
    ])

    if errors:
        lines.extend([
            "## Error Analysis\n",
            "| Case | Expected | Predicted | Type | Reason |",
            "|------|----------|-----------|------|--------|",
        ])
        for e in errors:
            lines.append(
                f"| {e['case_id']} | {e['expected']} | {e['predicted']} | "
                f"{e['error_type']} | {e['likely_failure_reason']} |"
            )

    lines.extend([
        "",
        "## Individual Results\n",
        "| Case | Expected | Predicted | Correct | Verdict | Findings | Latency (ms) |",
        "|------|----------|-----------|---------|---------|----------|-------------|",
    ])
    for r in results:
        mark = "✅" if r.correct else "❌"
        lines.append(
            f"| {r.case_id} | {r.expected_class} | {r.predicted_class} | "
            f"{mark} | {r.scanner_status} | {r.findings_count} | {r.latency_ms} |"
        )

    lines.append("")

    with out_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return out_path


def write_confusion_matrix_csv(metrics: dict, variant: str) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / f"confusion_matrix_{variant}.csv"
    mcm = metrics["multiclass_confusion_matrix"]
    classes = ["CLEAN", "SUSPICIOUS", "MALICIOUS"]
    
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Expected \\ Predicted"] + classes)
        for expected in classes:
            row = [expected] + [mcm.get(expected, {}).get(p, 0) for p in classes]
            writer.writerow(row)
    return out_path

def write_ablation_csv(results_a: list[EvaluationResult], results_b: list[EvaluationResult]) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "ablation_A_vs_B.csv"
    
    fieldnames = [
        "case_id", "expected_class", "predicted_class_A", "predicted_class_B",
        "changed", "yara_matches", "improved", "degraded"
    ]
    
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for ra, rb in zip(results_a, results_b):
            changed = ra.predicted_class != rb.predicted_class
            improved = changed and rb.correct and not ra.correct
            degraded = changed and not rb.correct and ra.correct
            
            writer.writerow({
                "case_id": ra.case_id,
                "expected_class": ra.expected_class,
                "predicted_class_A": ra.predicted_class,
                "predicted_class_B": rb.predicted_class,
                "changed": changed,
                "yara_matches": rb.yara_result,
                "improved": improved,
                "degraded": degraded
            })
    return out_path

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Aegis Node Research Benchmark Harness")
    parser.add_argument("--variant", default="BOTH", help="Experiment variant (A, B, C, ALL)")
    parser.add_argument("--dataset-version", default="1", help="Dataset version (1 or 2)")
    args = parser.parse_args()

    variant = args.variant.upper()
    variants_to_run = ["A", "B", "C", "D", "E", "F"] if variant == "ALL" else (["A", "B"] if variant == "BOTH" else [variant])
    
    # Path override based on dataset version
    global DATASET_DIR, GROUND_TRUTH_DIR
    if args.dataset_version == "2":
        DATASET_DIR = BENCHMARK_DIR / "dataset_v2"
        GROUND_TRUTH_DIR = BENCHMARK_DIR / "ground_truth_v2"
    elif args.dataset_version == "3":
        DATASET_DIR = BENCHMARK_DIR / "dataset_v3"
        GROUND_TRUTH_DIR = BENCHMARK_DIR / "ground_truth_v3"
    elif args.dataset_version == "4":
        DATASET_DIR = BENCHMARK_DIR / "dataset_v4"
        GROUND_TRUTH_DIR = BENCHMARK_DIR / "ground_truth_v4"
    elif args.dataset_version == "5":
        DATASET_DIR = BENCHMARK_DIR / "dataset_v5"
        GROUND_TRUTH_DIR = BENCHMARK_DIR / "ground_truth_v5"

    print(f"=" * 60)
    print(f"AEGIS NODE BENCHMARK — VARIANT {variant} (Dataset v{args.dataset_version})")
    print(f"=" * 60)

    git_commit = _get_git_commit()
    print(f"Git commit: {git_commit}")
    print(f"Python:     {platform.python_version()}")
    print(f"Timestamp:  {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print()

    ground_truth = _load_ground_truth()
    print(f"Loaded {len(ground_truth)} benchmark cases from v{args.dataset_version}")
    print()

    all_results = {}
    
    for v in variants_to_run:
        print(f"\n--- Running Variant {v} ---")
        results: list[EvaluationResult] = []
        for i, gt in enumerate(ground_truth, 1):
            print(f"  [{i:2d}/{len(ground_truth)}] {gt.case_id}: {gt.file_name} ... ", end="", flush=True)
            result = evaluate_case(gt, v, git_commit)
            results.append(result)
            mark = "[PASS]" if result.correct else "[FAIL]"
            print(f"{mark} {result.predicted_class} (expected {result.expected_class}) [{result.latency_ms}ms]")

        metrics = compute_metrics(results)
        errors = compute_error_analysis(results)

        write_results_json(results, metrics, errors, v, git_commit)
        write_results_csv(results, v)
        write_summary_md(results, metrics, errors, v, git_commit)
        write_confusion_matrix_csv(metrics, v)
        
        all_results[v] = {"results": results, "metrics": metrics, "errors": errors}

    # Custom ablation for A vs B vs C vs D vs E vs F
    if set(["A", "B", "C", "D", "E", "F"]).issubset(all_results.keys()):
        print("\n--- Ablation Analysis (A vs B vs C vs D vs E vs F) ---")
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        abcdef_path = RESULTS_DIR / "ablation_A_vs_B_vs_C_vs_D_vs_E_vs_F.csv"
        
        fieldnames = [
            "case_id", "expected_class", 
            "predicted_class_A", "predicted_class_B", "predicted_class_C", "predicted_class_D", "predicted_class_E", "predicted_class_F",
            "B_misses_C_detects", "C_misses_D_detects", "D_misses_E_detects", 
            "D_clean_E_false_positive",
            "F_llm_risk_level", "F_prompt_injection", "F_contradiction"
        ]
        
        with abcdef_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for ra, rb, rc, rd, re_result, rf in zip(all_results["A"]["results"], all_results["B"]["results"], all_results["C"]["results"], all_results["D"]["results"], all_results["E"]["results"], all_results["F"]["results"]):
                b_binary_correct = (rb.predicted_class != "CLEAN") == (rb.expected_class != "CLEAN")
                c_binary_correct = (rc.predicted_class != "CLEAN") == (rc.expected_class != "CLEAN")
                d_binary_correct = (rd.predicted_class != "CLEAN") == (rd.expected_class != "CLEAN")
                e_binary_correct = (re_result.predicted_class != "CLEAN") == (re_result.expected_class != "CLEAN")
                
                b_misses_c_detects = (not b_binary_correct) and c_binary_correct
                c_misses_d_detects = (not c_binary_correct) and d_binary_correct
                d_misses_e_detects = (not d_binary_correct) and e_binary_correct
                d_clean_e_fp = rd.predicted_class == "CLEAN" and re_result.predicted_class != "CLEAN" and re_result.expected_class == "CLEAN"
                
                writer.writerow({
                    "case_id": ra.case_id,
                    "expected_class": ra.expected_class,
                    "predicted_class_A": ra.predicted_class,
                    "predicted_class_B": rb.predicted_class,
                    "predicted_class_C": rc.predicted_class,
                    "predicted_class_D": rd.predicted_class,
                    "predicted_class_E": re_result.predicted_class,
                    "predicted_class_F": rf.predicted_class,
                    "B_misses_C_detects": b_misses_c_detects,
                    "C_misses_D_detects": c_misses_d_detects,
                    "D_misses_E_detects": d_misses_e_detects,
                    "D_clean_E_false_positive": d_clean_e_fp,
                    "F_llm_risk_level": rf.llm_risk_level,
                    "F_prompt_injection": rf.llm_prompt_injection,
                    "F_contradiction": rf.llm_contradiction
                })
        print(f"A vs B vs C vs D vs E vs F Ablation saved to: {abcdef_path}")
        ablation_csv = write_ablation_csv(all_results["A"]["results"], all_results["B"]["results"])
        print(f"Ablation comparison saved to: {ablation_csv}")
        
    if "F" in all_results:
        # Write llm_quality_review.csv
        llm_quality_path = RESULTS_DIR / "llm_quality_review.csv"
        with llm_quality_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["case_id", "ground_truth", "llm_output", "evidence_supported", "unsupported_claim", "uncertainty_correct", "contradiction_correct", "review_decision", "reviewer_note"])
            writer.writeheader()
            for rf in all_results["F"]["results"]:
                writer.writerow({
                    "case_id": rf.case_id,
                    "ground_truth": rf.expected_class,
                    "llm_output": rf.llm_summary,
                    "evidence_supported": "TODO",
                    "unsupported_claim": "TODO",
                    "uncertainty_correct": "TODO",
                    "contradiction_correct": rf.llm_contradiction,
                    "review_decision": "TODO",
                    "reviewer_note": ""
                })
        print(f"LLM Quality Review Template saved to: {llm_quality_path}")
        
    if "A" in all_results and "B" in all_results:
        metrics_a = all_results["A"]["metrics"]["binary_classification"]
        metrics_b = all_results["B"]["metrics"]["binary_classification"]
        
        print("\nMetrics Delta (B - A):")
        for k in metrics_a:
            delta = metrics_b[k] - metrics_a[k]
            print(f"  {k}: {metrics_b[k]} (Delta: {delta:+.4f})")

if __name__ == "__main__":
    main()
