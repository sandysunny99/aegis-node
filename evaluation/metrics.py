"""
Aegis Node — Evaluation Metrics Calculator.
Provides safe, zero-denominator-guaranteed metrics for classification, latency performance,
LLM token consumption, and remediation effectiveness.

Pure Python standard library implementation — zero SciPy/NumPy overhead.
"""

import statistics
from dataclasses import dataclass, field

# ─── Classification Metrics ───────────────────────────────────────────────────

@dataclass
class ClassificationMetrics:
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    @property
    def accuracy(self) -> float:
        if self.total == 0:
            return 0.0
        return round((self.tp + self.tn) / self.total, 4)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        if denom == 0:
            return 0.0
        return round(self.tp / denom, 4)

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        if denom == 0:
            return 0.0
        return round(self.tp / denom, 4)

    @property
    def f1_score(self) -> float:
        p = self.precision
        r = self.recall
        if (p + r) == 0:
            return 0.0
        return round(2 * (p * r) / (p + r), 4)

    @property
    def false_positive_rate(self) -> float:
        denom = self.fp + self.tn
        if denom == 0:
            return 0.0
        return round(self.fp / denom, 4)

    @property
    def false_negative_rate(self) -> float:
        denom = self.fn + self.tp
        if denom == 0:
            return 0.0
        return round(self.fn / denom, 4)

    def to_dict(self) -> dict:
        return {
            "tp": self.tp,
            "tn": self.tn,
            "fp": self.fp,
            "fn": self.fn,
            "total": self.total,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
        }


# ─── Latency & Performance Metrics ───────────────────────────────────────────

@dataclass
class PerformanceMetrics:
    durations_ms: list[float] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.durations_ms)

    @property
    def total_duration_ms(self) -> float:
        return round(sum(self.durations_ms), 2)

    @property
    def mean_duration_ms(self) -> float:
        if not self.durations_ms:
            return 0.0
        return round(statistics.mean(self.durations_ms), 2)

    @property
    def median_duration_ms(self) -> float:
        if not self.durations_ms:
            return 0.0
        return round(statistics.median(self.durations_ms), 2)

    @property
    def min_duration_ms(self) -> float:
        if not self.durations_ms:
            return 0.0
        return round(min(self.durations_ms), 2)

    @property
    def max_duration_ms(self) -> float:
        if not self.durations_ms:
            return 0.0
        return round(max(self.durations_ms), 2)

    @property
    def stddev_duration_ms(self) -> float:
        if len(self.durations_ms) < 2:
            return 0.0
        return round(statistics.stdev(self.durations_ms), 2)

    @property
    def datasets_per_second(self) -> float:
        total_sec = self.total_duration_ms / 1000.0
        if total_sec == 0:
            return 0.0
        return round(self.count / total_sec, 2)

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "total_duration_ms": self.total_duration_ms,
            "mean_duration_ms": self.mean_duration_ms,
            "median_duration_ms": self.median_duration_ms,
            "min_duration_ms": self.min_duration_ms,
            "max_duration_ms": self.max_duration_ms,
            "stddev_duration_ms": self.stddev_duration_ms,
            "datasets_per_second": self.datasets_per_second,
        }


# ─── LLM Consumption Metrics ─────────────────────────────────────────────────

@dataclass
class LlmMetrics:
    llm_requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    available: bool = True

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def avg_tokens_per_dataset(self) -> float:
        if self.llm_requests == 0:
            return 0.0
        return round(self.total_tokens / self.llm_requests, 1)

    @property
    def avg_llm_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        return round(statistics.mean(self.latencies_ms), 2)

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "llm_requests": self.llm_requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "avg_tokens_per_dataset": self.avg_tokens_per_dataset,
            "avg_llm_latency_ms": self.avg_llm_latency_ms,
        }


# ─── Remediation Metrics ──────────────────────────────────────────────────────

@dataclass
class RemediationMetrics:
    total_remediated: int = 0
    successful_remediations: int = 0
    threat_reductions_pct: list[float] = field(default_factory=list)
    total_before_findings: int = 0
    total_after_findings: int = 0
    durations_ms: list[float] = field(default_factory=list)

    @property
    def total_resolved_findings(self) -> int:
        return max(0, self.total_before_findings - self.total_after_findings)

    @property
    def remediation_success_rate(self) -> float:
        if self.total_remediated == 0:
            return 0.0
        return round((self.successful_remediations / self.total_remediated) * 100.0, 2)

    @property
    def avg_threat_reduction_percent(self) -> float:
        if not self.threat_reductions_pct:
            return 0.0
        return round(statistics.mean(self.threat_reductions_pct), 2)

    @property
    def avg_remediation_duration_ms(self) -> float:
        if not self.durations_ms:
            return 0.0
        return round(statistics.mean(self.durations_ms), 2)

    def to_dict(self) -> dict:
        return {
            "total_remediated": self.total_remediated,
            "successful_remediations": self.successful_remediations,
            "remediation_success_rate": self.remediation_success_rate,
            "avg_threat_reduction_percent": self.avg_threat_reduction_percent,
            "total_before_findings": self.total_before_findings,
            "total_after_findings": self.total_after_findings,
            "total_resolved_findings": self.total_resolved_findings,
            "avg_remediation_duration_ms": self.avg_remediation_duration_ms,
        }
