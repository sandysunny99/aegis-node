"""
Aegis Node — Lightweight Prompt Guard (Research Evaluation Module)

A heuristic-based prompt-injection classifier designed for the ablation study.
This is NOT a production component. It exists purely in the research layer
to evaluate what a dedicated prompt-injection detection stage would contribute
beyond the existing PROMPT-001/PROMPT-002 regex rules.

Design constraints (per user directive):
- No PyTorch, Transformers, or heavy ML dependencies
- Pure Python + stdlib only
- Bounded resource usage
- Does not modify production scanner behavior

Detection approach:
- Multi-pattern semantic scoring across injection categories
- Confidence threshold gating
- Explicit evidence recording for each signal
"""

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Signal patterns — each scores independently
# ---------------------------------------------------------------------------

@dataclass
class PromptGuardSignal:
    """A single detected prompt-injection signal."""
    signal_id: str
    category: str
    description: str
    matched_text: str
    confidence: float  # 0.0 - 1.0


# Category 1: Direct instruction override (extends PROMPT-001 coverage)
_INSTRUCTION_OVERRIDE_PATTERNS = [
    (re.compile(r'\b(?:ignore|disregard|forget|override|bypass|skip|cancel|dismiss)\s+(?:all\s+)?(?:prior|previous|earlier|above|existing|current|your)\s+(?:instructions|rules|guidelines|constraints|directives|prompts?|context|system\s+prompt)', re.IGNORECASE),
     "IO-001", "Direct instruction override", 0.95),
    (re.compile(r'\b(?:do\s+not\s+follow|stop\s+following|cease\s+following)\s+(?:any|all|the|your)?\s*(?:instructions|rules|guidelines)', re.IGNORECASE),
     "IO-002", "Instruction negation", 0.90),
    (re.compile(r'\bnew\s+instruction[s]?\s*:', re.IGNORECASE),
     "IO-003", "Explicit new instruction marker", 0.85),
    (re.compile(r'\bfrom\s+now\s+on\b.*\b(?:you\s+will|you\s+must|you\s+should|respond|act|behave)', re.IGNORECASE),
     "IO-004", "Behavioral override via temporal framing", 0.80),
]

# Category 2: Role manipulation / persona hijacking
_ROLE_MANIPULATION_PATTERNS = [
    (re.compile(r'\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:you\s+are|to\s+be)|roleplay\s+as|simulate\s+being|behave\s+as\s+if\s+you\s+(?:are|were))\b.*\b(?:no\s+(?:restrictions?|limits?|filters?|safety|guidelines|rules)|unrestricted|unfiltered|uncensored)', re.IGNORECASE | re.DOTALL),
     "RM-001", "Role hijacking with restriction removal", 0.95),
    (re.compile(r'\b(?:you\s+are\s+now\s+(?:DAN|evil|jailbr(?:oken|eak)|uncensored|unrestricted))\b', re.IGNORECASE),
     "RM-002", "Known jailbreak persona", 0.98),
    (re.compile(r'\b(?:enter|switch\s+to|activate|enable)\s+(?:developer|debug|admin|maintenance|god|root|sudo)\s+mode\b', re.IGNORECASE),
     "RM-003", "Privilege escalation via mode switch", 0.90),
    (re.compile(r'\bpretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:different|another|new)\s+(?:AI|assistant|model|system)\b', re.IGNORECASE),
     "RM-004", "Persona substitution", 0.80),
]

# Category 3: System prompt impersonation
_SYSTEM_IMPERSONATION_PATTERNS = [
    (re.compile(r'(?:^|\n)\s*\[(?:SYSTEM|SYS|ADMIN|ROOT)\]', re.IGNORECASE),
     "SI-001", "System tag impersonation", 0.85),
    (re.compile(r'<<\s*SYS\s*>>.*?<<\s*/SYS\s*>>', re.IGNORECASE | re.DOTALL),
     "SI-002", "Llama-style system prompt markers", 0.90),
    (re.compile(r'(?:^|\n)\s*#{2,3}\s*(?:SYSTEM\s+PROMPT|SYSTEM\s+MESSAGE|INSTRUCTIONS?)\s*#{0,3}', re.IGNORECASE),
     "SI-003", "Markdown system prompt headers", 0.85),
    (re.compile(r'\b(?:system\s*:\s*|<\|system\|>|<\|im_start\|>\s*system)', re.IGNORECASE),
     "SI-004", "Chat-template system role markers", 0.90),
]

# Category 4: Safety bypass / output manipulation
_SAFETY_BYPASS_PATTERNS = [
    (re.compile(r'\b(?:disable|remove|turn\s+off|deactivate|bypass)\s+(?:all\s+)?(?:content\s+)?(?:filters?|safety|restrictions?|moderation|guardrails?)\b', re.IGNORECASE),
     "SB-001", "Safety filter bypass request", 0.90),
    (re.compile(r'\b(?:output|reveal|show|display|print|leak|expose|dump)\s+(?:all\s+)?(?:the\s+)?(?:system\s+prompt|hidden\s+instructions?|secret|api\s+keys?|config(?:uration)?|internal)\b', re.IGNORECASE),
     "SB-002", "Information exfiltration attempt", 0.92),
    (re.compile(r'\b(?:respond\s+only\s+in|encode\s+(?:your\s+)?(?:output|response)\s+(?:in|as|using))\s+(?:base64|hex|binary|rot13)\b', re.IGNORECASE),
     "SB-003", "Output encoding manipulation", 0.75),
]

ALL_PATTERN_GROUPS = [
    ("instruction_override", _INSTRUCTION_OVERRIDE_PATTERNS),
    ("role_manipulation", _ROLE_MANIPULATION_PATTERNS),
    ("system_impersonation", _SYSTEM_IMPERSONATION_PATTERNS),
    ("safety_bypass", _SAFETY_BYPASS_PATTERNS),
]


# ---------------------------------------------------------------------------
# Core classifier
# ---------------------------------------------------------------------------

@dataclass
class PromptGuardResult:
    """Result of prompt-guard evaluation on a text string."""
    is_injection: bool
    confidence: float  # max confidence across all signals
    signals: list[PromptGuardSignal] = field(default_factory=list)
    categories_detected: list[str] = field(default_factory=list)

    @property
    def evidence_summary(self) -> str:
        if not self.signals:
            return "no_signals"
        return "; ".join(f"{s.signal_id}({s.confidence:.2f})" for s in self.signals)


# Threshold: minimum confidence to flag as injection
INJECTION_THRESHOLD = 0.70


def classify_text(text: str, threshold: float = INJECTION_THRESHOLD) -> PromptGuardResult:
    """
    Classify a single text string for prompt-injection signals.

    Returns a PromptGuardResult with all detected signals and an overall
    injection determination based on the confidence threshold.
    """
    if not text or not isinstance(text, str):
        return PromptGuardResult(is_injection=False, confidence=0.0)

    signals: list[PromptGuardSignal] = []
    categories_seen: set[str] = set()

    for category_name, patterns in ALL_PATTERN_GROUPS:
        for pattern, signal_id, description, base_confidence in patterns:
            match = pattern.search(text)
            if match:
                signals.append(PromptGuardSignal(
                    signal_id=signal_id,
                    category=category_name,
                    description=description,
                    matched_text=match.group(0)[:200],
                    confidence=base_confidence,
                ))
                categories_seen.add(category_name)

    max_confidence = max((s.confidence for s in signals), default=0.0)

    # Multi-category boost: if signals from 2+ categories fire, increase confidence
    if len(categories_seen) >= 2:
        max_confidence = min(max_confidence + 0.05, 1.0)

    return PromptGuardResult(
        is_injection=max_confidence >= threshold,
        confidence=round(max_confidence, 4),
        signals=signals,
        categories_detected=sorted(categories_seen),
    )


def classify_file_cells(rows: list[dict[str, str]], threshold: float = INJECTION_THRESHOLD) -> list[PromptGuardResult]:
    """
    Classify all string cells in a list of row dicts.
    Returns one PromptGuardResult per row (worst signal wins).
    """
    results = []
    for row in rows:
        row_signals: list[PromptGuardSignal] = []
        for _col, value in row.items():
            if isinstance(value, str) and len(value) > 5:
                cell_result = classify_text(value, threshold)
                row_signals.extend(cell_result.signals)

        max_conf = max((s.confidence for s in row_signals), default=0.0)
        cats = sorted(set(s.category for s in row_signals))
        if len(cats) >= 2:
            max_conf = min(max_conf + 0.05, 1.0)

        results.append(PromptGuardResult(
            is_injection=max_conf >= threshold,
            confidence=round(max_conf, 4),
            signals=row_signals,
            categories_detected=cats,
        ))
    return results
