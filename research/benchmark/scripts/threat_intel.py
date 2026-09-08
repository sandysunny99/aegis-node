"""
Aegis Node — Research Threat Intelligence Module (Mock API)

Extracts indicators (IPs, URLs, Hashes) from text and looks them up
against a simulated external Threat Intelligence database.
"""
import re
import asyncio
from dataclasses import dataclass, field

@dataclass
class ThreatIntelSignal:
    indicator: str
    indicator_type: str  # ip, domain, url, hash
    source: str
    verdict: str  # malicious, clean, unknown, error, rate_limited, timeout
    confidence: str
    
@dataclass
class ThreatIntelResult:
    is_malicious: bool
    signals: list[ThreatIntelSignal] = field(default_factory=list)
    available: bool = True
    error_str: str = "none"

# Common regexes for extraction
IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')

# Simulated External Database
_MOCK_INTEL_DB = {
    # 1. Known malicious reputation
    "198.51.100.1": {"verdict": "malicious", "confidence": "high"},
    "evil-c2-domain.com": {"verdict": "malicious", "confidence": "medium"},
    "44d88612fea8a8f36de82e1278abb02f": {"verdict": "malicious", "confidence": "high"}, # malicious hash
    
    # 2. Known clean reputation
    "8.8.8.8": {"verdict": "clean", "confidence": "high"},
    "google.com": {"verdict": "clean", "confidence": "high"},
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"verdict": "clean", "confidence": "high"}, # empty SHA256
    
    # 3. Unknown indicator
    "203.0.113.50": {"verdict": "unknown", "confidence": "none"},
    "unknown-domain-999.org": {"verdict": "unknown", "confidence": "none"},
    
    # 4. API unavailable
    "api-down.test": {"verdict": "error", "error_type": "unavailable"},
    
    # 5. API timeout
    "timeout.test": {"verdict": "error", "error_type": "timeout"},
    
    # 6. API rate-limited
    "rate-limit.test": {"verdict": "error", "error_type": "rate_limited"},
    
    # 7. Conflicting intelligence (one source says clean, one says malicious)
    "conflict.test": {"verdict": "conflict", "confidence": "low"},
    
    # 8. Malformed indicator (handled by regex typically, but we can simulate API rejection)
    "malformed...test": {"verdict": "error", "error_type": "malformed"},
    
    # 10. Benign security research indicator
    "eicar.org": {"verdict": "clean", "confidence": "high"},  # eicar domain is clean, the file is bad
}

def _lookup_indicator(indicator: str, ind_type: str) -> ThreatIntelSignal:
    entry = _MOCK_INTEL_DB.get(indicator, {"verdict": "unknown", "confidence": "none"})
    
    verdict = entry.get("verdict")
    
    if verdict == "error":
        return ThreatIntelSignal(indicator, ind_type, "MockVT", entry.get("error_type", "error"), "none")
    elif verdict == "conflict":
        # Simulate returning malicious but low confidence
        return ThreatIntelSignal(indicator, ind_type, "MockVT", "malicious", "low")
    
    return ThreatIntelSignal(indicator, ind_type, "MockVT", verdict, entry.get("confidence", "none"))

def scan_text(text: str) -> list[ThreatIntelSignal]:
    signals = []
    
    # Extract IP
    for ip in IPV4_REGEX.findall(text):
        signals.append(_lookup_indicator(ip, "ip"))
        
    # Extract Domain
    for dom in DOMAIN_REGEX.findall(text):
        # basic filter
        if dom.lower() not in ["csv", "json", "txt", "com", "org", "net"] and not re.match(r'^\d+\.\d+$', dom):
            signals.append(_lookup_indicator(dom.lower(), "domain"))
            
    # Extract MD5
    for md5 in MD5_REGEX.findall(text):
        signals.append(_lookup_indicator(md5.lower(), "md5"))
        
    # Extract SHA256
    for sha in SHA256_REGEX.findall(text):
        signals.append(_lookup_indicator(sha.lower(), "sha256"))
        
    return signals

def evaluate_rows(rows: list[dict[str, str]]) -> ThreatIntelResult:
    all_signals = []
    has_error = False
    error_str = "none"
    
    for row in rows:
        for _col, val in row.items():
            if isinstance(val, str):
                sigs = scan_text(val)
                all_signals.extend(sigs)
                
    # Determine overall verdict
    is_malicious = False
    for s in all_signals:
        if s.verdict in ["timeout", "unavailable", "rate_limited", "malformed", "error"]:
            has_error = True
            error_str = s.verdict
        if s.verdict == "malicious":
            is_malicious = True
            
    return ThreatIntelResult(
        is_malicious=is_malicious,
        signals=all_signals,
        available=not has_error,
        error_str=error_str
    )
