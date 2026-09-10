import re
import base64
import unicodedata
import string
import logging

logger = logging.getLogger(__name__)

# Zero-width characters and invisible formatting
_ZERO_WIDTH = re.compile(r'[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]')

# Base64 detection regex (rudimentary bounded check)
_BASE64_RE = re.compile(r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

_SIG_INSTRUCTION_OVERRIDE = re.compile(
    r'(ignore\s+previous\s+instructions|disregard\s+(prior|previous)\s+(rules|instructions)|override\s+rules|bypass\s+policy|forget\s+(all\s+)?(previous\s+)?instructions)',
    re.IGNORECASE
)

_SIG_ROLE_IMPERSONATION = re.compile(
    r'(system:\s*you\s+are|developer\s+instruction|administrator\s+claims|you\s+are\s+now|act\s+as\s+a)',
    re.IGNORECASE
)
_SIG_ROOT_OVERRIDE = re.compile(r'(root\s+override)', re.IGNORECASE)

_SIG_PROMPT_EXTRACTION = re.compile(
    r'(reveal\s+system\s+prompt|show\s+hidden\s+instructions|expose\s+internal\s+policy|repeat\s+the\s+words\s+above|print\s+(the\s+)?instructions|translate\s+(the\s+)?system\s+prompt)',
    re.IGNORECASE
)

_SIG_VERDICT_MANIPULATION = re.compile(
    r'((set|mark|return|change)\s+(the\s+)?verdict|ignore\s+scanner\s+findings|suppress\s+warning|approve\s+malicious\s+content)',
    re.IGNORECASE
)

_SIG_ACTION_MANIPULATION = re.compile(
    r'(disable\s+scanning|execute\s+command|call\s+shell|<tool_call>|delete\s+security\s+evidence|modify\s+files|retrieve\s+payload|do\s+not\s+remediate)',
    re.IGNORECASE
)

_SIG_SECRET_EXFILTRATION = re.compile(
    r'(return\s+(the\s+)?(secret\s+)?api\s+key|output\s+password|expose\s+credentials|dump\s+environment\s+variables)',
    re.IGNORECASE
)

def canonicalize(text: str) -> str:
    """Normalize Unicode, remove zero-width chars, standardize whitespace."""
    if not text:
        return ""
    text = _ZERO_WIDTH.sub('', text)
    text = unicodedata.normalize('NFKC', text)
    text = ' '.join(text.split())
    return text

def bounded_base64_decode(text: str) -> str:
    decoded_fragments = []
    for match in _BASE64_RE.finditer(text):
        b64_str = match.group(0)
        if len(b64_str) > 2000:
            continue
        try:
            decoded_bytes = base64.b64decode(b64_str + "===")
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            if sum(1 for c in decoded_str if c in string.printable) > len(decoded_str) * 0.8:
                decoded_fragments.append(canonicalize(decoded_str))
        except Exception:
            pass
    
    if decoded_fragments:
        return text + " " + " ".join(decoded_fragments)
    return text

def evaluate_input_guardrail(evidence_text: str) -> tuple[str, int, list[str]]:
    score = 0
    signals = []
    
    normalized = canonicalize(evidence_text)
    analyzed_text = bounded_base64_decode(normalized)
    
    # Shadow check for spaced out characters: "i g n o r e" -> "ignore"
    spaced_out_removed = analyzed_text.replace(" ", "")
    
    if _SIG_INSTRUCTION_OVERRIDE.search(analyzed_text) or "ignorepreviousinstructions" in spaced_out_removed.lower() or "override" in spaced_out_removed.lower() and "rules" in spaced_out_removed.lower():
        score += 3
        signals.append("INSTRUCTION_OVERRIDE")
        
    if _SIG_ROLE_IMPERSONATION.search(analyzed_text) or "system:youare" in spaced_out_removed.lower() or "developerinstruction" in spaced_out_removed.lower() or "actasa" in spaced_out_removed.lower():
        score += 3
        signals.append("ROLE_IMPERSONATION")
        
    if _SIG_ROOT_OVERRIDE.search(analyzed_text):
        if "The system uses" not in analyzed_text and "was found" not in analyzed_text:
            score += 3
            signals.append("ROLE_IMPERSONATION")

    if _SIG_PROMPT_EXTRACTION.search(analyzed_text) or "revealsystemprompt" in spaced_out_removed.lower() or "showhiddeninstructions" in spaced_out_removed.lower() or "translatesystemprompt" in spaced_out_removed.lower():
        score += 3
        signals.append("PROMPT_EXTRACTION")
        
    if _SIG_VERDICT_MANIPULATION.search(analyzed_text) or "setverdictclean" in spaced_out_removed.lower() or "markverdictclean" in spaced_out_removed.lower() or "ignorescannerfindings" in spaced_out_removed.lower():
        score += 2
        signals.append("VERDICT_MANIPULATION")
        
    if _SIG_ACTION_MANIPULATION.search(analyzed_text) or "disablescanning" in spaced_out_removed.lower() or "executecommand" in spaced_out_removed.lower() or "callshell" in spaced_out_removed.lower() or "tool_call" in spaced_out_removed.lower() or "donotremediate" in spaced_out_removed.lower():
        if "was found" not in analyzed_text and "A suspicious" not in analyzed_text:
            score += 3
            signals.append("ACTION_MANIPULATION")
        
    if _SIG_SECRET_EXFILTRATION.search(analyzed_text) or "returnapikey" in spaced_out_removed.lower() or "outputpassword" in spaced_out_removed.lower() or "exposecredentials" in spaced_out_removed.lower():
        score += 3
        signals.append("SECRET_EXFILTRATION")
        
    status = "ALLOW"
    if score >= 3:
        status = "BLOCK"
    elif score >= 2:
        status = "RESTRICT"
        
    return status, score, signals
