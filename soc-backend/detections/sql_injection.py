import re
from django.conf import settings
from datetime import datetime

# Configuration defaults (can be overridden in Django settings)
CONFIDENCE = getattr(settings, "SQL_INJECTION_CONFIDENCE", 0.99)

# Common SQL injection patterns (case‑insensitive)
SQLI_PATTERNS = [
    r"'\s*or\s*'1'\s*=\s*'1'",
    r'"\s*or\s*"1"\s*=\s*"1"',
    r"union\s+select",
    r"drop\s+table",
    r"select\s+\*",
    r";\s*--",
    r"xp_cmdshell",
    r"information_schema",
]

COMPILED_PATTERNS = [re.compile(pat, re.IGNORECASE) for pat in SQLI_PATTERNS]


def _search_fields(data: dict) -> bool:
    """Search relevant fields for any SQLi pattern.

    Args:
        data: Incoming log payload dictionary.
    Returns:
        True if any pattern matches, False otherwise.
    """
    fields = []
    for key in ["username", "request_path", "query_string", "raw_payload"]:
        if key in data:
            value = data[key]
            if isinstance(value, dict):
                # Serialize dict to string for pattern matching
                value = str(value)
            fields.append(str(value))
    combined = " ".join(fields)
    for regex in COMPILED_PATTERNS:
        if regex.search(combined):
            return True
    return False


def detect_sql_injection(message: dict):
    """Detect potential SQL injection attacks.

    Args:
        message: Raw Kafka message payload (already a dict).
    Returns:
        dict | None: Detection result dict if an injection is detected.
    """
    if _search_fields(message):
        return {
            "verdict": "ATTACK",
            "attack_type": "sql_injection",
            "confidence": CONFIDENCE,
            "reason": "Potential SQL injection pattern detected in request data.",
        }
    return None
