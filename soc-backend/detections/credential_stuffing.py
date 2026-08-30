import re
from django.conf import settings
from datetime import datetime, timedelta
from django.utils import timezone

# Configuration defaults (can be overridden in Django settings)
WINDOW_MINUTES = getattr(settings, "CRED_STUFFING_WINDOW_MINUTES", 5)
USERNAME_THRESHOLD = getattr(settings, "CRED_STUFFING_USERNAME_THRESHOLD", 5)
CONFIDENCE = getattr(settings, "CRED_STUFFING_CONFIDENCE", 0.95)

def detect_credential_stuffing(ip: str, username: str, event_ts: datetime):
    """Detect credential stuffing attacks.

    Args:
        ip: Source IP address of the login attempt.
        username: Username used in the login attempt.
        event_ts: Timestamp of the event (timezone-aware).
    Returns:
        dict | None: Detection result dictionary matching the rule engine schema
        or None if no attack is detected.
    """
    # Use a simple in‑memory cache keyed by IP. For production you might use Redis.
    from django.core.cache import cache
    cache_key = f"cred_stuff:{ip}"
    record = cache.get(cache_key)
    now = event_ts
    # Initialise or prune old record
    if not record:
        record = {"usernames": set([username]), "first_seen": now}
    else:
        # Remove usernames older than the window based on first_seen
        window_start = now - timedelta(minutes=WINDOW_MINUTES)
        if record["first_seen"] < window_start:
            # Reset the window
            record = {"usernames": set([username]), "first_seen": now}
        else:
            record["usernames"].add(username)
    # Persist back to cache with a TTL slightly longer than the window
    cache.set(cache_key, record, timeout=WINDOW_MINUTES * 60 * 2)

    if len(record["usernames"]) >= USERNAME_THRESHOLD:
        return {
            "verdict": "ATTACK",
            "attack_type": "credential_stuffing",
            "confidence": CONFIDENCE,
            "reason": "Multiple login failures detected across different user accounts from the same IP address.",
        }
    return None
