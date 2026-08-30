def detect_brute_force(failed_attempts: int, ip: str, ts) -> dict | None:
    """Detect brute force attacks based on failed login count.

    Args:
        failed_attempts: Number of failed login attempts in the rolling window.
        ip: Source IP address.
        ts: Timestamp of the current event.
    Returns:
        dict | None: Detection result matching rule engine schema or None.
    """
    if failed_attempts > 5:
        return {
            "verdict": "ATTACK",
            "attack_type": "brute_force",
            "confidence": 0.95,
            "reason": f"Brute force detection: {failed_attempts} failed login attempts from {ip}",
        }
    return None
