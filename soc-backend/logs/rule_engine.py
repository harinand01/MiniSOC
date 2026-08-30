"""
Rule-Based Threat Detection Engine.
Replaces the threat detection module with simple, deterministic security checks.
"""

# Known malicious IPs
BLACKLISTED_IPS = {
    "10.0.0.1",
    "192.168.100.100",
    "1.2.3.4",
    "5.5.5.5",
    "45.33.32.156",    # Known scan host
    "198.20.69.74",
    "66.240.192.138",
}


def analyze(log_data: dict) -> dict:
    """
    Analyze log data using deterministic security rules:
    1. Blacklisted IP Detection:
       - If IP exists in BLACKLISTED_IPS
       - Verdict = ATTACK
       - Attack Type = blacklisted_ip
    2. Brute Force Detection:
       - If failed_attempts > 5
       - Verdict = ATTACK
       - Attack Type = brute_force
    3. Suspicious Login:
       - If failed_attempts is between 3 and 5 (inclusive)
       - Verdict = SUSPICIOUS
       - Attack Type = suspicious_login
    4. Otherwise:
       - Verdict = NORMAL
       - Attack Type = none
    """
    ip = log_data.get("ip_address", "0.0.0.0")
    failed_attempts = int(log_data.get("failed_attempts", 0))

    # Dynamic Blocked IP Database Check
    db_checked = False
    try:
        from django.apps import apps
        if apps.ready:
            db_checked = True
            from logs.models import BlockedIP
            if BlockedIP.objects.filter(ip_address=ip).exists():
                return {
                    "verdict": "ATTACK",
                    "attack_type": "blacklisted_ip",
                    "confidence": 1.0,
                    "reason": f"IP {ip} matches dynamically blocked IP list in database",
                }
    except Exception:
        pass

    # Rule 1: Blacklisted IP Detection (Only fallback if DB check was not performed)
    if not db_checked:
        if ip in BLACKLISTED_IPS:
            return {
                "verdict": "ATTACK",
                "attack_type": "blacklisted_ip",
                "confidence": 1.0,
                "reason": f"IP {ip} matches known threat intelligence blacklist",
            }

    # Rule 2: Brute Force Detection
    if failed_attempts > 5:
        return {
            "verdict": "ATTACK",
            "attack_type": "brute_force",
            "confidence": 0.95,
            "reason": f"Brute force detection: {failed_attempts} failed login attempts from {ip}",
        }

    # Rule 3: Suspicious Login
    if 3 <= failed_attempts <= 5:
        return {
            "verdict": "SUSPICIOUS",
            "attack_type": "suspicious_login",
            "confidence": 0.75,
            "reason": f"Suspicious activity: {failed_attempts} failed login attempts from {ip}",
        }

    # Rule 4: Normal Traffic
    return {
        "verdict": "NORMAL",
        "attack_type": "none",
        "confidence": 1.0,
        "reason": "Log traffic conforms to normal signature rules",
    }
