import random
import time
from faker import Faker

fake = Faker()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

EVENT_TYPES = ["login_success", "login_failure", "api_access"]

# Attack distribution probabilities (must sum to 1.0)
BRUTE_FORCE_PROB = 0.15
CRED_STUFFING_PROB = 0.10
SQL_INJECTION_PROB = 0.05
NORMAL_TRAFFIC_PROB = 0.70

# Request paths – generic traffic can hit any, SQL injection limited to a subset
REQUEST_PATHS = ["/login", "/admin", "/api/login", "/auth", "/user/login"]
SQL_INJECTION_PATHS = ["/login", "/admin", "/api/login"]

# ---------------------------------------------------------------------------
# Attack campaign state trackers
# ---------------------------------------------------------------------------

# Brute‑force: one IP, one target username per campaign
brute_force_campaigns = {}  # ip -> {"username": str, "start_time": int, "count": int}

# Credential stuffing: one IP, many distinct usernames per campaign
credential_stuffing_campaigns = {}  # ip -> {"usernames": set, "start_time": int, "count": int}

# SQL injection: one IP, multiple payload attempts per campaign
sql_injection_campaigns = {}  # ip -> {"payload_index": int, "start_time": int, "count": int}

# Configurable thresholds
CRED_STUFFING_MIN_USERNAMES = 10
CRED_STUFFING_MAX_USERNAMES = 20
SQL_INJECTION_MIN_EVENTS = 10
SQL_INJECTION_MAX_EVENTS = 20
BRUTE_FORCE_MIN_EVENTS = 10
BRUTE_FORCE_MAX_EVENTS = 20

SQL_INJECTION_PAYLOADS = [
    "admin' OR '1'='1",
    "' UNION SELECT * FROM users --",
    "admin\"; DROP TABLE users; --",
    "' OR 1=1 --",
    "information_schema",
]

# ---------------------------------------------------------------------------
# Helper: generate a normal benign event
# ---------------------------------------------------------------------------

def generate_random_event():
    """Generate a normal, benign event with a random request path."""
    return {
        "ip": fake.ipv4(),
        "username": fake.user_name(),
        "user_agent": fake.user_agent(),
        "event_type": random.choice(EVENT_TYPES),
        "request_path": random.choice(REQUEST_PATHS),
        "timestamp": int(time.time()),
        "failed_attempts": 0,
        "source": "log-generator",
    }

# ---------------------------------------------------------------------------
# Brute‑Force attack simulation
# ---------------------------------------------------------------------------

def generate_brute_force_attack():
    """Simulate a brute‑force campaign targeting the same username.

    * Reuse the same username for the whole campaign.
    * Keep campaign alive for 10‑20 events.
    * Include campaign metadata (start_time, attack_count, campaign_duration).
    """
    # Initialise a new campaign if needed
    if not brute_force_campaigns or (len(brute_force_campaigns) < 5 and random.random() < 0.3):
        ip = fake.ipv4()
        username = "admin"  # fixed target for realism – can be random if desired
        brute_force_campaigns[ip] = {
            "username": username,
            "start_time": int(time.time()),
            "count": 0,
        }
    # Pick an active campaign
    attack_ip = random.choice(list(brute_force_campaigns.keys()))
    campaign = brute_force_campaigns[attack_ip]
    campaign["count"] += 1
    # Determine if campaign should end
    if campaign["count"] >= random.randint(BRUTE_FORCE_MIN_EVENTS, BRUTE_FORCE_MAX_EVENTS):
        del brute_force_campaigns[attack_ip]
    # Build event
    now = int(time.time())
    return {
        "ip": attack_ip,
        "username": campaign["username"],
        "user_agent": fake.user_agent(),
        "event_type": "login_failure",
        "request_path": random.choice(REQUEST_PATHS),
        "timestamp": now,
        "failed_attempts": 0,
        "source": "log-generator",
        "campaign_start": campaign["start_time"],
        "attack_count": campaign["count"],
        "campaign_duration": now - campaign["start_time"],
    }

# ---------------------------------------------------------------------------
# Credential‑Stuffing attack simulation
# ---------------------------------------------------------------------------

def generate_credential_stuffing_attack():
    """Simulate credential‑stuffing: same IP, many distinct usernames.

    * Campaign persists until a configurable number of distinct usernames
      (10‑20) is reached.
    * Includes same campaign metadata as brute‑force.
    """
    # Initialise a new campaign if needed
    if not credential_stuffing_campaigns or (len(credential_stuffing_campaigns) < 5 and random.random() < 0.3):
        ip = fake.ipv4()
        credential_stuffing_campaigns[ip] = {
            "usernames": set(),
            "start_time": int(time.time()),
            "count": 0,
        }
    attack_ip = random.choice(list(credential_stuffing_campaigns.keys()))
    campaign = credential_stuffing_campaigns[attack_ip]
    # Generate a new unique username for this IP
    username = fake.user_name()
    campaign["usernames"].add(username)
    campaign["count"] += 1
    # Cleanup after reaching threshold
    if len(campaign["usernames"]) >= random.randint(CRED_STUFFING_MIN_USERNAMES, CRED_STUFFING_MAX_USERNAMES):
        del credential_stuffing_campaigns[attack_ip]
    now = int(time.time())
    return {
        "ip": attack_ip,
        "username": username,
        "user_agent": fake.user_agent(),
        "event_type": "login_failure",
        "request_path": random.choice(REQUEST_PATHS),
        "timestamp": now,
        "failed_attempts": 0,
        "source": "log-generator",
        "campaign_start": campaign["start_time"],
        "attack_count": campaign["count"],
        "campaign_duration": now - campaign["start_time"],
    }

# ---------------------------------------------------------------------------
# SQL Injection attack simulation
# ---------------------------------------------------------------------------

def generate_sql_injection_attack():
    """Simulate a SQL‑injection campaign from a single attacker IP.

    * Reuse the same IP across multiple payload attempts.
    * Cycle through the payload list.
    * Keep campaign alive for 10‑20 events.
    """
    # Initialise or reuse a campaign
    if not sql_injection_campaigns or (len(sql_injection_campaigns) < 5 and random.random() < 0.3):
        ip = fake.ipv4()
        sql_injection_campaigns[ip] = {
            "payload_index": 0,
            "start_time": int(time.time()),
            "count": 0,
        }
    attack_ip = random.choice(list(sql_injection_campaigns.keys()))
    campaign = sql_injection_campaigns[attack_ip]
    # Choose current payload and advance index
    payload = SQL_INJECTION_PAYLOADS[campaign["payload_index"] % len(SQL_INJECTION_PAYLOADS)]
    campaign["payload_index"] += 1
    campaign["count"] += 1
    # End campaign after enough events
    if campaign["count"] >= random.randint(SQL_INJECTION_MIN_EVENTS, SQL_INJECTION_MAX_EVENTS):
        del sql_injection_campaigns[attack_ip]
    now = int(time.time())
    return {
        "ip": attack_ip,
        "username": payload,
        "user_agent": fake.user_agent(),
        "event_type": "login_failure",
        "request_path": random.choice(SQL_INJECTION_PATHS),
        "timestamp": now,
        "failed_attempts": 0,
        "source": "log-generator",
        "campaign_start": campaign["start_time"] if "start_time" in campaign else now,
        "attack_count": campaign["count"],
        "campaign_duration": now - (campaign["start_time"] if "start_time" in campaign else now),
    }

# ---------------------------------------------------------------------------
# Main event generator – chooses an attack based on distribution
# ---------------------------------------------------------------------------

def generate_event():
    """Select which type of event to emit according to the probability matrix.

    The function returns a dict ready to be serialized and sent to Kafka.
    """
    roll = random.random()
    if roll < BRUTE_FORCE_PROB:
        return generate_brute_force_attack()
    roll -= BRUTE_FORCE_PROB
    if roll < CRED_STUFFING_PROB:
        return generate_credential_stuffing_attack()
    roll -= CRED_STUFFING_PROB
    if roll < SQL_INJECTION_PROB:
        return generate_sql_injection_attack()
    # Normal traffic
    return generate_random_event()
