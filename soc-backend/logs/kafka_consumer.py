"""
Kafka Consumer — reads from soc-logs topic, runs Rule-Based analysis, saves to DB.
"""

import json
import logging
from detections.credential_stuffing import detect_credential_stuffing
from detections.sql_injection import detect_sql_injection
from detections.brute_force import detect_brute_force
import os
import asyncio
import datetime
import time

import django
from kafka import KafkaConsumer
# Compatibility shim for the `NoBrokersAvailable` exception.
# Older kafka-python versions expose this name directly; newer versions
# expose the generic `KafkaError`. We alias the generic exception to the
# expected name so the retry logic works without changes.
try:
    from kafka.errors import NoBrokersAvailable  # older kafka-python
except ImportError:  # newer kafka-python versions
    from kafka.errors import KafkaError as NoBrokersAvailable  # type: ignore

logger = logging.getLogger(__name__)

ATTACK_PRIORITY = {
    "sql_injection": 50,
    "credential_stuffing": 40,
    "brute_force": 30,
    "blacklisted_ip": 20,
    "suspicious_login": 10,
    "none": 0,
}


def get_consumer(broker: str, topic: str, retries: int = 30) -> KafkaConsumer:


    """Create a KafkaConsumer with retry logic."""
    import time
    for attempt in range(1, retries + 1):
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=[broker],
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                auto_offset_reset="latest",      # Only process new messages
                enable_auto_commit=True,
                group_id="soc-consumer-group",
                consumer_timeout_ms=1000,        # Poll timeout
            )
            logger.info(f"Connected to Kafka broker at {broker}, topic: {topic}")
            return consumer
        except NoBrokersAvailable:
            logger.warning(f"Kafka not available (attempt {attempt}/{retries}). Retrying in 3s...")
            time.sleep(3)
    raise RuntimeError(f"Could not connect to Kafka at {broker} after {retries} attempts.")


def process_message(message: dict):
    """
    Process a single Kafka message:
      1. Parse the payload
      2. Expire old active campaigns/incidents (>10 min inactive)
      3. Calculate failed logins via DB (rolling 5 min window)
      4. Run Rule-Based analysis
      5. Save Log to DB
      6. Correlate and Save Alert (in-place update or create active alert)
      7. Correlate and Save Incident (link to existing or create if >=3 alerts)
      8. Push WebSocket updates
    """
    # Import here so Django is already set up when this runs
    from django.conf import settings
    from django.utils import timezone
    from logs.models import Log, Alert
    from logs.rule_engine import analyze
    from incidents.models import Incident

    # ── Build log_data from payload ──────────────────────────────────────────
    ip = message.get("ip", "0.0.0.0")
    event_type = message.get("event_type", "api_access")
    username = message.get("username", "unknown")
    user_agent = message.get("user_agent", "")

    # Parse timestamp from the message (Unix epoch int)
    raw_ts = message.get("timestamp")
    if raw_ts:
        ts = datetime.datetime.fromtimestamp(raw_ts, tz=datetime.timezone.utc)
    else:
        ts = timezone.now()

    # ── 1. Automatic Campaign Expiry (10 minutes inactivity) ───────────────────
    ten_minutes_ago = ts - datetime.timedelta(minutes=10)
    
    # Auto-resolve alerts inactive for >= 10 mins
    Alert.objects.filter(
        log__ip_address=ip,
        status="active",
        last_seen__lt=ten_minutes_ago
    ).update(status="resolved")
    
    # Auto-close incidents inactive for >= 10 mins (updated_at is older than 10 mins)
    open_incidents = Incident.objects.filter(
        source_ip=ip,
        status="open",
        updated_at__lt=ten_minutes_ago
    )
    for incident in open_incidents:
        incident.status = "closed"
        incident.investigation_notes += f"\n[System Auto-Close] Closed automatically due to 10 minutes of inactivity."
        incident.save()

    # ── 2. Move Failure Counting to the SOC (5 min rolling window) ─────────────
    rolling_window_mins = getattr(settings, "SOC_ROLLING_WINDOW_MINUTES", 5)
    
    if event_type == "login_failure":
        window_start = ts - datetime.timedelta(minutes=rolling_window_mins)
        # Count preceding failed logins in the database
        db_failures = Log.objects.filter(
            ip_address=ip,
            event_type="login_failure",
            timestamp__gte=window_start
        ).count()
        failed_attempts = db_failures + 1
    else:
        failed_attempts = 0

    # ── 3. Run Detection Logic ──────────────────────────────────────
    # Run all detections and pick the one with the highest priority classification.
    # Detections: SQL injection, credential stuffing, brute force, and fallback rule engine.
    detections = []

    # 1. SQL Injection
    sqli_res = detect_sql_injection(message)
    if sqli_res:
        detections.append(sqli_res)

    # 2. Credential Stuffing
    cred_res = detect_credential_stuffing(ip, username, ts)
    if cred_res:
        detections.append(cred_res)

    # 3. Brute Force
    bf_res = detect_brute_force(failed_attempts, ip, ts)
    if bf_res:
        detections.append(bf_res)

    # 4. Fallback Rule Engine (always evaluated to check blacklist / suspicious / normal)
    log_data = {
        "ip_address": ip,
        "failed_attempts": failed_attempts,
    }
    rule_res = analyze(log_data)
    detections.append(rule_res)

    # Choose the detection result with the highest priority classification
    result = max(detections, key=lambda d: ATTACK_PRIORITY.get(d.get("attack_type", "none"), 0))
    verdict = result["verdict"]
    attack_type = result["attack_type"]
    confidence = result["confidence"]
    reason = result["reason"]

    # Check for possible account compromise
    is_compromise = False
    if event_type == "login_success":
        compromise_window_mins = getattr(settings, "SOC_ROLLING_WINDOW_MINUTES", 5)
        window_start = ts - datetime.timedelta(minutes=compromise_window_mins)
        failed_count = Log.objects.filter(
            ip_address=ip,
            event_type="login_failure",
            timestamp__gte=window_start
        ).count()
        if failed_count >= 3:
            is_compromise = True
            verdict = "ATTACK"
            confidence = 1.0
            reason = "Successful login detected after multiple failed login attempts. Possible account compromise."
            if failed_count > 5:
                attack_type = "brute_force"
            else:
                attack_type = "suspicious_login"

    # ── 4. Save Log to DB ──────────────────────────────────────────────────────
    log_obj = Log.objects.create(
        ip_address=ip,
        event_type=event_type,
        failed_attempts=failed_attempts,
        user_agent=user_agent,
        username=username,
        timestamp=ts,
        raw_payload=message,
        verdict=verdict,
        confidence=confidence,
        reason=reason,
        attack_type=attack_type,
    )

    # ── 5. Alert Correlation ───────────────────────────────────────────────────
    if verdict in ["ATTACK", "SUSPICIOUS"]:
        # Query for any existing active alert for this IP regardless of attack type
        # to maintain a single primary active alert campaign.
        alert_obj = Alert.objects.filter(
            log__ip_address=ip,
            verdict__in=["ATTACK", "SUSPICIOUS"],
            status="active",
        ).first()

        if alert_obj:
            # Update existing alert (in-place correlation)
            alert_obj.log = log_obj  # Point to latest log
            alert_obj.attack_count += 1
            alert_obj.last_seen = ts
            if is_compromise:
                alert_obj.compromise_detected = True

            existing_priority = ATTACK_PRIORITY.get(alert_obj.attack_type, 0)
            new_priority = ATTACK_PRIORITY.get(attack_type, 0)

            if new_priority > existing_priority:
                # Upgrade the primary classification to the higher priority threat
                alert_obj.attack_type = attack_type
                alert_obj.verdict = verdict
                alert_obj.confidence = max(alert_obj.confidence, confidence)
                
                # Ensure original reason is formatted/prefixed
                if not alert_obj.reason.startswith("["):
                    first_time = alert_obj.first_seen.strftime('%H:%M') if alert_obj.first_seen else ts.strftime('%H:%M')
                    alert_obj.reason = f"[{first_time}] {alert_obj.reason}"
                
                human_attack = dict(Alert.ATTACK_TYPE_CHOICES).get(attack_type, attack_type.replace('_', ' ').title())
                alert_obj.reason += f"\n\n[{ts.strftime('%H:%M')}] Upgraded to {human_attack}\nReason: {reason}"
                logger.info(f"Correlated alert: Upgraded active alert #{alert_obj.id} for IP {ip} to {attack_type} (count: {alert_obj.attack_count})")
            else:
                # Maintain the existing higher-priority classification
                # Allow escalation of verdict (e.g. SUSPICIOUS -> ATTACK) if new verdict is more severe
                if verdict == "ATTACK" and alert_obj.verdict == "SUSPICIOUS":
                    alert_obj.verdict = "ATTACK"
                    if not alert_obj.reason.startswith("["):
                        first_time = alert_obj.first_seen.strftime('%H:%M') if alert_obj.first_seen else ts.strftime('%H:%M')
                        alert_obj.reason = f"[{first_time}] {alert_obj.reason}"
                    alert_obj.reason += f"\n\n[{ts.strftime('%H:%M')}] Verdict escalated to ATTACK"
                alert_obj.confidence = max(alert_obj.confidence, confidence)
                if is_compromise:
                    if not alert_obj.reason.startswith("["):
                        first_time = alert_obj.first_seen.strftime('%H:%M') if alert_obj.first_seen else ts.strftime('%H:%M')
                        alert_obj.reason = f"[{first_time}] {alert_obj.reason}"
                    alert_obj.reason += f"\n\n[{ts.strftime('%H:%M')}] Account Compromise Detected\nReason: {reason}"
                logger.info(f"Correlated alert: Appended activity to active alert #{alert_obj.id} (primary: {alert_obj.attack_type}, count: {alert_obj.attack_count})")
            
            alert_obj.save()
        else:
            # Create new active alert campaign
            alert_obj = Alert.objects.create(
                log=log_obj,
                verdict=verdict,
                attack_type=attack_type,
                confidence=confidence,
                reason=f"[{ts.strftime('%H:%M')}] {reason}",
                status="active",
                attack_count=1,
                first_seen=ts,
                last_seen=ts,
                compromise_detected=is_compromise,
            )
            logger.info(f"Correlated alert: Created new active alert #{alert_obj.id} for IP {ip} as {attack_type}")
    else:
        # Normal verdict: save standard resolved alert
        alert_obj = Alert.objects.create(
            log=log_obj,
            verdict=verdict,
            attack_type=attack_type,
            confidence=confidence,
            reason=reason,
            status="resolved",
            attack_count=1,
            first_seen=ts,
            last_seen=ts,
            compromise_detected=is_compromise,
        )

    # ── 6. Incident Correlation ────────────────────────────────────────────────
    if verdict == "ATTACK":
        try:
            # Count the number of ATTACK log events from this IP in the last 5 minutes
            five_minutes_ago = ts - datetime.timedelta(minutes=5)
            
            # Check if this IP is blacklisted (statically or dynamically)
            from django.apps import apps
            from logs.rule_engine import BLACKLISTED_IPS
            is_blacklisted_db = False
            try:
                if apps.ready:
                    from logs.models import BlockedIP
                    if BlockedIP.objects.filter(ip_address=ip).exists():
                        is_blacklisted_db = True
            except Exception:
                pass

            if ip in BLACKLISTED_IPS or is_blacklisted_db:
                # Every log from a blacklisted IP is an attack
                attack_alerts_count = Log.objects.filter(
                    ip_address=ip,
                    timestamp__gte=five_minutes_ago
                ).count()
            else:
                # Count all ATTACK logs in the last 5 minutes
                attack_alerts_count = Log.objects.filter(
                    ip_address=ip,
                    verdict="ATTACK",
                    timestamp__gte=five_minutes_ago
                ).count()

            open_incident = Incident.objects.filter(source_ip=ip, status="open").first()
            
            if open_incident:
                # Link this alert and update the existing incident campaign description
                open_incident.alerts.add(alert_obj)
                
                # Check if the incident's attack_type needs upgrading
                new_priority = ATTACK_PRIORITY.get(alert_obj.attack_type, 0)
                existing_incident_priority = ATTACK_PRIORITY.get(open_incident.attack_type, 0)
                
                if new_priority > existing_incident_priority:
                    open_incident.attack_type = alert_obj.attack_type
                    human_attack = dict(Alert.ATTACK_TYPE_CHOICES).get(alert_obj.attack_type, alert_obj.attack_type.replace('_', ' ').title())
                    open_incident.title = f"Auto: {human_attack} from {ip}"
                    logger.info(f"Correlated incident: Upgraded incident #{open_incident.id} for IP {ip} to {alert_obj.attack_type}")
                
                open_incident.description = f"Automated incident - {attack_alerts_count} attacks detected from {ip} in 5 minutes"
                
                # Severity Escalation
                has_compromise = open_incident.alerts.filter(compromise_detected=True).exists() or is_compromise
                if has_compromise:
                    open_incident.severity = "critical"
                    open_incident.compromise_detected = True
                elif open_incident.attack_type == "brute_force":
                    open_incident.severity = "high"
                elif open_incident.attack_type == "suspicious_login":
                    open_incident.severity = "medium"
                
                open_incident.save()
                logger.info(f"Correlated incident: Linked alert #{alert_obj.id} and updated incident #{open_incident.id}")
            else:
                # If no open incident, only escalate if we have at least 3 attacks in the 5 minute window OR it's a compromise!
                if attack_alerts_count >= 3 or is_compromise:
                    # Create incident title based on the actual attack type detected
                    primary_type = alert_obj.attack_type
                    
                    if is_compromise:
                        severity = "critical"
                    elif primary_type == "brute_force":
                        severity = "high"
                    elif primary_type == "suspicious_login":
                        severity = "medium"
                    else:
                        severity = "high"
                        
                    human_attack = dict(Alert.ATTACK_TYPE_CHOICES).get(primary_type, primary_type.replace('_', ' ').title())
                    incident = Incident.objects.create(
                        title=f"Auto: {human_attack} from {ip}",
                        severity=severity,
                        status="open",
                        source_ip=ip,
                        attack_type=primary_type,
                        description=f"Automated incident - {attack_alerts_count} attacks detected from {ip} in 5 minutes",
                        compromise_detected=is_compromise
                    )
                    incident.alerts.add(alert_obj)
                    logger.info(f"Correlated incident: Auto-created incident #{incident.id} for IP {ip}")
        except Exception as auto_err:
            logger.error(f"Failed to process auto-incident creation/correlation: {auto_err}", exc_info=True)

    # ── 7. Push to WebSocket via Django Channels ────────────────────────────────
    try:
        from channels.layers import get_channel_layer
        channel_layer = get_channel_layer()
        if channel_layer is not None:
            payload = {
                "type":         "send_alert",
                "data": {
                    "id":           alert_obj.id,
                    "log_id":       log_obj.id,
                    "ip_address":   ip,
                    "event_type":   event_type,
                    "username":     username,
                    "verdict":      verdict,
                    "attack_type":  attack_type,
                    "confidence":   confidence,
                    "reason":       reason,
                    "timestamp":    ts.isoformat(),
                    "created_at":   alert_obj.created_at.isoformat(),
                    "attack_count": alert_obj.attack_count,
                    "first_seen":   alert_obj.first_seen.isoformat() if alert_obj.first_seen else ts.isoformat(),
                    "last_seen":    alert_obj.last_seen.isoformat() if alert_obj.last_seen else ts.isoformat(),
                    "status":       alert_obj.status,
                    "compromise_detected": alert_obj.compromise_detected,
                },
            }
            asyncio.run(
                channel_layer.group_send("soc_alerts", payload)
            )
    except Exception as ws_err:
        logger.warning(f"WebSocket push failed (non-critical): {ws_err}")

    logger.info(
        f"[{verdict:10s}] {event_type:15s} | IP: {ip:15s} | "
        f"fails={failed_attempts} | type={attack_type} | conf={confidence:.2f}"
    )


# ── Periodic global cleanup configurations ──────────────────────────────────
STALE_CHECK_INTERVAL = 30  # seconds
_last_stale_check = 0.0

def expire_stale_alerts():
    """Resolve active alerts and close incidents that have been inactive for >= 10 minutes."""
    try:
        from django.utils import timezone
        from logs.models import Alert
        from incidents.models import Incident
        
        now = timezone.now()
        ten_minutes_ago = now - datetime.timedelta(minutes=10)
        
        # 1. Auto-resolve alerts inactive for >= 10 mins
        stale_alerts = Alert.objects.filter(status="active", last_seen__lt=ten_minutes_ago)
        count_alerts = stale_alerts.count()
        if count_alerts > 0:
            stale_alerts.update(status="resolved")
            logger.info(f"[Periodic Cleanup] Auto-resolved {count_alerts} stale active alerts due to 10 minutes of inactivity.")
            
        # 2. Auto-close incidents inactive for >= 10 mins
        stale_incidents = Incident.objects.filter(status="open", updated_at__lt=ten_minutes_ago)
        count_incidents = stale_incidents.count()
        for incident in stale_incidents:
            incident.status = "closed"
            incident.investigation_notes += f"\n[System Auto-Close] Closed automatically due to 10 minutes of inactivity."
            incident.save()
        if count_incidents > 0:
            logger.info(f"[Periodic Cleanup] Auto-closed {count_incidents} stale incidents due to 10 minutes of inactivity.")
            
    except Exception as cleanup_err:
        logger.error(f"Failed to execute periodic cleanup of stale alerts/incidents: {cleanup_err}", exc_info=True)


def run_consumer():
    """Main consumer loop — runs indefinitely."""
    broker = os.getenv("KAFKA_BROKER", "localhost:9092")
    topic  = os.getenv("KAFKA_TOPIC",  "soc-logs")

    consumer = get_consumer(broker, topic)

    logger.info("Consumer started. Waiting for messages...")
    processed = 0
    errors = 0

    try:
        while True:
            for message in consumer:
                try:
                    process_message(message.value)
                    processed += 1
                    if processed % 100 == 0:
                        logger.info(f"Processed {processed} messages ({errors} errors)")
                except Exception as e:
                    errors += 1
                    logger.error(f"Error processing message: {e}", exc_info=True)

            # Periodic global cleanup (runs when poll times out)
            global _last_stale_check
            now_ts = time.time()
            if now_ts - _last_stale_check >= STALE_CHECK_INTERVAL:
                expire_stale_alerts()
                _last_stale_check = now_ts
    except KeyboardInterrupt:
        logger.info(f"Consumer stopped. Total processed: {processed}, errors: {errors}")
    finally:
        consumer.close()
