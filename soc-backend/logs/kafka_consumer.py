"""
Kafka Consumer — reads from soc-logs topic, runs Rule-Based analysis, saves to DB.
"""

import json
import logging
import os
import asyncio
import datetime

import django
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

logger = logging.getLogger(__name__)


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
      2. Run Rule-Based analysis
      3. Save Log + Alert to DB
    """
    # Import here so Django is already set up when this runs
    from logs.models import Log, Alert
    from logs.rule_engine import analyze

    # ── Build log_data for analyzer ───────────────────────────────────────────
    ip = message.get("ip", "0.0.0.0")
    failed_attempts = int(message.get("failed_attempts", 0))
    event_type = message.get("event_type", "api_access")
    username = message.get("username", "unknown")
    user_agent = message.get("user_agent", "")

    # Parse timestamp from the message (Unix epoch int)
    raw_ts = message.get("timestamp")
    if raw_ts:
        ts = datetime.datetime.utcfromtimestamp(raw_ts).replace(tzinfo=datetime.timezone.utc)
    else:
        ts = datetime.datetime.now(datetime.timezone.utc)

    log_data = {
        "ip_address": ip,
        "failed_attempts": failed_attempts,
    }

    # ── Run Rule-Based Analysis ────────────────────────────────────────────────
    result = analyze(log_data)
    verdict = result["verdict"]
    attack_type = result["attack_type"]
    confidence = result["confidence"]
    reason = result["reason"]

    # ── Save Log to DB ─────────────────────────────────────────────────────────
    log_obj = Log.objects.create(
        ip_address=ip,
        event_type=event_type,
        failed_attempts=failed_attempts,
        user_agent=user_agent,
        username=username,
        timestamp=ts,
        raw_payload=message,
    )

    # ── Save Alert to DB ───────────────────────────────────────────────────────
    alert_obj = Alert.objects.create(
        log=log_obj,
        verdict=verdict,
        attack_type=attack_type,
        confidence=confidence,
        reason=reason,
    )

    # ── Auto-create Incident Logic ─────────────────────────────────────────────
    if verdict == "ATTACK":
        try:
            from django.utils import timezone
            from incidents.models import Incident

            five_minutes_ago = timezone.now() - datetime.timedelta(minutes=5)
            # Count ATTACK alerts from this IP address in the last 5 minutes
            recent_attacks = Alert.objects.filter(
                log__ip_address=ip,
                verdict="ATTACK",
                created_at__gte=five_minutes_ago
            )
            attack_count = recent_attacks.count()

            if attack_count >= 3:
                open_incident = Incident.objects.filter(source_ip=ip, status="open").first()
                if not open_incident:
                    # Create new incident and link all matching recent alerts
                    incident = Incident.objects.create(
                        title=f"Auto: Brute Force from {ip}",
                        severity="high",
                        status="open",
                        source_ip=ip,
                        attack_type=attack_type,
                        description=f"Automated incident - {attack_count} attacks detected from {ip} in 5 minutes"
                    )
                    incident.alerts.set(recent_attacks)
                    logger.info(f"Auto-created incident #{incident.id} for IP {ip}")
                else:
                    # Link current alert to existing open incident
                    open_incident.alerts.add(alert_obj)
                    # Optionally update the description with the new count
                    # But we'll keep it simple or append as required.
                    logger.info(f"Linked alert #{alert_obj.id} to existing incident #{open_incident.id}")
        except Exception as auto_err:
            logger.error(f"Failed to process auto-incident creation: {auto_err}", exc_info=True)


    # ── Push to WebSocket via Django Channels ──────────────────────────────────
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
    except KeyboardInterrupt:
        logger.info(f"Consumer stopped. Total processed: {processed}, errors: {errors}")
    finally:
        consumer.close()
