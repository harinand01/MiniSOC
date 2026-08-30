
from django.db import migrations

def populate_log_classification(apps, schema_editor):
    Log = apps.get_model('logs', 'Log')
    Alert = apps.get_model('logs', 'Alert')
    
    # Import detections and analyze inside migration
    from logs.rule_engine import analyze
    from detections.brute_force import detect_brute_force
    from detections.credential_stuffing import detect_credential_stuffing
    from detections.sql_injection import detect_sql_injection
    
    # Process all logs in chronological order so failed attempt sequence is correct
    logs = Log.objects.order_by('timestamp')
    for log in logs:
        # Find if there is an alert directly pointing to this log
        alert = Alert.objects.filter(log=log).first()
        if alert:
            log.verdict = alert.verdict
            log.confidence = alert.confidence
            log.reason = alert.reason
            log.attack_type = alert.attack_type
        else:
            # Re-run detection to classify this individual attempt
            detection_result = detect_brute_force(log.failed_attempts, log.ip_address, log.timestamp)
            if not detection_result:
                detection_result = detect_credential_stuffing(log.ip_address, log.username, log.timestamp)
            if not detection_result:
                detection_result = detect_sql_injection(log.raw_payload)
            
            if detection_result:
                result = detection_result
            else:
                # Fallback to standard rule engine
                log_data = {
                    "ip_address": log.ip_address,
                    "failed_attempts": log.failed_attempts,
                }
                result = analyze(log_data)
            
            log.verdict = result.get("verdict", "PENDING")
            log.confidence = result.get("confidence", 0.0)
            log.reason = result.get("reason", "Pending classification")
            log.attack_type = result.get("attack_type", "none")
            
        log.save()

def reverse_log_classification(apps, schema_editor):
    # Reversing does not need to clear the log records, just a no-op
    pass

class Migration(migrations.Migration):

    dependencies = [
        ('logs', '0007_log_attack_count_log_attack_type_and_more'),
    ]

    operations = [
        migrations.RunPython(populate_log_classification, reverse_log_classification),
    ]
