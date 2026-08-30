from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.utils import timezone
import datetime

from logs.models import Log, Alert
from incidents.models import Incident
from logs.kafka_consumer import process_message

class IncidentTests(APITestCase):

    def setUp(self):
        # Create some initial Logs and Alerts
        self.log1 = Log.objects.create(
            ip_address="192.168.1.100",
            event_type="login_failure",
            failed_attempts=6,
            user_agent="Mozilla",
            username="attacker",
            timestamp=timezone.now(),
            raw_payload={}
        )
        self.alert1 = Alert.objects.create(
            log=self.log1,
            verdict="ATTACK",
            attack_type="brute_force",
            confidence=0.95,
            reason="Too many failures"
        )
        
        self.incident_data = {
            "title": "Manual Test Incident",
            "description": "Manual analysis",
            "severity": "medium",
            "status": "open",
            "source_ip": "192.168.1.100",
            "attack_type": "brute_force",
            "alert_ids": [self.alert1.id]
        }

    def test_create_incident_manual(self):
        self.alert1.attack_count = 12
        self.alert1.save()
        url = reverse('incident-list-create')
        response = self.client.post(url, self.incident_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['title'], "Manual Test Incident")
        self.assertEqual(response.data['alerts_count'], 1)
        self.assertEqual(response.data['attack_count'], 12)

    def test_list_incidents(self):
        # Create an incident first
        Incident.objects.create(
            title="Existing Incident",
            description="Details",
            severity="high",
            status="open",
            source_ip="10.0.0.1",
            attack_type="blacklisted_ip"
        )
        url = reverse('incident-list-create')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data['results']) >= 1)

    def test_incident_detail(self):
        inc = Incident.objects.create(
            title="Detail Incident",
            description="Details",
            severity="high",
            status="open",
            source_ip="10.0.0.1",
            attack_type="blacklisted_ip"
        )
        url = reverse('incident-detail-update-delete', kwargs={'pk': inc.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], "Detail Incident")

    def test_patch_incident(self):
        inc = Incident.objects.create(
            title="Patch Incident",
            description="Details",
            severity="high",
            status="open",
            source_ip="10.0.0.1",
            attack_type="blacklisted_ip"
        )
        url = reverse('incident-detail-update-delete', kwargs={'pk': inc.id})
        patch_data = {"status": "in_progress", "assigned_to": "Investigator Bob"}
        response = self.client.patch(url, patch_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], "in_progress")
        self.assertEqual(response.data['assigned_to'], "Investigator Bob")

    def test_link_alert_endpoint(self):
        inc = Incident.objects.create(
            title="Link Incident",
            description="Details",
            severity="high",
            status="open",
            source_ip="10.0.0.1",
            attack_type="blacklisted_ip"
        )
        url = reverse('incident-link-alert', kwargs={'pk': inc.id})
        response = self.client.post(url, {"alert_id": self.alert1.id}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['alerts_count'], 1)

    def test_open_incidents(self):
        Incident.objects.create(title="Open 1", description="desc", status="open", source_ip="1.1.1.1")
        Incident.objects.create(title="Closed 1", description="desc", status="closed", source_ip="1.1.1.1")
        url = reverse('incident-open-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data['results']
        for r in results:
            self.assertEqual(r['status'], 'open')

    def test_stats_endpoint(self):
        Incident.objects.create(title="Stats 1", severity="critical", status="open", source_ip="1.1.1.1")
        Incident.objects.create(title="Stats 2", severity="high", status="in_progress", source_ip="1.1.1.1")
        url = reverse('incident-stats')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['by_status']['open'], 1)
        self.assertEqual(response.data['by_status']['in_progress'], 1)
        self.assertEqual(response.data['by_severity']['critical'], 1)
        self.assertEqual(response.data['by_severity']['high'], 1)

    def test_automated_incident_creation_rule(self):
        # IP to use: "192.168.9.9"
        payload = {
            "ip": "192.168.9.9",
            "username": "attacker",
            "user_agent": "Mozilla",
            "event_type": "login_failure",
            "timestamp": int(timezone.now().timestamp()),
            "failed_attempts": 0
        }

        # Send 5 failed attempts (verdicts: NORMAL and SUSPICIOUS, no ATTACK alerts yet)
        for _ in range(5):
            process_message(payload)
            self.assertEqual(Incident.objects.filter(source_ip="192.168.9.9").count(), 0)

        # 6th failed attempt -> verdict: ATTACK (alert.attack_count = 1)
        process_message(payload)
        self.assertEqual(Incident.objects.filter(source_ip="192.168.9.9").count(), 0)

        # 7th failed attempt -> verdict: ATTACK (alert.attack_count = 2)
        process_message(payload)
        self.assertEqual(Incident.objects.filter(source_ip="192.168.9.9").count(), 0)

        # 8th failed attempt -> verdict: ATTACK (alert.attack_count = 3) -> triggers auto creation!
        process_message(payload)
        self.assertEqual(Incident.objects.filter(source_ip="192.168.9.9").count(), 1)
        
        # Verify details of auto-created incident
        inc = Incident.objects.get(source_ip="192.168.9.9")
        self.assertEqual(inc.title, "Auto: Brute Force from 192.168.9.9")
        self.assertEqual(inc.severity, "high")
        self.assertEqual(inc.status, "open")
        self.assertEqual(inc.alerts.count(), 1)

    def test_single_log_classification_prioritization(self):
        """Verify a log with both SQLi patterns and high failed attempts gets classified as SQLi."""
        payload = {
            "ip": "192.168.20.20",
            "username": "attacker' or '1'='1'",
            "user_agent": "Mozilla",
            "event_type": "login_failure",
            "timestamp": int(timezone.now().timestamp()),
            "failed_attempts": 10  # This would trigger brute force (> 5)
        }
        process_message(payload)
        
        # Get the created log and verify its classification
        log = Log.objects.filter(ip_address="192.168.20.20").first()
        self.assertIsNotNone(log)
        self.assertEqual(log.verdict, "ATTACK")
        self.assertEqual(log.attack_type, "sql_injection") # SQLi has higher priority than brute force

    def test_alert_correlation_high_priority_first(self):
        """Verify a subsequent lower-priority attack is correlated to the existing higher-priority alert campaign."""
        # 1. Send SQL injection (Priority 50)
        sqli_payload = {
            "ip": "192.168.30.30",
            "username": "attacker' or '1'='1'",
            "user_agent": "Mozilla",
            "event_type": "api_access",
            "timestamp": int(timezone.now().timestamp()),
        }
        process_message(sqli_payload)
        
        # Verify alert created
        alert = Alert.objects.filter(log__ip_address="192.168.30.30", status="active").first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.attack_type, "sql_injection")
        self.assertEqual(alert.attack_count, 1)

        # Create 5 preceding login failures in the database to trigger brute force for the 2nd request
        for _ in range(5):
            Log.objects.create(
                ip_address="192.168.30.30",
                event_type="login_failure",
                failed_attempts=0,
                user_agent="Mozilla",
                username="victim",
                timestamp=timezone.now(),
                raw_payload={}
            )

        # 2. Send brute force (Priority 30)
        bf_payload = {
            "ip": "192.168.30.30",
            "username": "victim",
            "user_agent": "Mozilla",
            "event_type": "login_failure",
            "timestamp": int(timezone.now().timestamp()),
            "failed_attempts": 6
        }
        process_message(bf_payload)

        # Verify no new alert was created, and existing alert is updated but keeps primary classification
        alerts = Alert.objects.filter(log__ip_address="192.168.30.30", status="active")
        self.assertEqual(alerts.count(), 1)
        alert = alerts.first()
        self.assertEqual(alert.attack_type, "sql_injection")
        self.assertEqual(alert.attack_count, 2)

    def test_alert_promotion_low_priority_first(self):
        """Verify an existing lower-priority alert campaign is upgraded to a higher-priority type when one is detected."""
        # Create 5 preceding login failures in the database to trigger brute force for the 1st request
        for _ in range(5):
            Log.objects.create(
                ip_address="192.168.40.40",
                event_type="login_failure",
                failed_attempts=0,
                user_agent="Mozilla",
                username="victim",
                timestamp=timezone.now(),
                raw_payload={}
            )

        # 1. Send brute force first
        bf_payload = {
            "ip": "192.168.40.40",
            "username": "victim",
            "user_agent": "Mozilla",
            "event_type": "login_failure",
            "timestamp": int(timezone.now().timestamp()),
            "failed_attempts": 6
        }
        process_message(bf_payload)
        
        alert = Alert.objects.filter(log__ip_address="192.168.40.40", status="active").first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.attack_type, "brute_force")
        self.assertEqual(alert.attack_count, 1)

        # 2. Send SQL injection next
        sqli_payload = {
            "ip": "192.168.40.40",
            "username": "attacker' or '1'='1'",
            "user_agent": "Mozilla",
            "event_type": "api_access",
            "timestamp": int(timezone.now().timestamp()),
        }
        process_message(sqli_payload)

        # Verify active alert is upgraded
        alerts = Alert.objects.filter(log__ip_address="192.168.40.40", status="active")
        self.assertEqual(alerts.count(), 1)
        alert = alerts.first()
        self.assertEqual(alert.attack_type, "sql_injection")
        self.assertEqual(alert.attack_count, 2)
        self.assertIn("SQL injection", alert.reason)

    def test_incident_promotion_low_priority_first(self):
        """Verify that when an alert is promoted, its linked open incident is also promoted."""
        # Send 8 brute force attacks to trigger auto incident creation
        bf_payload = {
            "ip": "192.168.50.50",
            "username": "victim",
            "user_agent": "Mozilla",
            "event_type": "login_failure",
            "timestamp": int(timezone.now().timestamp()),
            "failed_attempts": 0
        }
        for _ in range(8):
            process_message(bf_payload)

        # Verify incident exists and is brute_force
        incident = Incident.objects.filter(source_ip="192.168.50.50", status="open").first()
        self.assertIsNotNone(incident)
        self.assertEqual(incident.attack_type, "brute_force")
        self.assertEqual(incident.title, "Auto: Brute Force from 192.168.50.50")

        # Now send SQL injection payload
        sqli_payload = {
            "ip": "192.168.50.50",
            "username": "attacker' or '1'='1'",
            "user_agent": "Mozilla",
            "event_type": "api_access",
            "timestamp": int(timezone.now().timestamp()),
        }
        process_message(sqli_payload)

        # Verify incident and alert are promoted
        incident.refresh_from_db()
        self.assertEqual(incident.attack_type, "sql_injection")
        self.assertEqual(incident.title, "Auto: SQL Injection from 192.168.50.50")

    def test_account_compromise_detection_new_incident(self):
        """Verify that a successful login after multiple failures triggers a compromise alert and creates a Critical incident."""
        ip = "192.168.60.60"
        username = "admin"
        
        # Send 3 failed attempts (so it meets the 'multiple' threshold)
        payload_fail = {
            "ip": ip,
            "username": username,
            "user_agent": "Mozilla",
            "event_type": "login_failure",
            "timestamp": int(timezone.now().timestamp()),
            "failed_attempts": 0
        }
        for _ in range(3):
            process_message(payload_fail)

        # Send successful login
        payload_success = {
            "ip": ip,
            "username": username,
            "user_agent": "Mozilla",
            "event_type": "login_success",
            "timestamp": int(timezone.now().timestamp()),
        }
        process_message(payload_success)

        # Verify Alert created and marked compromise
        alert = Alert.objects.filter(log__ip_address=ip, verdict="ATTACK").first()
        self.assertIsNotNone(alert)
        self.assertTrue(alert.compromise_detected)
        self.assertEqual(alert.attack_type, "suspicious_login")
        self.assertIn("Possible account compromise", alert.reason)

        # Verify Critical Incident was auto-created
        incident = Incident.objects.filter(source_ip=ip, status="open").first()
        self.assertIsNotNone(incident)
        self.assertEqual(incident.severity, "critical")
        self.assertEqual(incident.attack_type, "suspicious_login")
        self.assertTrue(incident.compromise_detected)

    def test_account_compromise_escalates_existing_incident(self):
        """Verify that compromise warning escalates an existing open incident to Critical."""
        ip = "192.168.70.70"
        username = "admin"
        
        # Ingest 8 failed attempts to auto-create a brute force incident
        payload_fail = {
            "ip": ip,
            "username": username,
            "user_agent": "Mozilla",
            "event_type": "login_failure",
            "timestamp": int(timezone.now().timestamp()),
            "failed_attempts": 0
        }
        for _ in range(8):
            process_message(payload_fail)
            
        incident = Incident.objects.filter(source_ip=ip, status="open").first()
        self.assertIsNotNone(incident)
        self.assertEqual(incident.severity, "high")
        self.assertFalse(incident.compromise_detected)

        # Send successful login
        payload_success = {
            "ip": ip,
            "username": username,
            "user_agent": "Mozilla",
            "event_type": "login_success",
            "timestamp": int(timezone.now().timestamp()),
        }
        process_message(payload_success)

        # Verify incident escalated to Critical and compromise_detected set to True
        incident.refresh_from_db()
        self.assertEqual(incident.severity, "critical")
        self.assertTrue(incident.compromise_detected)
        self.assertEqual(incident.attack_type, "brute_force")

    def test_credential_stuffing_compromise_detection(self):
        """Verify that credential stuffing failures across multiple usernames trigger a compromise alert upon a successful login."""
        ip = "192.168.99.99"
        usernames = ["userA", "userB", "userC"]
        for u in usernames:
            process_message({
                "ip": ip,
                "username": u,
                "user_agent": "Mozilla",
                "event_type": "login_failure",
                "timestamp": int(timezone.now().timestamp())
            })
        
        # Verify no compromise detected yet
        self.assertEqual(Alert.objects.filter(log__ip_address=ip, compromise_detected=True).count(), 0)

        # Successful login on a different username
        process_message({
            "ip": ip,
            "username": "userD",
            "user_agent": "Mozilla",
            "event_type": "login_success",
            "timestamp": int(timezone.now().timestamp())
        })

        # Verify compromise alert created
        alert = Alert.objects.filter(log__ip_address=ip, compromise_detected=True).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.verdict, "ATTACK")
        self.assertIn("Possible account compromise", alert.reason)

    def test_investigation_notes_persistence(self):
        """Verify GET and POST endpoints for IP investigation notes."""
        ip = "192.168.99.99"
        url = reverse('ip-notes')

        # 1. Fetch empty note
        response = self.client.get(f"{url}?ip={ip}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['notes'], "")

        # 2. Save note
        save_data = {"ip_address": ip, "notes": "Persistent SOC notes text"}
        response = self.client.post(url, save_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['notes'], "Persistent SOC notes text")

        # 3. Retrieve note again
        response = self.client.get(f"{url}?ip={ip}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['notes'], "Persistent SOC notes text")

    def test_alert_upgrade_history_preservation(self):
        """Verify that Alert reason preserves threat upgrades and verdict escalations."""
        ip = "1.2.3.4"
        
        # 1. Trigger low priority attack (e.g. blacklisted IP)
        process_message({
            "ip": ip,
            "username": "attacker",
            "user_agent": "Mozilla",
            "event_type": "api_access",
            "timestamp": int(timezone.now().timestamp()),
            "failed_attempts": 0
        })
        
        alert = Alert.objects.filter(log__ip_address=ip, status="active").first()
        self.assertIsNotNone(alert)
        self.assertTrue(alert.reason.startswith("["))
        self.assertIn("matches", alert.reason)
        original_reason = alert.reason
        
        # 2. Trigger high priority SQL injection attack
        process_message({
            "ip": ip,
            "username": "attacker' or '1'='1'",
            "user_agent": "Mozilla",
            "event_type": "api_access",
            "timestamp": int(timezone.now().timestamp()),
            "failed_attempts": 0
        })
        
        alert.refresh_from_db()
        self.assertEqual(alert.attack_type, "sql_injection")
        self.assertIn(original_reason, alert.reason)
        self.assertIn("Upgraded to SQL Injection", alert.reason)

