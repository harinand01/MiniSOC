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
        url = reverse('incident-list-create')
        response = self.client.post(url, self.incident_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['title'], "Manual Test Incident")
        self.assertEqual(response.data['alerts_count'], 1)

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
            "failed_attempts": 6
        }

        # First message
        process_message(payload)
        self.assertEqual(Incident.objects.filter(source_ip="192.168.9.9").count(), 0)

        # Second message
        process_message(payload)
        self.assertEqual(Incident.objects.filter(source_ip="192.168.9.9").count(), 0)

        # Third message -> triggers auto creation!
        process_message(payload)
        self.assertEqual(Incident.objects.filter(source_ip="192.168.9.9").count(), 1)
        
        # Verify details of auto-created incident
        inc = Incident.objects.get(source_ip="192.168.9.9")
        self.assertEqual(inc.title, "Auto: Brute Force from 192.168.9.9")
        self.assertEqual(inc.severity, "high")
        self.assertEqual(inc.status, "open")
        self.assertEqual(inc.alerts.count(), 3)
