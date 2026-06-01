from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.utils import timezone
import datetime

from logs.models import Log, Alert
from incidents.models import Incident

class ReportsTests(APITestCase):

    def setUp(self):
        # Create test logs & alerts
        self.now = timezone.now()
        
        self.log_normal = Log.objects.create(
            ip_address="192.168.1.50",
            event_type="api_access",
            failed_attempts=0,
            user_agent="Mozilla",
            username="user1",
            timestamp=self.now,
            raw_payload={}
        )
        self.alert_normal = Alert.objects.create(
            log=self.log_normal,
            verdict="NORMAL",
            attack_type="none",
            confidence=1.0,
            reason="conforms to normal signature rules"
        )

        self.log_attack = Log.objects.create(
            ip_address="45.33.32.156",
            event_type="login_failure",
            failed_attempts=8,
            user_agent="Mozilla",
            username="attacker",
            timestamp=self.now,
            raw_payload={}
        )
        self.alert_attack = Alert.objects.create(
            log=self.log_attack,
            verdict="ATTACK",
            attack_type="brute_force",
            confidence=0.95,
            reason="brute force logged"
        )

        # Create test incident
        self.incident = Incident.objects.create(
            title="Brute Force from 45.33.32.156",
            description="Automated report testing",
            severity="high",
            status="open",
            source_ip="45.33.32.156",
            attack_type="brute_force"
        )
        self.incident.alerts.add(self.alert_attack)

    def test_reports_dashboard_index(self):
        url = reverse('reports_index')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_daily_report_api(self):
        url = reverse('api_reports_daily')
        date_str = self.now.strftime('%Y-%m-%d')
        response = self.client.get(f"{url}?date={date_str}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['total_logs'], 2)
        self.assertEqual(response.data['total_attacks'], 1)
        self.assertEqual(response.data['total_suspicious'], 0)
        self.assertEqual(response.data['total_normal'], 1)
        self.assertEqual(response.data['total_incidents'], 1)
        self.assertEqual(response.data['detection_rate'], "50.0%")
        self.assertEqual(len(response.data['top_attacking_ips']), 1)
        self.assertEqual(response.data['top_attacking_ips'][0]['ip'], "45.33.32.156")

    def test_weekly_report_api(self):
        url = reverse('api_reports_weekly')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('summary', response.data)
        self.assertIn('daily_breakdown', response.data)
        self.assertEqual(len(response.data['daily_breakdown']), 7)
        self.assertEqual(response.data['summary']['total_logs'], 2)

    def test_top_ips_api(self):
        url = reverse('api_reports_top_ips')
        response = self.client.get(f"{url}?limit=5")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['ip_address'], "45.33.32.156")
        self.assertEqual(response.data[0]['total_attacks'], 1)

    def test_attack_types_api(self):
        url = reverse('api_reports_attack_types')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['type'], "brute_force")
        self.assertEqual(response.data[0]['count'], 1)

    def test_summary_api(self):
        url = reverse('api_reports_summary')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['total_logs'], 2)
        self.assertEqual(response.data['total_attacks'], 1)
        self.assertEqual(response.data['total_suspicious'], 0)
        self.assertEqual(response.data['total_normal'], 1)
        self.assertEqual(response.data['total_incidents'], 1)
        self.assertEqual(response.data['detection_rate'], "50.0%")
        self.assertEqual(len(response.data['attack_type_breakdown']), 1)
        self.assertEqual(len(response.data['hourly_trend']), 24)
        self.assertEqual(len(response.data['top_attacking_ips']), 1)
