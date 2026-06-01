import unittest
from logs.rule_engine import analyze

class TestRuleEngine(unittest.TestCase):

    def test_rule_brute_force(self):
        """Rule: failed_attempts > 5 should be ATTACK and brute_force"""
        log_data = {
            "ip_address": "1.1.1.1",
            "failed_attempts": 6,
        }
        result = analyze(log_data)
        self.assertEqual(result['verdict'], 'ATTACK')
        self.assertEqual(result['attack_type'], 'brute_force')

    def test_rule_blacklist(self):
        """Rule: Blacklisted IP should be ATTACK and blacklisted_ip"""
        log_data = {
            "ip_address": "10.0.0.1",
            "failed_attempts": 0,
        }
        result = analyze(log_data)
        self.assertEqual(result['verdict'], 'ATTACK')
        self.assertEqual(result['attack_type'], 'blacklisted_ip')

    def test_suspicious_login(self):
        """Rule: failed_attempts between 3 and 5 should be SUSPICIOUS"""
        # Lower boundary
        log_data = {
            "ip_address": "192.168.1.50",
            "failed_attempts": 3,
        }
        result = analyze(log_data)
        self.assertEqual(result['verdict'], 'SUSPICIOUS')
        self.assertEqual(result['attack_type'], 'suspicious_login')

        # Upper boundary
        log_data["failed_attempts"] = 5
        result = analyze(log_data)
        self.assertEqual(result['verdict'], 'SUSPICIOUS')

    def test_rule_normal(self):
        """Normal behavior should return NORMAL"""
        log_data = {
            "ip_address": "192.168.1.50",
            "failed_attempts": 2,
        }
        result = analyze(log_data)
        self.assertEqual(result['verdict'], 'NORMAL')
        self.assertEqual(result['attack_type'], 'none')

        log_data["failed_attempts"] = 0
        result = analyze(log_data)
        self.assertEqual(result['verdict'], 'NORMAL')

    def test_brute_force_threshold(self):
        """Threshold checks for Brute Force"""
        log_data = {"failed_attempts": 5, "ip_address": "9.9.9.9"}
        result = analyze(log_data)
        self.assertEqual(result['verdict'], 'SUSPICIOUS')  # 5 is suspicious

        log_data["failed_attempts"] = 6
        result = analyze(log_data)
        self.assertEqual(result['verdict'], 'ATTACK')  # 6 is brute force

    def test_confidence_scores(self):
        """Verify confidence is within 0-1 range"""
        log_data = {"failed_attempts": 10, "ip_address": "1.1.1.1"}
        result = analyze(log_data)
        self.assertTrue(0 <= result['confidence'] <= 1)

    def test_reason_string(self):
        """Verify a reason is provided in the result"""
        log_data = {"ip_address": "10.0.0.1"}
        result = analyze(log_data)
        self.assertTrue(len(result['reason']) > 0)

if __name__ == '__main__':
    unittest.main()
