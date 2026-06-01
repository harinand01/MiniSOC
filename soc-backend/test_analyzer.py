"""
End-to-end test for the Rule-Based Threat Detection Engine.
Run from inside soc-backend/ with the venv active.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logs.rule_engine import analyze

test_cases = [
    (
        {"ip_address": "192.168.1.1", "failed_attempts": 8},
        "ATTACK",   # Brute force: > 5 attempts
    ),
    (
        {"ip_address": "10.0.0.1", "failed_attempts": 0},
        "ATTACK",   # Blacklisted IP
    ),
    (
        {"ip_address": "203.0.113.55", "failed_attempts": 4},
        "SUSPICIOUS",  # Suspicious login: failed_attempts is 4 (between 3 and 5)
    ),
    (
        {"ip_address": "172.20.1.5", "failed_attempts": 2},
        "NORMAL",   # Normal traffic: failed_attempts < 3
    ),
]

if __name__ == "__main__":
    print("=" * 60)
    print("  Rule-Based Analysis Engine - Test Suite")
    print("=" * 60)
    all_passed = True
    for log_data, expected in test_cases:
        result = analyze(log_data)
        passed = result["verdict"] == expected
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False
        print(f"\n[{status}] IP={log_data['ip_address']} failures={log_data['failed_attempts']}")
        print(f"       Expected : {expected}")
        print(f"       Got      : {result['verdict']} | {result['attack_type']} | confidence={result['confidence']}")
        print(f"       Reason   : {result['reason']}")

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED" if all_passed else "SOME TESTS FAILED")
    print("=" * 60)
    sys.exit(0 if all_passed else 1)
