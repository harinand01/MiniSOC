import random
import time
from faker import Faker

fake = Faker()

EVENT_TYPES = ['login_success', 'login_failure', 'api_access']

# A mechanism to occasionally simulate a brute force attack
attack_ips = {}

def generate_random_event():
    return {
        "ip": fake.ipv4(),
        "username": fake.user_name(),
        "user_agent": fake.user_agent(),
        "event_type": random.choice(EVENT_TYPES),
        "timestamp": int(time.time()),
        "failed_attempts": 0
    }

def generate_event():
    global attack_ips
    
    # 5% chance to simulate an attack (brute force)
    if random.random() < 0.05:
        if not attack_ips:
            attack_ips[fake.ipv4()] = 1
        
        attack_ip = random.choice(list(attack_ips.keys()))
        attack_ips[attack_ip] += 1
        
        event = {
            "ip": attack_ip,
            "username": fake.user_name(),
            "user_agent": fake.user_agent(),
            "event_type": "login_failure",
            "timestamp": int(time.time()),
            "failed_attempts": attack_ips[attack_ip]
        }
        
        # Clean up attack IP after 10 attempts to start fresh attacks later
        if attack_ips[attack_ip] > 10:
            del attack_ips[attack_ip]
            
        return event

    return generate_random_event()
