from django.db import models

class Log(models.Model):
    EVENT_CHOICES = [
        ('login_success', 'Login Success'),
        ('login_failure', 'Login Failure'),
        ('api_access', 'API Access'),
    ]
    
    ip_address = models.CharField(max_length=45)
    event_type = models.CharField(max_length=50, choices=EVENT_CHOICES)
    failed_attempts = models.IntegerField(default=0)
    user_agent = models.TextField()
    username = models.CharField(max_length=150)
    timestamp = models.DateTimeField()
    raw_payload = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.event_type} from {self.ip_address}"

class Alert(models.Model):
    VERDICT_CHOICES = [
        ('ATTACK', 'Attack'),
        ('SUSPICIOUS', 'Suspicious'),
        ('NORMAL', 'Normal'),
    ]
    ATTACK_TYPE_CHOICES = [
        ('brute_force', 'Brute Force'),
        ('suspicious_login', 'Suspicious Login'),
        ('blacklisted_ip', 'Blacklisted IP'),
        ('none', 'None'),
    ]

    log = models.OneToOneField(Log, on_delete=models.CASCADE)
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES)
    attack_type = models.CharField(max_length=50, choices=ATTACK_TYPE_CHOICES)
    confidence = models.FloatField()
    reason = models.TextField()
    is_reviewed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Alert: {self.verdict} - {self.attack_type}"

class BlockedIP(models.Model):
    ip_address = models.CharField(max_length=45, unique=True)
    reason = models.TextField(blank=True, default='')
    blocked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} (Blocked at {self.blocked_at})"

