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
    # New fields for richer investigation
    request_path = models.CharField(max_length=255, blank=True, null=True)
    source = models.CharField(max_length=50, blank=True, null=True)
    campaign_start = models.DateTimeField(blank=True, null=True)
    attack_count = models.IntegerField(default=0, blank=True, null=True)
    campaign_duration = models.IntegerField(blank=True, null=True)  # seconds
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Classification fields
    verdict = models.CharField(max_length=20, default='PENDING', blank=True)
    confidence = models.FloatField(default=0.0, blank=True)
    reason = models.TextField(default='Pending classification', blank=True)
    attack_type = models.CharField(max_length=50, default='none', blank=True)

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
        ('credential_stuffing', 'Credential Stuffing'),
        ('sql_injection', 'SQL Injection'),
        ('none', 'None'),
    ]

    log = models.OneToOneField(Log, on_delete=models.CASCADE)
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES)
    attack_type = models.CharField(max_length=50, choices=ATTACK_TYPE_CHOICES)
    confidence = models.FloatField()
    reason = models.TextField()
    is_reviewed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Correlation and tracking fields
    attack_count = models.IntegerField(default=1)
    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, default='active')
    compromise_detected = models.BooleanField(default=False)

    def __str__(self):
        return f"Alert: {self.verdict} - {self.attack_type}"

class BlockedIP(models.Model):
    ip_address = models.CharField(max_length=45, unique=True)
    reason = models.TextField(blank=True, default='')
    blocked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} (Blocked at {self.blocked_at})"


class InvestigationNote(models.Model):
    ip_address = models.CharField(max_length=45, unique=True)
    notes = models.TextField(blank=True, default='')
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Notes for {self.ip_address}"

