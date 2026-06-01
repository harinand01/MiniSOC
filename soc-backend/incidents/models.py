from django.db import models
from logs.models import Alert

class Incident(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('closed', 'Closed'),
    ]

    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    source_ip = models.CharField(max_length=45)
    attack_type = models.CharField(max_length=100)
    alerts = models.ManyToManyField(Alert, related_name='incidents')
    assigned_to = models.CharField(max_length=100, blank=True, default='')
    investigation_notes = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        import django.utils.timezone as timezone
        if self.status == 'closed':
            if not self.resolved_at:
                self.resolved_at = timezone.now()
        else:
            self.resolved_at = None
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Incident #{self.id}: {self.title} ({self.status})"
