"""
Serializers for Log and Alert models.
"""
from rest_framework import serializers
from .models import Log, Alert, BlockedIP



class LogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Log
        fields = [
            "id", "ip_address", "event_type", "failed_attempts",
            "username", "user_agent", "timestamp", "created_at", "raw_payload",
        ]


class AlertSerializer(serializers.ModelSerializer):
    # Inline log info so the dashboard doesn't need a second request
    ip_address   = serializers.CharField(source="log.ip_address",   read_only=True)
    event_type   = serializers.CharField(source="log.event_type",   read_only=True)
    username     = serializers.CharField(source="log.username",      read_only=True)
    timestamp    = serializers.DateTimeField(source="log.timestamp", read_only=True)
    log_id       = serializers.IntegerField(source="log.id",         read_only=True)

    class Meta:
        model = Alert
        fields = [
            "id", "log_id", "ip_address", "event_type", "username",
            "timestamp", "verdict", "attack_type", "confidence",
            "reason", "is_reviewed", "created_at",
        ]


class BlockedIPSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedIP
        fields = ["id", "ip_address", "reason", "blocked_at"]

