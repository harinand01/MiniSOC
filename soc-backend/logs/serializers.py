"""
Serializers for Log and Alert models.
"""
from rest_framework import serializers
from .models import Log, Alert, BlockedIP, InvestigationNote



class LogSerializer(serializers.ModelSerializer):
    verdict = serializers.SerializerMethodField()
    confidence = serializers.SerializerMethodField()
    reason = serializers.SerializerMethodField()
    attack_type = serializers.SerializerMethodField()

    class Meta:
        model = Log
        fields = [
            "id", "ip_address", "event_type", "failed_attempts",
            "username", "user_agent", "timestamp", "created_at", "raw_payload",
            "verdict", "confidence", "reason", "attack_type",
        ]

    def get_verdict(self, obj):
        val = getattr(obj, 'verdict', None)
        if val is not None and val != "" and val != "PENDING":
            return val
        if hasattr(obj, 'alert') and obj.alert:
            return obj.alert.verdict
        return val if val else "PENDING"

    def get_confidence(self, obj):
        val = getattr(obj, 'confidence', None)
        if val is not None and val != 0.0:
            return val
        if hasattr(obj, 'alert') and obj.alert:
            return obj.alert.confidence
        return val if val is not None else 0.0

    def get_reason(self, obj):
        val = getattr(obj, 'reason', None)
        if val is not None and val != "" and val != "-" and val != "Pending classification":
            return val
        if hasattr(obj, 'alert') and obj.alert:
            return obj.alert.reason
        return val if val else "Pending classification"

    def get_attack_type(self, obj):
        val = getattr(obj, 'attack_type', None)
        if val is not None and val != "" and val != "none":
            return val
        if hasattr(obj, 'alert') and obj.alert:
            return obj.alert.attack_type
        return val if val else "none"


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
            "attack_count", "first_seen", "last_seen", "status",
            "compromise_detected",
        ]


class BlockedIPSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedIP
        fields = ["id", "ip_address", "reason", "blocked_at"]


class InvestigationNoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = InvestigationNote
        fields = ["id", "ip_address", "notes", "updated_at"]

