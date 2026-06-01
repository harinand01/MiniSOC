from rest_framework import serializers
from .models import Incident
from logs.serializers import AlertSerializer
from logs.models import Alert

class IncidentSerializer(serializers.ModelSerializer):
    alerts = AlertSerializer(many=True, read_only=True)
    alerts_count = serializers.IntegerField(source='alerts.count', read_only=True)
    alert_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False
    )

    class Meta:
        model = Incident
        fields = [
            'id', 'title', 'description', 'severity', 'status', 
            'source_ip', 'attack_type', 'alerts', 'alerts_count',
            'alert_ids', 'assigned_to', 'investigation_notes',
            'created_at', 'updated_at', 'resolved_at'
        ]

    def create(self, validated_data):
        alert_ids = validated_data.pop('alert_ids', [])
        incident = Incident.objects.create(**validated_data)
        if alert_ids:
            incident.alerts.set(Alert.objects.filter(id__in=alert_ids))
        return incident

    def update(self, instance, validated_data):
        alert_ids = validated_data.pop('alert_ids', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if alert_ids is not None:
            instance.alerts.set(Alert.objects.filter(id__in=alert_ids))
        return instance
