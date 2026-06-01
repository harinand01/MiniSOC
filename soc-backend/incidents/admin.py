from django.contrib import admin
from .models import Incident

@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'severity', 'status', 'source_ip', 'attack_type', 'assigned_to', 'created_at')
    list_filter = ('severity', 'status', 'attack_type')
    search_fields = ('title', 'source_ip', 'assigned_to', 'description')
    filter_horizontal = ('alerts',)
