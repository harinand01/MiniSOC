from django.contrib import admin
from .models import Log, Alert, BlockedIP

@admin.register(Log)
class LogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'event_type', 'username', 'failed_attempts', 'timestamp')
    list_filter = ('event_type',)
    search_fields = ('ip_address', 'username')

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('log', 'verdict', 'attack_type', 'confidence', 'is_reviewed', 'created_at')
    list_filter = ('verdict', 'attack_type', 'is_reviewed')
    search_fields = ('log__ip_address',)

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'blocked_at')
    search_fields = ('ip_address',)

