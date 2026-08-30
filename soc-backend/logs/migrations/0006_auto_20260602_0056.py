from django.db import migrations

def populate_blocked_ips(apps, schema_editor):
    BlockedIP = apps.get_model('logs', 'BlockedIP')
    blacklist_ips = [
        "10.0.0.1",
        "192.168.100.100",
        "1.2.3.4",
        "5.5.5.5",
        "45.33.32.156",
        "198.20.69.74",
        "66.240.192.138",
    ]
    for ip in blacklist_ips:
        BlockedIP.objects.get_or_create(
            ip_address=ip,
            defaults={'reason': 'Initial threat intelligence blacklist migration'}
        )

def remove_blocked_ips(apps, schema_editor):
    BlockedIP = apps.get_model('logs', 'BlockedIP')
    blacklist_ips = [
        "10.0.0.1",
        "192.168.100.100",
        "1.2.3.4",
        "5.5.5.5",
        "45.33.32.156",
        "198.20.69.74",
        "66.240.192.138",
    ]
    BlockedIP.objects.filter(ip_address__in=blacklist_ips).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('logs', '0005_alert_attack_count_alert_first_seen_alert_last_seen_and_more'),
    ]

    operations = [
        migrations.RunPython(populate_blocked_ips, remove_blocked_ips),
    ]
