"""
URL patterns for the logs app API.
"""
from django.urls import path
from . import views

urlpatterns = [
    path("logs/",                  views.log_list,          name="log-list"),
    path("alerts/",                views.alert_list,        name="alert-list"),
    path("alerts/unreviewed/",     views.alert_unreviewed,  name="alert-unreviewed"),
    path("alerts/<int:pk>/",       views.alert_detail,      name="alert-detail"),
    path("stats/",                 views.stats,             name="stats"),
    path("blocked-ips/",           views.blocked_ip_list_create, name="blocked-ip-list-create"),
    path("blocked-ips/<str:ip_address>/", views.blocked_ip_delete, name="blocked-ip-delete"),
]

